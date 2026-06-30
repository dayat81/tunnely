#!/usr/bin/env python3
"""
Extended unit tests for SNI pipeline components.

Covers:
- SniParser edge cases (malformed TLS, truncated packets, weird extensions)
- DomainCache behavior (LRU, overflow, thread safety, TTL)
- PacketFlowTracker lifecycle (aging, eviction, reconnect, display logic)
- FlowEntry display properties (domain primary, IP secondary)
- Android-specific patterns (carrier NAT, split tunneling, background)
- Real-world TLS ClientHello variants
"""

import struct
import socket
import unittest
import threading
import time
from typing import Optional, List, Dict

# Import from the simulation module
from test_ssl_traffic_simulation import (
    extract_sni, build_ip_header, build_tcp_header, build_tls_client_hello,
    build_tls_server_hello, build_syn_packet, build_syn_ack_packet,
    build_ack_packet, build_data_packet, build_udp_packet, build_dns_query,
    PacketFlowTracker, DomainCache, FlowStats,
    CLIENT_IP, SERVER_IP, CDN_IP, API_IP, LOCAL_DNS,
    TLS_HANDSHAKE, CLIENT_HELLO, SNI_EXTENSION, SNI_HOST_NAME,
    TrafficSimulator,
)


# ============================================================
# Helpers
# ============================================================

def build_raw_tls_record(content_type: int, payload: bytes) -> bytes:
    """Build a raw TLS record (no IP/TCP wrapper)."""
    return bytes([content_type]) + struct.pack('!H', 0x0301) + struct.pack('!H', len(payload)) + payload


def build_malformed_client_hello(variant: str) -> bytes:
    """Build various malformed ClientHello packets for edge case testing."""
    if variant == "no_extensions":
        # ClientHello with empty extensions
        random = b'\x00' * 32
        session_id = b'\x00' * 0  # empty session
        cs_data = struct.pack('!H', 0x1301)  # single cipher suite
        compression = b'\x01\x00'
        extensions = b'\x00\x00'  # length=0, no extensions
        ch_body = (struct.pack('!H', 0x0303) + random +
                   bytes([len(session_id)]) + session_id +
                   struct.pack('!H', len(cs_data)) + cs_data +
                   compression +
                   extensions)
        ch = bytes([CLIENT_HELLO]) + bytes([(len(ch_body) >> 16) & 0xFF]) + struct.pack('!H', len(ch_body)) + ch_body
        return build_raw_tls_record(TLS_HANDSHAKE, ch)

    elif variant == "sni_with_multiple_names":
        # SNI extension with multiple server names (unusual but valid)
        sni_name1 = b'www.example.com'
        sni_name2 = b'api.example.com'
        sni_entry1 = bytes([SNI_HOST_NAME]) + struct.pack('!H', len(sni_name1)) + sni_name1
        sni_entry2 = bytes([SNI_HOST_NAME]) + struct.pack('!H', len(sni_name2)) + sni_name2
        sni_list = sni_entry1 + sni_entry2
        sni_ext_data = struct.pack('!H', len(sni_list)) + sni_list
        sni_ext = struct.pack('!HH', SNI_EXTENSION, len(sni_ext_data)) + sni_ext_data

        random = b'\x00' * 32
        cs_data = struct.pack('!H', 0x1301)
        compression = b'\x01\x00'
        extensions = struct.pack('!H', len(sni_ext)) + sni_ext
        ch_body = (struct.pack('!H', 0x0303) + random +
                   b'\x00' +  # session id len=0
                   struct.pack('!H', len(cs_data)) + cs_data +
                   compression +
                   extensions)
        ch = bytes([CLIENT_HELLO]) + bytes([(len(ch_body) >> 16) & 0xFF]) + struct.pack('!H', len(ch_body)) + ch_body
        return build_raw_tls_record(TLS_HANDSHAKE, ch)

    elif variant == "sni_empty_hostname":
        # SNI with empty hostname (type=0, length=0)
        sni_ext_data = struct.pack('!H', 3) + bytes([SNI_HOST_NAME]) + struct.pack('!H', 0)
        sni_ext = struct.pack('!HH', SNI_EXTENSION, len(sni_ext_data)) + sni_ext_data

        random = b'\x00' * 32
        cs_data = struct.pack('!H', 0x1301)
        compression = b'\x01\x00'
        extensions = struct.pack('!H', len(sni_ext)) + sni_ext
        ch_body = (struct.pack('!H', 0x0303) + random +
                   b'\x00' +
                   struct.pack('!H', len(cs_data)) + cs_data +
                   compression +
                   extensions)
        ch = bytes([CLIENT_HELLO]) + bytes([(len(ch_body) >> 16) & 0xFF]) + struct.pack('!H', len(ch_body)) + ch_body
        return build_raw_tls_record(TLS_HANDSHAKE, ch)

    elif variant == "sni_before_other_extensions":
        # SNI extension NOT at the start of extensions list
        other_ext = struct.pack('!HH', 0x000a, 4) + b'\x00\x02\x00\x1d'  # supported_groups
        sni_name = b'example.com'
        sni_ext_data = struct.pack('!H', 1 + 2 + len(sni_name)) + bytes([SNI_HOST_NAME]) + struct.pack('!H', len(sni_name)) + sni_name
        sni_ext = struct.pack('!HH', SNI_EXTENSION, len(sni_ext_data)) + sni_ext_data

        random = b'\x00' * 32
        cs_data = struct.pack('!H', 0x1301)
        compression = b'\x01\x00'
        extensions = struct.pack('!H', len(other_ext) + len(sni_ext)) + other_ext + sni_ext
        ch_body = (struct.pack('!H', 0x0303) + random +
                   b'\x00' +
                   struct.pack('!H', len(cs_data)) + cs_data +
                   compression +
                   extensions)
        ch = bytes([CLIENT_HELLO]) + bytes([(len(ch_body) >> 16) & 0xFF]) + struct.pack('!H', len(ch_body)) + ch_body
        return build_raw_tls_record(TLS_HANDSHAKE, ch)

    elif variant == "large_cipher_suites":
        # ClientHello with many cipher suites (like Chrome)
        cs_list = list(range(0x1301, 0x1301 + 50))  # 50 cipher suites
        cs_data = b''.join(struct.pack('!H', c) for c in cs_list)
        sni_name = b'google.com'
        sni_ext_data = struct.pack('!H', 1 + 2 + len(sni_name)) + bytes([SNI_HOST_NAME]) + struct.pack('!H', len(sni_name)) + sni_name
        sni_ext = struct.pack('!HH', SNI_EXTENSION, len(sni_ext_data)) + sni_ext_data

        random = b'\x00' * 32
        compression = b'\x01\x00'
        extensions = struct.pack('!H', len(sni_ext)) + sni_ext
        ch_body = (struct.pack('!H', 0x0303) + random +
                   b'\x00' +
                   struct.pack('!H', len(cs_data)) + cs_data +
                   compression +
                   extensions)
        ch = bytes([CLIENT_HELLO]) + bytes([(len(ch_body) >> 16) & 0xFF]) + struct.pack('!H', len(ch_body)) + ch_body
        return build_raw_tls_record(TLS_HANDSHAKE, ch)

    elif variant == "non_ascii_sni":
        # SNI with non-ASCII bytes (should return None)
        sni_bytes = bytes([0xFF, 0xFE, 0x80, 0x81])  # invalid ASCII
        sni_ext_data = struct.pack('!H', 1 + 2 + len(sni_bytes)) + bytes([SNI_HOST_NAME]) + struct.pack('!H', len(sni_bytes)) + sni_bytes
        sni_ext = struct.pack('!HH', SNI_EXTENSION, len(sni_ext_data)) + sni_ext_data

        random = b'\x00' * 32
        cs_data = struct.pack('!H', 0x1301)
        compression = b'\x01\x00'
        extensions = struct.pack('!H', len(sni_ext)) + sni_ext
        ch_body = (struct.pack('!H', 0x0303) + random +
                   b'\x00' +
                   struct.pack('!H', len(cs_data)) + cs_data +
                   compression +
                   extensions)
        ch = bytes([CLIENT_HELLO]) + bytes([(len(ch_body) >> 16) & 0xFF]) + struct.pack('!H', len(ch_body)) + ch_body
        return build_raw_tls_record(TLS_HANDSHAKE, ch)

    elif variant == "wrong_handshake_type":
        # Certificate message (type 11) instead of ClientHello (type 1)
        random = b'\x00' * 32
        body = struct.pack('!H', 0x0303) + random + b'\x00' + struct.pack('!H', 2) + b'\x00\x01' + b'\x01\x00' + b'\x00\x00'
        cert_msg = bytes([11]) + bytes([(len(body) >> 16) & 0xFF]) + struct.pack('!H', len(body)) + body
        return build_raw_tls_record(TLS_HANDSHAKE, cert_msg)

    elif variant == "wrong_content_type":
        # Application Data (0x17) instead of Handshake (0x16)
        random = b'\x00' * 32
        body = struct.pack('!H', 0x0303) + random + b'\x00' + struct.pack('!H', 2) + b'\x00\x01' + b'\x01\x00' + b'\x00\x00'
        ch = bytes([CLIENT_HELLO]) + bytes([(len(body) >> 16) & 0xFF]) + struct.pack('!H', len(body)) + body
        return build_raw_tls_record(0x17, ch)

    elif variant == "tls13":
        # TLS 1.3 style ClientHello with supported_versions extension
        sni_name = b'tls13.example.com'
        sni_ext_data = struct.pack('!H', 1 + 2 + len(sni_name)) + bytes([SNI_HOST_NAME]) + struct.pack('!H', len(sni_name)) + sni_name
        sni_ext = struct.pack('!HH', SNI_EXTENSION, len(sni_ext_data)) + sni_ext_data
        # supported_versions with TLS 1.3
        sv_ext = struct.pack('!HH', 0x002b, 3) + b'\x02\x03\x04'

        random = b'\x00' * 32
        cs_data = struct.pack('!H', 0x1301)
        compression = b'\x01\x00'
        extensions = struct.pack('!H', len(sni_ext) + len(sv_ext)) + sni_ext + sv_ext
        ch_body = (struct.pack('!H', 0x0303) + random +
                   b'\x00' +
                   struct.pack('!H', len(cs_data)) + cs_data +
                   compression +
                   extensions)
        ch = bytes([CLIENT_HELLO]) + bytes([(len(ch_body) >> 16) & 0xFF]) + struct.pack('!H', len(ch_body)) + ch_body
        return build_raw_tls_record(TLS_HANDSHAKE, ch)

    else:
        raise ValueError(f"Unknown variant: {variant}")


def wrap_in_ip_tcp(payload: bytes, src_ip=CLIENT_IP, dst_ip=SERVER_IP,
                   src_port=30000, dst_port=443, seq=100, ack=200) -> bytes:
    """Wrap TLS payload in IP+TCP headers."""
    return build_data_packet(src_ip, dst_ip, src_port, dst_port, seq, ack, payload)


# ============================================================
# Test: SniParser Edge Cases
# ============================================================

class TestSniParserEdgeCases(unittest.TestCase):
    """Edge cases for SNI extraction from TLS ClientHello."""

    def test_client_hello_no_extensions(self):
        """ClientHello with no extensions → no SNI."""
        ch = build_malformed_client_hello("no_extensions")
        pkt = wrap_in_ip_tcp(ch)
        self.assertIsNone(extract_sni(pkt))

    def test_sni_with_multiple_server_names(self):
        """SNI with multiple names → returns first one."""
        ch = build_malformed_client_hello("sni_with_multiple_names")
        pkt = wrap_in_ip_tcp(ch)
        domain = extract_sni(pkt)
        self.assertEqual(domain, "www.example.com")

    def test_sni_empty_hostname(self):
        """SNI with empty hostname → returns empty string."""
        ch = build_malformed_client_hello("sni_empty_hostname")
        pkt = wrap_in_ip_tcp(ch)
        domain = extract_sni(pkt)
        self.assertEqual(domain, "")

    def test_sni_not_first_extension(self):
        """SNI extension appears after other extensions."""
        ch = build_malformed_client_hello("sni_before_other_extensions")
        pkt = wrap_in_ip_tcp(ch)
        self.assertEqual(extract_sni(pkt), "example.com")

    def test_sni_with_large_cipher_suites(self):
        """Chrome-style ClientHello with 50 cipher suites."""
        ch = build_malformed_client_hello("large_cipher_suites")
        pkt = wrap_in_ip_tcp(ch)
        self.assertEqual(extract_sni(pkt), "google.com")

    def test_sni_non_ascii_bytes(self):
        """Non-ASCII bytes in SNI → returns None."""
        ch = build_malformed_client_hello("non_ascii_sni")
        pkt = wrap_in_ip_tcp(ch)
        self.assertIsNone(extract_sni(pkt))

    def test_wrong_handshake_type(self):
        """Certificate message (type 11) instead of ClientHello → None."""
        ch = build_malformed_client_hello("wrong_handshake_type")
        pkt = wrap_in_ip_tcp(ch)
        self.assertIsNone(extract_sni(pkt))

    def test_wrong_content_type(self):
        """Application Data (0x17) instead of Handshake (0x16) → None."""
        ch = build_malformed_client_hello("wrong_content_type")
        pkt = wrap_in_ip_tcp(ch)
        self.assertIsNone(extract_sni(pkt))

    def test_tls13_client_hello(self):
        """TLS 1.3 ClientHello with supported_versions extension."""
        ch = build_malformed_client_hello("tls13")
        pkt = wrap_in_ip_tcp(ch)
        self.assertEqual(extract_sni(pkt), "tls13.example.com")

    def test_ip_options_ihl_6(self):
        """IP header with options (IHL=6, 24 bytes instead of 20)."""
        # Build IP header with IHL=6 (24 bytes)
        ip = bytearray(24)
        ip[0] = (4 << 4) | 6  # version=4, IHL=6
        ip[1] = 0
        struct.pack_into('!H', ip, 2, 24 + 20 + 100)  # total length
        struct.pack_into('!H', ip, 4, 0x1234)
        struct.pack_into('!H', ip, 6, 0x4000)
        ip[8] = 64
        ip[9] = 6  # TCP
        struct.pack_into('!H', ip, 10, 0)  # checksum
        ip[12:16] = socket.inet_aton(CLIENT_IP)
        ip[16:20] = socket.inet_aton(SERVER_IP)
        # IP options (4 bytes padding)
        ip[20:24] = b'\x00\x00\x00\x00'

        tcp = build_tcp_header(30000, 443, 100, 200, 0x18,
                               build_tls_client_hello("options.example.com"))
        pkt = bytes(ip) + tcp
        self.assertEqual(extract_sni(pkt), "options.example.com")

    def test_tcp_with_options(self):
        """TCP header with options (data offset > 5)."""
        ch = build_tls_client_hello("tcpoptions.example.com")
        # TCP header with 8 extra bytes of options (data offset = 7)
        tcp_header = bytearray(7 * 4)  # 28 bytes
        struct.pack_into('!H', tcp_header, 0, 30000)
        struct.pack_into('!H', tcp_header, 2, 443)
        struct.pack_into('!I', tcp_header, 4, 100)
        struct.pack_into('!I', tcp_header, 8, 200)
        tcp_header[12] = (7 << 4)  # data offset = 7
        tcp_header[13] = 0x18  # PSH+ACK
        struct.pack_into('!H', tcp_header, 14, 65535)
        # TCP options (8 bytes)
        tcp_header[20:24] = b'\x02\x04\x05\xb4'  # MSS 1460
        tcp_header[24:28] = b'\x01\x01\x01\x01'  # NOP padding

        ip = build_ip_header(CLIENT_IP, SERVER_IP, 6, 28 + len(ch))
        pkt = ip + bytes(tcp_header) + ch
        self.assertEqual(extract_sni(pkt), "tcpoptions.example.com")

    def test_icmp_packet(self):
        """ICMP packet → returns None (not TCP)."""
        icmp = b'\x08\x00\x00\x00\x00\x01\x00\x01' + b'\x00' * 20
        pkt = build_ip_header(CLIENT_IP, SERVER_IP, 1, len(icmp)) + icmp
        self.assertIsNone(extract_sni(pkt))

    def test_gre_packet(self):
        """GRE packet → returns None (protocol 47)."""
        gre = b'\x00\x00\x08\x00' + b'\x00' * 20
        pkt = build_ip_header(CLIENT_IP, SERVER_IP, 47, len(gre)) + gre
        self.assertIsNone(extract_sni(pkt))

    def test_packet_exactly_minimum_size(self):
        """Packet exactly 20 bytes (IP header only, no TCP)."""
        pkt = build_ip_header(CLIENT_IP, SERVER_IP, 6, 0)
        self.assertIsNone(extract_sni(pkt))

    def test_tcp_no_payload(self):
        """TCP SYN with no payload → no TLS record."""
        pkt = build_syn_packet(CLIENT_IP, SERVER_IP, 30000, 443, 100)
        self.assertIsNone(extract_sni(pkt))

    def test_tls_record_truncated_after_header(self):
        """TLS record header present but payload truncated."""
        # TLS content type + version + length=100 but only 3 bytes of payload
        tls_header = bytes([TLS_HANDSHAKE]) + struct.pack('!H', 0x0301) + struct.pack('!H', 100)
        tls_payload = b'\x00\x00\x00'  # Only 3 bytes, need 6+
        tls_record = tls_header + tls_payload

        pkt = build_data_packet(CLIENT_IP, SERVER_IP, 30000, 443,
                                100, 200, tls_record)
        self.assertIsNone(extract_sni(pkt))

    def test_tls_record_very_small_length(self):
        """TLS record with length field smaller than actual data."""
        tls_record = bytes([TLS_HANDSHAKE]) + struct.pack('!H', 0x0301) + struct.pack('!H', 2) + b'\x01\x01'
        pkt = build_data_packet(CLIENT_IP, SERVER_IP, 30000, 443, 100, 200, tls_record)
        self.assertIsNone(extract_sni(pkt))


# ============================================================
# Test: DomainCache Behavior
# ============================================================

class TestDomainCacheExtended(unittest.TestCase):
    """Extended tests for DomainCache (mirrors DomainCache.kt)."""

    def test_basic_put_get(self):
        """Basic put/get works."""
        cache = DomainCache()
        cache.put_domain("1.2.3.4", "example.com")
        self.assertEqual(cache.get_domain("1.2.3.4"), "example.com")

    def test_case_normalization(self):
        """Domains stored in lowercase."""
        cache = DomainCache()
        cache.put_domain("1.2.3.4", "GOOGLE.COM")
        self.assertEqual(cache.get_domain("1.2.3.4"), "google.com")

    def test_overwrite_existing(self):
        """New domain overwrites old one for same IP."""
        cache = DomainCache()
        cache.put_domain("1.2.3.4", "old.example.com")
        cache.put_domain("1.2.3.4", "new.example.com")
        self.assertEqual(cache.get_domain("1.2.3.4"), "new.example.com")

    def test_missing_key_returns_none(self):
        """Unknown IP returns None."""
        cache = DomainCache()
        self.assertIsNone(cache.get_domain("10.0.0.1"))

    def test_lru_eviction_at_capacity(self):
        """Oldest entry evicted when MAX_ENTRIES reached."""
        cache = DomainCache()
        cache.MAX_ENTRIES = 3  # Override for testing

        cache.put_domain("1.0.0.1", "a.com")
        cache.put_domain("1.0.0.2", "b.com")
        cache.put_domain("1.0.0.3", "c.com")
        cache.put_domain("1.0.0.4", "d.com")  # Should evict "a.com"

        self.assertIsNone(cache.get_domain("1.0.0.1"))
        self.assertEqual(cache.get_domain("1.0.0.2"), "b.com")
        self.assertEqual(cache.get_domain("1.0.0.3"), "c.com")
        self.assertEqual(cache.get_domain("1.0.0.4"), "d.com")

    def test_lru_access_refreshes_order(self):
        """Accessing an entry does NOT refresh order in Python DomainCache.
        
        Python DomainCache uses dict iteration order (insertion-based FIFO eviction),
        NOT LinkedHashMap(accessOrder=true) like Kotlin.
        This test verifies the actual Python behavior.
        """
        cache = DomainCache()
        cache.MAX_ENTRIES = 3

        cache.put_domain("1.0.0.1", "a.com")
        cache.put_domain("1.0.0.2", "b.com")
        cache.put_domain("1.0.0.3", "c.com")

        # Access a.com — does NOT refresh order in Python dict
        cache.get_domain("1.0.0.1")

        # Add d.com — evicts oldest (a.com, insertion order)
        cache.put_domain("1.0.0.4", "d.com")

        # a.com is evicted (FIFO, not LRU) — Kotlin DomainCache IS LRU
        self.assertIsNone(cache.get_domain("1.0.0.1"))  # Evicted (FIFO)
        self.assertEqual(cache.get_domain("1.0.0.2"), "b.com")
        self.assertEqual(cache.get_domain("1.0.0.3"), "c.com")
        self.assertEqual(cache.get_domain("1.0.0.4"), "d.com")

    def test_clear_resets_cache(self):
        """clear() removes all entries."""
        cache = DomainCache()
        cache.put_domain("1.2.3.4", "example.com")
        cache.clear()
        self.assertIsNone(cache.get_domain("1.2.3.4"))
        self.assertEqual(cache.size(), 0)

    def test_size_tracking(self):
        """size() returns correct count."""
        cache = DomainCache()
        self.assertEqual(cache.size(), 0)
        cache.put_domain("1.0.0.1", "a.com")
        self.assertEqual(cache.size(), 1)
        cache.put_domain("1.0.0.2", "b.com")
        self.assertEqual(cache.size(), 2)

    def test_concurrent_access(self):
        """Thread-safe: multiple threads read/write simultaneously."""
        cache = DomainCache()
        errors = []

        def writer(start: int, count: int):
            try:
                for i in range(start, start + count):
                    cache.put_domain(f"10.0.{i // 256}.{i % 256}", f"site{i}.com")
            except Exception as e:
                errors.append(f"Writer: {e}")

        def reader(start: int, count: int):
            try:
                for i in range(start, start + count):
                    cache.get_domain(f"10.0.{i // 256}.{i % 256}")
            except Exception as e:
                errors.append(f"Reader: {e}")

        threads = []
        for t in range(4):
            threads.append(threading.Thread(target=writer, args=(t * 100, 100)))
            threads.append(threading.Thread(target=reader, args=(t * 100, 100)))

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        self.assertEqual(errors, [])

    def test_many_domains_no_crash(self):
        """1000 domains stored and retrieved correctly."""
        cache = DomainCache()
        for i in range(1000):
            cache.put_domain(f"10.{i // 256}.{i % 256}.1", f"domain{i}.com")

        self.assertEqual(cache.size(), 1000)
        # All 1000 fit (eviction triggers when size > MAX_ENTRIES, not >=)
        self.assertEqual(cache.get_domain("10.0.0.1"), "domain0.com")
        self.assertEqual(cache.get_domain("10.3.231.1"), "domain999.com")

        # Adding #1001 triggers eviction of first entry
        cache.put_domain("10.4.0.1", "overflow.com")
        self.assertEqual(cache.size(), 1000)
        self.assertIsNone(cache.get_domain("10.0.0.1"))  # Evicted
        self.assertEqual(cache.get_domain("10.4.0.1"), "overflow.com")


# ============================================================
# Test: PacketFlowTracker Lifecycle
# ============================================================

class TestFlowTrackerLifecycle(unittest.TestCase):
    """Test flow tracker lifecycle: connect, browse, disconnect, reconnect."""

    def test_empty_tracker(self):
        """New tracker has no flows."""
        tracker = PacketFlowTracker()
        self.assertEqual(len(tracker.get_flows()), 0)
        self.assertEqual(tracker.total_packets, 0)

    def test_connect_disconnect_reconnect(self):
        """Simulate connect → browse → disconnect → reconnect."""
        tracker = PacketFlowTracker()
        sim = TrafficSimulator()
        sim.tracker = tracker

        # Connect + browse
        sim.simulate_tls_connection("142.250.185.78", "google.com")
        self.assertGreater(len(tracker.flows), 0)
        self.assertGreater(tracker.sni_extracted, 0)

        # Disconnect (clear)
        tracker.clear()
        self.assertEqual(len(tracker.flows), 0)

        # Reconnect + browse
        sim.simulate_tls_connection("151.101.1.140", "reddit.com")
        self.assertGreater(len(tracker.flows), 0)

        flows = tracker.get_flows()
        tls_flows = [f for f in flows if f.protocol == "TCP" and f.domain]
        self.assertEqual(len(tls_flows), 1)
        self.assertEqual(tls_flows[0].domain, "reddit.com")

    def test_flow_bytes_accumulate(self):
        """Bytes accumulate correctly over multiple packets."""
        tracker = PacketFlowTracker()

        # Send 3 data packets to same destination
        for i in range(3):
            payload = b'x' * 100
            pkt = build_data_packet(CLIENT_IP, SERVER_IP, 30000, 443,
                                    100 + i * 100, 200, payload)
            tracker.process_packet(pkt, is_uplink=True)

        flows = tracker.get_flows()
        self.assertEqual(len(flows), 1)
        # Each packet = IP header (20) + TCP header (20) + payload (100) = 140 bytes
        self.assertEqual(flows[0].uplink_bytes, 140 * 3)

    def test_flow_direction_tracking(self):
        """Uplink and downlink bytes tracked separately."""
        tracker = PacketFlowTracker()

        # Uplink
        up = build_data_packet(CLIENT_IP, SERVER_IP, 30000, 443,
                               100, 200, b'x' * 50)
        tracker.process_packet(up, is_uplink=True)

        # Downlink
        down = build_data_packet(SERVER_IP, CLIENT_IP, 443, 30000,
                                 200, 100, b'y' * 200)
        tracker.process_packet(down, is_uplink=False)

        flows = tracker.get_flows()
        self.assertEqual(len(flows), 1)
        self.assertGreater(flows[0].uplink_bytes, 0)
        self.assertGreater(flows[0].downlink_bytes, 0)
        self.assertGreater(flows[0].downlink_bytes, flows[0].uplink_bytes)

    def test_flow_sort_by_bytes(self):
        """Flows sorted by total bytes descending."""
        tracker = PacketFlowTracker()
        sim = TrafficSimulator()
        sim.tracker = tracker

        # Small transfer
        sim.simulate_tls_connection("1.1.1.1", "small.example.com")
        # Large transfer (add extra data)
        for _ in range(10):
            sim.simulate_tls_connection("2.2.2.2", "large.example.com")

        flows = tracker.get_flows()
        tls_flows = [f for f in flows if f.protocol == "TCP" and f.remote_port == 443]

        # Verify sorted by total bytes descending
        for i in range(len(tls_flows) - 1):
            total_i = tls_flows[i].uplink_bytes + tls_flows[i].downlink_bytes
            total_next = tls_flows[i + 1].uplink_bytes + tls_flows[i + 1].downlink_bytes
            self.assertGreaterEqual(total_i, total_next)

    def test_flow_key_stability(self):
        """Same connection always maps to same flow key."""
        tracker = PacketFlowTracker()

        # Send packets from same src to same dst
        for i in range(5):
            pkt = build_data_packet(CLIENT_IP, SERVER_IP, 30000, 443,
                                    100 + i * 100, 200, b'\x00' * 10)
            tracker.process_packet(pkt, is_uplink=True)

        self.assertEqual(len(tracker.flows), 1)

    def test_different_src_ports_same_dst_single_flow(self):
        """Same dst but different src ports = SINGLE flow (keyed by remote, not local).
        
        Flow key = remote_ip:remote_port/proto. For uplink, remote = dst.
        Multiple local ports to same remote endpoint merge into one flow.
        """
        tracker = PacketFlowTracker()

        for port in [30000, 30001, 30002]:
            pkt = build_data_packet(CLIENT_IP, SERVER_IP, port, 443,
                                    100, 200, b'\x00' * 10)
            tracker.process_packet(pkt, is_uplink=True)

        # All merge into single flow (same remote = SERVER_IP:443)
        self.assertEqual(len(tracker.flows), 1)
        # Bytes accumulate from all 3 packets
        flows = tracker.get_flows()
        self.assertEqual(flows[0].uplink_bytes, 50 * 3)  # 50 bytes per packet (20+20+10)

    def test_udp_and_tcp_separate_flows(self):
        """Same IP, different protocols = different flows."""
        tracker = PacketFlowTracker()

        # TCP
        tcp = build_data_packet(CLIENT_IP, "1.1.1.1", 30000, 443, 100, 200, b'\x00' * 10)
        tracker.process_packet(tcp, is_uplink=True)

        # UDP
        udp = build_udp_packet(CLIENT_IP, "1.1.1.1", 30001, 443, b'\x00' * 10)
        tracker.process_packet(udp, is_uplink=True)

        self.assertEqual(len(tracker.flows), 2)


# ============================================================
# Test: Display Logic (FlowEntry equivalent)
# ============================================================

class TestDisplayLogic(unittest.TestCase):
    """Test how flows are displayed in the UI (mirrors FlowEntry.displayServer)."""

    def _make_flow(self, domain: Optional[str], ip: str, port: int) -> FlowStats:
        return FlowStats(remote_ip=ip, remote_port=port, protocol="TCP", domain=domain)

    def test_domain_primary_ip_secondary(self):
        """With domain: display shows domain, IP:port secondary."""
        flow = self._make_flow("google.com", "142.250.185.78", 443)
        # Mirrors FlowEntry.displayServer
        display = flow.domain if flow.domain else f"{flow.remote_ip}:{flow.remote_port}"
        self.assertEqual(display, "google.com")

    def test_ip_when_no_domain(self):
        """Without domain: display shows IP:port."""
        flow = self._make_flow(None, "142.250.185.78", 443)
        display = flow.domain if flow.domain else f"{flow.remote_ip}:{flow.remote_port}"
        self.assertEqual(display, "142.250.185.78:443")

    def test_non_standard_port_with_domain(self):
        """Domain on non-443 port shows domain, not port."""
        flow = self._make_flow("api.example.com", "1.2.3.4", 8443)
        display = flow.domain if flow.domain else f"{flow.remote_ip}:{flow.remote_port}"
        self.assertEqual(display, "api.example.com")

    def test_non_standard_port_without_domain(self):
        """Non-443 port without domain shows IP:port."""
        flow = self._make_flow(None, "1.2.3.4", 8080)
        display = flow.domain if flow.domain else f"{flow.remote_ip}:{flow.remote_port}"
        self.assertEqual(display, "1.2.3.4:8080")

    def test_dns_flow_no_domain(self):
        """DNS flow (UDP :53) has no domain."""
        flow = FlowStats(remote_ip="8.8.8.8", remote_port=53, protocol="UDP")
        display = flow.domain if flow.domain else f"{flow.remote_ip}:{flow.remote_port}"
        self.assertEqual(display, "8.8.8.8:53")

    def test_icmp_flow_no_domain(self):
        """ICMP flow has no domain."""
        flow = FlowStats(remote_ip="1.1.1.1", remote_port=0, protocol="ICMP")
        display = flow.domain if flow.domain else f"{flow.remote_ip}:{flow.remote_port}"
        self.assertEqual(display, "1.1.1.1:0")


# ============================================================
# Test: Android-Specific Patterns
# ============================================================

class TestAndroidPatterns(unittest.TestCase):
    """Test patterns specific to Android VPN usage."""

    def test_indonesian_carrier_nat_rebind(self):
        """Indonesian carrier rebinds UDP port — same IP, different dst ports.
        
        Flow key includes dst port. Different DNS servers = different flows.
        Same src port change doesn't create new flow (keyed by remote).
        """
        tracker = PacketFlowTracker()

        # DNS to Google (8.8.8.8:53)
        pkt1 = build_udp_packet("119.235.222.139", "8.8.8.8", 12345, 53,
                                build_dns_query("google.com"))
        tracker.process_packet(pkt1, is_uplink=True)

        # DNS to Cloudflare (1.1.1.1:53) — different remote = different flow
        pkt2 = build_udp_packet("119.235.222.139", "1.1.1.1", 54321, 53,
                                build_dns_query("example.com"))
        tracker.process_packet(pkt2, is_uplink=True)

        flows = tracker.get_flows()
        self.assertEqual(len(flows), 2)  # Different remotes

        # But same remote with different src port = same flow
        pkt3 = build_udp_packet("119.235.222.139", "8.8.8.8", 55555, 53,
                                build_dns_query("test.com"))
        tracker.process_packet(pkt3, is_uplink=True)

        flows = tracker.get_flows()
        self.assertEqual(len(flows), 2)  # Still 2 (8.8.8.8:53 merged)

    def test_background_app_traffic(self):
        """Background apps generate small keepalive packets."""
        tracker = PacketFlowTracker()
        sim = TrafficSimulator()
        sim.tracker = tracker

        # Simulate background noise
        sim.simulate_background_noise()

        flows = tracker.get_flows()
        # Should have mDNS (5353), NTP (123), and GCM (5228)
        self.assertGreaterEqual(len(flows), 3)

        # None should have domains (non-TLS)
        for f in flows:
            self.assertIsNone(f.domain)

    def test_split_tunnel_excluded_app(self):
        """Excluded app traffic is NOT tracked (would not reach tracker)."""
        tracker = PacketFlowTracker()

        # Only process packets that would bypass the VPN
        # In reality, excluded apps' packets don't reach processPacket at all
        # Simulate: only packets from VPN tunnel are processed

        # This is a TCP connection that WOULD go through VPN
        pkt = build_data_packet(CLIENT_IP, SERVER_IP, 30000, 443,
                                100, 200, build_tls_client_hello("example.com"))
        tracker.process_packet(pkt, is_uplink=True)

        flows = tracker.get_flows()
        self.assertEqual(len(flows), 1)

    def test_quic_traffic_udp_443(self):
        """QUIC traffic on UDP :443 — no SNI in UDP."""
        tracker = PacketFlowTracker()

        # QUIC uses UDP :443 but SNI is encrypted in QUIC
        quic_pkt = build_udp_packet(CLIENT_IP, "142.250.185.78", 30000, 443,
                                    b'\x00' * 100)
        tracker.process_packet(quic_pkt, is_uplink=True)

        flows = tracker.get_flows()
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].protocol, "UDP")
        self.assertIsNone(flows[0].domain)

    def test_dns_over_https_traffic(self):
        """DNS-over-HTTPS shows as regular TLS to Cloudflare/Google."""
        tracker = PacketFlowTracker()
        sim = TrafficSimulator()
        sim.tracker = tracker

        # DoH to Cloudflare
        sim.simulate_tls_connection("1.1.1.1", "cloudflare-dns.com")

        flows = tracker.get_flows()
        tls_flows = [f for f in flows if f.protocol == "TCP" and f.domain]
        self.assertTrue(any(f.domain == "cloudflare-dns.com" for f in tls_flows))

    def test_multiple_connections_same_domain(self):
        """Multiple connections to same domain merge into one flow.
        
        Flow key = remote_ip:remote_port/proto. All 3 connections go to
        SERVER_IP:443, so they merge into a single flow with accumulated bytes.
        """
        tracker = PacketFlowTracker()

        for port in [30000, 30001, 30002]:
            pkt = build_data_packet(CLIENT_IP, SERVER_IP, port, 443,
                                    100, 200,
                                    build_tls_client_hello("google.com"))
            tracker.process_packet(pkt, is_uplink=True)

        flows = tracker.get_flows()
        # All merge into single flow (same remote)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].domain, "google.com")
        # Bytes accumulated from all 3 packets
        self.assertGreater(flows[0].uplink_bytes, 0)

    def test_high_port_tls(self):
        """TLS on high ports (CDN, custom services)."""
        tracker = PacketFlowTracker()

        ports = [8443, 9443, 2096, 8080, 8888]
        for port in ports:
            pkt = build_data_packet(CLIENT_IP, "1.2.3.4", 30000 + port, port,
                                    100, 200,
                                    build_tls_client_hello(f"port{port}.example.com"))
            tracker.process_packet(pkt, is_uplink=True)

        flows = tracker.get_flows()
        self.assertEqual(len(flows), 5)
        for f in flows:
            self.assertIsNotNone(f.domain)


# ============================================================
# Test: Stress & Performance
# ============================================================

class TestStress(unittest.TestCase):
    """Stress tests for high-throughput scenarios."""

    def test_1000_flows_performance(self):
        """1000 flows tracked without degradation."""
        tracker = PacketFlowTracker()
        start = time.time()

        for i in range(1000):
            ip = f"10.{i // 256}.{i % 256}.{(i * 7) % 256}"
            pkt = build_data_packet(CLIENT_IP, ip, 30000, 443,
                                    100, 200,
                                    build_tls_client_hello(f"site{i}.example.com"))
            tracker.process_packet(pkt, is_uplink=True)

        elapsed = time.time() - start
        flows = tracker.get_flows()

        self.assertEqual(len(flows), 500)  # MAX_FLOWS = 500
        self.assertLess(elapsed, 5.0, f"1000 flows took {elapsed:.1f}s, too slow")
        self.assertEqual(tracker.sni_extracted, 1000)

    def test_rapid_packet_processing(self):
        """Process 10000 packets rapidly."""
        tracker = PacketFlowTracker()
        start = time.time()

        for i in range(10000):
            payload = b'\x00' * (10 + (i % 100))
            pkt = build_data_packet(CLIENT_IP, SERVER_IP, 30000, 443,
                                    100 + i * 100, 200, payload)
            tracker.process_packet(pkt, is_uplink=(i % 3 != 0))  # Mix up/down

        elapsed = time.time() - start
        self.assertLess(elapsed, 10.0, f"10000 packets took {elapsed:.1f}s")
        self.assertEqual(tracker.total_packets, 10000)

    def test_debug_stats_after_stress(self):
        """Debug stats remain consistent after stress."""
        tracker = PacketFlowTracker()
        sim = TrafficSimulator()
        sim.tracker = tracker

        # 50 connections
        for i in range(50):
            ip = f"10.0.{i // 256}.{i % 256}"
            sim.simulate_tls_connection(ip, f"stress{i}.example.com")

        stats = tracker.get_debug_stats()
        self.assertIn("packets=", stats)
        self.assertIn("sniExtracted=50", stats)


if __name__ == '__main__':
    unittest.main(verbosity=2)
