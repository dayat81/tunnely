#!/usr/bin/env python3
"""
Exhaustive edge cases for SNI pipeline components.

Covers boundary conditions, protocol variants, and real-world quirks:
- SniParser: max-length hostnames, TLS record variants, fragments, TCP flags
- DomainCache: boundary values, domain formats, many-to-one mappings
- PacketFlowTracker: timeout, stale cleanup, zero-byte packets, protocol mix
- Display: extreme values, formatting edge cases
- Android: IPv6, multicast, loopback, DNS responses, TCP keepalive
- Integration: timing, domain injection order, cache consistency
"""

import struct
import socket
import unittest
import threading
import time
from typing import Optional

from test_ssl_traffic_simulation import (
    extract_sni, build_ip_header, build_tcp_header, build_tls_client_hello,
    build_tls_server_hello, build_syn_packet, build_syn_ack_packet,
    build_ack_packet, build_data_packet, build_udp_packet, build_dns_query,
    PacketFlowTracker, DomainCache, FlowStats, TrafficSimulator,
    CLIENT_IP, SERVER_IP, CDN_IP, API_IP, TLS_HANDSHAKE, CLIENT_HELLO,
    SNI_EXTENSION, SNI_HOST_NAME,
)


# ============================================================
# Helpers
# ============================================================

def build_raw_client_hello(sni_hostname: str = None,
                           session_id: bytes = b'',
                           extensions: bytes = None,
                           cipher_suites: bytes = None) -> bytes:
    """Build a raw TLS ClientHello (not wrapped in IP/TCP).
    
    extensions: raw extension data WITHOUT length prefix (caller adds it)
    cipher_suites: raw cipher suite bytes WITHOUT length prefix
    """
    random = b'\x00' * 32

    if not session_id:
        session_id = b''

    if cipher_suites is None:
        cipher_suites = struct.pack('!H', 0x1301)

    if extensions is None:
        ext_parts = b''
        if sni_hostname:
            sni_bytes = sni_hostname.encode('ascii')
            sni_entry = bytes([SNI_HOST_NAME]) + struct.pack('!H', len(sni_bytes)) + sni_bytes
            sni_list = struct.pack('!H', len(sni_entry)) + sni_entry
            sni_ext = struct.pack('!HH', SNI_EXTENSION, len(sni_list)) + sni_list
            ext_parts += sni_ext
        extensions = struct.pack('!H', len(ext_parts)) + ext_parts

    compression = b'\x01\x00'  # length=1, method=null

    ch_body = (
        struct.pack('!H', 0x0303) + random +
        bytes([len(session_id)]) + session_id +
        struct.pack('!H', len(cipher_suites)) + cipher_suites +
        compression + extensions
    )
    ch = (bytes([CLIENT_HELLO]) +
          bytes([(len(ch_body) >> 16) & 0xFF]) +
          struct.pack('!H', len(ch_body)) +
          ch_body)
    return (bytes([TLS_HANDSHAKE]) +
            struct.pack('!H', 0x0301) +
            struct.pack('!H', len(ch)) +
            ch)


def wrap_in_ip_tcp(payload: bytes, src_ip=CLIENT_IP, dst_ip=SERVER_IP,
                   src_port=30000, dst_port=443, seq=100, ack=200) -> bytes:
    return build_data_packet(src_ip, dst_ip, src_port, dst_port, seq, ack, payload)


def make_ip_packet(protocol: int, payload: bytes, src_ip=CLIENT_IP,
                   dst_ip=SERVER_IP, flags: int = 0x4000, fragment_offset: int = 0) -> bytes:
    """Build IP packet with custom flags/fragment offset."""
    header = bytearray(20)
    header[0] = (4 << 4) | 5  # IPv4, IHL=5
    struct.pack_into('!H', header, 2, 20 + len(payload))
    struct.pack_into('!H', header, 4, 0x1234)  # ID
    struct.pack_into('!H', header, 6, flags | fragment_offset)
    header[8] = 64  # TTL
    header[9] = protocol
    header[12:16] = socket.inet_aton(src_ip)
    header[16:20] = socket.inet_aton(dst_ip)
    return bytes(header) + payload


# ============================================================
# Test: SniParser — Hostname Boundary Values
# ============================================================

class TestSniParserHostnameBounds(unittest.TestCase):
    """Test SNI extraction with various hostname lengths and formats."""

    def test_single_label_domain(self):
        """Single-label domain (no dots)."""
        pkt = wrap_in_ip_tcp(build_raw_client_hello("localhost"))
        self.assertEqual(extract_sni(pkt), "localhost")

    def test_two_label_domain(self):
        """Minimal two-label domain."""
        pkt = wrap_in_ip_tcp(build_raw_client_hello("a.b"))
        self.assertEqual(extract_sni(pkt), "a.b")

    def test_long_subdomain_chain(self):
        """Deeply nested subdomain."""
        hostname = "a.b.c.d.e.f.g.h.i.j.example.com"
        pkt = wrap_in_ip_tcp(build_raw_client_hello(hostname))
        self.assertEqual(extract_sni(pkt), hostname)

    def test_max_length_hostname(self):
        """Maximum SNI hostname (253 chars — DNS limit)."""
        # Build 253-char hostname: "a." * 126 + "com" = 255... let's do 253
        labels = []
        remaining = 253
        while remaining > 0:
            label_len = min(63, remaining - 1)  # Leave room for dot
            if label_len <= 0:
                break
            labels.append("a" * label_len)
            remaining -= (label_len + 1)  # +1 for dot
        hostname = ".".join(labels)
        if len(hostname) > 253:
            hostname = hostname[:253]

        pkt = wrap_in_ip_tcp(build_raw_client_hello(hostname))
        result = extract_sni(pkt)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), len(hostname))

    def test_single_char_labels(self):
        """Domain with single-char labels."""
        hostname = "a.b.c.d.e"
        pkt = wrap_in_ip_tcp(build_raw_client_hello(hostname))
        self.assertEqual(extract_sni(pkt), hostname)

    def test_numeric_labels(self):
        """Domain with only numeric labels."""
        hostname = "123.456.789"
        pkt = wrap_in_ip_tcp(build_raw_client_hello(hostname))
        self.assertEqual(extract_sni(pkt), hostname)

    def test_hyphenated_domain(self):
        """Domain with hyphens."""
        hostname = "my-app.sub-domain.example-site.com"
        pkt = wrap_in_ip_tcp(build_raw_client_hello(hostname))
        self.assertEqual(extract_sni(pkt), hostname)

    def test_wildcard_like_domain(self):
        """Domain with asterisk (wildcard cert)."""
        hostname = "*.example.com"
        pkt = wrap_in_ip_tcp(build_raw_client_hello(hostname))
        # Asterisk is valid ASCII, should be extracted
        self.assertEqual(extract_sni(pkt), hostname)

    def test_ip_address_as_sni(self):
        """SNI with IP address literal."""
        hostname = "192.168.1.1"
        pkt = wrap_in_ip_tcp(build_raw_client_hello(hostname))
        self.assertEqual(extract_sni(pkt), hostname)

    def test_localhost_sni(self):
        """SNI = 'localhost'."""
        pkt = wrap_in_ip_tcp(build_raw_client_hello("localhost"))
        self.assertEqual(extract_sni(pkt), "localhost")


# ============================================================
# Test: SniParser — TLS Record Variants
# ============================================================

class TestSniParserTlsVariants(unittest.TestCase):
    """Test various TLS record structures."""

    def test_tls10_record_version(self):
        """TLS 1.0 record version (0x0301)."""
        ch = build_raw_client_hello("tls10.example.com")
        # Verify it has TLS 1.0 record version
        self.assertEqual(ch[1:3], b'\x03\x01')
        pkt = wrap_in_ip_tcp(ch)
        self.assertEqual(extract_sni(pkt), "tls10.example.com")

    def test_tls12_record_version(self):
        """TLS 1.2 record version (0x0303)."""
        ch = build_raw_client_hello("tls12.example.com")
        # Modify record version to 1.2
        ch = ch[:1] + b'\x03\x03' + ch[3:]
        pkt = wrap_in_ip_tcp(ch)
        self.assertEqual(extract_sni(pkt), "tls12.example.com")

    def test_client_hello_with_session_id(self):
        """ClientHello with non-empty session ID (resumption)."""
        session_id = b'\x01\x02\x03\x04\x05\x06\x07\x08' * 4  # 32 bytes
        ch = build_raw_client_hello("resume.example.com", session_id=session_id)
        pkt = wrap_in_ip_tcp(ch)
        self.assertEqual(extract_sni(pkt), "resume.example.com")

    def test_client_hello_with_large_session_id(self):
        """ClientHello with maximum session ID (32 bytes)."""
        session_id = b'\xff' * 32
        ch = build_raw_client_hello("bigsession.example.com", session_id=session_id)
        pkt = wrap_in_ip_tcp(ch)
        self.assertEqual(extract_sni(pkt), "bigsession.example.com")

    def test_sni_last_extension(self):
        """SNI extension is the last one in the list."""
        # Build extensions with SNI at the end
        ext1 = struct.pack('!HH', 0x000a, 4) + b'\x00\x02\x00\x1d'  # supported_groups
        ext2 = struct.pack('!HH', 0x000d, 4) + b'\x00\x02\x04\x03'  # sig_algorithms
        sni_name = b'last.example.com'
        sni_entry = bytes([SNI_HOST_NAME]) + struct.pack('!H', len(sni_name)) + sni_name
        sni_list = struct.pack('!H', len(sni_entry)) + sni_entry
        sni_ext = struct.pack('!HH', SNI_EXTENSION, len(sni_list)) + sni_list
        all_exts = ext1 + ext2 + sni_ext
        extensions = struct.pack('!H', len(all_exts)) + all_exts

        ch = build_raw_client_hello(extensions=extensions)
        pkt = wrap_in_ip_tcp(ch)
        self.assertEqual(extract_sni(pkt), "last.example.com")

    def test_sni_first_extension(self):
        """SNI extension is the first one (most common)."""
        sni_name = b'first.example.com'
        sni_entry = bytes([SNI_HOST_NAME]) + struct.pack('!H', len(sni_name)) + sni_name
        sni_list = struct.pack('!H', len(sni_entry)) + sni_entry
        sni_ext = struct.pack('!HH', SNI_EXTENSION, len(sni_list)) + sni_list
        other_ext = struct.pack('!HH', 0x000a, 4) + b'\x00\x02\x00\x1d'
        all_exts = sni_ext + other_ext
        extensions = struct.pack('!H', len(all_exts)) + all_exts

        ch = build_raw_client_hello(extensions=extensions)
        pkt = wrap_in_ip_tcp(ch)
        self.assertEqual(extract_sni(pkt), "first.example.com")

    def test_sni_extension_only(self):
        """Only SNI extension, no others."""
        sni_name = b'only.example.com'
        sni_entry = bytes([SNI_HOST_NAME]) + struct.pack('!H', len(sni_name)) + sni_name
        sni_list = struct.pack('!H', len(sni_entry)) + sni_entry
        sni_ext = struct.pack('!HH', SNI_EXTENSION, len(sni_list)) + sni_list
        extensions = struct.pack('!H', len(sni_ext)) + sni_ext

        ch = build_raw_client_hello(extensions=extensions)
        pkt = wrap_in_ip_tcp(ch)
        self.assertEqual(extract_sni(pkt), "only.example.com")

    def test_sni_with_non_hostname_name_type(self):
        """SNI extension with name type != 0 (not hostname) → skip."""
        # name_type = 1 (reserved), should be skipped
        sni_entry = bytes([1]) + struct.pack('!H', 10) + b'\x00' * 10
        sni_list = struct.pack('!H', len(sni_entry)) + sni_entry
        sni_ext = struct.pack('!HH', SNI_EXTENSION, len(sni_list)) + sni_list
        extensions = struct.pack('!H', len(sni_ext)) + sni_ext

        ch = build_raw_client_hello(extensions=extensions)
        pkt = wrap_in_ip_tcp(ch)
        self.assertIsNone(extract_sni(pkt))

    def test_sni_with_zero_length_list(self):
        """SNI extension with zero-length server name list."""
        sni_list = struct.pack('!H', 0)  # empty list
        sni_ext = struct.pack('!HH', SNI_EXTENSION, len(sni_list)) + sni_list
        extensions = struct.pack('!H', len(sni_ext)) + sni_ext

        ch = build_raw_client_hello(extensions=extensions)
        pkt = wrap_in_ip_tcp(ch)
        self.assertIsNone(extract_sni(pkt))

    def test_multiple_sni_extensions(self):
        """Two SNI extensions — should return first one found."""
        sni1_name = b'first.example.com'
        sni1_entry = bytes([SNI_HOST_NAME]) + struct.pack('!H', len(sni1_name)) + sni1_name
        sni1_list = struct.pack('!H', len(sni1_entry)) + sni1_entry
        sni1_ext = struct.pack('!HH', SNI_EXTENSION, len(sni1_list)) + sni1_list

        sni2_name = b'second.example.com'
        sni2_entry = bytes([SNI_HOST_NAME]) + struct.pack('!H', len(sni2_name)) + sni2_name
        sni2_list = struct.pack('!H', len(sni2_entry)) + sni2_entry
        sni2_ext = struct.pack('!HH', SNI_EXTENSION, len(sni2_list)) + sni2_list

        all_exts = sni1_ext + sni2_ext
        extensions = struct.pack('!H', len(all_exts)) + all_exts

        ch = build_raw_client_hello(extensions=extensions)
        pkt = wrap_in_ip_tcp(ch)
        self.assertEqual(extract_sni(pkt), "first.example.com")

    def test_empty_extensions_block(self):
        """Extensions block with length=0."""
        extensions = struct.pack('!H', 0)
        ch = build_raw_client_hello(extensions=extensions)
        pkt = wrap_in_ip_tcp(ch)
        self.assertIsNone(extract_sni(pkt))

    def test_grease_cipher_suites(self):
        """Chrome-style GREASE cipher suites (0x?a?a pattern)."""
        grease_ciphers = [0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x1301, 0x1302]
        cs_data = b''.join(struct.pack('!H', c) for c in grease_ciphers)
        ch = build_raw_client_hello("grease.example.com", cipher_suites=cs_data)
        pkt = wrap_in_ip_tcp(ch)
        self.assertEqual(extract_sni(pkt), "grease.example.com")


# ============================================================
# Test: SniParser — TCP/IP Variants
# ============================================================

class TestSniParserTcpIpVariants(unittest.TestCase):
    """Test SNI extraction with various TCP/IP header configurations."""

    def test_tcp_fin_psh_ack(self):
        """TCP FIN+PSH+ACK packet with TLS payload."""
        ch = build_raw_client_hello("fin.example.com")
        ip = build_ip_header(CLIENT_IP, SERVER_IP, 6, 20 + len(ch))
        tcp = build_tcp_header(30000, 443, 100, 200, 0x11, ch)  # FIN+ACK
        pkt = ip + tcp
        # extract_sni only checks protocol=TCP, not flags
        self.assertEqual(extract_sni(pkt), "fin.example.com")

    def test_tcp_rst_packet(self):
        """TCP RST packet — no payload expected, but parser should handle."""
        ip = build_ip_header(CLIENT_IP, SERVER_IP, 6, 20)
        tcp = build_tcp_header(30000, 443, 100, 200, 0x04)  # RST
        pkt = ip + tcp
        self.assertIsNone(extract_sni(pkt))

    def test_tcp_window_update(self):
        """TCP window update — pure ACK, no payload."""
        ip = build_ip_header(CLIENT_IP, SERVER_IP, 6, 20)
        tcp = build_tcp_header(30000, 443, 100, 200, 0x10)  # ACK only
        pkt = ip + tcp
        self.assertIsNone(extract_sni(pkt))

    def test_ip_fragment_offset_nonzero(self):
        """IP fragment with offset > 0 (not first fragment)."""
        tcp = build_tcp_header(30000, 443, 100, 200, 0x18, b'\x00' * 50)
        # Fragment with offset=100 (bytes 800-849)
        pkt = make_ip_packet(6, tcp, flags=0x2000, fragment_offset=100)
        # Parser should still try to parse — it doesn't check fragmentation
        # But TCP header won't be at expected offset, so it may fail gracefully
        result = extract_sni(pkt)
        # Should be None (garbled TCP header at wrong offset)
        self.assertIsNone(result)

    def test_ip_mf_flag_set(self):
        """IP More Fragments flag set (first fragment)."""
        tcp = build_tcp_header(30000, 443, 100, 200, 0x18, b'\x00' * 50)
        pkt = make_ip_packet(6, tcp, flags=0x2000, fragment_offset=0)
        # First fragment should still be parseable
        result = extract_sni(pkt)
        # TCP header is present, but no TLS payload
        self.assertIsNone(result)

    def test_very_small_tcp_payload(self):
        """TCP with 1-byte payload."""
        pkt = build_data_packet(CLIENT_IP, SERVER_IP, 30000, 443,
                                100, 200, b'\x16')  # Just TLS content type
        self.assertIsNone(extract_sni(pkt))

    def test_tcp_data_offset_15(self):
        """TCP with maximum data offset (15 * 4 = 60 bytes)."""
        ch = build_raw_client_hello("maxoffset.example.com")
        tcp_header = bytearray(60)  # Maximum TCP header
        struct.pack_into('!H', tcp_header, 0, 30000)
        struct.pack_into('!H', tcp_header, 2, 443)
        struct.pack_into('!I', tcp_header, 4, 100)
        struct.pack_into('!I', tcp_header, 8, 200)
        tcp_header[12] = (15 << 4)  # data offset = 15
        tcp_header[13] = 0x18  # PSH+ACK

        ip = build_ip_header(CLIENT_IP, SERVER_IP, 6, 60 + len(ch))
        pkt = ip + bytes(tcp_header) + ch
        self.assertEqual(extract_sni(pkt), "maxoffset.example.com")

    def test_ip_header_checksum_zero(self):
        """IP header with zero checksum (parser should still work)."""
        ch = build_raw_client_hello("nochecksum.example.com")
        ip = build_ip_header(CLIENT_IP, SERVER_IP, 6, 20 + len(ch))
        # Zero out checksum
        ip = ip[:10] + b'\x00\x00' + ip[12:]
        tcp = build_tcp_header(30000, 443, 100, 200, 0x18, ch)
        pkt = ip + tcp
        # Parser doesn't verify checksum, should still extract SNI
        self.assertEqual(extract_sni(pkt), "nochecksum.example.com")

    def test_ip_ttl_zero(self):
        """IP packet with TTL=0 (shouldn't exist in practice)."""
        ch = build_raw_client_hello("ttl0.example.com")
        ip = bytearray(build_ip_header(CLIENT_IP, SERVER_IP, 6, 20 + len(ch)))
        ip[8] = 0  # TTL = 0
        tcp = build_tcp_header(30000, 443, 100, 200, 0x18, ch)
        pkt = bytes(ip) + tcp
        # Parser doesn't check TTL
        self.assertEqual(extract_sni(pkt), "ttl0.example.com")


# ============================================================
# Test: DomainCache — Boundary Values
# ============================================================

class TestDomainCacheBounds(unittest.TestCase):
    """DomainCache boundary conditions."""

    def test_empty_string_domain(self):
        """Empty string domain is valid."""
        cache = DomainCache()
        cache.put_domain("1.2.3.4", "")
        self.assertEqual(cache.get_domain("1.2.3.4"), "")

    def test_very_long_domain(self):
        """Very long domain (1000 chars)."""
        cache = DomainCache()
        long_domain = "a" * 1000
        cache.put_domain("1.2.3.4", long_domain)
        self.assertEqual(cache.get_domain("1.2.3.4"), long_domain.lower())

    def test_domain_with_special_chars(self):
        """Domain with special ASCII characters."""
        cache = DomainCache()
        # Underscore, hyphen, digits
        cache.put_domain("1.2.3.4", "my_app-2024.example.com")
        self.assertEqual(cache.get_domain("1.2.3.4"), "my_app-2024.example.com")

    def test_ip_as_key_various_formats(self):
        """Various IP address formats as keys."""
        cache = DomainCache()
        cache.put_domain("0.0.0.0", "zero.example.com")
        cache.put_domain("255.255.255.255", "broadcast.example.com")
        cache.put_domain("127.0.0.1", "loopback.example.com")

        self.assertEqual(cache.get_domain("0.0.0.0"), "zero.example.com")
        self.assertEqual(cache.get_domain("255.255.255.255"), "broadcast.example.com")
        self.assertEqual(cache.get_domain("127.0.0.1"), "loopback.example.com")

    def test_many_ips_same_domain(self):
        """Multiple IPs mapping to same domain (CDN pattern)."""
        cache = DomainCache()
        for i in range(100):
            cache.put_domain(f"10.0.{i // 256}.{i % 256}", "cdn.example.com")

        self.assertEqual(cache.size(), 100)
        for i in range(100):
            self.assertEqual(cache.get_domain(f"10.0.{i // 256}.{i % 256}"), "cdn.example.com")

    def test_same_ip_different_domains_overwrite(self):
        """Same IP with different domains — last write wins."""
        cache = DomainCache()
        cache.put_domain("1.2.3.4", "first.com")
        cache.put_domain("1.2.3.4", "second.com")
        cache.put_domain("1.2.3.4", "third.com")
        self.assertEqual(cache.get_domain("1.2.3.4"), "third.com")
        self.assertEqual(cache.size(), 1)

    def test_rapid_put_get_cycles(self):
        """Rapid put/get in tight loop."""
        cache = DomainCache()
        for i in range(10000):
            cache.put_domain(f"10.0.{i % 256}.1", f"site{i}.com")
            cache.get_domain(f"10.0.{i % 256}.1")
        # Should not crash or leak memory
        self.assertLessEqual(cache.size(), 1000)


# ============================================================
# Test: PacketFlowTracker — Timeout & Cleanup
# ============================================================

class TestFlowTrackerTimeout(unittest.TestCase):
    """Flow timeout, stale cleanup, and edge cases."""

    def test_stale_flow_cleanup_on_get_flows(self):
        """Stale flows removed when getFlows() called."""
        tracker = PacketFlowTracker()
        tracker.FLOW_TIMEOUT = 0  # Immediate timeout

        pkt = build_syn_packet(CLIENT_IP, SERVER_IP, 30000, 443, 100)
        tracker.process_packet(pkt, is_uplink=True)
        self.assertEqual(len(tracker.flows), 1)

        time.sleep(0.01)  # Let it age
        flows = tracker.get_flows()
        self.assertEqual(len(flows), 0)  # Stale flow removed

    def test_active_flow_not_cleaned(self):
        """Active flows survive cleanup."""
        tracker = PacketFlowTracker()
        tracker.FLOW_TIMEOUT = 300  # 5 min

        pkt = build_syn_packet(CLIENT_IP, SERVER_IP, 30000, 443, 100)
        tracker.process_packet(pkt, is_uplink=True)

        flows = tracker.get_flows()
        self.assertEqual(len(flows), 1)

    def test_flow_last_seen_updated_on_packet(self):
        """Flow lastSeen updated when new packet arrives."""
        tracker = PacketFlowTracker()
        tracker.FLOW_TIMEOUT = 0.1  # 100ms timeout

        pkt = build_syn_packet(CLIENT_IP, SERVER_IP, 30000, 443, 100)
        tracker.process_packet(pkt, is_uplink=True)

        time.sleep(0.05)  # 50ms — within timeout

        # Send another packet — refreshes lastSeen
        pkt2 = build_ack_packet(CLIENT_IP, SERVER_IP, 30000, 443, 101, 200)
        tracker.process_packet(pkt2, is_uplink=True)

        time.sleep(0.06)  # 110ms total — would have timed out without refresh

        flows = tracker.get_flows()
        self.assertEqual(len(flows), 1)  # Still alive

    def test_zero_byte_tcp_payload(self):
        """TCP packet with zero-byte payload (pure ACK)."""
        tracker = PacketFlowTracker()
        pkt = build_ack_packet(CLIENT_IP, SERVER_IP, 30000, 443, 100, 200)
        tracker.process_packet(pkt, is_uplink=True)

        flows = tracker.get_flows()
        self.assertEqual(len(flows), 1)
        # Bytes = IP header (20) + TCP header (20) = 40
        self.assertEqual(flows[0].uplink_bytes, 40)

    def test_max_flows_exact_boundary(self):
        """Exactly MAX_FLOWS flows — no eviction needed."""
        tracker = PacketFlowTracker()
        tracker.MAX_FLOWS = 5

        for i in range(5):
            pkt = build_syn_packet(CLIENT_IP, f"10.0.0.{i + 1}", 30000, 443, 100)
            tracker.process_packet(pkt, is_uplink=True)

        self.assertEqual(len(tracker.flows), 5)

    def test_max_flows_plus_one_eviction(self):
        """MAX_FLOWS + 1 triggers eviction."""
        tracker = PacketFlowTracker()
        tracker.MAX_FLOWS = 5

        for i in range(6):
            pkt = build_syn_packet(CLIENT_IP, f"10.0.0.{i + 1}", 30000, 443, 100)
            tracker.process_packet(pkt, is_uplink=True)

        self.assertLessEqual(len(tracker.flows), 5)

    def test_flow_key_case_sensitive_protocol(self):
        """Protocol name case matters in flow key."""
        tracker = PacketFlowTracker()
        # All protocols are uppercase in the code, so this shouldn't matter
        # But verify consistency
        tcp_pkt = build_syn_packet(CLIENT_IP, SERVER_IP, 30000, 443, 100)
        tracker.process_packet(tcp_pkt, is_uplink=True)

        flows = tracker.get_flows()
        self.assertEqual(flows[0].protocol, "TCP")  # Always uppercase

    def test_mixed_protocol_same_ip(self):
        """Same IP, TCP and UDP are separate flows."""
        tracker = PacketFlowTracker()

        tcp = build_data_packet(CLIENT_IP, "1.1.1.1", 30000, 443, 100, 200, b'\x00' * 10)
        udp = build_udp_packet(CLIENT_IP, "1.1.1.1", 30001, 443, b'\x00' * 10)

        tracker.process_packet(tcp, is_uplink=True)
        tracker.process_packet(udp, is_uplink=True)

        self.assertEqual(len(tracker.flows), 2)
        protocols = {f.protocol for f in tracker.get_flows()}
        self.assertEqual(protocols, {"TCP", "UDP"})

    def test_very_large_packet(self):
        """Packet near MTU limit (1400 bytes)."""
        tracker = PacketFlowTracker()
        payload = b'x' * 1400
        pkt = build_data_packet(CLIENT_IP, SERVER_IP, 30000, 443, 100, 200, payload)
        tracker.process_packet(pkt, is_uplink=True)

        flows = tracker.get_flows()
        self.assertEqual(flows[0].uplink_bytes, 20 + 20 + 1400)  # IP + TCP + payload


# ============================================================
# Test: Display — Extreme Values
# ============================================================

class TestDisplayEdgeCases(unittest.TestCase):
    """Display logic with extreme values."""

    def _display(self, flow: FlowStats) -> str:
        return flow.domain if flow.domain else f"{flow.remote_ip}:{flow.remote_port}"

    def test_port_zero(self):
        """Port 0 (ICMP, raw IP)."""
        flow = FlowStats(remote_ip="1.1.1.1", remote_port=0, protocol="ICMP")
        self.assertEqual(self._display(flow), "1.1.1.1:0")

    def test_port_65535(self):
        """Maximum port number."""
        flow = FlowStats(remote_ip="1.1.1.1", remote_port=65535, protocol="TCP")
        self.assertEqual(self._display(flow), "1.1.1.1:65535")

    def test_zero_ip(self):
        """IP 0.0.0.0."""
        flow = FlowStats(remote_ip="0.0.0.0", remote_port=80, protocol="TCP")
        self.assertEqual(self._display(flow), "0.0.0.0:80")

    def test_broadcast_ip(self):
        """Broadcast IP."""
        flow = FlowStats(remote_ip="255.255.255.255", remote_port=67, protocol="UDP")
        self.assertEqual(self._display(flow), "255.255.255.255:67")

    def test_loopback_ip(self):
        """Loopback IP."""
        flow = FlowStats(remote_ip="127.0.0.1", remote_port=8080, protocol="TCP")
        self.assertEqual(self._display(flow), "127.0.0.1:8080")

    def test_very_long_domain_display(self):
        """Very long domain in display."""
        long_domain = "a" * 200 + ".example.com"
        flow = FlowStats(remote_ip="1.1.1.1", remote_port=443, protocol="TCP",
                         domain=long_domain)
        self.assertEqual(self._display(flow), long_domain)

    def test_domain_with_numbers(self):
        """Domain that looks like an IP."""
        flow = FlowStats(remote_ip="1.2.3.4", remote_port=443, protocol="TCP",
                         domain="123.456.789")
        self.assertEqual(self._display(flow), "123.456.789")

    def test_bytes_zero(self):
        """Zero bytes — still a valid flow."""
        flow = FlowStats(remote_ip="1.1.1.1", remote_port=443, protocol="TCP",
                         uplink_bytes=0, downlink_bytes=0)
        self.assertEqual(flow.uplink_bytes, 0)
        self.assertEqual(flow.downlink_bytes, 0)

    def test_bytes_max_value(self):
        """Very large byte counts."""
        flow = FlowStats(remote_ip="1.1.1.1", remote_port=443, protocol="TCP",
                         uplink_bytes=1024 * 1024 * 1024,  # 1 GB
                         downlink_bytes=1024 * 1024 * 1024 * 10)  # 10 GB
        self.assertEqual(flow.uplink_bytes, 1073741824)
        self.assertEqual(flow.downlink_bytes, 10737418240)


# ============================================================
# Test: Android-Specific — Protocol Edge Cases
# ============================================================

class TestAndroidProtocolEdgeCases(unittest.TestCase):
    """Protocol-level edge cases for Android VPN."""

    def test_ipv6_traffic_ignored(self):
        """IPv6 packets are ignored by the parser."""
        # IPv6 header: version=6, 40 bytes
        ipv6_header = b'\x60' + b'\x00' * 39
        payload = b'\x00' * 50
        pkt = ipv6_header + payload
        self.assertIsNone(extract_sni(pkt))

    def test_multicast_dst_ip(self):
        """Multicast destination IP (224.0.0.x)."""
        tracker = PacketFlowTracker()
        udp = build_udp_packet(CLIENT_IP, "224.0.0.251", 5353, 5353,
                               b'\x00' * 20)
        tracker.process_packet(udp, is_uplink=True)

        flows = tracker.get_flows()
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].remote_ip, "224.0.0.251")

    def test_loopback_traffic(self):
        """Loopback traffic (127.0.0.1)."""
        tracker = PacketFlowTracker()
        pkt = build_data_packet("127.0.0.1", "127.0.0.1", 30000, 8080,
                                100, 200, b'\x00' * 10)
        tracker.process_packet(pkt, is_uplink=True)

        flows = tracker.get_flows()
        self.assertEqual(len(flows), 1)

    def test_dns_response_tracking(self):
        """DNS response (downlink) merges into same flow as query (uplink).
        
        Both have remote = 8.8.8.8:53, so same flow key.
        """
        tracker = PacketFlowTracker()

        # DNS query (uplink)
        query = build_udp_packet(CLIENT_IP, "8.8.8.8", 54321, 53,
                                 build_dns_query("google.com"))
        tracker.process_packet(query, is_uplink=True)

        # DNS response (downlink — src=8.8.8.8:53)
        response = build_udp_packet("8.8.8.8", CLIENT_IP, 53, 54321,
                                    b'\x00' * 100)
        tracker.process_packet(response, is_uplink=False)

        # Same flow key (remote=8.8.8.8:53), bytes accumulate
        flows = tracker.get_flows()
        self.assertEqual(len(flows), 1)
        self.assertGreater(flows[0].uplink_bytes, 0)
        self.assertGreater(flows[0].downlink_bytes, 0)

    def test_tcp_keepalive_packet(self):
        """TCP keepalive (ACK with seq-1, 1 byte payload)."""
        tracker = PacketFlowTracker()
        # Keepalive: 1 byte payload with previous sequence number
        pkt = build_data_packet(CLIENT_IP, SERVER_IP, 30000, 443,
                                99, 200, b'\x00', flags=0x10)  # ACK
        tracker.process_packet(pkt, is_uplink=True)

        flows = tracker.get_flows()
        self.assertEqual(len(flows), 1)

    def test_udp_zero_length_payload(self):
        """UDP packet with zero-length payload."""
        tracker = PacketFlowTracker()
        # Zero-length UDP payload
        udp_header = struct.pack('!HHHH', 30000, 53, 8, 0)
        ip = build_ip_header(CLIENT_IP, "8.8.8.8", 17, 8)
        pkt = ip + udp_header
        tracker.process_packet(pkt, is_uplink=True)

        flows = tracker.get_flows()
        self.assertEqual(len(flows), 1)

    def test_dns_query_as_udp_flow(self):
        """DNS query creates UDP flow."""
        tracker = PacketFlowTracker()
        query = build_dns_query("google.com")
        pkt = build_udp_packet(CLIENT_IP, "8.8.8.8", 54321, 53, query)
        tracker.process_packet(pkt, is_uplink=True)

        flows = tracker.get_flows()
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].protocol, "UDP")
        self.assertEqual(flows[0].remote_port, 53)
        self.assertIsNone(flows[0].domain)  # No SNI in UDP

    def test_multiple_dns_queries_different_servers(self):
        """DNS queries to different servers = different flows."""
        tracker = PacketFlowTracker()

        for dns_server in ["8.8.8.8", "1.1.1.1", "8.8.4.4"]:
            pkt = build_udp_packet(CLIENT_IP, dns_server, 54321, 53,
                                   build_dns_query("example.com"))
            tracker.process_packet(pkt, is_uplink=True)

        flows = tracker.get_flows()
        self.assertEqual(len(flows), 3)


# ============================================================
# Test: Integration — Domain Injection Order
# ============================================================

class TestIntegrationDomainInjection(unittest.TestCase):
    """Test domain injection ordering and cache consistency."""

    def test_domain_appears_after_client_hello(self):
        """Domain appears in flow only after ClientHello processed."""
        tracker = PacketFlowTracker()

        # SYN — no domain
        syn = build_syn_packet(CLIENT_IP, SERVER_IP, 30000, 443, 100)
        tracker.process_packet(syn, is_uplink=True)
        flows = tracker.get_flows()
        self.assertIsNone(flows[0].domain)

        # SYN-ACK — no domain
        syn_ack = build_syn_ack_packet(SERVER_IP, CLIENT_IP, 443, 30000, 200, 101)
        tracker.process_packet(syn_ack, is_uplink=False)
        flows = tracker.get_flows()
        self.assertIsNone(flows[0].domain)

        # ACK — no domain
        ack = build_ack_packet(CLIENT_IP, SERVER_IP, 30000, 443, 101, 201)
        tracker.process_packet(ack, is_uplink=True)
        flows = tracker.get_flows()
        self.assertIsNone(flows[0].domain)

        # ClientHello — DOMAIN APPEARS
        ch = build_raw_client_hello("example.com")
        ch_pkt = build_data_packet(CLIENT_IP, SERVER_IP, 30000, 443, 101, 201, ch)
        tracker.process_packet(ch_pkt, is_uplink=True)
        flows = tracker.get_flows()
        self.assertEqual(flows[0].domain, "example.com")

    def test_domain_from_cache_on_downlink(self):
        """Downlink packets get domain from DomainCache."""
        tracker = PacketFlowTracker()

        # First: uplink with SNI
        ch = build_raw_client_hello("cached.example.com")
        ch_pkt = build_data_packet(CLIENT_IP, SERVER_IP, 30000, 443, 100, 200, ch)
        tracker.process_packet(ch_pkt, is_uplink=True)

        # Clear the flow (simulate new flow to same IP)
        tracker.flows.clear()

        # Downlink packet — should get domain from cache
        down = build_data_packet(SERVER_IP, CLIENT_IP, 443, 30000, 200, 100,
                                 b'\x17\x03\x03' + b'\x00' * 50)
        tracker.process_packet(down, is_uplink=False)

        flows = tracker.get_flows()
        self.assertEqual(flows[0].domain, "cached.example.com")

    def test_cache_consistency_after_clear(self):
        """Cache is cleared with tracker — no stale domains."""
        tracker = PacketFlowTracker()

        # Establish domain in cache
        ch = build_raw_client_hello("before.example.com")
        ch_pkt = build_data_packet(CLIENT_IP, SERVER_IP, 30000, 443, 100, 200, ch)
        tracker.process_packet(ch_pkt, is_uplink=True)
        self.assertEqual(tracker.domain_cache.size(), 1)

        # Clear
        tracker.clear()
        self.assertEqual(tracker.domain_cache.size(), 0)

        # New connection — should NOT have old domain
        down = build_data_packet(SERVER_IP, CLIENT_IP, 443, 30000, 200, 100,
                                 b'\x17\x03\x03' + b'\x00' * 50)
        tracker.process_packet(down, is_uplink=False)

        flows = tracker.get_flows()
        self.assertIsNone(flows[0].domain)

    def test_domain_update_overwrites_none(self):
        """Domain set on existing flow that had no domain."""
        tracker = PacketFlowTracker()

        # Create flow without domain (SYN)
        syn = build_syn_packet(CLIENT_IP, SERVER_IP, 30000, 443, 100)
        tracker.process_packet(syn, is_uplink=True)

        flows = tracker.get_flows()
        self.assertIsNone(flows[0].domain)

        # Send ClientHello — domain should be set
        ch = build_raw_client_hello("newdomain.example.com")
        ch_pkt = build_data_packet(CLIENT_IP, SERVER_IP, 30000, 443, 101, 200, ch)
        tracker.process_packet(ch_pkt, is_uplink=True)

        flows = tracker.get_flows()
        self.assertEqual(flows[0].domain, "newdomain.example.com")

    def test_domain_does_not_overwrite_existing(self):
        """Once domain is set, it's NOT overwritten by later packets."""
        tracker = PacketFlowTracker()

        # First ClientHello
        ch1 = build_raw_client_hello("first.example.com")
        ch1_pkt = build_data_packet(CLIENT_IP, SERVER_IP, 30000, 443, 100, 200, ch1)
        tracker.process_packet(ch1_pkt, is_uplink=True)

        # Second ClientHello (unusual but possible — TLS renegotiation)
        ch2 = build_raw_client_hello("second.example.com")
        ch2_pkt = build_data_packet(CLIENT_IP, SERVER_IP, 30000, 443, 300, 200, ch2)
        tracker.process_packet(ch2_pkt, is_uplink=True)

        flows = tracker.get_flows()
        # First domain wins (condition: domain != null && existing.domain == null)
        self.assertEqual(flows[0].domain, "first.example.com")

    def test_full_lifecycle_3_connections(self):
        """Full lifecycle: 3 connections, each with domain."""
        tracker = PacketFlowTracker()
        sim = TrafficSimulator()
        sim.tracker = tracker

        connections = [
            (SERVER_IP, "www.google.com"),
            (CDN_IP, "www.reddit.com"),
            (API_IP, "api.github.com"),
        ]

        for ip, domain in connections:
            sim.simulate_tls_connection(ip, domain)

        flows = tracker.get_flows()
        tls_flows = [f for f in flows if f.protocol == "TCP" and f.domain]
        found = {f.domain for f in tls_flows}

        for _, domain in connections:
            self.assertIn(domain, found)

        # Debug stats should show all extractions
        self.assertEqual(tracker.sni_extracted, len(connections))

    def test_rapid_reconnect_same_server(self):
        """Rapid disconnect/reconnect to same server."""
        tracker = PacketFlowTracker()

        for i in range(10):
            ch = build_raw_client_hello("stable.example.com")
            ch_pkt = build_data_packet(CLIENT_IP, SERVER_IP, 30000, 443,
                                       100 + i * 1000, 200, ch)
            tracker.process_packet(ch_pkt, is_uplink=True)

        flows = tracker.get_flows()
        # All packets go to same flow (same remote)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].domain, "stable.example.com")


# ============================================================
# Test: Debug Counter Accuracy
# ============================================================

class TestDebugCounters(unittest.TestCase):
    """Verify debug counters are accurate."""

    def test_total_packets_counter(self):
        """totalPacketsProcessed increments correctly."""
        tracker = PacketFlowTracker()

        for i in range(50):
            pkt = build_syn_packet(CLIENT_IP, f"10.0.0.{i % 256}", 30000, 443, 100)
            tracker.process_packet(pkt, is_uplink=True)

        self.assertEqual(tracker.total_packets, 50)

    def test_uplink_tcp_counter(self):
        """uplinkTcpPackets counts only uplink TCP."""
        tracker = PacketFlowTracker()

        # 3 uplink TCP
        for i in range(3):
            pkt = build_syn_packet(CLIENT_IP, SERVER_IP, 30000 + i, 443, 100)
            tracker.process_packet(pkt, is_uplink=True)

        # 2 downlink TCP
        for i in range(2):
            pkt = build_syn_ack_packet(SERVER_IP, CLIENT_IP, 443, 30000 + i, 200, 101)
            tracker.process_packet(pkt, is_uplink=False)

        # 1 uplink UDP
        pkt = build_udp_packet(CLIENT_IP, "8.8.8.8", 54321, 53, b'\x00' * 10)
        tracker.process_packet(pkt, is_uplink=True)

        self.assertEqual(tracker.total_packets, 6)
        self.assertEqual(tracker.uplink_tcp, 3)

    def test_sni_extracted_counter(self):
        """sniDomainsExtracted counts successful SNI extractions."""
        tracker = PacketFlowTracker()

        # 2 TLS ClientHellos
        for domain in ["a.com", "b.com"]:
            ch = build_raw_client_hello(domain)
            pkt = wrap_in_ip_tcp(ch, dst_ip=f"10.0.0.{hash(domain) % 256}")
            tracker.process_packet(pkt, is_uplink=True)

        # 1 SYN (no SNI)
        syn = build_syn_packet(CLIENT_IP, "10.0.0.99", 30000, 443, 100)
        tracker.process_packet(syn, is_uplink=True)

        self.assertEqual(tracker.sni_extracted, 2)

    def test_cache_hits_counter(self):
        """cacheHits increments on cache lookups."""
        tracker = PacketFlowTracker()

        # Establish domain in cache
        ch = build_raw_client_hello("cached.com")
        ch_pkt = wrap_in_ip_tcp(ch)
        tracker.process_packet(ch_pkt, is_uplink=True)

        initial_hits = tracker.cache_hits

        # Downlink packets to same IP — each should hit cache
        for _ in range(5):
            down = build_data_packet(SERVER_IP, CLIENT_IP, 443, 30000,
                                     5000, 5000, b'\x17\x03\x03' + b'\x00' * 10)
            tracker.process_packet(down, is_uplink=False)

        self.assertEqual(tracker.cache_hits, initial_hits + 5)

    def test_counters_reset_on_clear(self):
        """All counters reset on clear()."""
        tracker = PacketFlowTracker()

        # Generate some activity
        for i in range(10):
            ch = build_raw_client_hello(f"site{i}.com")
            pkt = wrap_in_ip_tcp(ch, dst_ip=f"10.0.{i}.1")
            tracker.process_packet(pkt, is_uplink=True)

        self.assertGreater(tracker.total_packets, 0)
        self.assertGreater(tracker.sni_extracted, 0)

        tracker.clear()

        self.assertEqual(tracker.total_packets, 0)
        self.assertEqual(tracker.uplink_tcp, 0)
        self.assertEqual(tracker.sni_extracted, 0)
        self.assertEqual(tracker.cache_hits, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
