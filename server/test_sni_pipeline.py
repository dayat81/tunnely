#!/usr/bin/env python3
"""
SNI pipeline integration tests — tests the full chain:
  packet → TLS detection → ClientHello check → SniParser → DomainCache → FlowEntry

Mirrors the exact logic in PacketFlowTracker.processPacket() and getFlows().
Covers the pipeline counter stages: pkts → tcp → tls → ch → parse → fail/sni → cache
"""

import struct
import socket
import unittest
import time
from typing import Optional, Dict, List, Tuple

from test_ssl_traffic_simulation import (
    extract_sni, build_ip_header, build_tcp_header, build_tls_client_hello,
    build_tls_server_hello, build_syn_packet, build_syn_ack_packet,
    build_ack_packet, build_data_packet, build_udp_packet, build_dns_query,
    PacketFlowTracker, DomainCache, FlowStats,
    CLIENT_IP, SERVER_IP, CDN_IP, API_IP, TLS_HANDSHAKE, CLIENT_HELLO,
)


# ============================================================
# Pipeline Tracker — mirrors Kotlin PacketFlowTracker exactly
# ============================================================

class PipelineTracker:
    """Mirrors the Kotlin PacketFlowTracker with all debug counters."""

    def __init__(self):
        self.flows: Dict[str, FlowStats] = {}
        self.domain_cache = DomainCache()

        # Pipeline counters (mirrors @Volatile fields)
        self.total_packets = 0
        self.uplink_tcp = 0
        self.tls_records = 0
        self.client_hellos = 0
        self.parse_attempts = 0
        self.parse_failures = 0
        self.sni_extracted = 0
        self.cache_hits = 0

    def clear(self):
        self.flows.clear()
        self.domain_cache.clear()
        self.total_packets = 0
        self.uplink_tcp = 0
        self.tls_records = 0
        self.client_hellos = 0
        self.parse_attempts = 0
        self.parse_failures = 0
        self.sni_extracted = 0
        self.cache_hits = 0

    def get_debug_stats(self) -> str:
        flow_info = sorted(self.flows.values(),
                           key=lambda f: f.uplink_bytes + f.downlink_bytes,
                           reverse=True)[:3]
        flow_domains = "; ".join(
            f"{f.remote_ip}:{f.remote_port} domain={f.domain or 'NULL'} cached={self.domain_cache.get_domain(f.remote_ip) or 'NULL'}"
            for f in flow_info
        )
        return (f"pkts={self.total_packets} tcp={self.uplink_tcp} "
                f"tls={self.tls_records} ch={self.client_hellos} "
                f"parse={self.parse_attempts} fail={self.parse_failures} "
                f"sni={self.sni_extracted} cache={self.cache_hits}/{self.domain_cache.size()}\n"
                f"{flow_domains}")

    def process_packet(self, packet: bytes, is_uplink: bool):
        """Process packet with full pipeline tracking. Mirrors Kotlin code exactly."""
        if len(packet) < 20:
            return

        version = (packet[0] & 0xF0) >> 4
        if version != 4:
            return

        ihl = (packet[0] & 0x0F) * 4
        if ihl < 20 or len(packet) < ihl:
            return

        protocol = packet[9] & 0xFF
        src_ip = self._ip_to_string(packet, 12)
        dst_ip = self._ip_to_string(packet, 16)

        src_port = 0
        dst_port = 0
        if len(packet) >= ihl + 4:
            src_port = ((packet[ihl] & 0xFF) << 8) | (packet[ihl + 1] & 0xFF)
            dst_port = ((packet[ihl + 2] & 0xFF) << 8) | (packet[ihl + 3] & 0xFF)

        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(protocol, f"IP/{protocol}")
        self.total_packets += 1

        if is_uplink:
            remote_ip = dst_ip
            remote_port = dst_port
        else:
            remote_ip = src_ip
            remote_port = src_port

        # Extract SNI — mirrors Kotlin code exactly
        domain = None
        if is_uplink and proto_name == "TCP":
            self.uplink_tcp += 1
            # Check TLS record header
            tcp_data_offset = ((packet[ihl + 12] & 0xF0) >> 4) * 4 if len(packet) >= ihl + 12 else 0
            payload_start = ihl + tcp_data_offset
            if len(packet) > payload_start + 5:
                tls_content_type = packet[payload_start] & 0xFF
                if tls_content_type == 0x16:  # TLS Handshake
                    self.tls_records += 1
                    handshake_type = packet[payload_start + 5] & 0xFF
                    if handshake_type == 0x01:  # ClientHello
                        self.client_hellos += 1
                        self.parse_attempts += 1
                        domain = extract_sni(packet)
                        if domain is not None:
                            self.sni_extracted += 1
                            self.domain_cache.put_domain(remote_ip, domain)
                        else:
                            self.parse_failures += 1

        # Cache fallback
        if domain is None:
            cached = self.domain_cache.get_domain(remote_ip)
            if cached is not None:
                domain = cached
                self.cache_hits += 1

        # Normalize
        if domain is not None:
            domain = domain.lower()

        # Update flow
        key = f"{remote_ip}:{remote_port}/{proto_name}"
        now = time.time()
        packet_len = len(packet)

        if key in self.flows:
            flow = self.flows[key]
            if is_uplink:
                flow.uplink_bytes += packet_len
            else:
                flow.downlink_bytes += packet_len
            flow.last_seen = now
            if domain is not None and flow.domain is None:
                flow.domain = domain
        else:
            self.flows[key] = FlowStats(
                remote_ip=remote_ip, remote_port=remote_port,
                protocol=proto_name, domain=domain,
                uplink_bytes=packet_len if is_uplink else 0,
                downlink_bytes=0 if is_uplink else packet_len,
                last_seen=now,
            )

    def get_flows(self) -> List[FlowStats]:
        """Get flows with DomainCache fallback. Mirrors Kotlin getFlows()."""
        now = time.time()
        self.flows = {k: v for k, v in self.flows.items()
                      if now - v.last_seen < 300}
        result = []
        for f in sorted(self.flows.values(),
                        key=lambda f: f.uplink_bytes + f.downlink_bytes,
                        reverse=True):
            # DomainCache fallback — mirrors Kotlin code
            domain = f.domain if f.domain else self.domain_cache.get_domain(f.remote_ip)
            result.append(FlowStats(
                remote_ip=f.remote_ip, remote_port=f.remote_port,
                protocol=f.protocol, domain=domain,
                uplink_bytes=f.uplink_bytes, downlink_bytes=f.downlink_bytes,
            ))
        return result

    @staticmethod
    def _ip_to_string(packet: bytes, offset: int) -> str:
        return (f"{packet[offset] & 0xFF}.{packet[offset+1] & 0xFF}."
                f"{packet[offset+2] & 0xFF}.{packet[offset+3] & 0xFF}")


# ============================================================
# Helper — simulate TLS connection with full handshake
# ============================================================

def simulate_tls_connection(tracker: PipelineTracker, dst_ip: str,
                            hostname: str, dst_port: int = 443) -> dict:
    """Simulate full TLS handshake through the tracker."""
    src_port = 30000 + (hash(dst_ip) % 30000)
    result = {}

    # 1. DNS
    dns = build_udp_packet(CLIENT_IP, "8.8.8.8", 54321, 53,
                           build_dns_query(hostname))
    tracker.process_packet(dns, is_uplink=True)

    # 2. SYN (uplink)
    syn = build_syn_packet(CLIENT_IP, dst_ip, src_port, dst_port, 1000)
    tracker.process_packet(syn, is_uplink=True)
    result['syn'] = True

    # 3. SYN-ACK (downlink)
    syn_ack = build_syn_ack_packet(dst_ip, CLIENT_IP, dst_port, src_port, 2000, 1001)
    tracker.process_packet(syn_ack, is_uplink=False)
    result['syn_ack'] = True

    # 4. ACK (uplink)
    ack = build_ack_packet(CLIENT_IP, dst_ip, src_port, dst_port, 1001, 2001)
    tracker.process_packet(ack, is_uplink=True)
    result['ack'] = True

    # 5. ClientHello (uplink) — THE KEY PACKET
    client_hello = build_tls_client_hello(hostname)
    ch_pkt = build_data_packet(CLIENT_IP, dst_ip, src_port, dst_port,
                               1001, 2001, client_hello)
    tracker.process_packet(ch_pkt, is_uplink=True)
    result['client_hello'] = True

    # 6. ServerHello (downlink)
    server_hello = build_tls_server_hello()
    sh_pkt = build_data_packet(dst_ip, CLIENT_IP, dst_port, src_port,
                               2001, 1001 + len(client_hello), server_hello)
    tracker.process_packet(sh_pkt, is_uplink=False)
    result['server_hello'] = True

    # 7. Application data (bidirectional)
    app_req = b'GET / HTTP/1.1\r\nHost: ' + hostname.encode() + b'\r\n\r\n'
    req_pkt = build_data_packet(CLIENT_IP, dst_ip, src_port, dst_port,
                                1001 + len(client_hello), 2001 + len(server_hello), app_req)
    tracker.process_packet(req_pkt, is_uplink=True)

    app_resp = b'HTTP/1.1 200 OK\r\n\r\n' + b'x' * 500
    resp_pkt = build_data_packet(dst_ip, CLIENT_IP, dst_port, src_port,
                                 2001 + len(server_hello),
                                 1001 + len(client_hello) + len(app_req), app_resp)
    tracker.process_packet(resp_pkt, is_uplink=False)

    return result


# ============================================================
# Test: Pipeline Counter Stages
# ============================================================

class TestPipelineCounters(unittest.TestCase):
    """Test each stage of the SNI pipeline counter chain."""

    def test_full_pipeline_single_connection(self):
        """Single TLS connection goes through all pipeline stages."""
        tracker = PipelineTracker()
        simulate_tls_connection(tracker, SERVER_IP, "google.com")

        stats = tracker.get_debug_stats()
        # Verify each stage
        self.assertGreater(tracker.total_packets, 0, "pkts should be > 0")
        self.assertGreater(tracker.uplink_tcp, 0, "tcp should be > 0")
        self.assertGreater(tracker.tls_records, 0, "tls should be > 0")
        self.assertGreater(tracker.client_hellos, 0, "ch should be > 0")
        self.assertGreater(tracker.parse_attempts, 0, "parse should be > 0")
        self.assertEqual(tracker.parse_failures, 0, "fail should be 0")
        self.assertEqual(tracker.sni_extracted, 1, "sni should be 1")
        self.assertGreater(tracker.cache_hits, 0, "cache should be > 0")

    def test_pipeline_5_connections(self):
        """5 TLS connections — all should extract SNI."""
        tracker = PipelineTracker()
        domains = [
            (SERVER_IP, "google.com"),
            (CDN_IP, "reddit.com"),
            (API_IP, "github.com"),
            ("13.107.42.14", "teams.microsoft.com"),
            ("31.13.65.36", "facebook.com"),
        ]
        for ip, domain in domains:
            simulate_tls_connection(tracker, ip, domain)

        self.assertEqual(tracker.sni_extracted, 5)
        self.assertEqual(tracker.parse_failures, 0)
        self.assertEqual(tracker.client_hellos, 5)

    def test_pipeline_dns_only(self):
        """DNS packets — no TCP/TLS stages."""
        tracker = PipelineTracker()
        dns = build_udp_packet(CLIENT_IP, "8.8.8.8", 54321, 53,
                               build_dns_query("google.com"))
        tracker.process_packet(dns, is_uplink=True)

        self.assertEqual(tracker.total_packets, 1)
        self.assertEqual(tracker.uplink_tcp, 0)  # Not TCP
        self.assertEqual(tracker.tls_records, 0)
        self.assertEqual(tracker.sni_extracted, 0)

    def test_pipeline_syn_only(self):
        """SYN packet — TCP but no TLS payload."""
        tracker = PipelineTracker()
        syn = build_syn_packet(CLIENT_IP, SERVER_IP, 30000, 443, 1000)
        tracker.process_packet(syn, is_uplink=True)

        self.assertEqual(tracker.total_packets, 1)
        self.assertEqual(tracker.uplink_tcp, 1)
        self.assertEqual(tracker.tls_records, 0)  # No TLS in SYN
        self.assertEqual(tracker.client_hellos, 0)

    def test_pipeline_non_tls_tcp(self):
        """HTTP (non-TLS) TCP — TCP but no TLS record."""
        tracker = PipelineTracker()
        http = build_data_packet(CLIENT_IP, SERVER_IP, 30000, 80,
                                 100, 200,
                                 b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n')
        tracker.process_packet(http, is_uplink=True)

        self.assertEqual(tracker.uplink_tcp, 1)
        self.assertEqual(tracker.tls_records, 0)  # Not TLS
        self.assertEqual(tracker.sni_extracted, 0)

    def test_pipeline_tls_server_hello(self):
        """ServerHello — TLS record but NOT ClientHello."""
        tracker = PipelineTracker()
        server_hello = build_tls_server_hello()
        pkt = build_data_packet(SERVER_IP, CLIENT_IP, 443, 30000,
                                200, 100, server_hello)
        tracker.process_packet(pkt, is_uplink=False)

        # Downlink — not checked for SNI
        self.assertEqual(tracker.uplink_tcp, 0)
        self.assertEqual(tracker.tls_records, 0)

    def test_pipeline_tls_other_handshake(self):
        """TLS Certificate message (type 11) — TLS but not ClientHello."""
        tracker = PipelineTracker()
        # Build TLS Certificate handshake
        cert_body = b'\x00' * 50
        cert_msg = bytes([11]) + bytes([(len(cert_body) >> 16) & 0xFF]) + \
                   struct.pack('!H', len(cert_body)) + cert_body
        tls_record = bytes([0x16]) + struct.pack('!H', 0x0301) + \
                     struct.pack('!H', len(cert_msg)) + cert_msg
        pkt = build_data_packet(CLIENT_IP, SERVER_IP, 30000, 443,
                                100, 200, tls_record)
        tracker.process_packet(pkt, is_uplink=True)

        self.assertEqual(tracker.uplink_tcp, 1)
        self.assertEqual(tracker.tls_records, 1)  # TLS record seen
        self.assertEqual(tracker.client_hellos, 0)  # But not ClientHello
        self.assertEqual(tracker.parse_attempts, 0)

    def test_pipeline_tls_application_data(self):
        """TLS Application Data (0x17) — not handshake."""
        tracker = PipelineTracker()
        app_data = bytes([0x17]) + struct.pack('!H', 0x0303) + \
                   struct.pack('!H', 100) + b'\x00' * 100
        pkt = build_data_packet(CLIENT_IP, SERVER_IP, 30000, 443,
                                100, 200, app_data)
        tracker.process_packet(pkt, is_uplink=True)

        self.assertEqual(tracker.uplink_tcp, 1)
        self.assertEqual(tracker.tls_records, 0)  # Not handshake type
        self.assertEqual(tracker.sni_extracted, 0)


# ============================================================
# Test: DomainCache Fallback in getFlows()
# ============================================================

class TestDomainCacheFallback(unittest.TestCase):
    """Test that getFlows() uses DomainCache when FlowStats.domain is null."""

    def test_cache_fallback_works(self):
        """Domain in cache → processPacket sets it on flow, getFlows() returns it."""
        tracker = PipelineTracker()

        # Manually set domain in cache (simulates prior SNI extraction)
        tracker.domain_cache.put_domain("1.2.3.4", "example.com")

        # Create flow (SYN packet) — cache fallback in processPacket sets domain
        syn = build_syn_packet(CLIENT_IP, "1.2.3.4", 30000, 443, 1000)
        tracker.process_packet(syn, is_uplink=True)

        # Domain IS set from cache in processPacket (cache fallback runs there too)
        flow_key = "1.2.3.4:443/TCP"
        self.assertEqual(tracker.flows[flow_key].domain, "example.com")
        self.assertGreater(tracker.cache_hits, 0)

        # getFlows() also returns domain
        flows = tracker.get_flows()
        self.assertEqual(flows[0].domain, "example.com")

    def test_cache_fallback_not_used_when_domain_set(self):
        """Domain set on flow → getFlows() uses flow domain, not cache."""
        tracker = PipelineTracker()

        # Set domain in cache
        tracker.domain_cache.put_domain("1.2.3.4", "cached.com")

        # Create flow WITH domain (simulates ClientHello)
        ch = build_tls_client_hello("flow.com")
        ch_pkt = build_data_packet(CLIENT_IP, "1.2.3.4", 30000, 443,
                                   100, 200, ch)
        tracker.process_packet(ch_pkt, is_uplink=True)

        # FlowStats.domain should be set
        flow_key = "1.2.3.4:443/TCP"
        self.assertIsNotNone(tracker.flows[flow_key].domain)

        # getFlows() should use flow domain (not cache)
        flows = tracker.get_flows()
        self.assertEqual(flows[0].domain, "flow.com")

    def test_cache_fallback_multiple_flows(self):
        """Multiple flows — only cached ones get domain from cache."""
        tracker = PipelineTracker()

        # Cache has domain for 1.2.3.4 only
        tracker.domain_cache.put_domain("1.2.3.4", "cached.com")

        # Create flows for different IPs
        for ip in ["1.2.3.4", "5.6.7.8", "9.10.11.12"]:
            syn = build_syn_packet(CLIENT_IP, ip, 30000, 443, 1000)
            tracker.process_packet(syn, is_uplink=True)

        flows = tracker.get_flows()
        domains = {f.remote_ip: f.domain for f in flows}

        self.assertEqual(domains["1.2.3.4"], "cached.com")
        self.assertIsNone(domains["5.6.7.8"])
        self.assertIsNone(domains["9.10.11.12"])

    def test_cache_fallback_after_clear(self):
        """Clear removes cache — fallback returns null."""
        tracker = PipelineTracker()
        tracker.domain_cache.put_domain("1.2.3.4", "example.com")

        syn = build_syn_packet(CLIENT_IP, "1.2.3.4", 30000, 443, 1000)
        tracker.process_packet(syn, is_uplink=True)

        # Before clear — cache works
        flows = tracker.get_flows()
        self.assertEqual(flows[0].domain, "example.com")

        # After clear — cache empty
        tracker.clear()
        syn2 = build_syn_packet(CLIENT_IP, "1.2.3.4", 30000, 443, 1000)
        tracker.process_packet(syn2, is_uplink=True)

        flows = tracker.get_flows()
        self.assertIsNone(flows[0].domain)


# ============================================================
# Test: Pipeline Stage Gaps
# ============================================================

class TestPipelineStageGaps(unittest.TestCase):
    """Test scenarios where pipeline stages have gaps."""

    def test_many_tcp_few_tls(self):
        """Many TCP packets but few TLS records (mostly HTTP)."""
        tracker = PipelineTracker()

        # 10 HTTP packets (no TLS)
        for i in range(10):
            http = build_data_packet(CLIENT_IP, SERVER_IP, 30000 + i, 80,
                                     100, 200, b'GET / HTTP/1.1\r\n\r\n')
            tracker.process_packet(http, is_uplink=True)

        # 1 TLS connection
        simulate_tls_connection(tracker, SERVER_IP, "google.com")

        self.assertEqual(tracker.uplink_tcp, 14)  # 10 HTTP + 4 TLS (SYN, ACK, CH, data)
        self.assertEqual(tracker.tls_records, 1)  # Only 1 TLS record
        self.assertEqual(tracker.sni_extracted, 1)

    def test_many_tls_few_client_hello(self):
        """Many TLS records but few ClientHellos (mostly ServerHello, AppData)."""
        tracker = PipelineTracker()

        # 1 ClientHello (uplink)
        simulate_tls_connection(tracker, SERVER_IP, "google.com")

        # 5 ServerHello-like records (downlink — not checked)
        for i in range(5):
            server_hello = build_tls_server_hello()
            pkt = build_data_packet(SERVER_IP, CLIENT_IP, 443, 30000,
                                    200 + i, 100, server_hello)
            tracker.process_packet(pkt, is_uplink=False)

        # 5 Application Data records (uplink, but not handshake)
        for i in range(5):
            app_data = bytes([0x17]) + struct.pack('!H', 0x0303) + \
                       struct.pack('!H', 50) + b'\x00' * 50
            pkt = build_data_packet(CLIENT_IP, SERVER_IP, 30000, 443,
                                    1000 + i, 200, app_data)
            tracker.process_packet(pkt, is_uplink=True)

        self.assertEqual(tracker.tls_records, 1)  # Only 1 handshake record
        self.assertEqual(tracker.client_hellos, 1)
        self.assertEqual(tracker.sni_extracted, 1)

    def test_parse_attempts_match_client_hellos(self):
        """parse_attempts should always equal client_hellos."""
        tracker = PipelineTracker()

        for i in range(10):
            simulate_tls_connection(tracker, f"10.0.0.{i}", f"site{i}.com")

        self.assertEqual(tracker.parse_attempts, tracker.client_hellos)
        self.assertEqual(tracker.parse_attempts, 10)

    def test_sni_plus_failures_equals_parse_attempts(self):
        """sni_extracted + parse_failures should equal parse_attempts."""
        tracker = PipelineTracker()

        # Valid connections
        for i in range(5):
            simulate_tls_connection(tracker, f"10.0.0.{i}", f"site{i}.com")

        # This should always hold
        self.assertEqual(tracker.sni_extracted + tracker.parse_failures,
                         tracker.parse_attempts)


# ============================================================
# Test: Cache Consistency Through Pipeline
# ============================================================

class TestCacheConsistency(unittest.TestCase):
    """Test DomainCache consistency through the pipeline."""

    def test_cache_populated_on_sni_extraction(self):
        """SNI extraction populates DomainCache."""
        tracker = PipelineTracker()
        simulate_tls_connection(tracker, SERVER_IP, "google.com")

        cached = tracker.domain_cache.get_domain(SERVER_IP)
        self.assertEqual(cached, "google.com")

    def test_cache_used_on_subsequent_packets(self):
        """Subsequent packets to same IP use cache."""
        tracker = PipelineTracker()

        # First: TLS connection (populates cache)
        simulate_tls_connection(tracker, SERVER_IP, "google.com")
        initial_hits = tracker.cache_hits

        # Then: downlink packets (should use cache)
        for _ in range(5):
            down = build_data_packet(SERVER_IP, CLIENT_IP, 443, 30000,
                                     5000, 5000, b'\x17\x03\x03' + b'\x00' * 50)
            tracker.process_packet(down, is_uplink=False)

        self.assertEqual(tracker.cache_hits, initial_hits + 5)

    def test_cache_domain_appears_in_get_flows(self):
        """Domain from cache appears in getFlows() output."""
        tracker = PipelineTracker()

        # Extract SNI
        simulate_tls_connection(tracker, SERVER_IP, "google.com")

        # Clear flows but keep cache
        tracker.flows.clear()

        # Create new flow to same IP (no SNI)
        syn = build_syn_packet(CLIENT_IP, SERVER_IP, 30001, 443, 1000)
        tracker.process_packet(syn, is_uplink=True)

        # getFlows() should show domain from cache
        flows = tracker.get_flows()
        self.assertEqual(flows[0].domain, "google.com")

    def test_cache_size_matches_unique_domains(self):
        """Cache size equals number of unique domains extracted."""
        tracker = PipelineTracker()

        domains = [
            (SERVER_IP, "google.com"),
            (CDN_IP, "reddit.com"),
            (API_IP, "github.com"),
        ]
        for ip, domain in domains:
            simulate_tls_connection(tracker, ip, domain)

        self.assertEqual(tracker.domain_cache.size(), 3)

    def test_cache_overwrites_same_ip(self):
        """Same IP with different domain — last write wins."""
        tracker = PipelineTracker()

        tracker.domain_cache.put_domain("1.2.3.4", "first.com")
        tracker.domain_cache.put_domain("1.2.3.4", "second.com")

        self.assertEqual(tracker.domain_cache.get_domain("1.2.3.4"), "second.com")
        self.assertEqual(tracker.domain_cache.size(), 1)


# ============================================================
# Test: Debug Stats Format
# ============================================================

class TestDebugStatsFormat(unittest.TestCase):
    """Test debug stats string format and accuracy."""

    def test_stats_format_after_tls(self):
        """Debug stats show correct counts after TLS connection."""
        tracker = PipelineTracker()
        simulate_tls_connection(tracker, SERVER_IP, "google.com")

        stats = tracker.get_debug_stats()
        self.assertIn("pkts=", stats)
        self.assertIn("tcp=", stats)
        self.assertIn("tls=", stats)
        self.assertIn("ch=", stats)
        self.assertIn("parse=", stats)
        self.assertIn("fail=0", stats)
        self.assertIn("sni=1", stats)
        self.assertIn("cache=", stats)

    def test_stats_format_after_clear(self):
        """Debug stats reset after clear."""
        tracker = PipelineTracker()
        simulate_tls_connection(tracker, SERVER_IP, "google.com")
        tracker.clear()

        stats = tracker.get_debug_stats()
        self.assertIn("pkts=0", stats)
        self.assertIn("tcp=0", stats)
        self.assertIn("tls=0", stats)
        self.assertIn("ch=0", stats)
        self.assertIn("sni=0", stats)

    def test_stats_shows_flow_domains(self):
        """Debug stats show flow domain and cache info."""
        tracker = PipelineTracker()
        simulate_tls_connection(tracker, SERVER_IP, "google.com")

        stats = tracker.get_debug_stats()
        # Stats should contain domain and cached info for top flows
        self.assertIn("domain=", stats)
        self.assertIn("cached=", stats)
        self.assertIn("google.com", stats.lower())


# ============================================================
# Test: Edge Cases in Pipeline
# ============================================================

class TestPipelineEdgeCases(unittest.TestCase):
    """Edge cases in the pipeline."""

    def test_empty_packet(self):
        """Empty packet — no counters increment."""
        tracker = PipelineTracker()
        tracker.process_packet(b'', is_uplink=True)
        self.assertEqual(tracker.total_packets, 0)

    def test_ipv6_packet(self):
        """IPv6 packet — ignored."""
        tracker = PipelineTracker()
        ipv6 = b'\x60' + b'\x00' * 39
        tracker.process_packet(ipv6, is_uplink=True)
        self.assertEqual(tracker.total_packets, 0)

    def test_icmp_packet(self):
        """ICMP packet — counted but no TCP/TLS."""
        tracker = PipelineTracker()
        icmp = build_ip_header(CLIENT_IP, SERVER_IP, 1, 8) + b'\x08\x00\x00\x00\x00\x01\x00\x01'
        tracker.process_packet(icmp, is_uplink=True)
        self.assertEqual(tracker.total_packets, 1)
        self.assertEqual(tracker.uplink_tcp, 0)

    def test_downlink_tcp_not_checked_for_sni(self):
        """Downlink TCP packets are NOT checked for SNI."""
        tracker = PipelineTracker()
        # ServerHello (downlink)
        sh = build_tls_server_hello()
        pkt = build_data_packet(SERVER_IP, CLIENT_IP, 443, 30000, 200, 100, sh)
        tracker.process_packet(pkt, is_uplink=False)
        self.assertEqual(tracker.uplink_tcp, 0)
        self.assertEqual(tracker.tls_records, 0)

    def test_packet_with_ip_options(self):
        """Packet with IP options (IHL > 5) — should still work."""
        tracker = PipelineTracker()
        # IHL = 6 (24 bytes)
        ip = bytearray(24)
        ip[0] = (4 << 4) | 6
        struct.pack_into('!H', ip, 2, 24 + 20 + 50)
        ip[8] = 64
        ip[9] = 6
        ip[12:16] = socket.inet_aton(CLIENT_IP)
        ip[16:20] = socket.inet_aton(SERVER_IP)
        ip[20:24] = b'\x00\x00\x00\x00'  # options

        tcp = build_tcp_header(30000, 443, 100, 200, 0x18,
                               build_tls_client_hello("options.example.com"))
        pkt = bytes(ip) + tcp
        tracker.process_packet(pkt, is_uplink=True)

        self.assertEqual(tracker.sni_extracted, 1)

    def test_rapid_fire_connections(self):
        """100 rapid connections — all should extract SNI."""
        tracker = PipelineTracker()
        for i in range(100):
            simulate_tls_connection(tracker, f"10.0.{i // 256}.{i % 256}", f"site{i}.com")

        self.assertEqual(tracker.sni_extracted, 100)
        self.assertEqual(tracker.parse_failures, 0)
        self.assertEqual(tracker.client_hellos, 100)


if __name__ == '__main__':
    unittest.main(verbosity=2)
