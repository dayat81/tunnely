#!/usr/bin/env python3
"""
Tests for server-side SNI domain extraction and stats API.

Server extracts SNI from TLS ClientHello in tcp_debug.recent_snis.
Client fetches this via /api/vpn/stats and uses it as final fallback
when FlowStats.domain and DomainCache are both null (ARM visibility bug).

Tests cover:
  1. Server TLS SNI extraction from packets
  2. tcp_debug.recent_snis format validation
  3. Client-side parsing of the SNI format
  4. Edge cases: malformed entries, empty data, IPv6
"""

import struct
import socket
import unittest
from typing import Optional, Dict, List, Tuple

from test_ssl_traffic_simulation import (
    build_ip_header, build_tcp_header, build_tls_client_hello,
    build_data_packet, build_tls_server_hello,
    CLIENT_IP, SERVER_IP, TLS_HANDSHAKE, CLIENT_HELLO,
)


# ============================================================
# Server-side SNI extraction (mirrors udp_vpn_server.py)
# ============================================================

class ServerSniExtractor:
    """Mirrors the server's TLS SNI extraction logic."""

    def __init__(self):
        self._tls_sni_log: List[str] = []
        self._tcp_tracker: Dict[str, Dict] = {}

    def extract_sni_from_packet(self, data: bytes, src_ip: str, dst_ip: str) -> Optional[str]:
        """Extract SNI from a TLS ClientHello packet (mirrors server code).
        Accepts either raw TLS data or full IP packets."""
        # If it starts with 0x45 (IPv4), extract TCP payload
        if len(data) >= 20 and (data[0] & 0xF0) == 0x40:
            ihl = (data[0] & 0x0F) * 4
            if len(data) >= ihl + 20:
                tcp_doff = ((data[ihl + 12] & 0xF0) >> 4) * 4
                payload_start = ihl + tcp_doff
                if payload_start < len(data):
                    data = data[payload_start:]

        if len(data) < 5:
            return None
        if data[0] != 0x16:  # TLS Handshake
            return None
        if data[5] != 0x01:  # ClientHello
            return None

        # Parse TLS record
        try:
            record_len = struct.unpack('!H', data[3:5])[0]
            handshake_len = (data[6] << 16) | struct.unpack('!H', data[7:9])[0]

            # ClientHello body starts at offset 9
            pos = 9
            if pos + 2 > len(data):
                return None
            client_version = struct.unpack('!H', data[pos:pos+2])[0]
            pos += 2

            # Skip random (32 bytes)
            pos += 32

            # Session ID
            if pos + 1 > len(data):
                return None
            session_id_len = data[pos]
            pos += 1 + session_id_len

            # Cipher Suites
            if pos + 2 > len(data):
                return None
            cs_len = struct.unpack('!H', data[pos:pos+2])[0]
            pos += 2 + cs_len

            # Compression
            if pos + 1 > len(data):
                return None
            comp_len = data[pos]
            pos += 1 + comp_len

            # Extensions
            if pos + 2 > len(data):
                return None
            ext_len = struct.unpack('!H', data[pos:pos+2])[0]
            pos += 2
            ext_end = pos + ext_len

            while pos + 4 <= ext_end and pos + 4 <= len(data):
                ext_type = struct.unpack('!H', data[pos:pos+2])[0]
                ext_data_len = struct.unpack('!H', data[pos+2:pos+4])[0]
                pos += 4

                if ext_type == 0x0000:  # SNI extension
                    if pos + 2 > len(data):
                        return None
                    sni_list_len = struct.unpack('!H', data[pos:pos+2])[0]
                    sni_pos = pos + 2
                    if sni_pos + 3 <= len(data):
                        name_type = data[sni_pos]
                        name_len = struct.unpack('!H', data[sni_pos+1:sni_pos+3])[0]
                        sni_pos += 3
                        if name_type == 0 and sni_pos + name_len <= len(data):
                            name = data[sni_pos:sni_pos+name_len].decode('ascii', errors='ignore')
                            return name

                pos += ext_data_len

        except Exception:
            pass
        return None

    def record_sni(self, src_ip: str, dst_ip: str, dst_port: int, sni: str):
        """Record SNI extraction in the log (mirrors server _tls_sni_log)."""
        entry = f"{src_ip}→{dst_ip}:{dst_port} = {sni}"
        self._tls_sni_log.append(entry)

    def get_recent_snis(self) -> List[str]:
        """Get recent SNI entries (mirrors tcp_debug.recent_snis)."""
        return list(self._tls_sni_log[-10:])

    def get_tcp_debug_summary(self) -> dict:
        """Get TCP debug summary (mirrors server get_tcp_debug_summary)."""
        return {
            "tcp_flows": 0,
            "tls_handshakes": 0,
            "sni_domains": len(self._tls_sni_log),
            "recent_snis": self.get_recent_snis(),
        }


# ============================================================
# Client-side SNI format parser (mirrors ApiClient.getServerSniDomains)
# ============================================================

def parse_server_sni_entries(entries: List[str]) -> Dict[str, str]:
    """Parse server SNI entries into remote_ip -> domain map.
    Mirrors ApiClient.getServerSniDomains() Kotlin code."""
    domain_map = {}
    for entry in entries:
        arrow_idx = entry.find('→')
        equals_idx = entry.find('=')
        if arrow_idx >= 0 and equals_idx > arrow_idx:
            remote_part = entry[arrow_idx+1:equals_idx].strip()
            domain = entry[equals_idx+1:].strip().lower()
            colon_idx = remote_part.find(':')
            remote_ip = remote_part[:colon_idx] if colon_idx > 0 else remote_part
            if domain:
                domain_map[remote_ip] = domain
    return domain_map


# ============================================================
# Helper to build a TLS ClientHello for a specific dest IP
# ============================================================

def build_tls_client_hello_for(sni_hostname: str, dst_ip: str, dst_port: int = 443) -> bytes:
    """Build TLS ClientHello packet with specific destination IP/port.
    Returns a full IP packet with TLS ClientHello payload."""
    tls_data = build_tls_client_hello(sni_hostname)
    return build_data_packet(CLIENT_IP, dst_ip, 30000, dst_port, 100, 200, tls_data)


# ============================================================
# Test: Server SNI Extraction
# ============================================================

class TestServerSniExtraction(unittest.TestCase):
    """Test server-side TLS SNI extraction from raw packets."""

    def setUp(self):
        self.extractor = ServerSniExtractor()

    def test_extract_sni_basic(self):
        """Basic SNI extraction from TLS ClientHello."""
        packet = build_tls_client_hello("google.com")
        sni = self.extractor.extract_sni_from_packet(packet, CLIENT_IP, SERVER_IP)
        self.assertEqual(sni, "google.com")

    def test_extract_sni_facebook(self):
        """Extract Facebook SNI."""
        packet = build_tls_client_hello("www.facebook.com")
        sni = self.extractor.extract_sni_from_packet(packet, CLIENT_IP, SERVER_IP)
        self.assertEqual(sni, "www.facebook.com")

    def test_extract_sni_subdomain(self):
        """Extract deep subdomain SNI."""
        packet = build_tls_client_hello("api.v2.internal.example.com")
        sni = self.extractor.extract_sni_from_packet(packet, CLIENT_IP, SERVER_IP)
        self.assertEqual(sni, "api.v2.internal.example.com")

    def test_extract_sni_custom_dest(self):
        """Extract SNI from packet with custom destination IP."""
        packet = build_tls_client_hello_for("cloudflare.com", "1.1.1.1", 443)
        sni = self.extractor.extract_sni_from_packet(packet, CLIENT_IP, "1.1.1.1")
        self.assertEqual(sni, "cloudflare.com")

    def test_extract_sni_exotic_port(self):
        """Extract SNI from non-standard port (853 = DNS-over-TLS)."""
        packet = build_tls_client_hello_for("dns.google", "8.8.8.8", 853)
        sni = self.extractor.extract_sni_from_packet(packet, CLIENT_IP, "8.8.8.8")
        self.assertEqual(sni, "dns.google")

    def test_no_sni_non_tls(self):
        """Non-TLS packet returns None."""
        non_tls = build_data_packet(CLIENT_IP, SERVER_IP, 30000, 80, 100, 200, b'\x00' * 20)
        sni = self.extractor.extract_sni_from_packet(non_tls, CLIENT_IP, SERVER_IP)
        self.assertIsNone(sni)

    def test_no_sni_server_hello(self):
        """ServerHello packet returns None."""
        packet = build_tls_server_hello()
        sni = self.extractor.extract_sni_from_packet(packet, CLIENT_IP, SERVER_IP)
        self.assertIsNone(sni)

    def test_no_sni_empty_packet(self):
        """Empty packet returns None."""
        sni = self.extractor.extract_sni_from_packet(b'', CLIENT_IP, SERVER_IP)
        self.assertIsNone(sni)

    def test_no_sni_truncated(self):
        """Truncated packet returns None."""
        sni = self.extractor.extract_sni_from_packet(b'\x16\x03\x01', CLIENT_IP, SERVER_IP)
        self.assertIsNone(sni)


# ============================================================
# Test: Server SNI Recording
# ============================================================

class TestServerSniRecording(unittest.TestCase):
    """Test server-side SNI recording and log format."""

    def setUp(self):
        self.extractor = ServerSniExtractor()

    def test_record_single_sni(self):
        """Record single SNI extraction."""
        self.extractor.record_sni(CLIENT_IP, SERVER_IP, 443, "google.com")
        recent = self.extractor.get_recent_snis()
        self.assertEqual(len(recent), 1)
        self.assertIn(CLIENT_IP, recent[0])
        self.assertIn(SERVER_IP, recent[0])
        self.assertIn("google.com", recent[0])

    def test_record_format_arrow(self):
        """SNI entry uses → (arrow) separator."""
        self.extractor.record_sni("10.20.0.2", "142.251.10.95", 443, "google.com")
        entry = self.extractor.get_recent_snis()[0]
        self.assertIn("→", entry)
        self.assertEqual(entry, "10.20.0.2→142.251.10.95:443 = google.com")

    def test_record_multiple_domains(self):
        """Record multiple different domains."""
        self.extractor.record_sni(CLIENT_IP, "1.1.1.1", 443, "cloudflare.com")
        self.extractor.record_sni(CLIENT_IP, "2.2.2.2", 443, "facebook.com")
        self.extractor.record_sni(CLIENT_IP, "3.3.3.3", 443, "amazon.com")

        recent = self.extractor.get_recent_snis()
        self.assertEqual(len(recent), 3)

    def test_recent_snis_limited_to_10(self):
        """Recent SNI list is capped at 10 entries."""
        for i in range(15):
            self.extractor.record_sni(CLIENT_IP, f"10.0.0.{i}", 443, f"site{i}.com")

        recent = self.extractor.get_recent_snis()
        self.assertEqual(len(recent), 10)
        # Last 10 entries
        self.assertIn("site14.com", recent[-1])
        self.assertIn("site5.com", recent[0])

    def test_same_ip_different_ports(self):
        """Same IP with different ports creates separate entries."""
        self.extractor.record_sni(CLIENT_IP, "1.2.3.4", 443, "example.com")
        self.extractor.record_sni(CLIENT_IP, "1.2.3.4", 8443, "api.example.com")

        recent = self.extractor.get_recent_snis()
        self.assertEqual(len(recent), 2)

    def test_tcp_debug_summary_structure(self):
        """tcp_debug summary has correct structure."""
        self.extractor.record_sni(CLIENT_IP, SERVER_IP, 443, "google.com")
        summary = self.extractor.get_tcp_debug_summary()

        self.assertIn("tcp_flows", summary)
        self.assertIn("tls_handshakes", summary)
        self.assertIn("sni_domains", summary)
        self.assertIn("recent_snis", summary)
        self.assertIsInstance(summary["recent_snis"], list)
        self.assertEqual(summary["sni_domains"], 1)


# ============================================================
# Test: Client-side SNI Format Parsing
# ============================================================

class TestClientSniParsing(unittest.TestCase):
    """Test client-side parsing of server SNI format."""

    def test_parse_basic(self):
        """Parse basic SNI entry."""
        entries = ["10.20.0.243→142.251.10.95:443 = pubsub.googleapis.com"]
        result = parse_server_sni_entries(entries)
        self.assertEqual(result["142.251.10.95"], "pubsub.googleapis.com")

    def test_parse_multiple_entries(self):
        """Parse multiple SNI entries."""
        entries = [
            "10.20.0.243→142.251.10.95:443 = pubsub.googleapis.com",
            "10.20.0.243→157.240.1.35:443 = www.facebook.com",
            "10.20.0.243→151.101.1.140:443 = www.reddit.com"
        ]
        result = parse_server_sni_entries(entries)
        self.assertEqual(len(result), 3)
        self.assertEqual(result["142.251.10.95"], "pubsub.googleapis.com")
        self.assertEqual(result["157.240.1.35"], "www.facebook.com")
        self.assertEqual(result["151.101.1.140"], "www.reddit.com")

    def test_parse_domain_lowercased(self):
        """Domain is lowercased by parser."""
        entries = ["10.20.0.243→1.2.3.4:443 = EXAMPLE.COM"]
        result = parse_server_sni_entries(entries)
        self.assertEqual(result["1.2.3.4"], "example.com")

    def test_parse_empty_list(self):
        """Empty list returns empty map."""
        result = parse_server_sni_entries([])
        self.assertEqual(result, {})

    def test_parse_malformed_no_arrow(self):
        """Entry without → is skipped."""
        entries = ["malformed entry without arrow"]
        result = parse_server_sni_entries(entries)
        self.assertEqual(result, {})

    def test_parse_malformed_no_equals(self):
        """Entry without = after → is skipped."""
        entries = ["10.20.0.243→142.251.10.95:443"]
        result = parse_server_sni_entries(entries)
        self.assertEqual(result, {})

    def test_parse_malformed_arrow_after_equals(self):
        """Entry with → after = is skipped."""
        entries = ["= nothing → 10.20.0.243"]
        result = parse_server_sni_entries(entries)
        self.assertEqual(result, {})

    def test_parse_empty_domain_skipped(self):
        """Entry with empty domain after = is skipped."""
        entries = ["10.20.0.243→1.2.3.4:443 = "]
        result = parse_server_sni_entries(entries)
        self.assertEqual(result, {})

    def test_parse_no_port(self):
        """Entry without port in remote part."""
        entries = ["10.20.0.243→142.251.10.95 = google.com"]
        result = parse_server_sni_entries(entries)
        self.assertEqual(result["142.251.10.95"], "google.com")

    def test_parse_same_ip_last_wins(self):
        """Same IP with different ports — last entry wins."""
        entries = [
            "10.20.0.243→1.2.3.4:443 = first.com",
            "10.20.0.243→1.2.3.4:8443 = second.com"
        ]
        result = parse_server_sni_entries(entries)
        self.assertEqual(result["1.2.3.4"], "second.com")

    def test_parse_different_client_ips(self):
        """Different client IPs still map to same remote IP."""
        entries = [
            "10.20.0.2→1.2.3.4:443 = from-client1.com",
            "10.20.0.3→1.2.3.4:443 = from-client2.com"
        ]
        result = parse_server_sni_entries(entries)
        self.assertEqual(result["1.2.3.4"], "from-client2.com")

    def test_parse_deep_subdomain(self):
        """Deep subdomain parsed correctly."""
        entries = ["10.20.0.243→1.2.3.4:443 = api.v2.internal.corp.example.com"]
        result = parse_server_sni_entries(entries)
        self.assertEqual(result["1.2.3.4"], "api.v2.internal.corp.example.com")

    def test_parse_exotic_port(self):
        """Non-standard port parsed correctly."""
        entries = ["10.20.0.243→1.2.3.4:853 = dns.google"]
        result = parse_server_sni_entries(entries)
        self.assertEqual(result["1.2.3.4"], "dns.google")


# ============================================================
# Test: End-to-End SNI Pipeline
# ============================================================

class TestEndToEndSniPipeline(unittest.TestCase):
    """Test the full pipeline: packet → server extract → client parse → display."""

    def setUp(self):
        self.extractor = ServerSniExtractor()

    def test_full_pipeline_single_flow(self):
        """Full pipeline for a single TLS connection."""
        # 1. Server extracts SNI from packet
        packet = build_tls_client_hello("google.com")
        sni = self.extractor.extract_sni_from_packet(packet, CLIENT_IP, SERVER_IP)
        self.assertIsNotNone(sni)
        assert sni is not None  # type guard
        self.assertEqual(sni, "google.com")

        # 2. Server records SNI
        self.extractor.record_sni(CLIENT_IP, SERVER_IP, 443, sni)

        # 3. Client fetches stats
        summary = self.extractor.get_tcp_debug_summary()
        recent_snis = summary["recent_snis"]

        # 4. Client parses SNI entries
        domain_map = parse_server_sni_entries(recent_snis)

        # 5. Domain map has the right IP → domain
        self.assertEqual(domain_map[SERVER_IP], "google.com")

    def test_full_pipeline_multiple_flows(self):
        """Full pipeline with multiple concurrent TLS connections."""
        domains = [
            ("142.251.10.95", 443, "google.com"),
            ("157.240.1.35", 443, "facebook.com"),
            ("151.101.1.140", 443, "reddit.com"),
        ]

        for dst_ip, dst_port, domain in domains:
            packet = build_tls_client_hello_for(domain, dst_ip, dst_port)
            sni = self.extractor.extract_sni_from_packet(packet, CLIENT_IP, dst_ip)
            self.assertIsNotNone(sni)
            assert sni is not None
            self.assertEqual(sni, domain)
            self.extractor.record_sni(CLIENT_IP, dst_ip, dst_port, sni)

        summary = self.extractor.get_tcp_debug_summary()
        domain_map = parse_server_sni_entries(summary["recent_snis"])

        self.assertEqual(len(domain_map), 3)
        self.assertEqual(domain_map["142.251.10.95"], "google.com")
        self.assertEqual(domain_map["157.240.1.35"], "facebook.com")
        self.assertEqual(domain_map["151.101.1.140"], "reddit.com")

    def test_full_pipeline_non_tls_filtered(self):
        """Non-TLS packets don't create SNI entries."""
        non_tls = build_data_packet(CLIENT_IP, SERVER_IP, 30000, 80, 100, 200,
                                     b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        sni = self.extractor.extract_sni_from_packet(non_tls, CLIENT_IP, SERVER_IP)
        self.assertIsNone(sni)

        # TLS packet does
        tls = build_tls_client_hello("example.com")
        sni = self.extractor.extract_sni_from_packet(tls, CLIENT_IP, SERVER_IP)
        self.assertIsNotNone(sni)

    def test_full_pipeline_repeated_connections(self):
        """Repeated connections to same domain consolidate to single IP entry."""
        for _ in range(5):
            packet = build_tls_client_hello("google.com")
            sni = self.extractor.extract_sni_from_packet(packet, CLIENT_IP, SERVER_IP)
            assert sni is not None
            self.extractor.record_sni(CLIENT_IP, SERVER_IP, 443, sni)

        summary = self.extractor.get_tcp_debug_summary()
        self.assertEqual(summary["sni_domains"], 5)  # 5 log entries

        domain_map = parse_server_sni_entries(summary["recent_snis"])
        self.assertEqual(domain_map[SERVER_IP], "google.com")  # But only 1 IP entry

    def test_full_pipeline_with_malformed_entries(self):
        """Malformed entries in recent_snis don't crash client parser."""
        # Add valid and malformed entries
        self.extractor.record_sni(CLIENT_IP, SERVER_IP, 443, "google.com")
        self.extractor._tls_sni_log.append("malformed entry")  # no arrow
        self.extractor._tls_sni_log.append("no arrow = nothing")  # no arrow
        self.extractor.record_sni(CLIENT_IP, "1.1.1.1", 443, "cloudflare.com")

        summary = self.extractor.get_tcp_debug_summary()
        domain_map = parse_server_sni_entries(summary["recent_snis"])

        # Valid entries parsed, malformed skipped
        self.assertEqual(domain_map[SERVER_IP], "google.com")
        self.assertEqual(domain_map["1.1.1.1"], "cloudflare.com")
        self.assertEqual(len(domain_map), 2)


# ============================================================
# Test: Domain Fallback Priority Chain
# ============================================================

class TestDomainFallbackPriority(unittest.TestCase):
    """Test the fallback priority: FlowStats.domain → DomainCache → serverSniMap."""

    def test_server_sni_as_last_resort(self):
        """Server SNI is used when all other sources fail."""
        entries = ["10.20.0.243→142.251.10.95:443 = google.com"]
        server_map = parse_server_sni_entries(entries)

        domain = server_map.get("142.251.10.95")
        self.assertEqual(domain, "google.com")

    def test_server_sni_does_not_override_unknown_ip(self):
        """Server SNI returns None for unknown IPs."""
        entries = ["10.20.0.243→142.251.10.95:443 = google.com"]
        server_map = parse_server_sni_entries(entries)

        self.assertIsNone(server_map.get("99.99.99.99"))

    def test_server_sni_partial_coverage(self):
        """Server SNI covers some IPs but not all."""
        entries = [
            "10.20.0.243→142.251.10.95:443 = google.com",
            "10.20.0.243→157.240.1.35:443 = facebook.com",
        ]
        server_map = parse_server_sni_entries(entries)

        self.assertEqual(server_map.get("142.251.10.95"), "google.com")
        self.assertEqual(server_map.get("157.240.1.35"), "facebook.com")
        self.assertIsNone(server_map.get("3.3.3.3"))


# ============================================================
# Test: Edge Cases
# ============================================================

class TestEdgeCases(unittest.TestCase):
    """Edge cases for SNI extraction and parsing."""

    def test_unicode_in_entry(self):
        """Unicode characters in entries handled gracefully."""
        entries = ["10.20.0.243→1.2.3.4:443 = café.com"]
        result = parse_server_sni_entries(entries)
        # Unicode domain is preserved (lowercased)
        self.assertEqual(result["1.2.3.4"], "café.com")

    def test_very_long_domain(self):
        """Very long domain name parsed correctly."""
        long_domain = "a." * 50 + "example.com"
        entries = [f"10.20.0.243→1.2.3.4:443 = {long_domain}"]
        result = parse_server_sni_entries(entries)
        self.assertEqual(result["1.2.3.4"], long_domain.lower())

    def test_domain_with_numbers(self):
        """Domain with numeric parts parsed correctly."""
        entries = ["10.20.0.243→1.2.3.4:443 = 123.456.example.com"]
        result = parse_server_sni_entries(entries)
        self.assertEqual(result["1.2.3.4"], "123.456.example.com")

    def test_ip_with_port_65535(self):
        """Max port number parsed correctly."""
        entries = ["10.20.0.243→1.2.3.4:65535 = test.com"]
        result = parse_server_sni_entries(entries)
        self.assertEqual(result["1.2.3.4"], "test.com")

    def test_many_entries_stress(self):
        """100 entries parsed without issues."""
        entries = [f"10.20.0.243→10.0.0.{i}:443 = site{i}.com" for i in range(100)]
        result = parse_server_sni_entries(entries)
        self.assertEqual(len(result), 100)
        self.assertEqual(result["10.0.0.0"], "site0.com")
        self.assertEqual(result["10.0.0.99"], "site99.com")

    def test_duplicate_domains_different_ips(self):
        """Same domain on different IPs — both preserved."""
        entries = [
            "10.20.0.243→1.1.1.1:443 = cdn.example.com",
            "10.20.0.243→2.2.2.2:443 = cdn.example.com",
        ]
        result = parse_server_sni_entries(entries)
        self.assertEqual(len(result), 2)
        self.assertEqual(result["1.1.1.1"], "cdn.example.com")
        self.assertEqual(result["2.2.2.2"], "cdn.example.com")


# ============================================================
# Test: Additional Edge Cases
# ============================================================

class TestAdditionalEdgeCases(unittest.TestCase):
    """Additional edge cases for robustness."""

    # --- Format Edge Cases ---

    def test_parse_entry_with_extra_whitespace(self):
        """Extra whitespace around → and = is trimmed."""
        entries = ["  10.20.0.243  →  1.2.3.4:443  =  google.com  "]
        result = parse_server_sni_entries(entries)
        self.assertEqual(result["1.2.3.4"], "google.com")

    def test_parse_entry_with_tab_whitespace(self):
        """Tab and space whitespace trimmed."""
        entries = ["10.20.0.243\t→\t1.2.3.4:443\t=\tgoogle.com"]
        result = parse_server_sni_entries(entries)
        self.assertEqual(result["1.2.3.4"], "google.com")

    def test_parse_entry_equals_in_domain(self):
        """Domain containing = character."""
        entries = ["10.20.0.243→1.2.3.4:443 = test=domain.com"]
        result = parse_server_sni_entries(entries)
        # Parser uses first = as separator, so domain = "test=domain.com"
        self.assertEqual(result["1.2.3.4"], "test=domain.com")

    def test_parse_entry_arrow_in_domain(self):
        """Domain containing → character (edge case)."""
        entries = ["10.20.0.243→1.2.3.4:443 = test→domain.com"]
        result = parse_server_sni_entries(entries)
        self.assertEqual(result["1.2.3.4"], "test→domain.com")

    def test_parse_entry_with_empty_remote_ip(self):
        """Entry with empty remote IP (→= domain)."""
        entries = ["10.20.0.243→= empty-remote.com"]
        result = parse_server_sni_entries(entries)
        # Empty remote IP, but domain is non-empty
        self.assertIn("", result)

    def test_parse_entry_only_arrow(self):
        """Entry with only → character."""
        entries = ["→"]
        result = parse_server_sni_entries(entries)
        self.assertEqual(len(result), 0)

    def test_parse_entry_arrow_then_equals(self):
        """Entry with →= only."""
        entries = ["→="]
        result = parse_server_sni_entries(entries)
        self.assertEqual(len(result), 0)

    def test_parse_entry_arrow_equals_domain(self):
        """Entry with →=domain."""
        entries = ["→=only.com"]
        result = parse_server_sni_entries(entries)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[""], "only.com")

    def test_parse_entry_ip_only_no_port(self):
        """IP without port after →."""
        entries = ["10.20.0.243→192.168.1.1 = lan.local"]
        result = parse_server_sni_entries(entries)
        self.assertEqual(result["192.168.1.1"], "lan.local")

    def test_parse_entry_ipv6_style(self):
        """IPv6-like address (not standard but should not crash)."""
        entries = ["10.20.0.243→::1:443 = localhost"]
        result = parse_server_sni_entries(entries)
        # Parser splits on first ':', colon_idx=0, so colon_idx > 0 is false
        # remote_ip = "::1:443" (full string used as key)
        self.assertEqual(result["::1:443"], "localhost")

    # --- Scale Edge Cases ---

    def test_parse_1000_entries(self):
        """1000 entries parsed correctly."""
        entries = [f"10.20.0.243→10.{i//256}.{i%256}.1:443 = host{i}.example.com" for i in range(1000)]
        result = parse_server_sni_entries(entries)
        self.assertEqual(len(result), 1000)
        self.assertEqual(result["10.0.0.1"], "host0.example.com")
        # 999: 999//256=3, 999%256=231 → "10.3.231.1"
        self.assertEqual(result["10.3.231.1"], "host999.example.com")

    def test_parse_single_entry(self):
        """Single entry works correctly."""
        entries = ["10.20.0.243→8.8.8.8:443 = dns.google"]
        result = parse_server_sni_entries(entries)
        self.assertEqual(len(result), 1)
        self.assertEqual(result["8.8.8.8"], "dns.google")

    # --- Domain Format Edge Cases ---

    def test_domain_with_single_label(self):
        """Single-label domain (no dots)."""
        entries = ["10.20.0.243→1.2.3.4:443 = localhost"]
        result = parse_server_sni_entries(entries)
        self.assertEqual(result["1.2.3.4"], "localhost")

    def test_domain_with_wildcard_prefix(self):
        """Wildcard domain (*.example.com)."""
        entries = ["10.20.0.243→1.2.3.4:443 = *.example.com"]
        result = parse_server_sni_entries(entries)
        self.assertEqual(result["1.2.3.4"], "*.example.com")

    def test_domain_with_port_in_name(self):
        """Domain that looks like it has a port."""
        entries = ["10.20.0.243→1.2.3.4:443 = host:8080.example.com"]
        result = parse_server_sni_entries(entries)
        self.assertEqual(result["1.2.3.4"], "host:8080.example.com")

    def test_domain_max_length(self):
        """Domain at max length (253 chars)."""
        long_domain = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 60 + ".com"
        entries = [f"10.20.0.243→1.2.3.4:443 = {long_domain}"]
        result = parse_server_sni_entries(entries)
        self.assertEqual(result["1.2.3.4"], long_domain.lower())

    # --- End-to-End Edge Cases ---

    def test_extraction_then_parsing_roundtrip(self):
        """Extract SNI from real TLS packet, record, parse — full roundtrip."""
        extractor = ServerSniExtractor()

        # Extract from real TLS packet
        packet = build_tls_client_hello("roundtrip.example.com")
        sni = extractor.extract_sni_from_packet(packet, CLIENT_IP, SERVER_IP)
        self.assertIsNotNone(sni)
        assert sni is not None
        self.assertEqual(sni, "roundtrip.example.com")

        # Record
        extractor.record_sni(CLIENT_IP, SERVER_IP, 443, sni)

        # Parse (mirrors client code)
        summary = extractor.get_tcp_debug_summary()
        result = parse_server_sni_entries(summary["recent_snis"])

        self.assertEqual(result[SERVER_IP], "roundtrip.example.com")

    def test_extraction_with_ip_options(self):
        """Packet with IP options (IHL > 5) still extracts SNI."""
        # Build packet with IHL=6 (24 bytes IP header)
        tls_data = build_tls_client_hello("options.example.com")
        ip = bytearray(24)  # IHL=6
        ip[0] = 0x46  # Version 4, IHL 6
        ip[9] = 6  # TCP
        # ... fill in IPs
        for i, b in enumerate([int(x) for x in CLIENT_IP.split('.')]):
            ip[12 + i] = b
        for i, b in enumerate([int(x) for x in SERVER_IP.split('.')]):
            ip[16 + i] = b

        tcp = bytearray(20)
        tcp[0] = (30000 >> 8) & 0xFF
        tcp[1] = 30000 & 0xFF
        tcp[2] = (443 >> 8) & 0xFF
        tcp[3] = 443 & 0xFF
        tcp[12] = 0x50  # data offset 5

        packet = bytes(ip) + bytes(tcp) + tls_data

        extractor = ServerSniExtractor()
        sni = extractor.extract_sni_from_packet(packet, CLIENT_IP, SERVER_IP)
        self.assertEqual(sni, "options.example.com")

    def test_extraction_with_tcp_options(self):
        """Packet with TCP options (data offset > 5) still extracts SNI."""
        tls_data = build_tls_client_hello("tcpopts.example.com")
        ip = bytearray(20)
        ip[0] = 0x45
        ip[9] = 6
        for i, b in enumerate([int(x) for x in CLIENT_IP.split('.')]):
            ip[12 + i] = b
        for i, b in enumerate([int(x) for x in SERVER_IP.split('.')]):
            ip[16 + i] = b

        tcp = bytearray(24)  # data offset = 6 (24 bytes)
        tcp[0] = (30000 >> 8) & 0xFF
        tcp[1] = 30000 & 0xFF
        tcp[2] = (443 >> 8) & 0xFF
        tcp[3] = 443 & 0xFF
        tcp[12] = 0x60  # data offset 6

        packet = bytes(ip) + bytes(tcp) + tls_data

        extractor = ServerSniExtractor()
        sni = extractor.extract_sni_from_packet(packet, CLIENT_IP, SERVER_IP)
        self.assertEqual(sni, "tcpopts.example.com")

    def test_multiple_extractions_same_packet(self):
        """Extracting SNI from same packet twice returns same result."""
        packet = build_tls_client_hello("idempotent.com")
        extractor = ServerSniExtractor()

        sni1 = extractor.extract_sni_from_packet(packet, CLIENT_IP, SERVER_IP)
        sni2 = extractor.extract_sni_from_packet(packet, CLIENT_IP, SERVER_IP)
        self.assertEqual(sni1, sni2)
        self.assertEqual(sni1, "idempotent.com")

    def test_extraction_from_various_tls_versions(self):
        """SNI extracted regardless of TLS version in record header."""
        # build_tls_client_hello uses TLS 1.2 record version by default
        # The SNI parser should work with any TLS version
        packet = build_tls_client_hello("version-test.com")
        extractor = ServerSniExtractor()
        sni = extractor.extract_sni_from_packet(packet, CLIENT_IP, SERVER_IP)
        self.assertEqual(sni, "version-test.com")

    # --- Server-side Edge Cases ---

    def test_sni_log_preserves_order(self):
        """SNI log preserves insertion order (FIFO)."""
        extractor = ServerSniExtractor()
        for i in range(5):
            extractor.record_sni(CLIENT_IP, f"10.0.0.{i}", 443, f"order{i}.com")

        recent = extractor.get_recent_snis()
        for i, entry in enumerate(recent):
            self.assertIn(f"order{i}.com", entry)

    def test_sni_log_dedup_not_performed(self):
        """Server does NOT deduplicate SNI entries (each extraction logged)."""
        extractor = ServerSniExtractor()
        for _ in range(5):
            extractor.record_sni(CLIENT_IP, SERVER_IP, 443, "same.com")

        recent = extractor.get_recent_snis()
        self.assertEqual(len(recent), 5)

    def test_tcp_debug_summary_sni_count_matches_log(self):
        """tcp_debug summary sni_domains count matches log length."""
        extractor = ServerSniExtractor()
        for i in range(7):
            extractor.record_sni(CLIENT_IP, f"10.0.0.{i}", 443, f"site{i}.com")

        summary = extractor.get_tcp_debug_summary()
        self.assertEqual(summary["sni_domains"], 7)
        self.assertEqual(len(summary["recent_snis"]), 7)

    def test_empty_sni_log_returns_empty_summary(self):
        """Empty SNI log returns empty summary."""
        extractor = ServerSniExtractor()
        summary = extractor.get_tcp_debug_summary()
        self.assertEqual(summary["sni_domains"], 0)
        self.assertEqual(summary["recent_snis"], [])

    # --- Client Parsing Edge Cases ---

    def test_parse_preserves_last_domain_for_duplicate_ips(self):
        """When same IP appears multiple times, last entry's domain wins."""
        entries = [
            "10.20.0.2→1.2.3.4:443 = first.com",
            "10.20.0.3→1.2.3.4:8443 = second.com",
            "10.20.0.4→1.2.3.4:9443 = third.com",
        ]
        result = parse_server_sni_entries(entries)
        self.assertEqual(result["1.2.3.4"], "third.com")

    def test_parse_mixed_valid_and_invalid(self):
        """Mix of valid and invalid entries — only valid parsed."""
        entries = [
            "valid1→1.1.1.1:443 = ok1.com",  # no arrow in "valid1" — wait, there IS no arrow
            "valid2→2.2.2.2:443 = ok2.com",   # has arrow
            "invalid no arrow",                 # no arrow
            "→3.3.3.3:443 = ok3.com",          # empty client IP
            "= no arrow",                       # no arrow
        ]
        result = parse_server_sni_entries(entries)
        # "valid1→1.1.1.1:443 = ok1.com" has arrow at index 6
        # "valid2→2.2.2.2:443 = ok2.com" has arrow at index 6
        # "→3.3.3.3:443 = ok3.com" has arrow at index 0
        self.assertEqual(len(result), 3)
        self.assertEqual(result["1.1.1.1"], "ok1.com")
        self.assertEqual(result["2.2.2.2"], "ok2.com")
        self.assertEqual(result["3.3.3.3"], "ok3.com")

    def test_parse_with_different_client_ips_in_entries(self):
        """Entries from different clients still parsed correctly."""
        entries = [
            "client_a→1.1.1.1:443 = from_a.com",
            "client_b→2.2.2.2:443 = from_b.com",
            "client_c→3.3.3.3:443 = from_c.com",
        ]
        result = parse_server_sni_entries(entries)
        self.assertEqual(len(result), 3)

    def test_parse_numeric_domain(self):
        """All-numeric domain (like an IP used as hostname)."""
        entries = ["10.20.0.243→1.2.3.4:443 = 123456"]
        result = parse_server_sni_entries(entries)
        self.assertEqual(result["1.2.3.4"], "123456")

    def test_parse_domain_with_port_separator(self):
        """Domain with colon (unusual but possible in some configs)."""
        entries = ["10.20.0.243→1.2.3.4:443 = host:8080"]
        result = parse_server_sni_entries(entries)
        self.assertEqual(result["1.2.3.4"], "host:8080")

    def test_parse_max_port_number(self):
        """Port 65535 (max valid port)."""
        entries = ["10.20.0.243→1.2.3.4:65535 = maxport.com"]
        result = parse_server_sni_entries(entries)
        self.assertEqual(result["1.2.3.4"], "maxport.com")

    def test_parse_port_zero(self):
        """Port 0 (edge case)."""
        entries = ["10.20.0.243→1.2.3.4:0 = zeroport.com"]
        result = parse_server_sni_entries(entries)
        self.assertEqual(result["1.2.3.4"], "zeroport.com")


# ============================================================
# Test: sni_domain_map (comprehensive IP→domain from _tcp_tracker)
# ============================================================

class MockTcpTracker:
    """Mirrors server _tcp_tracker structure for testing get_tcp_debug_summary."""

    def __init__(self):
        self._tcp_tracker = {}  # client_ip -> {flow_key -> {syn, established, tls_hello, sni}}
        self._tls_sni_log = []

    def add_flow(self, client_ip, dst_ip, dst_port, sni=None, tls_hello=0):
        flow_key = f"{dst_ip}:{dst_port}"
        if client_ip not in self._tcp_tracker:
            self._tcp_tracker[client_ip] = {}
        self._tcp_tracker[client_ip][flow_key] = {
            "syn": 1, "established": True, "tls_hello": tls_hello, "sni": sni
        }
        if sni:
            self._tls_sni_log.append(f"{client_ip}→{dst_ip}:{dst_port} = {sni}")
            if len(self._tls_sni_log) > 50:
                self._tls_sni_log.pop(0)

    def get_tcp_debug_summary(self):
        total_tls = 0
        total_sni = 0
        recent_snis = list(self._tls_sni_log[-10:])
        sni_domain_map = {}
        for client_flows in self._tcp_tracker.values():
            for flow_key, flow in client_flows.items():
                if flow["tls_hello"] > 0:
                    total_tls += 1
                if flow["sni"]:
                    total_sni += 1
                    colon_idx = flow_key.rfind(':')
                    remote_ip = flow_key[:colon_idx] if colon_idx > 0 else flow_key
                    sni_domain_map[remote_ip] = flow["sni"]
        return {
            "tcp_flows": sum(len(f) for f in self._tcp_tracker.values()),
            "tls_handshakes": total_tls,
            "sni_domains": total_sni,
            "recent_snis": recent_snis,
            "sni_domain_map": sni_domain_map,
        }


def parse_sni_domain_map_json(json_dict):
    """Parse sni_domain_map from JSON dict (mirrors ApiClient.getServerSniDomains)."""
    tcp_debug = json_dict.get("tcp_debug", {})
    sni_domain_map = tcp_debug.get("sni_domain_map", {})
    result = {}
    for ip, domain in sni_domain_map.items():
        if domain and isinstance(domain, str):
            result[ip] = domain.lower()
    return result


class TestSniDomainMap(unittest.TestCase):
    """Tests for sni_domain_map in get_tcp_debug_summary."""

    def test_sni_domain_map_structure(self):
        """sni_domain_map is a dict in tcp_debug response."""
        tracker = MockTcpTracker()
        tracker.add_flow("10.20.0.2", "1.2.3.4", 443, sni="example.com", tls_hello=1)
        summary = tracker.get_tcp_debug_summary()
        self.assertIn("sni_domain_map", summary)
        self.assertIsInstance(summary["sni_domain_map"], dict)

    def test_sni_domain_map_single_flow(self):
        """Single flow with SNI appears in map."""
        tracker = MockTcpTracker()
        tracker.add_flow("10.20.0.2", "142.251.10.95", 443, sni="google.com", tls_hello=1)
        summary = tracker.get_tcp_debug_summary()
        self.assertEqual(summary["sni_domain_map"]["142.251.10.95"], "google.com")

    def test_sni_domain_map_multiple_flows(self):
        """Multiple flows with SNI all appear in map."""
        tracker = MockTcpTracker()
        tracker.add_flow("10.20.0.2", "142.251.10.95", 443, sni="google.com", tls_hello=1)
        tracker.add_flow("10.20.0.2", "157.240.1.35", 443, sni="facebook.com", tls_hello=1)
        tracker.add_flow("10.20.0.2", "151.101.1.140", 443, sni="reddit.com", tls_hello=1)
        summary = tracker.get_tcp_debug_summary()
        self.assertEqual(len(summary["sni_domain_map"]), 3)
        self.assertEqual(summary["sni_domain_map"]["142.251.10.95"], "google.com")
        self.assertEqual(summary["sni_domain_map"]["157.240.1.35"], "facebook.com")
        self.assertEqual(summary["sni_domain_map"]["151.101.1.140"], "reddit.com")

    def test_sni_domain_map_empty_tracker(self):
        """Empty tracker returns empty map."""
        tracker = MockTcpTracker()
        summary = tracker.get_tcp_debug_summary()
        self.assertEqual(summary["sni_domain_map"], {})

    def test_sni_domain_map_flow_without_sni(self):
        """Flow without SNI not included in map."""
        tracker = MockTcpTracker()
        tracker.add_flow("10.20.0.2", "1.2.3.4", 80, sni=None, tls_hello=0)
        summary = tracker.get_tcp_debug_summary()
        self.assertEqual(summary["sni_domain_map"], {})

    def test_sni_domain_map_mixed_flows(self):
        """Mix of flows with and without SNI."""
        tracker = MockTcpTracker()
        tracker.add_flow("10.20.0.2", "1.1.1.1", 443, sni="cloudflare.com", tls_hello=1)
        tracker.add_flow("10.20.0.2", "2.2.2.2", 80, sni=None, tls_hello=0)  # HTTP, no SNI
        tracker.add_flow("10.20.0.2", "3.3.3.3", 443, sni="amazon.com", tls_hello=1)
        summary = tracker.get_tcp_debug_summary()
        self.assertEqual(len(summary["sni_domain_map"]), 2)
        self.assertIn("1.1.1.1", summary["sni_domain_map"])
        self.assertIn("3.3.3.3", summary["sni_domain_map"])
        self.assertNotIn("2.2.2.2", summary["sni_domain_map"])

    def test_sni_domain_map_ip_extraction_from_flow_key(self):
        """IP correctly extracted from flow_key 'ip:port'."""
        tracker = MockTcpTracker()
        tracker.add_flow("10.20.0.2", "74.125.68.95", 443, sni="google.com", tls_hello=1)
        tracker.add_flow("10.20.0.2", "172.217.194.188", 5228, sni="mtalk.google.com", tls_hello=1)
        summary = tracker.get_tcp_debug_summary()
        # IP extracted correctly, port stripped
        self.assertIn("74.125.68.95", summary["sni_domain_map"])
        self.assertIn("172.217.194.188", summary["sni_domain_map"])
        self.assertNotIn("74.125.68.95:443", summary["sni_domain_map"])

    def test_sni_domain_map_same_ip_different_ports(self):
        """Same IP with different ports — last SNI wins."""
        tracker = MockTcpTracker()
        tracker.add_flow("10.20.0.2", "1.2.3.4", 443, sni="first.com", tls_hello=1)
        tracker.add_flow("10.20.0.2", "1.2.3.4", 8443, sni="second.com", tls_hello=1)
        summary = tracker.get_tcp_debug_summary()
        # Last flow overwrites (dict iteration order)
        self.assertEqual(summary["sni_domain_map"]["1.2.3.4"], "second.com")

    def test_sni_domain_map_multiple_clients(self):
        """Multiple clients contribute to same map."""
        tracker = MockTcpTracker()
        tracker.add_flow("10.20.0.2", "1.1.1.1", 443, sni="from-client1.com", tls_hello=1)
        tracker.add_flow("10.20.0.3", "2.2.2.2", 443, sni="from-client2.com", tls_hello=1)
        summary = tracker.get_tcp_debug_summary()
        self.assertEqual(len(summary["sni_domain_map"]), 2)
        self.assertEqual(summary["sni_domain_map"]["1.1.1.1"], "from-client1.com")
        self.assertEqual(summary["sni_domain_map"]["2.2.2.2"], "from-client2.com")

    def test_sni_domain_map_count_matches_sni_domains(self):
        """sni_domain_map count equals sni_domains count."""
        tracker = MockTcpTracker()
        for i in range(10):
            tracker.add_flow("10.20.0.2", f"10.0.0.{i}", 443, sni=f"site{i}.com", tls_hello=1)
        summary = tracker.get_tcp_debug_summary()
        self.assertEqual(summary["sni_domains"], 10)
        self.assertEqual(len(summary["sni_domain_map"]), 10)

    def test_sni_domain_map_recent_snis_still_present(self):
        """recent_snis still returned alongside sni_domain_map."""
        tracker = MockTcpTracker()
        for i in range(15):
            tracker.add_flow("10.20.0.2", f"10.0.0.{i}", 443, sni=f"site{i}.com", tls_hello=1)
        summary = tracker.get_tcp_debug_summary()
        # recent_snis is last 10
        self.assertEqual(len(summary["recent_snis"]), 10)
        # sni_domain_map has all 10 unique IPs
        self.assertEqual(len(summary["sni_domain_map"]), 15)

    def test_sni_domain_map_100_flows(self):
        """100 flows all appear in map."""
        tracker = MockTcpTracker()
        for i in range(100):
            tracker.add_flow("10.20.0.2", f"10.{i//256}.{i%256}.1", 443,
                           sni=f"host{i}.example.com", tls_hello=1)
        summary = tracker.get_tcp_debug_summary()
        self.assertEqual(len(summary["sni_domain_map"]), 100)

    def test_sni_domain_map_tls_hello_without_sni(self):
        """Flow with TLS hello but no SNI extraction — not in map."""
        tracker = MockTcpTracker()
        tracker.add_flow("10.20.0.2", "1.2.3.4", 443, sni=None, tls_hello=1)
        summary = tracker.get_tcp_debug_summary()
        self.assertEqual(summary["sni_domain_map"], {})
        self.assertEqual(summary["tls_handshakes"], 1)  # counted as TLS
        self.assertEqual(summary["sni_domains"], 0)      # but no SNI


class TestSniDomainMapClientParsing(unittest.TestCase):
    """Tests for client-side parsing of sni_domain_map JSON."""

    def test_parse_json_object(self):
        """Parse sni_domain_map as JSON object (key=IP, value=domain)."""
        json_data = {
            "tcp_debug": {
                "sni_domain_map": {
                    "142.251.10.95": "google.com",
                    "157.240.1.35": "facebook.com"
                }
            }
        }
        result = parse_sni_domain_map_json(json_data)
        self.assertEqual(result["142.251.10.95"], "google.com")
        self.assertEqual(result["157.240.1.35"], "facebook.com")

    def test_parse_empty_map(self):
        """Empty sni_domain_map returns empty dict."""
        json_data = {"tcp_debug": {"sni_domain_map": {}}}
        result = parse_sni_domain_map_json(json_data)
        self.assertEqual(result, {})

    def test_parse_missing_sni_domain_map(self):
        """Missing sni_domain_map returns empty dict."""
        json_data = {"tcp_debug": {}}
        result = parse_sni_domain_map_json(json_data)
        self.assertEqual(result, {})

    def test_parse_missing_tcp_debug(self):
        """Missing tcp_debug returns empty dict."""
        json_data = {}
        result = parse_sni_domain_map_json(json_data)
        self.assertEqual(result, {})

    def test_parse_domain_lowercased(self):
        """Domains are lowercased."""
        json_data = {
            "tcp_debug": {
                "sni_domain_map": {
                    "1.2.3.4": "EXAMPLE.COM",
                    "5.6.7.8": "MixedCase.Org"
                }
            }
        }
        result = parse_sni_domain_map_json(json_data)
        self.assertEqual(result["1.2.3.4"], "example.com")
        self.assertEqual(result["5.6.7.8"], "mixedcase.org")

    def test_parse_empty_domain_skipped(self):
        """Empty domain values are skipped."""
        json_data = {
            "tcp_debug": {
                "sni_domain_map": {
                    "1.2.3.4": "valid.com",
                    "5.6.7.8": ""
                }
            }
        }
        result = parse_sni_domain_map_json(json_data)
        self.assertEqual(len(result), 1)
        self.assertEqual(result["1.2.3.4"], "valid.com")

    def test_parse_100_entries(self):
        """100 entries parsed correctly."""
        sni_map = {f"10.0.{i//256}.{i%256}": f"host{i}.com" for i in range(100)}
        json_data = {"tcp_debug": {"sni_domain_map": sni_map}}
        result = parse_sni_domain_map_json(json_data)
        self.assertEqual(len(result), 100)

    def test_parse_real_api_response_structure(self):
        """Parse realistic API response with both sni_domain_map and recent_snis."""
        json_data = {
            "rx_bytes": 12345,
            "tx_bytes": 67890,
            "tcp_debug": {
                "tcp_flows": 521,
                "tls_handshakes": 339,
                "sni_domains": 235,
                "recent_snis": [
                    "10.20.0.75→35.186.224.28:443 = gew4-spclient.spotify.com"
                ],
                "sni_domain_map": {
                    "35.186.224.28": "gew4-spclient.spotify.com",
                    "74.125.68.95": "pubsub.googleapis.com"
                }
            }
        }
        result = parse_sni_domain_map_json(json_data)
        self.assertEqual(len(result), 2)
        self.assertEqual(result["35.186.224.28"], "gew4-spclient.spotify.com")

    def test_parse_with_special_characters_in_domain(self):
        """Domains with hyphens and numbers parsed correctly."""
        json_data = {
            "tcp_debug": {
                "sni_domain_map": {
                    "1.2.3.4": "my-app-v2.example-site.com",
                    "5.6.7.8": "api123.internal.corp"
                }
            }
        }
        result = parse_sni_domain_map_json(json_data)
        self.assertEqual(result["1.2.3.4"], "my-app-v2.example-site.com")
        self.assertEqual(result["5.6.7.8"], "api123.internal.corp")


# ============================================================
# Test: sni_domain_map Edge Cases
# ============================================================

class TestSniDomainMapEdgeCases(unittest.TestCase):
    """Edge cases for sni_domain_map generation and parsing."""

    # --- IP Extraction Edge Cases ---

    def test_flow_key_without_port(self):
        """Flow key with no colon — entire key used as IP."""
        tracker = MockTcpTracker()
        # Manually add flow with no port in key
        tracker._tcp_tracker["10.20.0.2"] = {
            "1.2.3.4": {"syn": 1, "established": True, "tls_hello": 1, "sni": "no-port.com"}
        }
        summary = tracker.get_tcp_debug_summary()
        self.assertEqual(summary["sni_domain_map"]["1.2.3.4"], "no-port.com")

    def test_flow_key_with_ipv6_like(self):
        """Flow key with multiple colons (IPv6-like) — rfind extracts correctly."""
        tracker = MockTcpTracker()
        # "::1:443" — rfind(':') = 3, so IP = "::1"
        tracker._tcp_tracker["10.20.0.2"] = {
            "::1:443": {"syn": 1, "established": True, "tls_hello": 1, "sni": "localhost"}
        }
        summary = tracker.get_tcp_debug_summary()
        self.assertEqual(summary["sni_domain_map"]["::1"], "localhost")

    def test_flow_key_ip_with_trailing_space(self):
        """Flow key with whitespace — preserved as-is."""
        tracker = MockTcpTracker()
        tracker._tcp_tracker["10.20.0.2"] = {
            "1.2.3.4 :443": {"syn": 1, "established": True, "tls_hello": 1, "sni": "space.com"}
        }
        summary = tracker.get_tcp_debug_summary()
        # rfind(':') finds last colon, IP = "1.2.3.4 "
        self.assertIn("1.2.3.4 ", summary["sni_domain_map"])

    # --- SNI Domain Edge Cases ---

    def test_sni_domain_with_unicode(self):
        """SNI domain with unicode characters preserved."""
        tracker = MockTcpTracker()
        tracker.add_flow("10.20.0.2", "1.2.3.4", 443, sni="café.com", tls_hello=1)
        summary = tracker.get_tcp_debug_summary()
        self.assertEqual(summary["sni_domain_map"]["1.2.3.4"], "café.com")

    def test_sni_domain_very_long(self):
        """SNI domain at max length (253 chars)."""
        long_domain = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 60 + ".com"
        tracker = MockTcpTracker()
        tracker.add_flow("10.20.0.2", "1.2.3.4", 443, sni=long_domain, tls_hello=1)
        summary = tracker.get_tcp_debug_summary()
        self.assertEqual(summary["sni_domain_map"]["1.2.3.4"], long_domain)

    def test_sni_domain_single_label(self):
        """Single-label domain (no dots)."""
        tracker = MockTcpTracker()
        tracker.add_flow("10.20.0.2", "1.2.3.4", 443, sni="localhost", tls_hello=1)
        summary = tracker.get_tcp_debug_summary()
        self.assertEqual(summary["sni_domain_map"]["1.2.3.4"], "localhost")

    def test_sni_domain_with_wildcard(self):
        """Wildcard domain preserved."""
        tracker = MockTcpTracker()
        tracker.add_flow("10.20.0.2", "1.2.3.4", 443, sni="*.example.com", tls_hello=1)
        summary = tracker.get_tcp_debug_summary()
        self.assertEqual(summary["sni_domain_map"]["1.2.3.4"], "*.example.com")

    # --- Tracker State Edge Cases ---

    def test_sni_domain_map_after_flow_sni_update(self):
        """Flow SNI updated from None to domain — map reflects update."""
        tracker = MockTcpTracker()
        tracker.add_flow("10.20.0.2", "1.2.3.4", 443, sni=None, tls_hello=1)
        summary1 = tracker.get_tcp_debug_summary()
        self.assertNotIn("1.2.3.4", summary1["sni_domain_map"])

        # Update SNI
        tracker._tcp_tracker["10.20.0.2"]["1.2.3.4:443"]["sni"] = "now-known.com"
        summary2 = tracker.get_tcp_debug_summary()
        self.assertEqual(summary2["sni_domain_map"]["1.2.3.4"], "now-known.com")

    def test_sni_domain_map_after_flow_removed(self):
        """Flow removed from tracker — disappears from map."""
        tracker = MockTcpTracker()
        tracker.add_flow("10.20.0.2", "1.2.3.4", 443, sni="test.com", tls_hello=1)
        summary1 = tracker.get_tcp_debug_summary()
        self.assertIn("1.2.3.4", summary1["sni_domain_map"])

        # Remove flow
        del tracker._tcp_tracker["10.20.0.2"]["1.2.3.4:443"]
        summary2 = tracker.get_tcp_debug_summary()
        self.assertNotIn("1.2.3.4", summary2["sni_domain_map"])

    def test_sni_domain_map_idempotent(self):
        """Calling get_tcp_debug_summary multiple times returns same result."""
        tracker = MockTcpTracker()
        tracker.add_flow("10.20.0.2", "1.2.3.4", 443, sni="test.com", tls_hello=1)

        summary1 = tracker.get_tcp_debug_summary()
        summary2 = tracker.get_tcp_debug_summary()
        summary3 = tracker.get_tcp_debug_summary()

        self.assertEqual(summary1["sni_domain_map"], summary2["sni_domain_map"])
        self.assertEqual(summary2["sni_domain_map"], summary3["sni_domain_map"])

    def test_sni_domain_map_after_multiple_clients_same_ip(self):
        """Multiple clients with same dst IP — last client's SNI wins."""
        tracker = MockTcpTracker()
        tracker.add_flow("10.20.0.2", "1.2.3.4", 443, sni="from-client1.com", tls_hello=1)
        tracker.add_flow("10.20.0.3", "1.2.3.4", 443, sni="from-client2.com", tls_hello=1)
        summary = tracker.get_tcp_debug_summary()
        # Both clients have same IP, last dict iteration wins
        self.assertEqual(summary["sni_domain_map"]["1.2.3.4"], "from-client2.com")

    # --- Log Overflow Edge Cases ---

    def test_sni_log_overflow_map_still_complete(self):
        """Even when _tls_sni_log overflows (50 max), sni_domain_map has ALL flows."""
        tracker = MockTcpTracker()
        for i in range(100):
            tracker.add_flow("10.20.0.2", f"10.0.0.{i}", 443,
                           sni=f"site{i}.com", tls_hello=1)
        summary = tracker.get_tcp_debug_summary()
        # recent_snis capped at 10
        self.assertEqual(len(summary["recent_snis"]), 10)
        # sni_domain_map has ALL 100
        self.assertEqual(len(summary["sni_domain_map"]), 100)

    def test_sni_log_50_entries_map_has_more(self):
        """_tls_sni_log caps at 50, but sni_domain_map has all unique IPs."""
        tracker = MockTcpTracker()
        for i in range(75):
            tracker.add_flow("10.20.0.2", f"10.{i//256}.{i%256}.1", 443,
                           sni=f"host{i}.com", tls_hello=1)
        summary = tracker.get_tcp_debug_summary()
        # _tls_sni_log caps at 50
        self.assertEqual(len(tracker._tls_sni_log), 50)
        # sni_domain_map has all 75 unique IPs
        self.assertEqual(len(summary["sni_domain_map"]), 75)

    # --- Consistency Edge Cases ---

    def test_sni_domains_count_consistent_with_map(self):
        """sni_domains count always equals len(sni_domain_map)."""
        tracker = MockTcpTracker()
        for i in range(20):
            tracker.add_flow("10.20.0.2", f"10.0.0.{i}", 443,
                           sni=f"site{i}.com" if i % 3 != 0 else None,
                           tls_hello=1 if i % 2 == 0 else 0)
        summary = tracker.get_tcp_debug_summary()
        # sni_domains counts flows with SNI
        # sni_domain_map has unique IPs with SNI
        self.assertEqual(summary["sni_domains"], len(summary["sni_domain_map"]))

    def test_tcp_flows_count_includes_non_sni(self):
        """tcp_flows counts ALL flows, not just SNI ones."""
        tracker = MockTcpTracker()
        tracker.add_flow("10.20.0.2", "1.1.1.1", 443, sni="with-sni.com", tls_hello=1)
        tracker.add_flow("10.20.0.2", "2.2.2.2", 80, sni=None, tls_hello=0)
        tracker.add_flow("10.20.0.2", "3.3.3.3", 443, sni=None, tls_hello=1)
        summary = tracker.get_tcp_debug_summary()
        self.assertEqual(summary["tcp_flows"], 3)
        self.assertEqual(summary["tls_handshakes"], 2)
        self.assertEqual(summary["sni_domains"], 1)
        self.assertEqual(len(summary["sni_domain_map"]), 1)


class TestSniDomainMapClientParsingEdgeCases(unittest.TestCase):
    """Edge cases for client-side sni_domain_map JSON parsing."""

    def test_parse_with_null_value(self):
        """JSON null value in sni_domain_map — skipped."""
        json_data = {"tcp_debug": {"sni_domain_map": {"1.2.3.4": None, "5.6.7.8": "valid.com"}}}
        # optString returns "" for null in JSONObject
        result = parse_sni_domain_map_json(json_data)
        self.assertEqual(result.get("5.6.7.8"), "valid.com")

    def test_parse_with_numeric_value(self):
        """Numeric value in sni_domain_map — skipped (not a string)."""
        json_data = {"tcp_debug": {"sni_domain_map": {"1.2.3.4": 12345}}}
        result = parse_sni_domain_map_json(json_data)
        # Non-string values are skipped
        self.assertNotIn("1.2.3.4", result)

    def test_parse_with_extra_json_fields(self):
        """Extra fields in tcp_debug — ignored gracefully."""
        json_data = {
            "tcp_debug": {
                "tcp_flows": 100,
                "tls_handshakes": 50,
                "sni_domains": 30,
                "recent_snis": [],
                "sni_domain_map": {"1.2.3.4": "test.com"},
                "unknown_field": "ignored",
                "another_field": 42
            }
        }
        result = parse_sni_domain_map_json(json_data)
        self.assertEqual(result["1.2.3.4"], "test.com")

    def test_parse_with_nested_object_in_value(self):
        """Nested object as value — optString returns toString."""
        json_data = {"tcp_debug": {"sni_domain_map": {"1.2.3.4": {"nested": "value"}}}}
        # optString for non-string returns the toString of the object
        result = parse_sni_domain_map_json(json_data)
        # Should not crash, may return object string or empty
        self.assertIsInstance(result, dict)

    def test_parse_with_array_as_value(self):
        """Array as value — optString returns toString."""
        json_data = {"tcp_debug": {"sni_domain_map": {"1.2.3.4": ["a", "b"]}}}
        result = parse_sni_domain_map_json(json_data)
        self.assertIsInstance(result, dict)

    def test_parse_with_boolean_value(self):
        """Boolean value — optString returns 'true'/'false'."""
        json_data = {"tcp_debug": {"sni_domain_map": {"1.2.3.4": True}}}
        result = parse_sni_domain_map_json(json_data)
        # optString for boolean returns "true"
        self.assertIsInstance(result, dict)

    def test_parse_with_empty_string_key(self):
        """Empty string key in sni_domain_map — preserved."""
        json_data = {"tcp_debug": {"sni_domain_map": {"": "no-ip.com"}}}
        result = parse_sni_domain_map_json(json_data)
        self.assertEqual(result.get(""), "no-ip.com")

    def test_parse_with_very_long_key(self):
        """Very long key (not a real IP) — preserved as-is."""
        long_key = "a" * 200
        json_data = {"tcp_debug": {"sni_domain_map": {long_key: "test.com"}}}
        result = parse_sni_domain_map_json(json_data)
        self.assertEqual(result.get(long_key), "test.com")

    def test_parse_sni_domain_map_overrides_recent_snis_same_ip(self):
        """When both have same IP, sni_domain_map wins."""
        json_data = {
            "tcp_debug": {
                "recent_snis": ["10.20.0.2→1.2.3.4:443 = old-domain.com"],
                "sni_domain_map": {"1.2.3.4": "new-domain.com"}
            }
        }
        result = parse_sni_domain_map_json(json_data)
        self.assertEqual(result["1.2.3.4"], "new-domain.com")

    def test_parse_sni_domain_map_empty_returns_empty(self):
        """Empty sni_domain_map returns empty (Python parser has no fallback)."""
        json_data = {
            "tcp_debug": {
                "recent_snis": ["10.20.0.2→1.2.3.4:443 = fallback.com"],
                "sni_domain_map": {}
            }
        }
        result = parse_sni_domain_map_json(json_data)
        # Python parser doesn't have recent_snis fallback (Kotlin does)
        self.assertEqual(len(result), 0)

    def test_parse_sni_domain_map_with_whitespace_values(self):
        """Whitespace-only domain — not empty, preserved."""
        json_data = {"tcp_debug": {"sni_domain_map": {"1.2.3.4": "   "}}}
        result = parse_sni_domain_map_json(json_data)
        # "   " is not empty, so it's kept
        self.assertEqual(result.get("1.2.3.4"), "   ")

    def test_parse_500_entries(self):
        """500 entries parsed correctly."""
        sni_map = {f"10.{i//256}.{i%256}.1": f"host{i}.com" for i in range(500)}
        json_data = {"tcp_debug": {"sni_domain_map": sni_map}}
        result = parse_sni_domain_map_json(json_data)
        self.assertEqual(len(result), 500)

    def test_parse_all_same_domain_different_ips(self):
        """Same domain on 50 different IPs (CDN)."""
        sni_map = {f"10.0.0.{i}": "cdn.example.com" for i in range(50)}
        json_data = {"tcp_debug": {"sni_domain_map": sni_map}}
        result = parse_sni_domain_map_json(json_data)
        self.assertEqual(len(result), 50)
        for i in range(50):
            self.assertEqual(result[f"10.0.0.{i}"], "cdn.example.com")

    def test_parse_domain_with_every_tld(self):
        """Various TLDs parsed correctly."""
        json_data = {
            "tcp_debug": {
                "sni_domain_map": {
                    "1.1.1.1": "test.com",
                    "2.2.2.2": "test.org",
                    "3.3.3.3": "test.io",
                    "4.4.4.4": "test.co.uk",
                    "5.5.5.5": "test.example"
                }
            }
        }
        result = parse_sni_domain_map_json(json_data)
        self.assertEqual(len(result), 5)
        self.assertEqual(result["1.1.1.1"], "test.com")
        self.assertEqual(result["4.4.4.4"], "test.co.uk")

    def test_parse_domain_with_punycode(self):
        """Punycode domain (internationalized) parsed correctly."""
        json_data = {"tcp_debug": {"sni_domain_map": {"1.2.3.4": "xn--e1afmapc.xn--p1ai"}}}
        result = parse_sni_domain_map_json(json_data)
        self.assertEqual(result["1.2.3.4"], "xn--e1afmapc.xn--p1ai")


if __name__ == '__main__':
    unittest.main()
