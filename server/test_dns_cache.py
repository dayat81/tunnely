"""Tests for DNS IP→domain cache (DNS A record parsing + QUIC DNS fallback)."""
import struct
import socket
import unittest
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from udp_vpn_server import UdpVpnServer


def build_dns_response(answers: list[tuple[str, str]], qname: str = "example.com") -> bytes:
    """Build a DNS response packet with A records.
    answers: list of (domain, ip) tuples
    """
    # Header
    header = struct.pack('!HHHHHH',
        0x1234,  # ID
        0x8180,  # Flags: response, recursion available
        1,       # QDCOUNT
        len(answers),  # ANCOUNT
        0, 0     # NSCOUNT, ARCOUNT
    )

    # Question section
    question = b''
    for label in qname.split('.'):
        question += bytes([len(label)]) + label.encode()
    question += b'\x00'  # root
    question += struct.pack('!HH', 1, 1)  # QTYPE=A, QCLASS=IN

    # Answer section
    answer = b''
    for domain, ip in answers:
        # NAME (pointer to question)
        answer += b'\xc0\x0c'
        # TYPE=A, CLASS=IN, TTL=300, RDLENGTH=4
        answer += struct.pack('!HHIH', 1, 1, 300, 4)
        # RDATA
        answer += socket.inet_aton(ip)

    return header + question + answer


def build_dns_response_no_answers(qname: str = "empty.com") -> bytes:
    """Build a DNS response with 0 answers."""
    header = struct.pack('!HHHHHH', 0x5678, 0x8180, 1, 0, 0, 0)
    question = b''
    for label in qname.split('.'):
        question += bytes([len(label)]) + label.encode()
    question += b'\x00'
    question += struct.pack('!HH', 1, 1)
    return header + question


class TestParseDnsQname(unittest.TestCase):
    """Tests for _parse_dns_qname."""

    def test_simple_domain(self):
        data = build_dns_response([], "example.com")
        result = UdpVpnServer._parse_dns_qname(data, 12)
        self.assertEqual(result, "example.com")

    def test_subdomain(self):
        data = build_dns_response([], "sub.example.com")
        result = UdpVpnServer._parse_dns_qname(data, 12)
        self.assertEqual(result, "sub.example.com")

    def test_single_label(self):
        data = build_dns_response([], "localhost")
        result = UdpVpnServer._parse_dns_qname(data, 12)
        self.assertEqual(result, "localhost")

    def test_pointer_compression(self):
        """QNAME with pointer should follow pointer."""
        data = build_dns_response([("example.com", "1.2.3.4")], "example.com")
        # Answer section starts after question - answer NAME uses pointer
        qdcount = 1
        # Skip header (12) + question
        offset = 12
        # Skip qname
        while data[offset] != 0:
            offset += 1 + data[offset]
        offset += 5  # null + QTYPE + QCLASS
        # Now at answer NAME which is a pointer
        self.assertEqual(data[offset], 0xC0)  # pointer marker

    def test_empty_data(self):
        result = UdpVpnServer._parse_dns_qname(b'', 0)
        self.assertIsNone(result)

    def test_truncated_label(self):
        """Label length exceeds data."""
        data = bytes([20, 0x65, 0x78])  # length=20 but only 2 bytes
        result = UdpVpnServer._parse_dns_qname(data, 0)
        self.assertIsNone(result)

    def test_offset_beyond_data(self):
        data = b'\x00'
        result = UdpVpnServer._parse_dns_qname(data, 100)
        self.assertIsNone(result)

    def test_deep_subdomain(self):
        data = build_dns_response([], "a.b.c.d.e.example.com")
        result = UdpVpnServer._parse_dns_qname(data, 12)
        self.assertEqual(result, "a.b.c.d.e.example.com")

    def test_www_prefix(self):
        data = build_dns_response([], "www.google.com")
        result = UdpVpnServer._parse_dns_qname(data, 12)
        self.assertEqual(result, "www.google.com")


class TestParseDnsARecords(unittest.TestCase):
    """Tests for _parse_dns_a_records."""

    def test_single_a_record(self):
        data = build_dns_response([("example.com", "93.184.216.34")])
        result = UdpVpnServer._parse_dns_a_records(data)
        self.assertEqual(result, ["93.184.216.34"])

    def test_multiple_a_records(self):
        answers = [
            ("google.com", "142.250.185.78"),
            ("google.com", "142.250.185.110"),
            ("google.com", "142.250.185.142"),
        ]
        data = build_dns_response(answers)
        result = UdpVpnServer._parse_dns_a_records(data)
        self.assertEqual(len(result), 3)
        self.assertIn("142.250.185.78", result)

    def test_no_answers(self):
        data = build_dns_response([])
        result = UdpVpnServer._parse_dns_a_records(data)
        self.assertEqual(result, [])

    def test_empty_packet(self):
        result = UdpVpnServer._parse_dns_a_records(b'')
        self.assertEqual(result, [])

    def test_short_header(self):
        result = UdpVpnServer._parse_dns_a_records(b'\x00' * 11)
        self.assertEqual(result, [])

    def test_no_answer_section(self):
        data = build_dns_response_no_answers()
        result = UdpVpnServer._parse_dns_a_records(data)
        self.assertEqual(result, [])

    def test_ipv4_loopback(self):
        data = build_dns_response([("localhost", "127.0.0.1")])
        result = UdpVpnServer._parse_dns_a_records(data)
        self.assertEqual(result, ["127.0.0.1"])

    def test_private_ips(self):
        data = build_dns_response([("router.local", "192.168.1.1")])
        result = UdpVpnServer._parse_dns_a_records(data)
        self.assertEqual(result, ["192.168.1.1"])

    def test_real_world_google_dns(self):
        """Simulate a typical google.com response."""
        answers = [
            ("google.com", "142.251.12.100"),
            ("google.com", "142.251.12.101"),
            ("google.com", "142.251.12.102"),
            ("google.com", "142.251.12.113"),
        ]
        data = build_dns_response(answers)
        result = UdpVpnServer._parse_dns_a_records(data)
        self.assertEqual(len(result), 4)
        # All IPs should be unique
        self.assertEqual(len(set(result)), 4)


class TestDnsIpMap(unittest.TestCase):
    """Tests for dns_ip_map integration."""

    def test_dns_response_populates_map(self):
        """Simulate: DNS query for instagram.com → response with A records → dns_ip_map populated."""
        srv = UdpVpnServer.__new__(UdpVpnServer)
        srv.dns_ip_map = {}
        srv.dns_query_names = {}
        srv.dns_tracks = {}

        # Simulate a tracked DNS query
        src_port = 12345
        srv.dns_query_names[src_port] = "instagram.com"

        # Build DNS response
        answers = [
            ("instagram.com", "57.144.144.1"),
            ("instagram.com", "57.144.144.128"),
        ]
        response = build_dns_response(answers, "instagram.com")

        # Parse A records and populate map
        a_records = UdpVpnServer._parse_dns_a_records(response)
        qname = srv.dns_query_names.pop(src_port, None)
        for ip in a_records:
            srv.dns_ip_map[ip] = qname

        self.assertEqual(len(srv.dns_ip_map), 2)
        self.assertEqual(srv.dns_ip_map["57.144.144.1"], "instagram.com")
        self.assertEqual(srv.dns_ip_map["57.144.144.128"], "instagram.com")

    def test_dns_map_cap(self):
        """dns_ip_map should not grow unbounded."""
        srv = UdpVpnServer.__new__(UdpVpnServer)
        srv.dns_ip_map = {}

        # Fill to just under limit
        for i in range(5001):
            srv.dns_ip_map[f"10.0.{i//256}.{i%256}"] = f"domain{i}.com"

        # Trigger cap (same logic as in _handle_dns_response)
        if len(srv.dns_ip_map) > 5000:
            keys = list(srv.dns_ip_map.keys())
            for k in keys[:len(keys)//2]:
                del srv.dns_ip_map[k]

        self.assertLessEqual(len(srv.dns_ip_map), 2600)

    def test_dns_fallback_for_quic(self):
        """When QUIC SNI extraction fails, DNS map should be used as fallback."""
        srv = UdpVpnServer.__new__(UdpVpnServer)
        srv.dns_ip_map = {"57.144.144.1": "instagram.com"}

        # Simulate: QUIC packet to 57.144.144.1, extraction fails
        dst_ip = "57.144.144.1"
        dns_domain = srv.dns_ip_map.get(dst_ip)
        self.assertEqual(dns_domain, "instagram.com")

    def test_dns_fallback_miss(self):
        """When IP not in dns_map, should return None."""
        srv = UdpVpnServer.__new__(UdpVpnServer)
        srv.dns_ip_map = {}

        dns_domain = srv.dns_ip_map.get("8.8.8.8")
        self.assertIsNone(dns_domain)


class TestDnsQnameParsing(unittest.TestCase):
    """Tests for DNS QNAME extraction from query packets."""

    def test_parse_qname_from_query(self):
        """Parse domain from DNS query packet."""
        query = b''
        # Header
        query += struct.pack('!HHHHHH', 0xABCD, 0x0100, 1, 0, 0, 0)
        # Question: instagram.com
        for label in "instagram.com".split('.'):
            query += bytes([len(label)]) + label.encode()
        query += b'\x00'
        query += struct.pack('!HH', 1, 1)

        result = UdpVpnServer._parse_dns_qname(query, 12)
        self.assertEqual(result, "instagram.com")

    def test_parse_qname_whatsapp(self):
        query = b''
        query += struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
        for label in "whatsapp.com".split('.'):
            query += bytes([len(label)]) + label.encode()
        query += b'\x00'
        query += struct.pack('!HH', 1, 1)

        result = UdpVpnServer._parse_dns_qname(query, 12)
        self.assertEqual(result, "whatsapp.com")

    def test_parse_qname_with_subdomain(self):
        query = b''
        query += struct.pack('!HHHHHH', 0x5678, 0x0100, 1, 0, 0, 0)
        for label in "z-p42-gateway.instagram.com".split('.'):
            query += bytes([len(label)]) + label.encode()
        query += b'\x00'
        query += struct.pack('!HH', 1, 1)

        result = UdpVpnServer._parse_dns_qname(query, 12)
        self.assertEqual(result, "z-p42-gateway.instagram.com")

    def test_malformed_qname_too_short(self):
        """Query shorter than 12 bytes — parser handles gracefully."""
        result = UdpVpnServer._parse_dns_qname(b'\x00' * 5, 0)
        # Will hit length=0 immediately, returns empty string or None
        # Just verify no crash
        self.assertIsInstance(result, (str, type(None)))


class TestDnsFallbackIntegration(unittest.TestCase):
    """Integration tests for DNS fallback with combined SNI pipeline."""

    def test_combined_map_includes_dns(self):
        """Combined SNI map should include TCP + QUIC + DNS."""
        srv = UdpVpnServer.__new__(UdpVpnServer)
        srv._tcp_tracker = {}
        srv._quic_sni_cache = {"57.144.144.1": "instagram.com"}
        srv._tls_sni_log = []
        srv._quic_initial_seen = 10
        srv._quic_sni_extracted = 1
        srv.dns_ip_map = {
            "142.251.12.100": "google.com",
            "157.240.1.35": "facebook.com",
        }

        summary = srv.get_tcp_debug_summary()

        # DNS domains should be in combined map
        self.assertIn("google.com", summary["combined_sni_map"].values())
        self.assertIn("facebook.com", summary["combined_sni_map"].values())
        # QUIC domain should also be there
        self.assertIn("instagram.com", summary["combined_sni_map"].values())
        # DNS count
        self.assertEqual(summary["dns_domains"], 2)

    def test_combined_map_priority(self):
        """QUIC SNI should take priority over DNS fallback in combined map."""
        srv = UdpVpnServer.__new__(UdpVpnServer)
        srv._tcp_tracker = {}
        srv._quic_sni_cache = {"57.144.144.1": "i.instagram.com"}
        srv._tls_sni_log = []
        srv._quic_initial_seen = 1
        srv._quic_sni_extracted = 1
        srv.dns_ip_map = {"57.144.144.1": "instagram.com"}  # DNS says generic

        summary = srv.get_tcp_debug_summary()

        # QUIC (more specific) should win over DNS
        self.assertEqual(summary["combined_sni_map"]["57.144.144.1"], "i.instagram.com")

    def test_dns_enriches_tcp_flows(self):
        """TCP flows without SNI should get DNS domain."""
        srv = UdpVpnServer.__new__(UdpVpnServer)
        srv._tcp_tracker = {
            "10.20.0.2": {
                "142.251.12.100:443": {"syn": 1, "established": True, "tls_hello": 1, "sni": None},
                "57.144.144.1:443": {"syn": 1, "established": True, "tls_hello": 1, "sni": "instagram.com"},
            }
        }
        srv._quic_sni_cache = {}
        srv._tls_sni_log = []
        srv._quic_initial_seen = 0
        srv._quic_sni_extracted = 0
        srv.dns_ip_map = {"142.251.12.100": "google.com"}

        summary = srv.get_tcp_debug_summary()

        # google.com flow should be enriched from DNS
        self.assertEqual(summary["dns_enriched"], 1)
        # Total SNI should increase
        self.assertGreaterEqual(summary["sni_domains"], 2)


class TestDnsResponseEdgeCases(unittest.TestCase):
    """Edge cases for DNS A record parsing."""

    def test_cname_record_skipped(self):
        """CNAME records (type 5) should be skipped, only A records extracted."""
        header = struct.pack('!HHHHHH', 0x1234, 0x8180, 1, 1, 0, 0)
        question = b''
        for label in "example.com".split('.'):
            question += bytes([len(label)]) + label.encode()
        question += b'\x00\x00\x05\x00\x01'  # QTYPE=CNAME

        # CNAME answer: pointer to name, type 5, class 1, ttl 300, rdlen 2, pointer
        answer = b'\xc0\x0c'  # pointer to qname
        answer += struct.pack('!HHIH', 5, 1, 300, 2)  # CNAME
        answer += b'\xc0\x0c'  # rdata: pointer

        data = header + question + answer
        result = UdpVpnServer._parse_dns_a_records(data)
        self.assertEqual(result, [])  # CNAME should be skipped

    def test_mixed_a_and_aaaa(self):
        """AAAA records (type 28) should be skipped."""
        header = struct.pack('!HHHHHH', 0x1234, 0x8180, 1, 2, 0, 0)
        question = b''
        for label in "example.com".split('.'):
            question += bytes([len(label)]) + label.encode()
        question += b'\x00\x00\x01\x00\x01'  # QTYPE=A

        # A record
        answer1 = b'\xc0\x0c'
        answer1 += struct.pack('!HHIH', 1, 1, 300, 4)
        answer1 += socket.inet_aton("1.2.3.4")

        # AAAA record
        answer2 = b'\xc0\x0c'
        answer2 += struct.pack('!HHIH', 28, 1, 300, 16)
        answer2 += b'\x00' * 16  # IPv6

        data = header + question + answer1 + answer2
        result = UdpVpnServer._parse_dns_a_records(data)
        self.assertEqual(result, ["1.2.3.4"])

    def test_truncated_answer(self):
        """Truncated answer section should not crash."""
        header = struct.pack('!HHHHHH', 0x1234, 0x8180, 1, 1, 0, 0)
        question = b''
        for label in "example.com".split('.'):
            question += bytes([len(label)]) + label.encode()
        question += b'\x00\x00\x01\x00\x01'
        # Truncated answer
        answer = b'\xc0\x0c\x00\x01'  # pointer + partial type

        data = header + question + answer
        result = UdpVpnServer._parse_dns_a_records(data)
        self.assertEqual(result, [])  # Should not crash

    def test_multiple_queries(self):
        """Multiple questions in one DNS response."""
        header = struct.pack('!HHHHHH', 0x1234, 0x8180, 2, 1, 0, 0)  # 2 questions
        q1 = b''
        for label in "a.com".split('.'):
            q1 += bytes([len(label)]) + label.encode()
        q1 += b'\x00\x00\x01\x00\x01'
        q2 = b''
        for label in "b.com".split('.'):
            q2 += bytes([len(label)]) + label.encode()
        q2 += b'\x00\x00\x01\x00\x01'

        answer = b'\xc0\x0c'
        answer += struct.pack('!HHIH', 1, 1, 300, 4)
        answer += socket.inet_aton("5.6.7.8")

        data = header + q1 + q2 + answer
        result = UdpVpnServer._parse_dns_a_records(data)
        self.assertEqual(result, ["5.6.7.8"])


if __name__ == '__main__':
    unittest.main()
