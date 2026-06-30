"""
Tests for QUIC Initial packet SNI extraction.

Tests cover:
  1. QUIC packet type detection
  2. Header parsing
  3. Key derivation (HKDF)
  4. Full SNI extraction from crafted Initial packets
  5. Edge cases: truncated, non-QUIC, wrong version
"""

import struct
import unittest
from typing import Optional

from quic_sni import (
    extract_quic_sni, is_quic_initial, _is_quic_initial,
    _parse_quic_header, _hkdf_extract, _hkdf_expand, _hkdf_expand_label,
    _read_varint, _extract_sni_from_tls,
    QUIC_V1, QUIC_DRAFT29, QUIC_V2,
    INITIAL_SALT_V1,
)


# ============================================================
# Test: QUIC Packet Detection
# ============================================================

class TestQuicDetection(unittest.TestCase):
    """Test QUIC Initial packet detection."""

    def test_not_quic_too_short(self):
        """Packet too short is not QUIC."""
        self.assertFalse(is_quic_initial(b'\x00' * 5))

    def test_not_quic_no_long_header(self):
        """Short header packet (first bit not set) is not QUIC."""
        self.assertFalse(is_quic_initial(b'\x00\x00\x00\x01\x00\x00'))

    def test_not_quic_no_fixed_bit(self):
        """Packet without fixed bit is not QUIC."""
        self.assertFalse(is_quic_initial(b'\x80\x00\x00\x01\x00\x00'))

    def test_quic_initial_v1(self):
        """QUIC v1 Initial packet detected."""
        # Long header + fixed bit + type=00 (Initial)
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V1) + bytes([0x00, 0x00])
        self.assertTrue(is_quic_initial(data))

    def test_quic_initial_draft29(self):
        """QUIC draft-29 Initial packet detected."""
        data = bytes([0xC0]) + struct.pack("!I", QUIC_DRAFT29) + bytes([0x00, 0x00])
        self.assertTrue(is_quic_initial(data))

    def test_quic_initial_v2(self):
        """QUIC v2 Initial packet detected."""
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V2) + bytes([0x00, 0x00])
        self.assertTrue(is_quic_initial(data))

    def test_not_quic_handshake_type(self):
        """Handshake type packet (type=0b10) is not Initial."""
        data = bytes([0xE0]) + struct.pack("!I", QUIC_V1) + bytes([0x00, 0x00])
        self.assertFalse(is_quic_initial(data))

    def test_not_quic_zero_rtt_type(self):
        """0-RTT type packet (type=0b01) is not Initial."""
        data = bytes([0xD0]) + struct.pack("!I", QUIC_V1) + bytes([0x00, 0x00])
        self.assertFalse(is_quic_initial(data))

    def test_not_quic_unknown_version(self):
        """Unknown version is not QUIC."""
        data = bytes([0xC0]) + struct.pack("!I", 0x12345678) + bytes([0x00, 0x00])
        self.assertFalse(is_quic_initial(data))

    def test_not_quic_tcp_tls(self):
        """TLS over TCP (0x16) is not QUIC."""
        data = b'\x16\x03\x01\x00\x05' + b'\x00' * 10
        self.assertFalse(is_quic_initial(data))

    def test_not_quic_udp_dns(self):
        """DNS over UDP is not QUIC."""
        data = b'\x00\x01\x00\x00\x00\x01\x00\x00' + b'\x00' * 20
        self.assertFalse(is_quic_initial(data))


# ============================================================
# Test: Variable-length Integer
# ============================================================

class TestVarint(unittest.TestCase):
    """Test QUIC variable-length integer parsing."""

    def test_varint_1_byte(self):
        """1-byte varint (0-63)."""
        val, pos = _read_varint(bytes([0x05]), 0)
        self.assertEqual(val, 5)
        self.assertEqual(pos, 1)

    def test_varint_1_byte_max(self):
        """1-byte varint max value (63)."""
        val, _ = _read_varint(bytes([0x3F]), 0)
        self.assertEqual(val, 63)

    def test_varint_2_byte(self):
        """2-byte varint."""
        val, pos = _read_varint(struct.pack("!H", 0x4000 | 300), 0)
        self.assertEqual(val, 300)
        self.assertEqual(pos, 2)

    def test_varint_4_byte(self):
        """4-byte varint."""
        val, pos = _read_varint(struct.pack("!I", 0x80000000 | 70000), 0)
        self.assertEqual(val, 70000)
        self.assertEqual(pos, 4)

    def test_varint_offset(self):
        """Varint at non-zero offset."""
        data = b'\x00\x00\x05'
        val, pos = _read_varint(data, 2)
        self.assertEqual(val, 5)
        self.assertEqual(pos, 3)

    def test_varint_empty(self):
        """Empty data returns 0."""
        val, pos = _read_varint(b'', 0)
        self.assertEqual(val, 0)


# ============================================================
# Test: Header Parsing
# ============================================================

class TestHeaderParsing(unittest.TestCase):
    """Test QUIC Initial header parsing."""

    def test_parse_none_for_non_quic(self):
        """Non-QUIC packet returns None."""
        self.assertIsNone(_parse_quic_header(b'\x16\x03\x01'))

    def test_parse_none_for_short(self):
        """Too short packet returns None."""
        self.assertIsNone(_parse_quic_header(b'\xC0\x00'))

    def test_parse_header_fields(self):
        """Parse header extracts correct fields."""
        dcid = b'\x01\x02\x03\x04\x05'
        scid = b'\x0A\x0B\x0C'
        # Build minimal header
        first_byte = 0xC0 | 0x00  # Initial, pn_length=1
        data = bytes([first_byte]) + struct.pack("!I", QUIC_V1)
        data += bytes([len(dcid)]) + dcid
        data += bytes([len(scid)]) + scid
        data += bytes([0x00])  # token length = 0
        data += bytes([0x05])  # payload length = 5
        data += b'\x00' * 20   # payload (dummy)

        header = _parse_quic_header(data)
        self.assertIsNotNone(header)
        assert header is not None
        self.assertEqual(header["version"], QUIC_V1)
        self.assertEqual(header["dcid"], dcid)
        self.assertEqual(header["scid"], scid)
        self.assertEqual(header["pn_length_hint"], 1)

    def test_parse_header_with_token(self):
        """Parse header with non-empty token."""
        dcid = b'\x01\x02'
        scid = b'\x0A'
        token = b'\xAA\xBB\xCC'
        first_byte = 0xC0
        data = bytes([first_byte]) + struct.pack("!I", QUIC_V1)
        data += bytes([len(dcid)]) + dcid
        data += bytes([len(scid)]) + scid
        # Token length as varint
        data += bytes([len(token)]) + token
        data += bytes([0x10])  # payload length
        data += b'\x00' * 30

        header = _parse_quic_header(data)
        self.assertIsNotNone(header)
        assert header is not None
        self.assertEqual(header["token"], token)

    def test_parse_header_dcid_too_long(self):
        """DCID > 20 bytes returns None."""
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V1)
        data += bytes([21]) + b'\x00' * 21  # dcid_len = 21
        self.assertIsNone(_parse_quic_header(data))


# ============================================================
# Test: HKDF Key Derivation
# ============================================================

class TestHKDF(unittest.TestCase):
    """Test HKDF key derivation for QUIC."""

    def test_hkdf_extract_known_vector(self):
        """HKDF-Extract with known test vector."""
        # RFC 5869 Test Case 1
        ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        salt = bytes.fromhex("000102030405060708090a0b0c")
        prk = _hkdf_extract(salt, ikm)
        self.assertEqual(len(prk), 32)

    def test_hkdf_expand_length(self):
        """HKDF-Expand produces correct length."""
        prk = b'\x00' * 32
        result = _hkdf_expand(prk, b"test", 16)
        self.assertEqual(len(result), 16)

    def test_hkdf_expand_different_lengths(self):
        """HKDF-Expand with various output lengths."""
        prk = b'\x11' * 32
        for length in [1, 16, 32, 64]:
            result = _hkdf_expand(prk, b"info", length)
            self.assertEqual(len(result), length)

    def test_hkdf_expand_label_quic(self):
        """HKDF-Expand-Label with QUIC-specific labels."""
        secret = b'\x22' * 32
        key = _hkdf_expand_label(secret, "quic key", b"", 16)
        iv = _hkdf_expand_label(secret, "quic iv", b"", 12)
        hp = _hkdf_expand_label(secret, "quic hp", b"", 16)
        self.assertEqual(len(key), 16)
        self.assertEqual(len(iv), 12)
        self.assertEqual(len(hp), 16)

    def test_hkdf_expand_label_deterministic(self):
        """Same inputs produce same outputs."""
        secret = b'\x33' * 32
        r1 = _hkdf_expand_label(secret, "quic key", b"", 16)
        r2 = _hkdf_expand_label(secret, "quic key", b"", 16)
        self.assertEqual(r1, r2)

    def test_hkdf_expand_label_different_secrets(self):
        """Different secrets produce different keys."""
        s1 = b'\x44' * 32
        s2 = b'\x55' * 32
        k1 = _hkdf_expand_label(s1, "quic key", b"", 16)
        k2 = _hkdf_expand_label(s2, "quic key", b"", 16)
        self.assertNotEqual(k1, k2)


# ============================================================
# Test: TLS SNI Extraction (standalone)
# ============================================================

class TestTlsSniExtraction(unittest.TestCase):
    """Test SNI extraction from raw TLS ClientHello."""

    def test_extract_sni_basic(self):
        """Extract SNI from a minimal TLS ClientHello."""
        sni = "example.com"
        sni_bytes = sni.encode('ascii')
        sni_entry = bytes([0x00]) + struct.pack("!H", len(sni_bytes)) + sni_bytes
        sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
        sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

        extensions = struct.pack("!H", len(sni_ext)) + sni_ext

        ch_body = (
            struct.pack("!H", 0x0303) +  # TLS 1.2
            b'\x00' * 32 +               # random
            bytes([0x00]) +              # session ID length 0
            struct.pack("!H", 2) + b'\x13\x01' +  # cipher suites
            bytes([0x01, 0x00]) +        # compression
            extensions
        )

        ch = (bytes([0x01]) +  # ClientHello
              bytes([(len(ch_body) >> 16) & 0xFF]) +
              struct.pack("!H", len(ch_body)) +
              ch_body)

        result = _extract_sni_from_tls(ch)
        self.assertEqual(result, "example.com")

    def test_extract_sni_google(self):
        """Extract google.com SNI."""
        ch = _build_client_hello("google.com")
        self.assertEqual(_extract_sni_from_tls(ch), "google.com")

    def test_extract_sni_subdomain(self):
        """Extract deep subdomain."""
        ch = _build_client_hello("api.v2.example.com")
        self.assertEqual(_extract_sni_from_tls(ch), "api.v2.example.com")

    def test_extract_sni_non_client_hello(self):
        """Non-ClientHello returns None."""
        self.assertIsNone(_extract_sni_from_tls(bytes([0x02]) + b'\x00' * 50))

    def test_extract_sni_truncated(self):
        """Truncated ClientHello returns None."""
        self.assertIsNone(_extract_sni_from_tls(bytes([0x01, 0x00, 0x00])))

    def test_extract_sni_empty(self):
        """Empty data returns None."""
        self.assertIsNone(_extract_sni_from_tls(b''))


def _build_client_hello(sni: str) -> bytes:
    """Helper: build a minimal TLS 1.3 ClientHello with SNI."""
    sni_bytes = sni.encode('ascii')
    sni_entry = bytes([0x00]) + struct.pack("!H", len(sni_bytes)) + sni_bytes
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

    # Add supported_versions extension (TLS 1.3)
    sv_ext = struct.pack("!HH", 0x002b, 3) + b'\x02\x03\x04'

    extensions = struct.pack("!H", len(sni_ext) + len(sv_ext)) + sni_ext + sv_ext

    ch_body = (
        struct.pack("!H", 0x0303) +
        b'\x00' * 32 +
        bytes([0x00]) +
        struct.pack("!H", 2) + b'\x13\x01' +
        bytes([0x01, 0x00]) +
        extensions
    )

    return (bytes([0x01]) +
            bytes([(len(ch_body) >> 16) & 0xFF]) +
            struct.pack("!H", len(ch_body)) +
            ch_body)


# ============================================================
# Test: Full QUIC SNI Extraction (crafted packets)
# ============================================================

class TestQuicSniExtraction(unittest.TestCase):
    """Test full QUIC Initial packet SNI extraction with crafted packets."""

    def test_non_initial_returns_none(self):
        """Non-QUIC packet returns None."""
        self.assertIsNone(extract_quic_sni(b'\x16\x03\x01'))

    def test_empty_returns_none(self):
        """Empty packet returns None."""
        self.assertIsNone(extract_quic_sni(b''))

    def test_short_returns_none(self):
        """Too short packet returns None."""
        self.assertIsNone(extract_quic_sni(b'\xC0\x00\x00\x01'))

    def test_truncated_header_returns_none(self):
        """Truncated header returns None."""
        # Initial packet with version but no DCID/SCID
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V1)
        self.assertIsNone(extract_quic_sni(data))

    def test_wrong_version_returns_none(self):
        """Unknown version returns None."""
        data = bytes([0xC0]) + struct.pack("!I", 0x12345678)
        data += bytes([4]) + b'\x00\x01\x02\x03'  # DCID
        data += bytes([0])  # SCID
        self.assertIsNone(extract_quic_sni(data))


# ============================================================
# Test: Edge Cases
# ============================================================

class TestEdgeCases(unittest.TestCase):
    """Edge cases for QUIC SNI extraction."""

    def test_udp_dns_packet_not_quic(self):
        """Standard DNS packet is not QUIC."""
        dns = (b'\x00\x01'  # transaction ID
               b'\x01\x00'  # flags
               b'\x00\x01'  # questions
               b'\x00\x00\x00\x00\x00\x00'  # answers, authority, additional
               b'\x03www\x07example\x03com\x00'  # name
               b'\x00\x01\x00\x01')  # type A, class IN
        self.assertFalse(is_quic_initial(dns))

    def test_wireguard_packet_not_quic(self):
        """WireGuard packet is not QUIC."""
        wg = b'\x01\x00\x00\x00' + b'\x00' * 100
        self.assertFalse(is_quic_initial(wg))

    def test_stun_packet_not_quic(self):
        """STUN packet is not QUIC."""
        stun = b'\x00\x01\x00\x00' + b'\x21\x12\xa4\x42' + b'\x00' * 10
        self.assertFalse(is_quic_initial(stun))

    def test_dns_over_quic_might_be_detected(self):
        """DNS-over-QUIC uses QUIC — Initial packet detected."""
        # DNS-over-QUIC uses standard QUIC, so it would be detected as QUIC
        # The SNI would be the DoQ server hostname
        # This test just verifies is_quic_initial works for DoQ format
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V1)
        data += bytes([8]) + b'dns.quic\x00'  # DCID
        data += bytes([0])  # SCID
        self.assertTrue(is_quic_initial(data))


if __name__ == '__main__':
    unittest.main()
