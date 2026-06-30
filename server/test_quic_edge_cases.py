"""
QUIC SNI Parser — Extended Edge Case Tests

Covers:
  1. DCID/SCID length boundaries (0, 1, 20, 21)
  2. Packet number lengths (1, 2, 3, 4) and values
  3. Token handling (empty, retry, large — proper varint encoding)
  4. Varint boundary values (0, 63, 64, 16383, 16384, 8-byte)
  5. CRYPTO frame parsing (padding, ACK, PING, truncated, unknown)
  6. TLS ClientHello edge cases (no SNI, empty SNI, non-ASCII, deep subdomain)
  7. Corruption detection (flip bits in payload, header, DCID)
  8. Version edge cases (v2, draft-29, GREASE, version 0)
  9. Non-QUIC traffic patterns (HTTP, BitTorrent, NTP, DHCP, OpenVPN)
 10. Full roundtrip with popular domains
 11. Header parsing boundaries (max DCID, max SCID, varint token)
 12. Concurrent access stress test
"""

import os
import struct
import unittest
from concurrent.futures import ThreadPoolExecutor

from quic_sni import (
    extract_quic_sni, is_quic_initial, _is_quic_initial,
    _parse_quic_header, _hkdf_extract, _hkdf_expand_label,
    _read_varint, _extract_sni_from_tls, _parse_crypto_frame,
    QUIC_V1, QUIC_DRAFT29, QUIC_V2, INITIAL_SALT_V1,
)
from test_quic_sni import _build_client_hello


# ============================================================
# Helpers
# ============================================================

def _write_varint(val: int) -> bytes:
    """Encode a QUIC variable-length integer."""
    if val < 64:
        return bytes([val])
    elif val < 16384:
        return struct.pack("!H", 0x4000 | val)
    elif val < (1 << 30):
        return struct.pack("!I", 0x80000000 | val)
    else:
        return struct.pack("!Q", 0xC000000000000000 | val)


def _make_crypto_frame(domain: str) -> bytes:
    """Build a CRYPTO frame with proper varint-encoded length."""
    ch = _build_client_hello(domain)
    frame = b'\x06' + _write_varint(0)  # CRYPTO type + offset=0
    frame += _write_varint(len(ch)) + ch
    return frame


def _build_roundtrip_packet(domain, dcid_len=8, scid_len=4,
                            pn_length=1, pn=0, token=b""):
    """Build a fully encrypted, header-protected QUIC Initial packet."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    dcid = os.urandom(dcid_len)
    scid = os.urandom(scid_len)

    ch = _build_client_hello(domain)
    clen = len(ch)
    crypto_frame = b'\x06' + _write_varint(0) + _write_varint(clen) + ch
    plaintext = crypto_frame + b'\x00' * max(0, 1200 - len(crypto_frame) - 16)

    initial_secret = _hkdf_extract(INITIAL_SALT_V1, dcid)
    client_key = _hkdf_expand_label(initial_secret, "quic key", b"", 16)
    client_iv = _hkdf_expand_label(initial_secret, "quic iv", b"", 12)
    client_hp = _hkdf_expand_label(initial_secret, "quic hp", b"", 16)

    pn_len = pn_length
    nonce = bytearray(client_iv)
    pn_padded = pn.to_bytes(12, 'big')
    for i in range(12):
        nonce[i] ^= pn_padded[i]

    first_byte = 0xC0 | (pn_len - 1)
    header = bytes([first_byte]) + struct.pack("!I", QUIC_V1)
    header += bytes([dcid_len]) + dcid
    header += bytes([scid_len]) + scid
    header += _write_varint(len(token)) + token
    payload_length = len(plaintext) + 16 + pn_len
    header += _write_varint(payload_length)

    pn_field = pn.to_bytes(pn_len, 'big')
    aad = header + pn_field

    aesgcm = AESGCM(client_key)
    encrypted = aesgcm.encrypt(bytes(nonce), plaintext, aad)

    packet = bytearray(header + pn_field + encrypted)

    sample_offset = len(header) + 4
    if sample_offset + 16 > len(packet):
        return None

    sample = bytes(packet[sample_offset:sample_offset + 16])
    cipher = Cipher(algorithms.AES(client_hp), modes.ECB())
    encryptor = cipher.encryptor()
    mask = encryptor.update(sample) + encryptor.finalize()

    packet[0] ^= (mask[0] & 0x0F)
    for i in range(pn_len):
        packet[len(header) + i] ^= mask[1 + i]

    return bytes(packet)


# ============================================================
# 1. DCID/SCID Length Boundaries
# ============================================================

class TestDcidScidBoundaries(unittest.TestCase):

    def _roundtrip(self, domain, **kwargs):
        pkt = _build_roundtrip_packet(domain, **kwargs)
        self.assertIsNotNone(pkt, f"Failed to build packet for {domain}")
        self.assertEqual(extract_quic_sni(pkt), domain)

    def test_dcid_1_byte(self):
        self._roundtrip("d1.example.com", dcid_len=1)

    def test_dcid_2_bytes(self):
        self._roundtrip("d2.example.com", dcid_len=2)

    def test_dcid_16_bytes(self):
        self._roundtrip("d16.example.com", dcid_len=16)

    def test_dcid_20_bytes_max(self):
        self._roundtrip("dmax.example.com", dcid_len=20)

    def test_scid_0_bytes(self):
        self._roundtrip("s0.example.com", scid_len=0)

    def test_scid_1_byte(self):
        self._roundtrip("s1.example.com", scid_len=1)

    def test_scid_16_bytes(self):
        self._roundtrip("s16.example.com", scid_len=16)

    def test_scid_20_bytes_max(self):
        self._roundtrip("smax.example.com", scid_len=20)

    def test_dcid_21_rejected(self):
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V1)
        data += bytes([21]) + b'\x00' * 21
        self.assertIsNone(_parse_quic_header(data))

    def test_scid_21_rejected(self):
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V1)
        data += bytes([4]) + b'\x01\x02\x03\x04'
        data += bytes([21]) + b'\x00' * 21
        self.assertIsNone(_parse_quic_header(data))

    def test_both_max_lengths(self):
        self._roundtrip("bothmax.example.com", dcid_len=20, scid_len=20)

    def test_both_min_lengths(self):
        self._roundtrip("bothmin.example.com", dcid_len=1, scid_len=0)


# ============================================================
# 2. Packet Number Lengths and Values
# ============================================================

class TestPacketNumberEdgeCases(unittest.TestCase):

    def _roundtrip(self, domain, **kwargs):
        pkt = _build_roundtrip_packet(domain, **kwargs)
        self.assertIsNotNone(pkt)
        self.assertEqual(extract_quic_sni(pkt), domain)

    def test_pn_0_1byte(self):
        self._roundtrip("pn0.test", pn=0, pn_length=1)

    def test_pn_1_1byte(self):
        self._roundtrip("pn1.test", pn=1, pn_length=1)

    def test_pn_255_max_1byte(self):
        self._roundtrip("pn255.test", pn=255, pn_length=1)

    def test_pn_256_2byte(self):
        self._roundtrip("pn256.test", pn=256, pn_length=2)

    def test_pn_16383_2byte(self):
        self._roundtrip("pn16k.test", pn=16383, pn_length=2)

    def test_pn_65535_2byte(self):
        self._roundtrip("pn65k.test", pn=65535, pn_length=2)

    def test_pn_70000_3byte(self):
        self._roundtrip("pn70k.test", pn=70000, pn_length=3)

    def test_pn_100000_4byte(self):
        self._roundtrip("pn100k.test", pn=100000, pn_length=4)

    def test_pn_max_3byte(self):
        self._roundtrip("pnmax3.test", pn=16777215, pn_length=3)


# ============================================================
# 3. Token Handling
# ============================================================

class TestTokenEdgeCases(unittest.TestCase):

    def _roundtrip(self, domain, **kwargs):
        pkt = _build_roundtrip_packet(domain, **kwargs)
        self.assertIsNotNone(pkt)
        self.assertEqual(extract_quic_sni(pkt), domain)

    def test_empty_token(self):
        self._roundtrip("notoken.test", token=b"")

    def test_1_byte_token(self):
        self._roundtrip("tok1.test", token=b'\xAA')

    def test_16_byte_token(self):
        self._roundtrip("tok16.test", token=os.urandom(16))

    def test_32_byte_retry_token(self):
        self._roundtrip("tok32.test", token=os.urandom(32))

    def test_64_byte_token(self):
        self._roundtrip("tok64.test", token=os.urandom(64))

    def test_100_byte_large_token(self):
        self._roundtrip("tok100.test", token=os.urandom(100))

    def test_200_byte_token(self):
        self._roundtrip("tok200.test", token=os.urandom(200))


# ============================================================
# 4. Varint Boundary Values
# ============================================================

class TestVarintBoundaries(unittest.TestCase):

    def test_0(self):
        val, pos = _read_varint(bytes([0x00]), 0)
        self.assertEqual(val, 0)
        self.assertEqual(pos, 1)

    def test_1(self):
        val, _ = _read_varint(bytes([0x01]), 0)
        self.assertEqual(val, 1)

    def test_62(self):
        val, _ = _read_varint(bytes([0x3E]), 0)
        self.assertEqual(val, 62)

    def test_63_max_1byte(self):
        val, _ = _read_varint(bytes([0x3F]), 0)
        self.assertEqual(val, 63)

    def test_64_min_2byte(self):
        val, _ = _read_varint(struct.pack("!H", 0x4040), 0)
        self.assertEqual(val, 64)

    def test_300_2byte(self):
        val, _ = _read_varint(struct.pack("!H", 0x4000 | 300), 0)
        self.assertEqual(val, 300)

    def test_16383_max_2byte(self):
        val, _ = _read_varint(struct.pack("!H", 0x7FFF), 0)
        self.assertEqual(val, 16383)

    def test_16384_min_4byte(self):
        val, _ = _read_varint(struct.pack("!I", 0x80004000), 0)
        self.assertEqual(val, 16384)

    def test_70000_4byte(self):
        val, _ = _read_varint(struct.pack("!I", 0x80000000 | 70000), 0)
        self.assertEqual(val, 70000)

    def test_max_4byte(self):
        val, _ = _read_varint(struct.pack("!I", 0xBFFFFFFF), 0)
        self.assertEqual(val, 0x3FFFFFFF)

    def test_8byte_value(self):
        val, pos = _read_varint(struct.pack("!Q", 0xC000000000001000), 0)
        self.assertEqual(val, 0x1000)
        self.assertEqual(pos, 8)

    def test_truncated_2byte_at_end(self):
        val, pos = _read_varint(b'\x40', 0)
        self.assertEqual(val, 0)

    def test_truncated_at_offset(self):
        data = b'\x00\x00\x40'
        val, pos = _read_varint(data, 2)
        self.assertEqual(val, 0)

    def test_past_end_offset(self):
        val, pos = _read_varint(b'\x05', 5)
        self.assertEqual(val, 0)
        self.assertEqual(pos, 5)

    def test_single_byte_at_end(self):
        val, pos = _read_varint(b'\x2A', 0)
        self.assertEqual(val, 42)
        self.assertEqual(pos, 1)

    def test_offset_at_middle(self):
        data = b'\xFF\xFF\x05\xFF'
        val, pos = _read_varint(data, 2)
        self.assertEqual(val, 5)
        self.assertEqual(pos, 3)


# ============================================================
# 5. CRYPTO Frame Parsing Edge Cases
# ============================================================

class TestCryptoFrameEdgeCases(unittest.TestCase):

    def test_padding_before_crypto(self):
        crypto = _make_crypto_frame("pad.test")
        payload = b'\x00\x00\x00\x00\x00' + crypto
        result = _parse_crypto_frame(payload)
        self.assertIsNotNone(result)
        self.assertEqual(_extract_sni_from_tls(result), "pad.test")

    def test_many_padding_before_crypto(self):
        crypto = _make_crypto_frame("manypad.test")
        payload = b'\x00' * 50 + crypto
        result = _parse_crypto_frame(payload)
        self.assertIsNotNone(result)
        self.assertEqual(_extract_sni_from_tls(result), "manypad.test")

    def test_ack_before_crypto(self):
        # ACK: type=0x02, largest_ack=5, delay=0, count=0, first_range=3
        ack = b'\x02\x05\x00\x00\x03'
        crypto = _make_crypto_frame("ack.test")
        result = _parse_crypto_frame(ack + crypto)
        self.assertIsNotNone(result)
        self.assertEqual(_extract_sni_from_tls(result), "ack.test")

    def test_ack_with_ranges(self):
        # ACK with 2 range count
        ack = b'\x02\x0A\x00\x02\x05'  # largest=10, delay=0, count=2, first=5
        ack += b'\x01\x02'              # gap=1, range=2
        ack += b'\x01\x01'              # gap=1, range=1
        crypto = _make_crypto_frame("ackrange.test")
        result = _parse_crypto_frame(ack + crypto)
        self.assertIsNotNone(result)
        self.assertEqual(_extract_sni_from_tls(result), "ackrange.test")

    def test_ack_ecn_before_crypto(self):
        """ACK with ECN (type 0x03)."""
        ack = b'\x03\x05\x00\x00\x03'  # ACK-ECN type
        ack += b'\x00\x00\x00'          # ECT(0), ECT(1), ECN-CE
        crypto = _make_crypto_frame("ackecn.test")
        result = _parse_crypto_frame(ack + crypto)
        self.assertIsNotNone(result)
        self.assertEqual(_extract_sni_from_tls(result), "ackecn.test")

    def test_ping_before_crypto(self):
        ping = b'\x01'
        crypto = _make_crypto_frame("ping.test")
        result = _parse_crypto_frame(ping + crypto)
        self.assertIsNotNone(result)
        self.assertEqual(_extract_sni_from_tls(result), "ping.test")

    def test_multiple_pings_then_crypto(self):
        pings = b'\x01\x01\x01\x01\x01'
        crypto = _make_crypto_frame("mping.test")
        result = _parse_crypto_frame(pings + crypto)
        self.assertIsNotNone(result)
        self.assertEqual(_extract_sni_from_tls(result), "mping.test")

    def test_empty_payload(self):
        self.assertIsNone(_parse_crypto_frame(b''))

    def test_only_padding(self):
        self.assertIsNone(_parse_crypto_frame(b'\x00\x00\x00'))

    def test_truncated_crypto_varint(self):
        """CRYPTO frame with varint that can't be decoded."""
        # \xC8 prefix = 4-byte varint, but only 2 bytes follow
        payload = b'\x06\x00\xC8\x00' + b'\x00' * 5
        # _read_varint returns 0 for truncated → length=0 → empty data
        result = _parse_crypto_frame(payload)
        # Returns empty bytes, not None — _extract_sni_from_tls(b'') → None
        if result is not None:
            self.assertEqual(len(result), 0)
            self.assertIsNone(_extract_sni_from_tls(result))

    def test_unknown_frame_type(self):
        """STREAM frame (0x08) — not handled."""
        payload = b'\x08\x00\x10' + b'\x00' * 20
        self.assertIsNone(_parse_crypto_frame(payload))

    def test_zero_length_crypto(self):
        """CRYPTO frame with 0-length data → empty bytes."""
        payload = b'\x06\x00\x00'
        result = _parse_crypto_frame(payload)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 0)
        # Empty TLS data → None
        self.assertIsNone(_extract_sni_from_tls(result))

    def test_padding_then_unknown(self):
        """PADDING then unknown frame → None."""
        payload = b'\x00\x00\x00\xFF\xFF'
        self.assertIsNone(_parse_crypto_frame(payload))

    def test_ack_then_ping_then_crypto(self):
        """Multiple frame types before CRYPTO."""
        ack = b'\x02\x03\x00\x00\x01'  # ACK
        ping = b'\x01'                  # PING
        crypto = _make_crypto_frame("multi.test")
        result = _parse_crypto_frame(ack + ping + crypto)
        self.assertIsNotNone(result)
        self.assertEqual(_extract_sni_from_tls(result), "multi.test")


# ============================================================
# 6. TLS ClientHello Edge Cases
# ============================================================

class TestTlsClientHelloEdgeCases(unittest.TestCase):

    def _build_ch_with_extras(self, domain, extra_exts=None, session_id_len=0,
                               cipher_suites=None):
        sni_bytes = domain.encode('ascii')
        sni_entry = bytes([0x00]) + struct.pack("!H", len(sni_bytes)) + sni_bytes
        sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
        sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
        sv_ext = struct.pack("!HH", 0x002b, 3) + b'\x02\x03\x04'
        extensions = sni_ext + sv_ext
        if extra_exts:
            extensions += extra_exts
        ext_total = struct.pack("!H", len(extensions)) + extensions

        cs = cipher_suites or (struct.pack("!H", 2) + b'\x13\x01')
        sid = bytes([session_id_len]) + b'\x01' * session_id_len

        ch_body = (
            struct.pack("!H", 0x0303) +
            b'\x00' * 32 +
            sid +
            cs +
            bytes([0x01, 0x00]) +
            ext_total
        )
        return (bytes([0x01]) +
                bytes([(len(ch_body) >> 16) & 0xFF]) +
                struct.pack("!H", len(ch_body)) +
                ch_body)

    def test_single_char_domain(self):
        ch = self._build_ch_with_extras("a.com")
        self.assertEqual(_extract_sni_from_tls(ch), "a.com")

    def test_max_length_domain_253(self):
        domain = "a" * 250 + ".com"
        ch = self._build_ch_with_extras(domain)
        self.assertEqual(_extract_sni_from_tls(ch), domain)

    def test_deep_subdomain(self):
        domain = "a.b.c.d.e.f.g.h.i.j.k.example.com"
        ch = self._build_ch_with_extras(domain)
        self.assertEqual(_extract_sni_from_tls(ch), domain)

    def test_numeric_domain(self):
        ch = self._build_ch_with_extras("123.456.789.com")
        self.assertEqual(_extract_sni_from_tls(ch), "123.456.789.com")

    def test_hyphenated_domain(self):
        ch = self._build_ch_with_extras("my-app.v2-stage.example.com")
        self.assertEqual(_extract_sni_from_tls(ch), "my-app.v2-stage.example.com")

    def test_long_tld(self):
        ch = self._build_ch_with_extras("test.museum")
        self.assertEqual(_extract_sni_from_tls(ch), "test.museum")

    def test_no_sni_extension(self):
        sv_ext = struct.pack("!HH", 0x002b, 3) + b'\x02\x03\x04'
        ext_total = struct.pack("!H", len(sv_ext)) + sv_ext
        ch_body = (
            struct.pack("!H", 0x0303) + b'\x00' * 32 + bytes([0x00]) +
            struct.pack("!H", 2) + b'\x13\x01' +
            bytes([0x01, 0x00]) + ext_total
        )
        ch = (bytes([0x01]) + bytes([(len(ch_body) >> 16) & 0xFF]) +
              struct.pack("!H", len(ch_body)) + ch_body)
        self.assertIsNone(_extract_sni_from_tls(ch))

    def test_sni_with_multiple_entries(self):
        sni1 = "first.com".encode('ascii')
        sni2 = "second.com".encode('ascii')
        entry1 = bytes([0x00]) + struct.pack("!H", len(sni1)) + sni1
        entry2 = bytes([0x00]) + struct.pack("!H", len(sni2)) + sni2
        sni_list = struct.pack("!H", len(entry1) + len(entry2)) + entry1 + entry2
        sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
        sv_ext = struct.pack("!HH", 0x002b, 3) + b'\x02\x03\x04'
        extensions = sni_ext + sv_ext
        ext_total = struct.pack("!H", len(extensions)) + extensions
        ch_body = (
            struct.pack("!H", 0x0303) + b'\x00' * 32 + bytes([0x00]) +
            struct.pack("!H", 2) + b'\x13\x01' +
            bytes([0x01, 0x00]) + ext_total
        )
        ch = (bytes([0x01]) + bytes([(len(ch_body) >> 16) & 0xFF]) +
              struct.pack("!H", len(ch_body)) + ch_body)
        self.assertEqual(_extract_sni_from_tls(ch), "first.com")

    def test_sni_empty_hostname(self):
        sni_entry = bytes([0x00]) + struct.pack("!H", 0)
        sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
        sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
        sv_ext = struct.pack("!HH", 0x002b, 3) + b'\x02\x03\x04'
        extensions = sni_ext + sv_ext
        ext_total = struct.pack("!H", len(extensions)) + extensions
        ch_body = (
            struct.pack("!H", 0x0303) + b'\x00' * 32 + bytes([0x00]) +
            struct.pack("!H", 2) + b'\x13\x01' +
            bytes([0x01, 0x00]) + ext_total
        )
        ch = (bytes([0x01]) + bytes([(len(ch_body) >> 16) & 0xFF]) +
              struct.pack("!H", len(ch_body)) + ch_body)
        result = _extract_sni_from_tls(ch)
        self.assertEqual(result, "")

    def test_sni_type_not_hostname(self):
        sni_entry = bytes([0x01]) + struct.pack("!H", 4) + b'\x00\x00\x00\x00'
        sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
        sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
        sv_ext = struct.pack("!HH", 0x002b, 3) + b'\x02\x03\x04'
        extensions = sni_ext + sv_ext
        ext_total = struct.pack("!H", len(extensions)) + extensions
        ch_body = (
            struct.pack("!H", 0x0303) + b'\x00' * 32 + bytes([0x00]) +
            struct.pack("!H", 2) + b'\x13\x01' +
            bytes([0x01, 0x00]) + ext_total
        )
        ch = (bytes([0x01]) + bytes([(len(ch_body) >> 16) & 0xFF]) +
              struct.pack("!H", len(ch_body)) + ch_body)
        self.assertIsNone(_extract_sni_from_tls(ch))

    def test_non_ascii_sni(self):
        sni_bytes = b'\xff\xfe\xfd'
        sni_entry = bytes([0x00]) + struct.pack("!H", len(sni_bytes)) + sni_bytes
        sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
        sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
        sv_ext = struct.pack("!HH", 0x002b, 3) + b'\x02\x03\x04'
        extensions = sni_ext + sv_ext
        ext_total = struct.pack("!H", len(extensions)) + extensions
        ch_body = (
            struct.pack("!H", 0x0303) + b'\x00' * 32 + bytes([0x00]) +
            struct.pack("!H", 2) + b'\x13\x01' +
            bytes([0x01, 0x00]) + ext_total
        )
        ch = (bytes([0x01]) + bytes([(len(ch_body) >> 16) & 0xFF]) +
              struct.pack("!H", len(ch_body)) + ch_body)
        self.assertIsNone(_extract_sni_from_tls(ch))

    def test_server_hello_rejected(self):
        data = bytes([0x02]) + b'\x00\x00\x40' + b'\x00' * 70
        self.assertIsNone(_extract_sni_from_tls(data))

    def test_truncated_before_extensions(self):
        data = bytes([0x01]) + b'\x00\x00\x03' + b'\x00' * 3
        self.assertIsNone(_extract_sni_from_tls(data))

    def test_sni_after_alpn(self):
        alpn_data = b'\x02h2\x05h3-19'
        alpn_ext = struct.pack("!HH", 0x0010, len(alpn_data)) + alpn_data

        sni_bytes = "alpn-first.test".encode('ascii')
        sni_entry = bytes([0x00]) + struct.pack("!H", len(sni_bytes)) + sni_bytes
        sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
        sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

        extensions = alpn_ext + sni_ext
        ext_total = struct.pack("!H", len(extensions)) + extensions
        ch_body = (
            struct.pack("!H", 0x0303) + b'\x00' * 32 + bytes([0x00]) +
            struct.pack("!H", 2) + b'\x13\x01' +
            bytes([0x01, 0x00]) + ext_total
        )
        ch = (bytes([0x01]) + bytes([(len(ch_body) >> 16) & 0xFF]) +
              struct.pack("!H", len(ch_body)) + ch_body)
        self.assertEqual(_extract_sni_from_tls(ch), "alpn-first.test")

    def test_sni_before_key_share(self):
        sni_bytes = "sni-first.test".encode('ascii')
        sni_entry = bytes([0x00]) + struct.pack("!H", len(sni_bytes)) + sni_bytes
        sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
        sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
        sv_ext = struct.pack("!HH", 0x002b, 3) + b'\x02\x03\x04'
        ks_data = b'\x00\x1d' + b'\x00\x20' + b'\x00' * 32
        ks_ext = struct.pack("!HH", 0x0033, len(ks_data)) + ks_data
        extensions = sni_ext + sv_ext + ks_ext
        ext_total = struct.pack("!H", len(extensions)) + extensions
        ch_body = (
            struct.pack("!H", 0x0303) + b'\x00' * 32 + bytes([0x00]) +
            struct.pack("!H", 2) + b'\x13\x01' +
            bytes([0x01, 0x00]) + ext_total
        )
        ch = (bytes([0x01]) + bytes([(len(ch_body) >> 16) & 0xFF]) +
              struct.pack("!H", len(ch_body)) + ch_body)
        self.assertEqual(_extract_sni_from_tls(ch), "sni-first.test")

    def test_large_session_id(self):
        ch = self._build_ch_with_extras("session32.test", session_id_len=32)
        self.assertEqual(_extract_sni_from_tls(ch), "session32.test")

    def test_large_cipher_suites(self):
        cs = struct.pack("!H", 10) + b'\x13\x01\x13\x02\x13\x03\xc0\x2c\xc0\x2b'
        ch = self._build_ch_with_extras("manycs.test", cipher_suites=cs)
        self.assertEqual(_extract_sni_from_tls(ch), "manycs.test")


# ============================================================
# 7. Corruption and Tamper Detection
# ============================================================

class TestCorruptionDetection(unittest.TestCase):

    def test_flip_byte_in_encrypted_payload(self):
        pkt = _build_roundtrip_packet("corrupt.test")
        self.assertIsNotNone(pkt)
        corrupted = bytearray(pkt)
        if len(corrupted) > 50:
            corrupted[50] ^= 0xFF
        self.assertIsNone(extract_quic_sni(bytes(corrupted)))

    def test_flip_byte_in_dcid(self):
        pkt = _build_roundtrip_packet("dcid.test")
        self.assertIsNotNone(pkt)
        corrupted = bytearray(pkt)
        if len(corrupted) > 8:
            corrupted[7] ^= 0xFF
        self.assertIsNone(extract_quic_sni(bytes(corrupted)))

    def test_flip_byte_in_sample_area(self):
        pkt = _build_roundtrip_packet("sample.test")
        self.assertIsNotNone(pkt)
        corrupted = bytearray(pkt)
        if len(corrupted) > 35:
            corrupted[35] ^= 0xFF
        _ = extract_quic_sni(bytes(corrupted))  # no crash

    def test_empty_packet(self):
        self.assertIsNone(extract_quic_sni(b''))

    def test_single_byte(self):
        self.assertIsNone(extract_quic_sni(b'\xC0'))

    def test_all_zeros(self):
        self.assertIsNone(extract_quic_sni(b'\x00' * 100))

    def test_all_ff(self):
        self.assertIsNone(extract_quic_sni(b'\xFF' * 100))

    def test_random_200_bytes(self):
        self.assertIsNone(extract_quic_sni(os.urandom(200)))

    def test_random_500_bytes(self):
        self.assertIsNone(extract_quic_sni(os.urandom(500)))

    def test_truncated_to_header_only(self):
        pkt = _build_roundtrip_packet("trunc.test")
        self.assertIsNotNone(pkt)
        self.assertIsNone(extract_quic_sni(pkt[:30]))

    def test_truncated_at_sample(self):
        pkt = _build_roundtrip_packet("truncsample.test")
        self.assertIsNotNone(pkt)
        self.assertIsNone(extract_quic_sni(pkt[:50]))

    def test_truncated_at_payload(self):
        pkt = _build_roundtrip_packet("truncpayload.test")
        self.assertIsNotNone(pkt)
        self.assertIsNone(extract_quic_sni(pkt[:100]))


# ============================================================
# 8. Version Edge Cases
# ============================================================

class TestVersionEdgeCases(unittest.TestCase):

    def _make_initial(self, version, dcid_len=4):
        data = bytes([0xC0]) + struct.pack("!I", version)
        data += bytes([dcid_len]) + os.urandom(dcid_len)
        data += bytes([0]) + bytes([0x00]) + bytes([0x10]) + b'\x00' * 30
        return data

    def test_v1_detected(self):
        self.assertTrue(is_quic_initial(self._make_initial(QUIC_V1)))

    def test_v2_detected(self):
        self.assertTrue(is_quic_initial(self._make_initial(QUIC_V2)))

    def test_draft29_detected(self):
        self.assertTrue(is_quic_initial(self._make_initial(QUIC_DRAFT29)))

    def test_version_0_unknown(self):
        self.assertFalse(is_quic_initial(self._make_initial(0x00000000)))

    def test_grease_version_unknown(self):
        self.assertFalse(is_quic_initial(self._make_initial(0x0A0A0A0A)))

    def test_random_version_unknown(self):
        self.assertFalse(is_quic_initial(self._make_initial(0xDEADBEEF)))

    def test_v1_roundtrip_works(self):
        pkt = _build_roundtrip_packet("v1.test")
        self.assertIsNotNone(pkt)
        self.assertEqual(extract_quic_sni(pkt), "v1.test")


# ============================================================
# 9. Header Parsing Boundaries
# ============================================================

class TestHeaderParsingBoundaries(unittest.TestCase):

    def test_dcid_max_20_parsed(self):
        dcid = b'\x01' * 20
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V1)
        data += bytes([20]) + dcid
        data += bytes([0]) + bytes([0x00]) + bytes([0x10]) + b'\x00' * 30
        header = _parse_quic_header(data)
        self.assertIsNotNone(header)
        self.assertEqual(len(header["dcid"]), 20)

    def test_scid_max_20_parsed(self):
        scid = b'\x02' * 20
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V1)
        data += bytes([4]) + b'\x01\x02\x03\x04'
        data += bytes([20]) + scid
        data += bytes([0x00]) + bytes([0x10]) + b'\x00' * 30
        header = _parse_quic_header(data)
        self.assertIsNotNone(header)
        self.assertEqual(len(header["scid"]), 20)

    def test_empty_dcid(self):
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V1)
        data += bytes([0]) + bytes([0]) + bytes([0x00]) + bytes([0x10]) + b'\x00' * 30
        header = _parse_quic_header(data)
        self.assertIsNotNone(header)
        self.assertEqual(header["dcid"], b'')

    def test_token_content_preserved(self):
        token = b'\xAA\xBB\xCC\xDD\xEE'
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V1)
        data += bytes([4]) + b'\x01\x02\x03\x04'
        data += bytes([0])
        data += bytes([len(token)]) + token
        data += bytes([0x10]) + b'\x00' * 30
        header = _parse_quic_header(data)
        self.assertIsNotNone(header)
        self.assertEqual(header["token"], token)

    def test_large_varint_token_length(self):
        token = b'\xAA' * 100
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V1)
        data += bytes([4]) + b'\x01\x02\x03\x04'
        data += bytes([0])
        data += struct.pack("!H", 0x4000 | len(token)) + token
        data += bytes([0x10]) + b'\x00' * 120
        header = _parse_quic_header(data)
        self.assertIsNotNone(header)
        self.assertEqual(len(header["token"]), 100)

    def test_first_byte_fields(self):
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V1)
        data += bytes([4]) + b'\x01\x02\x03\x04'
        data += bytes([0]) + bytes([0x00]) + bytes([0x10]) + b'\x00' * 30
        header = _parse_quic_header(data)
        self.assertIsNotNone(header)
        self.assertEqual(header["first_byte"], 0xC0)

    def test_payload_length_parsed(self):
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V1)
        data += bytes([4]) + b'\x01\x02\x03\x04'
        data += bytes([0]) + bytes([0x00])
        data += bytes([42])  # payload_length = 42
        data += b'\x00' * 60
        header = _parse_quic_header(data)
        self.assertIsNotNone(header)
        self.assertEqual(header["payload_length"], 42)


# ============================================================
# 10. Non-QUIC Traffic Patterns
# ============================================================

class TestNonQuicTrafficPatterns(unittest.TestCase):

    def test_http_get(self):
        self.assertFalse(is_quic_initial(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))

    def test_tls_over_tcp(self):
        self.assertFalse(is_quic_initial(b'\x16\x03\x01\x00\x05\x01\x00\x00\x00\x00'))

    def test_bittorrent_dht(self):
        self.assertFalse(is_quic_initial(b"d1:ad2:id20:abcdefghij0123456789e"))

    def test_ntp_packet(self):
        self.assertFalse(is_quic_initial(b'\x24\x01\x00\xe9' + b'\x00' * 44))

    def test_dhcp_packet(self):
        self.assertFalse(is_quic_initial(b'\x01\x01\x06\x00' + b'\x00' * 236))

    def test_ikev2_packet(self):
        self.assertFalse(is_quic_initial(b'\x00' * 8 + b'\x21\x20\x22\x08' + b'\x00' * 20))

    def test_openvpn_packet(self):
        self.assertFalse(is_quic_initial(b'\x00\x0e\x40\xc2' + b'\x00' * 50))

    def test_ssdp_packet(self):
        self.assertFalse(is_quic_initial(b"M-SEARCH * HTTP/1.1\r\n"))

    def test_wireguard_handshake(self):
        self.assertFalse(is_quic_initial(b'\x01\x00\x00\x00' + b'\x00' * 100))

    def test_stun_binding(self):
        self.assertFalse(is_quic_initial(b'\x00\x01\x00\x00' + b'\x21\x12\xa4\x42' + b'\x00' * 10))


# ============================================================
# 11. Full Roundtrip — Popular Domains
# ============================================================

class TestRoundtripPopularDomains(unittest.TestCase):

    def _verify(self, domain):
        pkt = _build_roundtrip_packet(domain)
        self.assertIsNotNone(pkt, f"Build failed for {domain}")
        self.assertEqual(extract_quic_sni(pkt), domain)

    def test_google_com(self):
        self._verify("google.com")

    def test_youtube_com(self):
        self._verify("youtube.com")

    def test_facebook_com(self):
        self._verify("facebook.com")

    def test_instagram_com(self):
        self._verify("instagram.com")

    def test_whatsapp_com(self):
        self._verify("whatsapp.com")

    def test_tiktok_com(self):
        self._verify("tiktok.com")

    def test_netflix_com(self):
        self._verify("netflix.com")

    def test_spotify_com(self):
        self._verify("spotify.com")

    def test_github_com(self):
        self._verify("github.com")

    def test_cloudflare_com(self):
        self._verify("cloudflare.com")

    def test_aws_s3(self):
        self._verify("s3.ap-southeast-1.amazonaws.com")

    def test_gcp_storage(self):
        self._verify("storage.googleapis.com")

    def test_azure_blob(self):
        self._verify("blob.core.windows.net")

    def test_www_prefix(self):
        self._verify("www.example.com")

    def test_api_v2(self):
        self._verify("api.v2.service.example.com")

    def test_cdn_assets(self):
        self._verify("cdn.static.assets.example.com")

    def test_reddit_com(self):
        self._verify("reddit.com")

    def test_twitter_com(self):
        self._verify("twitter.com")

    def test_telegram_org(self):
        self._verify("telegram.org")

    def test_wikipedia_org(self):
        self._verify("wikipedia.org")


# ============================================================
# 12. Stress / Concurrent Access
# ============================================================

class TestStressAndConcurrency(unittest.TestCase):

    def test_10_sequential_packets(self):
        for i in range(10):
            domain = f"stress{i}.test"
            pkt = _build_roundtrip_packet(domain)
            self.assertIsNotNone(pkt)
            self.assertEqual(extract_quic_sni(pkt), domain)

    def test_20_concurrent_extractions(self):
        domains = [f"concurrent{i}.test" for i in range(20)]
        packets = []
        for d in domains:
            pkt = _build_roundtrip_packet(d)
            self.assertIsNotNone(pkt)
            packets.append((d, pkt))

        def extract(args):
            domain, pkt = args
            return domain, extract_quic_sni(pkt)

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(extract, packets))

        for domain, result in results:
            self.assertEqual(result, domain)

    def test_mixed_valid_and_corrupt(self):
        import random
        packets = []
        for i in range(20):
            if random.random() < 0.5:
                domain = f"valid{i}.test"
                pkt = _build_roundtrip_packet(domain)
                packets.append(("valid", domain, pkt))
            else:
                pkt = os.urandom(random.randint(10, 200))
                packets.append(("corrupt", None, pkt))

        for kind, domain, pkt in packets:
            if kind == "valid":
                self.assertEqual(extract_quic_sni(pkt), domain)
            else:
                _ = extract_quic_sni(pkt)  # no crash


if __name__ == '__main__':
    unittest.main()
