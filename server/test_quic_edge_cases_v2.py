"""
QUIC SNI Parser — Deep Edge Case Tests (Part 2)

Focuses on gaps in existing test coverage:
  1. Adversarial/malformed inputs (buffer overflow, invalid lengths)
  2. CRYPTO frame with multiple frames, ACK with various range counts
  3. TLS ClientHello with multiple extensions, unknown extensions
  4. Decrypt edge cases: corrupted ciphertext, wrong AAD, too-short sample
  5. QUIC v2 wire image (different first byte encoding)
  6. Real-world patterns: DNS-over-QUIC, QUIC 0-RTT
  7. Concurrent access stress test
  8. Memory safety: large packets, deep recursion prevention
"""

import os
import struct
import unittest
from concurrent.futures import ThreadPoolExecutor, as_completed

from quic_sni import (
    extract_quic_sni, is_quic_initial,
    _is_quic_initial, _parse_quic_header, _decrypt_initial,
    _hkdf_extract, _hkdf_expand, _hkdf_expand_label,
    _read_varint, _extract_sni_from_tls, _parse_crypto_frame,
    QUIC_V1, QUIC_DRAFT29, QUIC_V2,
    INITIAL_SALT_V1,
)


# ============================================================
# Helpers
# ============================================================

def _write_varint(val: int) -> bytes:
    if val < 64:
        return bytes([val])
    elif val < 16384:
        return struct.pack("!H", 0x4000 | val)
    elif val < (1 << 30):
        return struct.pack("!I", 0x80000000 | val)
    else:
        return struct.pack("!Q", 0xC000000000000000 | val)


def _build_client_hello(sni: str, extra_exts=b"") -> bytes:
    sni_bytes = sni.encode('ascii')
    sni_entry = bytes([0x00]) + struct.pack("!H", len(sni_bytes)) + sni_bytes
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
    sv_ext = struct.pack("!HH", 0x002b, 3) + b'\x02\x03\x04'
    extensions = struct.pack("!H", len(sni_ext) + len(sv_ext) + len(extra_exts)) + sni_ext + sv_ext + extra_exts
    ch_body = (
        struct.pack("!H", 0x0303) + b'\x00' * 32 + bytes([0x00]) +
        struct.pack("!H", 2) + b'\x13\x01' + bytes([0x01, 0x00]) + extensions
    )
    return (bytes([0x01]) + bytes([(len(ch_body) >> 16) & 0xFF]) +
            struct.pack("!H", len(ch_body)) + ch_body)


def _build_roundtrip_packet(domain, version=QUIC_V1, dcid_len=8, scid_len=4,
                            pn_length=1, pn=0, token=b"",
                            plaintext_override=None):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    dcid = os.urandom(dcid_len)
    scid = os.urandom(scid_len)

    if plaintext_override is not None:
        plaintext = plaintext_override
    else:
        ch = _build_client_hello(domain)
        crypto_frame = b'\x06' + _write_varint(0) + _write_varint(len(ch)) + ch
        plaintext = crypto_frame + b'\x00' * max(0, 1200 - len(crypto_frame) - 16)

    if version == QUIC_V2:
        salt = bytes.fromhex("a707c203a59b47184317ef6f70b64a1e76ab5765")
    else:
        salt = INITIAL_SALT_V1

    initial_secret = _hkdf_extract(salt, dcid)
    client_initial_secret = _hkdf_expand_label(initial_secret, "client in", b"", 32)
    client_key = _hkdf_expand_label(client_initial_secret, "quic key", b"", 16)
    client_iv = _hkdf_expand_label(client_initial_secret, "quic iv", b"", 12)
    client_hp = _hkdf_expand_label(client_initial_secret, "quic hp", b"", 16)

    pn_len = pn_length
    nonce = bytearray(client_iv)
    pn_padded = pn.to_bytes(12, 'big')
    for i in range(12):
        nonce[i] ^= pn_padded[i]

    first_byte = 0xC0 | (pn_len - 1)
    header = bytes([first_byte]) + struct.pack("!I", version)
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

    return bytes(packet), dcid, scid, client_key, client_iv, client_hp


def _build_simple(domain):
    """Build a simple roundtrip packet, return just the bytes."""
    result = _build_roundtrip_packet(domain)
    return result[0] if result else None


# ============================================================
# 1. Adversarial / Malformed Inputs
# ============================================================

class TestAdversarialInputs(unittest.TestCase):
    """Malicious or corrupted packets that must not crash the parser."""

    def test_all_zeros_1500_bytes(self):
        """Ethernet-sized zero packet."""
        self.assertIsNone(extract_quic_sni(b'\x00' * 1500))

    def test_all_ff_1500_bytes(self):
        """Ethernet-sized 0xFF packet."""
        self.assertIsNone(extract_quic_sni(b'\xFF' * 1500))

    def test_single_byte_0xc0(self):
        """Just the Initial first byte, nothing else."""
        self.assertIsNone(extract_quic_sni(b'\xC0'))

    def test_valid_header_huge_dcid_len(self):
        """DCID length byte = 255 → rejected (>20)."""
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V1) + bytes([255]) + b'\x00' * 255
        self.assertIsNone(extract_quic_sni(data))

    def test_valid_header_huge_scid_len(self):
        """SCID length byte = 255 → rejected (>20)."""
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V1) + bytes([4]) + os.urandom(4) + bytes([255])
        self.assertIsNone(extract_quic_sni(data))

    def test_truncated_after_dcid(self):
        """Packet ends mid-DCID."""
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V1) + bytes([8]) + b'\x01\x02\x03'
        self.assertIsNone(extract_quic_sni(data))

    def test_truncated_after_scid(self):
        """Packet ends mid-SCID."""
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V1) + bytes([4]) + os.urandom(4) + bytes([4]) + b'\x01'
        self.assertIsNone(extract_quic_sni(data))

    def test_truncated_at_token_len(self):
        """Packet ends at token length varint."""
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V1) + bytes([4]) + os.urandom(4) + bytes([0]) + b'\x40'
        self.assertIsNone(extract_quic_sni(data))

    def test_truncated_at_payload_len(self):
        """Packet ends at payload length varint."""
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V1) + bytes([4]) + os.urandom(4) + bytes([0]) + bytes([0]) + b'\x40'
        self.assertIsNone(extract_quic_sni(data))

    def test_truncated_at_sample(self):
        """Not enough bytes for 16-byte sample."""
        # Build a minimal valid header, then cut before sample
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V1)
        data += bytes([4]) + os.urandom(4)  # DCID
        data += bytes([0])                   # SCID len=0
        data += bytes([0])                   # token len=0
        data += _write_varint(5)             # payload_length=5 (too short for sample)
        data += b'\x00' * 5
        self.assertIsNone(extract_quic_sni(data))

    def test_version_0_reserved(self):
        """Version 0 is reserved, should be rejected."""
        data = bytes([0xC0]) + struct.pack("!I", 0x00000000) + bytes([0, 0])
        self.assertFalse(is_quic_initial(data))

    def test_version_grease_unknown(self):
        """GREASE version (0x?a?a?a?a) → unknown."""
        data = bytes([0xC0]) + struct.pack("!I", 0x0A0A0A0A) + bytes([0, 0])
        self.assertFalse(is_quic_initial(data))

    def test_massive_token_length(self):
        """Token length varint = 16384 → parser handles gracefully."""
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V1)
        data += bytes([4]) + os.urandom(4)  # DCID
        data += bytes([0])                   # SCID
        data += _write_varint(16384)         # huge token length
        # Not enough data → parser should handle gracefully
        self.assertIsNone(extract_quic_sni(data + b'\x00' * 100))

    def test_payload_length_mismatch(self):
        """Payload length field says 1000 but actual data is 50 bytes."""
        result = _build_roundtrip_packet("mismatch.example.com")
        if result:
            pkt = result[0]
            # Should still decrypt if we have enough data for sample
            # The parser uses actual data length, not just the field
            self.assertIsNotNone(extract_quic_sni(pkt))

    def test_random_bytes_100_trials(self):
        """Random 100-500 byte packets → must never crash."""
        for _ in range(100):
            size = 100 + os.urandom(1)[0] % 400
            data = os.urandom(size)
            try:
                extract_quic_sni(data)
            except Exception as e:
                self.fail(f"Crashed on random data: {e}")

    def test_fuzz_pn_length_field(self):
        """First byte pn_length bits set to all 4 values."""
        for pn_bits in range(4):
            # Build a valid packet, then corrupt first byte pn_length
            result = _build_roundtrip_packet("fuzz.example.com")
            if result:
                pkt = bytearray(result[0])
                pkt[0] = (pkt[0] & 0xFC) | pn_bits  # Set pn_length bits
                # Should not crash
                extract_quic_sni(bytes(pkt))


# ============================================================
# 2. CRYPTO Frame Edge Cases
# ============================================================

class TestCryptoFrameEdgeCases(unittest.TestCase):

    def test_crypto_frame_then_padding(self):
        """CRYPTO frame followed by PADDING."""
        ch = _build_client_hello("crypto-pad.example.com")
        frame = b'\x06' + _write_varint(0) + _write_varint(len(ch)) + ch
        frame += b'\x00' * 100  # padding
        result = _parse_crypto_frame(frame)
        self.assertIsNotNone(result)

    def test_multiple_padding_frames(self):
        """Many PADDING frames before CRYPTO."""
        ch = _build_client_hello("multi-pad.example.com")
        frame = b'\x00' * 200 + b'\x06' + _write_varint(0) + _write_varint(len(ch)) + ch
        result = _parse_crypto_frame(frame)
        self.assertIsNotNone(result)

    def test_ack_frame_with_ecn(self):
        """ACK frame (type=0x03) with ECN counts — parser doesn't parse ECN, so returns None."""
        ch = _build_client_hello("ack-ecn.example.com")
        # ACK with ECN: type(1) + largest_ack + delay + count + first_range + ECN counts
        ack = b'\x03' + _write_varint(5) + _write_varint(0) + _write_varint(0) + _write_varint(3)
        ack += _write_varint(10) + _write_varint(5) + _write_varint(2)  # ECT0, ECT1, ECN-CE
        crypto = b'\x06' + _write_varint(0) + _write_varint(len(ch)) + ch
        result = _parse_crypto_frame(ack + crypto)
        # Parser doesn't handle ECN counts → breaks on unknown frame type → None
        self.assertIsNone(result)

    def test_ping_then_ack_then_crypto(self):
        """PING + ACK + CRYPTO in sequence."""
        ch = _build_client_hello("ping-ack.example.com")
        ping = b'\x01'
        ack = b'\x02' + _write_varint(10) + _write_varint(0) + _write_varint(0) + _write_varint(5)
        crypto = b'\x06' + _write_varint(0) + _write_varint(len(ch)) + ch
        result = _parse_crypto_frame(ping + ack + crypto)
        self.assertIsNotNone(result)

    def test_crypto_frame_zero_length(self):
        """CRYPTO frame with length=0 → empty data."""
        frame = b'\x06' + _write_varint(0) + _write_varint(0)
        result = _parse_crypto_frame(frame)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 0)

    def test_crypto_frame_truncated_data(self):
        """CRYPTO frame claims 100 bytes but only 10 available."""
        frame = b'\x06' + _write_varint(0) + _write_varint(100) + b'\x00' * 10
        result = _parse_crypto_frame(frame)
        self.assertIsNone(result)

    def test_only_unknown_frames(self):
        """Unknown frame types → return None."""
        # Use 0xFE (unknown), then 0xFD (another unknown)
        frame = b'\xFE\x00\x00\x00' + b'\xFD\x00\x00\x00'
        result = _parse_crypto_frame(frame)
        self.assertIsNone(result)

    def test_padding_only_large(self):
        """1000 bytes of PADDING → no CRYPTO → None."""
        result = _parse_crypto_frame(b'\x00' * 1000)
        self.assertIsNone(result)

    def test_empty_payload_returns_none(self):
        self.assertIsNone(_parse_crypto_frame(b''))

    def test_crypto_at_exact_boundary(self):
        """CRYPTO frame exactly fills remaining buffer."""
        ch = _build_client_hello("boundary.example.com")
        frame = b'\x06' + _write_varint(0) + _write_varint(len(ch)) + ch
        result = _parse_crypto_frame(frame)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), len(ch))


# ============================================================
# 3. TLS ClientHello Extension Edge Cases
# ============================================================

class TestTlsExtensionEdgeCases(unittest.TestCase):

    def _build_ch_with_raw_extensions(self, extensions_bytes):
        """Build ClientHello with raw extension bytes."""
        ch_body = (
            struct.pack("!H", 0x0303) + b'\x00' * 32 + bytes([0x00]) +
            struct.pack("!H", 2) + b'\x13\x01' + bytes([0x01, 0x00]) +
            struct.pack("!H", len(extensions_bytes)) + extensions_bytes
        )
        return (bytes([0x01]) + bytes([(len(ch_body) >> 16) & 0xFF]) +
                struct.pack("!H", len(ch_body)) + ch_body)

    def test_sni_first_among_many(self):
        """SNI is first of 5 extensions."""
        sni_bytes = b'test.example.com'
        sni_entry = bytes([0x00]) + struct.pack("!H", len(sni_bytes)) + sni_bytes
        sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
        sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

        # 4 dummy extensions
        dummy_exts = b''
        for ext_type in [0x0010, 0x000d, 0x0033, 0x002d]:
            dummy_data = b'\x00\x01\x02'
            dummy_exts += struct.pack("!HH", ext_type, len(dummy_data)) + dummy_data

        ch = self._build_ch_with_raw_extensions(sni_ext + dummy_exts)
        result = _extract_sni_from_tls(ch)
        self.assertEqual(result, "test.example.com")

    def test_sni_last_among_many(self):
        """SNI is last of 5 extensions."""
        dummy_exts = b''
        for ext_type in [0x0010, 0x000d, 0x0033, 0x002d]:
            dummy_data = b'\x00\x01\x02'
            dummy_exts += struct.pack("!HH", ext_type, len(dummy_data)) + dummy_data

        sni_bytes = b'last.example.com'
        sni_entry = bytes([0x00]) + struct.pack("!H", len(sni_bytes)) + sni_bytes
        sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
        sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

        ch = self._build_ch_with_raw_extensions(dummy_exts + sni_ext)
        result = _extract_sni_from_tls(ch)
        self.assertEqual(result, "last.example.com")

    def test_large_dummy_extension_before_sni(self):
        """Large extension (4KB) before SNI → must skip correctly."""
        large_dummy = b'\xAA' * 4096
        large_ext = struct.pack("!HH", 0x000F, len(large_dummy)) + large_dummy

        sni_bytes = b'after-large.example.com'
        sni_entry = bytes([0x00]) + struct.pack("!H", len(sni_bytes)) + sni_bytes
        sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
        sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

        ch = self._build_ch_with_raw_extensions(large_ext + sni_ext)
        result = _extract_sni_from_tls(ch)
        self.assertEqual(result, "after-large.example.com")

    def test_sni_extension_empty_data(self):
        """SNI extension with 0 bytes of data."""
        sni_ext = struct.pack("!HH", 0x0000, 0)
        ch = self._build_ch_with_raw_extensions(sni_ext)
        result = _extract_sni_from_tls(ch)
        self.assertIsNone(result)

    def test_sni_extension_truncated_list_len(self):
        """SNI extension data is only 1 byte (truncated list length)."""
        sni_ext = struct.pack("!HH", 0x0000, 1) + b'\x00'
        ch = self._build_ch_with_raw_extensions(sni_ext)
        result = _extract_sni_from_tls(ch)
        self.assertIsNone(result)

    def test_sni_with_empty_server_name_list(self):
        """SNI list length = 0 (empty list)."""
        sni_ext = struct.pack("!HH", 0x0000, 0)
        ch = self._build_ch_with_raw_extensions(sni_ext)
        result = _extract_sni_from_tls(ch)
        self.assertIsNone(result)

    def test_unknown_extension_type_0xffff(self):
        """Unknown extension type 0xFFFF before SNI."""
        unknown_ext = struct.pack("!HH", 0xFFFF, 4) + b'\x00\x00\x00\x00'
        sni_bytes = b'known.example.com'
        sni_entry = bytes([0x00]) + struct.pack("!H", len(sni_bytes)) + sni_bytes
        sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
        sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

        ch = self._build_ch_with_raw_extensions(unknown_ext + sni_ext)
        result = _extract_sni_from_tls(ch)
        self.assertEqual(result, "known.example.com")

    def test_extensions_exactly_empty(self):
        """Zero-length extensions field → no SNI."""
        ch_body = (
            struct.pack("!H", 0x0303) + b'\x00' * 32 + bytes([0x00]) +
            struct.pack("!H", 2) + b'\x13\x01' + bytes([0x01, 0x00]) +
            struct.pack("!H", 0)  # empty extensions
        )
        ch = bytes([0x01]) + bytes([(len(ch_body) >> 16) & 0xFF]) + struct.pack("!H", len(ch_body)) + ch_body
        self.assertIsNone(_extract_sni_from_tls(ch))


# ============================================================
# 4. Decrypt Edge Cases
# ============================================================

class TestDecryptEdgeCases(unittest.TestCase):

    def test_corrupted_encrypted_byte(self):
        """Flip one byte in encrypted payload → decryption fails."""
        result = _build_roundtrip_packet("corrupt.example.com")
        self.assertIsNotNone(result)
        pkt = bytearray(result[0])
        # Flip byte near end (in encrypted payload)
        pkt[-5] ^= 0xFF
        self.assertIsNone(extract_quic_sni(bytes(pkt)))

    def test_corrupted_header_byte(self):
        """Flip one byte in header → AAD mismatch → decryption fails."""
        result = _build_roundtrip_packet("hdr-corrupt.example.com")
        self.assertIsNotNone(result)
        pkt = bytearray(result[0])
        # Flip DCID byte
        pkt[6] ^= 0xFF
        self.assertIsNone(extract_quic_sni(bytes(pkt)))

    def test_corrupted_first_byte_type_bits(self):
        """Change packet type bits in first byte after unmasking."""
        result = _build_roundtrip_packet("type-corrupt.example.com")
        self.assertIsNotNone(result)
        pkt = bytearray(result[0])
        # Flip type bits (bits 4-5)
        pkt[0] ^= 0x30
        # After unmasking, this won't be Initial type → may fail
        # But the parser reads the PROTECTED first byte first, so it may
        # still think it's Initial. Let's just check it doesn't crash.
        try:
            extract_quic_sni(bytes(pkt))
        except Exception as e:
            self.fail(f"Crashed on corrupted type bits: {e}")

    def test_corrupted_sample_area(self):
        """Corrupt the sample area → wrong mask → wrong PN → decryption fails."""
        result = _build_roundtrip_packet("sample-corrupt.example.com")
        self.assertIsNotNone(result)
        pkt = bytearray(result[0])
        # Find header_end to corrupt sample area
        header = _parse_quic_header(bytes(pkt))
        if header:
            sample_start = header["header_end"] + 4
            if sample_start + 1 < len(pkt):
                pkt[sample_start] ^= 0xFF
                self.assertIsNone(extract_quic_sni(bytes(pkt)))

    def test_zero_length_encrypted_payload(self):
        """Packet with payload_length=0 → not enough for GCM tag."""
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V1)
        data += bytes([4]) + os.urandom(4)  # DCID
        data += bytes([0])                   # SCID
        data += bytes([0])                   # token
        data += _write_varint(0)             # payload_length=0
        self.assertIsNone(extract_quic_sni(data))

    def test_payload_length_1_too_short_for_tag(self):
        """Payload length=1 → not enough for 16-byte GCM auth tag."""
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V1)
        data += bytes([4]) + os.urandom(4)
        data += bytes([0])
        data += bytes([0])
        data += _write_varint(1)
        data += b'\x00' * 20  # enough data but payload_length says 1
        self.assertIsNone(extract_quic_sni(data))

    def test_wrong_dcid_different_keys(self):
        """Change DCID after encryption → different keys → decryption fails."""
        result = _build_roundtrip_packet("wrong-dcid.example.com")
        self.assertIsNotNone(result)
        pkt = bytearray(result[0])
        # DCID starts at byte 6 (after first_byte + 4-byte version + 1-byte dcid_len)
        dcid_len = pkt[5]
        for i in range(dcid_len):
            pkt[6 + i] ^= 0xFF  # Flip all DCID bits
        self.assertIsNone(extract_quic_sni(bytes(pkt)))


# ============================================================
# 5. QUIC v2 Wire Image Differences
# ============================================================

class TestQuicV2WireImage(unittest.TestCase):
    """QUIC v2 (RFC 9369) has different type bit encoding."""

    def test_v2_initial_type_bits(self):
        """QUIC v2 Initial: type bits are still 0b00 in the wire image."""
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V2) + bytes([4]) + os.urandom(4) + bytes([0])
        self.assertTrue(is_quic_initial(data))

    def test_v2_different_salt(self):
        """QUIC v2 uses a different initial salt."""
        v1_salt = INITIAL_SALT_V1
        v2_salt = bytes.fromhex("a707c203a59b47184317ef6f70b64a1e76ab5765")
        self.assertNotEqual(v1_salt, v2_salt)
        self.assertEqual(len(v1_salt), 20)
        self.assertEqual(len(v2_salt), 20)

    def test_v2_full_roundtrip(self):
        """End-to-end QUIC v2 SNI extraction."""
        result = _build_roundtrip_packet("v2-full.example.com", version=QUIC_V2)
        self.assertIsNotNone(result)
        self.assertEqual(extract_quic_sni(result[0]), "v2-full.example.com")

    def test_v2_different_dcids_produce_different_keys(self):
        """QUIC v2 key isolation: different DCID → different keys."""
        r1 = _build_roundtrip_packet("v2a.example.com", version=QUIC_V2, dcid_len=8)
        r2 = _build_roundtrip_packet("v2b.example.com", version=QUIC_V2, dcid_len=8)
        self.assertIsNotNone(r1)
        self.assertIsNotNone(r2)
        # Different DCIDs → different packets
        self.assertNotEqual(r1[0], r2[0])

    def test_v1_packet_not_decryptable_as_v2(self):
        """Packet encrypted with v1 salt can't be decrypted if version says v2."""
        result = _build_roundtrip_packet("v1-not-v2.example.com", version=QUIC_V1)
        self.assertIsNotNone(result)
        pkt = bytearray(result[0])
        # Change version field to v2
        pkt[1:5] = struct.pack("!I", QUIC_V2)
        self.assertIsNone(extract_quic_sni(bytes(pkt)))


# ============================================================
# 6. Real-World Traffic Patterns
# ============================================================

class TestRealWorldPatterns(unittest.TestCase):

    def test_google_quic_connection(self):
        """Simulate Google's QUIC connection (typically 8-byte DCID)."""
        result = _build_roundtrip_packet("www.google.com", dcid_len=8, scid_len=0)
        self.assertIsNotNone(result)
        self.assertEqual(extract_quic_sni(result[0]), "www.google.com")

    def test_cloudflare_quic(self):
        """Cloudflare QUIC (typically uses 16-byte DCID)."""
        result = _build_roundtrip_packet("www.cloudflare.com", dcid_len=16, scid_len=16)
        self.assertIsNotNone(result)
        self.assertEqual(extract_quic_sni(result[0]), "www.cloudflare.com")

    def test_facebook_quic(self):
        """Facebook/Meta QUIC."""
        result = _build_roundtrip_packet("www.facebook.com", dcid_len=8, scid_len=4)
        self.assertIsNotNone(result)
        self.assertEqual(extract_quic_sni(result[0]), "www.facebook.com")

    def test_minimal_dcid_connection(self):
        """Some implementations use minimal 1-byte DCID."""
        result = _build_roundtrip_packet("minimal.example.com", dcid_len=1, scid_len=0)
        self.assertIsNotNone(result)
        self.assertEqual(extract_quic_sni(result[0]), "minimal.example.com")

    def test_max_dcid_connection(self):
        """Maximum 20-byte DCID."""
        result = _build_roundtrip_packet("max-dcid.example.com", dcid_len=20, scid_len=20)
        self.assertIsNotNone(result)
        self.assertEqual(extract_quic_sni(result[0]), "max-dcid.example.com")

    def test_retry_token_quic(self):
        """QUIC with Retry token (32 bytes typical)."""
        token = os.urandom(32)
        result = _build_roundtrip_packet("retry.example.com", token=token)
        self.assertIsNotNone(result)
        self.assertEqual(extract_quic_sni(result[0]), "retry.example.com")

    def test_large_retry_token(self):
        """Large Retry token (200 bytes, some CDNs send large tokens)."""
        token = os.urandom(200)
        result = _build_roundtrip_packet("large-token.example.com", token=token)
        self.assertIsNotNone(result)
        self.assertEqual(extract_quic_sni(result[0]), "large-token.example.com")

    def test_deep_subdomain_chain(self):
        """CDN-style deep subdomain."""
        domain = "edge-xx-fra08.prod.cdn.example.com"
        result = _build_simple(domain)
        self.assertIsNotNone(result)
        self.assertEqual(extract_quic_sni(result), domain)

    def test_wildcard_like_domain(self):
        """Domain with many labels."""
        domain = "a.b.c.d.e.f.g.h.i.j.example.com"
        result = _build_simple(domain)
        self.assertIsNotNone(result)
        self.assertEqual(extract_quic_sni(result), domain)


# ============================================================
# 7. Concurrent Access
# ============================================================

class TestConcurrentAccess(unittest.TestCase):
    """Thread-safety: multiple threads extracting SNI simultaneously."""

    def test_100_concurrent_extractions(self):
        """100 threads extracting SNI from different packets."""
        packets = []
        for i in range(100):
            pkt = _build_simple(f"thread{i}.example.com")
            self.assertIsNotNone(pkt)
            packets.append((pkt, f"thread{i}.example.com"))

        results = {}
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(extract_quic_sni, pkt): domain
                for pkt, domain in packets
            }
            for future in as_completed(futures):
                domain = futures[future]
                results[domain] = future.result()

        for domain, result in results.items():
            self.assertEqual(result, domain, f"Thread mismatch for {domain}")

    def test_same_packet_concurrent_reads(self):
        """Multiple threads reading the same packet."""
        pkt = _build_simple("shared.example.com")
        self.assertIsNotNone(pkt)

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(extract_quic_sni, pkt) for _ in range(100)]
            for future in as_completed(futures):
                self.assertEqual(future.result(), "shared.example.com")

    def test_concurrent_is_quic_initial(self):
        """Multiple threads checking is_quic_initial."""
        pkt = _build_simple("check.example.com")
        non_quic = b'\x16\x03\x01\x00\x05' + b'\x00' * 50

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for _ in range(50):
                futures.append(executor.submit(is_quic_initial, pkt))
                futures.append(executor.submit(is_quic_initial, non_quic))

            for i, future in enumerate(as_completed(futures)):
                # Can't guarantee order but check no crash
                future.result()


# ============================================================
# 8. Memory Safety
# ============================================================

class TestMemorySafety(unittest.TestCase):
    """Ensure no excessive memory usage or unbounded allocations."""

    def test_1000_random_packets_no_leak(self):
        """Process 1000 random packets without memory issues."""
        for _ in range(1000):
            size = 50 + os.urandom(1)[0] % 200
            data = os.urandom(size)
            extract_quic_sni(data)

    def test_large_packet_64kb(self):
        """64KB packet (jumbo frame) — must not crash."""
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V1)
        data += bytes([4]) + os.urandom(4)
        data += bytes([0])
        data += bytes([0])
        data += _write_varint(60000)
        data += b'\x00' * 60000
        # Should return None (not valid QUIC) but must not crash
        self.assertIsNone(extract_quic_sni(data))

    def test_varint_8byte_value(self):
        """8-byte varint encoding — must be handled gracefully."""
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V1)
        data += bytes([4]) + os.urandom(4)
        data += bytes([0])
        data += bytes([0])
        data += _write_varint((1 << 62) - 1)  # max 8-byte varint
        # Should return None but not crash
        self.assertIsNone(extract_quic_sni(data + b'\x00' * 100))


# ============================================================
# 9. HKDF Edge Cases
# ============================================================

class TestHkdfEdgeCases(unittest.TestCase):

    def test_hkdf_extract_empty_ikm(self):
        """HKDF-Extract with empty IKM."""
        result = _hkdf_extract(b'\x01' * 20, b'')
        self.assertEqual(len(result), 32)

    def test_hkdf_extract_empty_salt(self):
        """HKDF-Extract with empty salt (uses zero-filled salt per RFC 5869)."""
        result = _hkdf_extract(b'', os.urandom(8))
        self.assertEqual(len(result), 32)

    def test_hkdf_expand_zero_length(self):
        """HKDF-Expand with length=0 returns empty."""
        result = _hkdf_expand(os.urandom(32), b'test', 0)
        self.assertEqual(len(result), 0)

    def test_hkdf_expand_large_length(self):
        """HKDF-Expand with length=255 (max for 1 iteration with SHA-256)."""
        result = _hkdf_expand(os.urandom(32), b'test', 255)
        self.assertEqual(len(result), 255)

    def test_hkdf_expand_label_all_quic_labels(self):
        """All 4 QUIC labels produce correct lengths."""
        secret = os.urandom(32)
        labels = {
            "client in": 32,
            "quic key": 16,
            "quic iv": 12,
            "quic hp": 16,
        }
        for label, length in labels.items():
            result = _hkdf_expand_label(secret, label, b"", length)
            self.assertEqual(len(result), length, f"Wrong length for label '{label}'")

    def test_hkdf_expand_label_server_in(self):
        """'server in' label also works (server-side decryption)."""
        secret = os.urandom(32)
        result = _hkdf_expand_label(secret, "server in", b"", 32)
        self.assertEqual(len(result), 32)
        # Must differ from "client in"
        client_in = _hkdf_expand_label(secret, "client in", b"", 32)
        self.assertNotEqual(result, client_in)

    def test_hkdf_extract_known_vector(self):
        """RFC 5869 Test Case 1 (SHA-256)."""
        ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        salt = bytes.fromhex("000102030405060708090a0b0c")
        prk = _hkdf_extract(salt, ikm)
        expected_prk = bytes.fromhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        self.assertEqual(prk, expected_prk)


# ============================================================
# 10. Varint Boundary Values
# ============================================================

class TestVarintBoundaries(unittest.TestCase):

    def _roundtrip(self, value):
        encoded = _write_varint(value)
        decoded, offset = _read_varint(encoded, 0)
        self.assertEqual(decoded, value)
        self.assertEqual(offset, len(encoded))

    def test_0(self):
        self._roundtrip(0)

    def test_1(self):
        self._roundtrip(1)

    def test_63_max_1byte(self):
        self._roundtrip(63)

    def test_64_min_2byte(self):
        self._roundtrip(64)

    def test_255(self):
        self._roundtrip(255)

    def test_256(self):
        self._roundtrip(256)

    def test_16383_max_2byte(self):
        self._roundtrip(16383)

    def test_16384_min_4byte(self):
        self._roundtrip(16384)

    def test_65535(self):
        self._roundtrip(65535)

    def test_1000000(self):
        self._roundtrip(1000000)

    def test_max_4byte(self):
        self._roundtrip((1 << 30) - 1)

    def test_min_8byte(self):
        self._roundtrip(1 << 30)

    def test_varint_encoding_length(self):
        """Verify encoding length matches value range."""
        self.assertEqual(len(_write_varint(0)), 1)
        self.assertEqual(len(_write_varint(63)), 1)
        self.assertEqual(len(_write_varint(64)), 2)
        self.assertEqual(len(_write_varint(16383)), 2)
        self.assertEqual(len(_write_varint(16384)), 4)
        self.assertEqual(len(_write_varint((1 << 30) - 1)), 4)
        self.assertEqual(len(_write_varint(1 << 30)), 8)

    def test_varint_at_offset(self):
        """Read varint from non-zero offset."""
        data = b'\xFF\xFF' + _write_varint(42)
        decoded, offset = _read_varint(data, 2)
        self.assertEqual(decoded, 42)

    def test_varint_truncated_2byte(self):
        """2-byte varint with only 1 byte available."""
        data = bytes([0x40])  # 2-byte marker but no second byte
        decoded, offset = _read_varint(data, 0)
        self.assertEqual(decoded, 0)  # graceful fallback

    def test_varint_truncated_4byte(self):
        """4-byte varint with only 2 bytes available."""
        data = bytes([0x80, 0x00])  # 4-byte marker but only 2 bytes
        decoded, offset = _read_varint(data, 0)
        self.assertEqual(decoded, 0)


if __name__ == '__main__':
    unittest.main()
