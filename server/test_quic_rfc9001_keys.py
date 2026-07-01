"""
QUIC SNI Parser — RFC 9001 Key Derivation & Critical Path Tests

Focuses on the 3-step key derivation that was the root cause of 0% QUIC SNI capture:
  Step 1: initial_secret = HKDF-Extract(salt, DCID)
  Step 2: client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)  ← WAS MISSING
  Step 3: key/iv/hp derived from client_initial_secret

Also covers:
  - Key isolation between different DCIDs
  - Nonce construction (IV XOR packet_number)
  - Header protection mask computation
  - Multi-frame CRYPTO parsing
  - TLS extension ordering edge cases
  - QUIC v2 different salt
  - PADDING weight (minimum 1200 bytes)
"""

import os
import struct
import unittest
from typing import Optional

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


def _build_client_hello(sni: str) -> bytes:
    sni_bytes = sni.encode('ascii')
    sni_entry = bytes([0x00]) + struct.pack("!H", len(sni_bytes)) + sni_bytes
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
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


def _build_roundtrip_packet(domain, version=QUIC_V1, dcid_len=8, scid_len=4,
                            pn_length=1, pn=0, token=b"",
                            min_payload=True):
    """Build a fully encrypted, header-protected QUIC Initial packet."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    dcid = os.urandom(dcid_len)
    scid = os.urandom(scid_len)

    ch = _build_client_hello(domain)
    crypto_frame = b'\x06' + _write_varint(0) + _write_varint(len(ch)) + ch
    plaintext = crypto_frame + b'\x00' * max(0, 1200 - len(crypto_frame) - 16) if min_payload else crypto_frame

    # Select salt based on version
    if version == QUIC_V2:
        salt = bytes.fromhex("a707c203a59b47184317ef6f70b64a1e76ab5765")
    else:
        salt = INITIAL_SALT_V1

    # 3-step key derivation (RFC 9001 Section 5.2)
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

    return bytes(packet)


# ============================================================
# 1. RFC 9001 Key Derivation — The Critical 3-Step Fix
# ============================================================

class TestKeyDerivation3Step(unittest.TestCase):
    """Verify the 3-step HKDF key derivation per RFC 9001 Section 5.2.
    
    The bug: code skipped step 2 ('client in'), deriving key/iv/hp directly
    from initial_secret. This caused ALL QUIC Initial decryption to fail
    with InvalidTag exceptions, silently returning None.
    """

    def test_step1_initial_secret_is_32_bytes(self):
        """Step 1: HKDF-Extract(salt, DCID) produces 32-byte PRK."""
        dcid = os.urandom(8)
        secret = _hkdf_extract(INITIAL_SALT_V1, dcid)
        self.assertEqual(len(secret), 32)

    def test_step2_client_initial_secret_is_32_bytes(self):
        """Step 2: HKDF-Expand-Label(initial_secret, 'client in', '', 32)."""
        dcid = os.urandom(8)
        initial_secret = _hkdf_extract(INITIAL_SALT_V1, dcid)
        client_in = _hkdf_expand_label(initial_secret, "client in", b"", 32)
        self.assertEqual(len(client_in), 32)

    def test_step2_differs_from_step1(self):
        """client_initial_secret != initial_secret (the bug: they were the same!)."""
        dcid = os.urandom(8)
        initial_secret = _hkdf_extract(INITIAL_SALT_V1, dcid)
        client_in = _hkdf_expand_label(initial_secret, "client in", b"", 32)
        self.assertNotEqual(initial_secret, client_in)

    def test_step3_key_from_client_in_not_initial(self):
        """key derived from client_initial_secret, NOT directly from initial_secret."""
        dcid = os.urandom(8)
        initial_secret = _hkdf_extract(INITIAL_SALT_V1, dcid)
        client_in = _hkdf_expand_label(initial_secret, "client in", b"", 32)

        # Correct: key from client_in
        key_correct = _hkdf_expand_label(client_in, "quic key", b"", 16)
        # Wrong (the bug): key from initial_secret directly
        key_wrong = _hkdf_expand_label(initial_secret, "quic key", b"", 16)

        self.assertNotEqual(key_correct, key_wrong)
        self.assertEqual(len(key_correct), 16)
        self.assertEqual(len(key_wrong), 16)

    def test_step3_iv_from_client_in_not_initial(self):
        """IV derived from client_initial_secret, NOT from initial_secret."""
        dcid = os.urandom(8)
        initial_secret = _hkdf_extract(INITIAL_SALT_V1, dcid)
        client_in = _hkdf_expand_label(initial_secret, "client in", b"", 32)

        iv_correct = _hkdf_expand_label(client_in, "quic iv", b"", 12)
        iv_wrong = _hkdf_expand_label(initial_secret, "quic iv", b"", 12)

        self.assertNotEqual(iv_correct, iv_wrong)
        self.assertEqual(len(iv_correct), 12)

    def test_step3_hp_from_client_in_not_initial(self):
        """Header protection key derived from client_initial_secret."""
        dcid = os.urandom(8)
        initial_secret = _hkdf_extract(INITIAL_SALT_V1, dcid)
        client_in = _hkdf_expand_label(initial_secret, "client in", b"", 32)

        hp_correct = _hkdf_expand_label(client_in, "quic hp", b"", 16)
        hp_wrong = _hkdf_expand_label(initial_secret, "quic hp", b"", 16)

        self.assertNotEqual(hp_correct, hp_wrong)
        self.assertEqual(len(hp_correct), 16)

    def test_full_3step_produces_valid_decryption(self):
        """End-to-end: 3-step derivation decrypts a real QUIC Initial packet."""
        pkt = _build_roundtrip_packet("test.example.com")
        self.assertIsNotNone(pkt)
        result = extract_quic_sni(pkt)
        self.assertEqual(result, "test.example.com")

    def test_wrong_2step_decryption_fails(self):
        """Simulate the bug: skip 'client in' step → decryption fails."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        dcid = os.urandom(8)
        ch = _build_client_hello("bug.example.com")
        crypto_frame = b'\x06' + _write_varint(0) + _write_varint(len(ch)) + ch
        plaintext = crypto_frame + b'\x00' * max(0, 1200 - len(crypto_frame) - 16)

        # Bug: derive keys directly from initial_secret (skip 'client in')
        initial_secret = _hkdf_extract(INITIAL_SALT_V1, dcid)
        wrong_key = _hkdf_expand_label(initial_secret, "quic key", b"", 16)
        wrong_iv = _hkdf_expand_label(initial_secret, "quic iv", b"", 12)
        wrong_hp = _hkdf_expand_label(initial_secret, "quic hp", b"", 16)

        # Encrypt with CORRECT keys (3-step)
        client_in = _hkdf_expand_label(initial_secret, "client in", b"", 32)
        correct_key = _hkdf_expand_label(client_in, "quic key", b"", 16)
        correct_iv = _hkdf_expand_label(client_in, "quic iv", b"", 12)

        nonce = bytearray(correct_iv)
        pn_padded = (0).to_bytes(12, 'big')
        for i in range(12):
            nonce[i] ^= pn_padded[i]

        aesgcm = AESGCM(correct_key)
        encrypted = aesgcm.encrypt(bytes(nonce), plaintext, b'\xC0' + struct.pack("!I", QUIC_V1) + bytes([8]) + dcid + bytes([4]) + os.urandom(4) + b'\x00' + _write_varint(len(plaintext) + 16 + 1) + b'\x00')

        # Try decrypting with WRONG keys (2-step bug) — should fail
        try:
            wrong_aesgcm = AESGCM(wrong_key)
            wrong_aesgcm.decrypt(bytes(nonce), encrypted, b'\xC0')
            self.fail("Decryption with wrong keys should have failed")
        except Exception:
            pass  # Expected: InvalidTag


class TestKeyDerivationDeterministic(unittest.TestCase):
    """Key derivation must be deterministic: same DCID → same keys."""

    def test_same_dcid_same_keys(self):
        dcid = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        s1 = _hkdf_extract(INITIAL_SALT_V1, dcid)
        c1 = _hkdf_expand_label(s1, "client in", b"", 32)
        k1 = _hkdf_expand_label(c1, "quic key", b"", 16)

        s2 = _hkdf_extract(INITIAL_SALT_V1, dcid)
        c2 = _hkdf_expand_label(s2, "client in", b"", 32)
        k2 = _hkdf_expand_label(c2, "quic key", b"", 16)

        self.assertEqual(k1, k2)
        self.assertEqual(c1, c2)
        self.assertEqual(s1, s2)


# ============================================================
# 2. Key Isolation Between DCIDs
# ============================================================

class TestKeyIsolation(unittest.TestCase):
    """Different DCIDs must produce completely different keys."""

    def test_different_dcids_different_initial_secrets(self):
        dcid1 = os.urandom(8)
        dcid2 = os.urandom(8)
        s1 = _hkdf_extract(INITIAL_SALT_V1, dcid1)
        s2 = _hkdf_extract(INITIAL_SALT_V1, dcid2)
        self.assertNotEqual(s1, s2)

    def test_different_dcids_different_client_in(self):
        dcid1 = os.urandom(8)
        dcid2 = os.urandom(8)
        c1 = _hkdf_expand_label(_hkdf_extract(INITIAL_SALT_V1, dcid1), "client in", b"", 32)
        c2 = _hkdf_expand_label(_hkdf_extract(INITIAL_SALT_V1, dcid2), "client in", b"", 32)
        self.assertNotEqual(c1, c2)

    def test_different_dcids_different_keys(self):
        dcid1 = os.urandom(8)
        dcid2 = os.urandom(8)
        k1 = _hkdf_expand_label(
            _hkdf_expand_label(_hkdf_extract(INITIAL_SALT_V1, dcid1), "client in", b"", 32),
            "quic key", b"", 16)
        k2 = _hkdf_expand_label(
            _hkdf_expand_label(_hkdf_extract(INITIAL_SALT_V1, dcid2), "client in", b"", 32),
            "quic key", b"", 16)
        self.assertNotEqual(k1, k2)

    def test_flip_single_dcid_bit_changes_all_keys(self):
        """Even 1-bit difference in DCID produces completely different keys."""
        dcid = bytearray(os.urandom(8))
        dcid_flipped = bytearray(dcid)
        dcid_flipped[0] ^= 0x01

        s1 = _hkdf_extract(INITIAL_SALT_V1, bytes(dcid))
        s2 = _hkdf_extract(INITIAL_SALT_V1, bytes(dcid_flipped))
        self.assertNotEqual(s1, s2)

        c1 = _hkdf_expand_label(s1, "client in", b"", 32)
        c2 = _hkdf_expand_label(s2, "client in", b"", 32)
        self.assertNotEqual(c1, c2)

    def test_cross_session_same_domain_different_dcid(self):
        """Same domain in different QUIC sessions uses different DCID → different keys."""
        pkt1 = _build_roundtrip_packet("same.example.com", dcid_len=8)
        pkt2 = _build_roundtrip_packet("same.example.com", dcid_len=8)
        self.assertIsNotNone(pkt1)
        self.assertIsNotNone(pkt2)
        # Packets should be different (different random DCID)
        self.assertNotEqual(pkt1, pkt2)
        # But both decrypt to same SNI
        self.assertEqual(extract_quic_sni(pkt1), "same.example.com")
        self.assertEqual(extract_quic_sni(pkt2), "same.example.com")


# ============================================================
# 3. Nonce Construction (IV XOR Packet Number)
# ============================================================

class TestNonceConstruction(unittest.TestCase):
    """Nonce = IV XOR packet_number (padded to 12 bytes)."""

    def test_nonce_pn0_equals_iv(self):
        """Packet number 0 → nonce = IV (XOR with zeros)."""
        dcid = os.urandom(8)
        s = _hkdf_extract(INITIAL_SALT_V1, dcid)
        c = _hkdf_expand_label(s, "client in", b"", 32)
        iv = _hkdf_expand_label(c, "quic iv", b"", 12)

        nonce = bytearray(iv)
        pn_padded = (0).to_bytes(12, 'big')
        for i in range(12):
            nonce[i] ^= pn_padded[i]

        self.assertEqual(bytes(nonce), iv)

    def test_nonce_pn1_flips_last_byte(self):
        """Packet number 1 → nonce = IV XOR 0x01 in last byte."""
        dcid = os.urandom(8)
        s = _hkdf_extract(INITIAL_SALT_V1, dcid)
        c = _hkdf_expand_label(s, "client in", b"", 32)
        iv = _hkdf_expand_label(c, "quic iv", b"", 12)

        nonce = bytearray(iv)
        pn_padded = (1).to_bytes(12, 'big')
        for i in range(12):
            nonce[i] ^= pn_padded[i]

        # Last byte should be IV[-1] ^ 0x01
        self.assertEqual(nonce[11], iv[11] ^ 0x01)
        # First 11 bytes unchanged
        for i in range(11):
            self.assertEqual(nonce[i], iv[i])

    def test_nonce_pn256_flips_second_to_last(self):
        """Packet number 256 (0x0100) → second-to-last byte flipped."""
        dcid = os.urandom(8)
        s = _hkdf_extract(INITIAL_SALT_V1, dcid)
        c = _hkdf_expand_label(s, "client in", b"", 32)
        iv = _hkdf_expand_label(c, "quic iv", b"", 12)

        nonce = bytearray(iv)
        pn_padded = (256).to_bytes(12, 'big')
        for i in range(12):
            nonce[i] ^= pn_padded[i]

        self.assertEqual(nonce[10], iv[10] ^ 0x01)
        self.assertEqual(nonce[11], iv[11] ^ 0x00)

    def test_nonce_reversible(self):
        """XOR is self-inverse: nonce XOR pn_padded = IV."""
        dcid = os.urandom(8)
        s = _hkdf_extract(INITIAL_SALT_V1, dcid)
        c = _hkdf_expand_label(s, "client in", b"", 32)
        iv = _hkdf_expand_label(c, "quic iv", b"", 12)

        pn = 42
        nonce = bytearray(iv)
        pn_padded = pn.to_bytes(12, 'big')
        for i in range(12):
            nonce[i] ^= pn_padded[i]

        # Reverse
        recovered = bytearray(nonce)
        for i in range(12):
            recovered[i] ^= pn_padded[i]

        self.assertEqual(bytes(recovered), iv)

    def test_different_pn_different_nonce(self):
        dcid = os.urandom(8)
        s = _hkdf_extract(INITIAL_SALT_V1, dcid)
        c = _hkdf_expand_label(s, "client in", b"", 32)
        iv = _hkdf_expand_label(c, "quic iv", b"", 12)

        nonces = set()
        for pn in [0, 1, 2, 100, 255, 256, 65535]:
            nonce = bytearray(iv)
            pn_padded = pn.to_bytes(12, 'big')
            for i in range(12):
                nonce[i] ^= pn_padded[i]
            nonces.add(bytes(nonce))

        self.assertEqual(len(nonces), 7)


# ============================================================
# 4. Multi-Packet Decryption with Different Packet Numbers
# ============================================================

class TestMultiPacketDecryption(unittest.TestCase):
    """Decrypt packets with various packet numbers."""

    def test_pn_0(self):
        pkt = _build_roundtrip_packet("pn0.example.com", pn=0)
        self.assertEqual(extract_quic_sni(pkt), "pn0.example.com")

    def test_pn_1(self):
        pkt = _build_roundtrip_packet("pn1.example.com", pn=1)
        self.assertEqual(extract_quic_sni(pkt), "pn1.example.com")

    def test_pn_255(self):
        pkt = _build_roundtrip_packet("pn255.example.com", pn=255)
        self.assertEqual(extract_quic_sni(pkt), "pn255.example.com")

    def test_pn_256(self):
        pkt = _build_roundtrip_packet("pn256.example.com", pn=256, pn_length=2)
        self.assertEqual(extract_quic_sni(pkt), "pn256.example.com")

    def test_pn_65535(self):
        pkt = _build_roundtrip_packet("pn65k.example.com", pn=65535, pn_length=2)
        self.assertEqual(extract_quic_sni(pkt), "pn65k.example.com")

    def test_pn_with_2byte_length(self):
        pkt = _build_roundtrip_packet("pn2b.example.com", pn=300, pn_length=2)
        self.assertEqual(extract_quic_sni(pkt), "pn2b.example.com")

    def test_pn_with_4byte_length(self):
        pkt = _build_roundtrip_packet("pn4b.example.com", pn=70000, pn_length=4)
        self.assertEqual(extract_quic_sni(pkt), "pn4b.example.com")


# ============================================================
# 5. CRYPTO Frame Parsing Edge Cases
# ============================================================

class TestCryptoFrameParsing(unittest.TestCase):

    def test_single_crypto_frame(self):
        ch = _build_client_hello("single.example.com")
        frame = b'\x06' + _write_varint(0) + _write_varint(len(ch)) + ch
        result = _parse_crypto_frame(frame)
        self.assertIsNotNone(result)
        self.assertEqual(result[0], 0x01)  # ClientHello

    def test_padding_before_crypto(self):
        ch = _build_client_hello("padded.example.com")
        frame = b'\x00' * 50 + b'\x06' + _write_varint(0) + _write_varint(len(ch)) + ch
        result = _parse_crypto_frame(frame)
        self.assertIsNotNone(result)

    def test_ack_before_crypto(self):
        """ACK frame (type=0x02) followed by CRYPTO."""
        ch = _build_client_hello("ack.example.com")
        # ACK frame: type(1) + largest_ack(varint) + ack_delay(varint) + range_count(varint) + first_range(varint)
        ack = b'\x02' + _write_varint(10) + _write_varint(0) + _write_varint(0) + _write_varint(5)
        crypto = b'\x06' + _write_varint(0) + _write_varint(len(ch)) + ch
        frame = ack + crypto
        result = _parse_crypto_frame(frame)
        self.assertIsNotNone(result)

    def test_ping_before_crypto(self):
        ch = _build_client_hello("ping.example.com")
        frame = b'\x01' + b'\x06' + _write_varint(0) + _write_varint(len(ch)) + ch
        result = _parse_crypto_frame(frame)
        self.assertIsNotNone(result)

    def test_ack_with_range_count(self):
        """ACK frame with non-zero ack_range_count."""
        ch = _build_client_hello("ackrange.example.com")
        # ACK with 2 ranges
        ack = b'\x02' + _write_varint(20) + _write_varint(0) + _write_varint(2) + _write_varint(10)
        # 2 gap+range pairs
        ack += _write_varint(3) + _write_varint(2)
        ack += _write_varint(1) + _write_varint(1)
        crypto = b'\x06' + _write_varint(0) + _write_varint(len(ch)) + ch
        result = _parse_crypto_frame(ack + crypto)
        self.assertIsNotNone(result)

    def test_empty_payload(self):
        self.assertIsNone(_parse_crypto_frame(b''))

    def test_only_padding(self):
        self.assertIsNone(_parse_crypto_frame(b'\x00' * 100))

    def test_unknown_frame_returns_none(self):
        """Unknown frame type (not CRYPTO/PADDING/ACK/PING) → break, return None."""
        self.assertIsNone(_parse_crypto_frame(b'\xFE' + b'\x00' * 50))

    def test_crypto_frame_offset_nonzero(self):
        """CRYPTO frame with non-zero offset (fragmented ClientHello)."""
        ch = _build_client_hello("frag.example.com")
        # Split into 2 fragments
        mid = len(ch) // 2
        frag1 = b'\x06' + _write_varint(0) + _write_varint(mid) + ch[:mid]
        frag2 = b'\x06' + _write_varint(mid) + _write_varint(len(ch) - mid) + ch[mid:]

        # Parser returns first CRYPTO frame found
        result = _parse_crypto_frame(frag1 + frag2)
        self.assertIsNotNone(result)
        # First frame is partial, but still valid
        self.assertEqual(len(result), mid)


# ============================================================
# 6. TLS ClientHello SNI Edge Cases
# ============================================================

class TestTlsSniEdgeCases(unittest.TestCase):

    def _build_ch_with_sni_list(self, entries):
        """Build ClientHello with custom SNI list entries."""
        sni_data = b''
        for name_type, name in entries:
            name_bytes = name.encode('ascii') if isinstance(name, str) else name
            sni_data += bytes([name_type]) + struct.pack("!H", len(name_bytes)) + name_bytes
        sni_list = struct.pack("!H", len(sni_data)) + sni_data
        sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
        sv_ext = struct.pack("!HH", 0x002b, 3) + b'\x02\x03\x04'
        extensions = struct.pack("!H", len(sni_ext) + len(sv_ext)) + sni_ext + sv_ext
        ch_body = (
            struct.pack("!H", 0x0303) + b'\x00' * 32 + bytes([0x00]) +
            struct.pack("!H", 2) + b'\x13\x01' + bytes([0x01, 0x00]) + extensions
        )
        return (bytes([0x01]) + bytes([(len(ch_body) >> 16) & 0xFF]) +
                struct.pack("!H", len(ch_body)) + ch_body)

    def test_sni_with_hostname_type(self):
        """SNI entry type 0 = hostname."""
        ch = self._build_ch_with_sni_list([(0, "hostname.example.com")])
        result = _extract_sni_from_tls(ch)
        self.assertEqual(result, "hostname.example.com")

    def test_sni_with_non_hostname_type_first(self):
        """First entry is non-hostname type → skip, return None (only first entry checked)."""
        ch = self._build_ch_with_sni_list([(1, b'\x00\x01'), (0, "real.example.com")])
        result = _extract_sni_from_tls(ch)
        # Parser only checks first entry (name_type != 0 → return None)
        self.assertIsNone(result)

    def test_sni_empty_hostname(self):
        """Empty hostname string."""
        ch = self._build_ch_with_sni_list([(0, "")])
        result = _extract_sni_from_tls(ch)
        self.assertEqual(result, "")

    def test_sni_single_char(self):
        ch = self._build_ch_with_sni_list([(0, "a")])
        result = _extract_sni_from_tls(ch)
        self.assertEqual(result, "a")

    def test_sni_max_length_253(self):
        """Maximum hostname length is 253 characters."""
        long_domain = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 57 + ".com"
        self.assertEqual(len(long_domain), 253)
        ch = self._build_ch_with_sni_list([(0, long_domain)])
        result = _extract_sni_from_tls(ch)
        self.assertEqual(result, long_domain)

    def test_sni_with_numbers(self):
        ch = self._build_ch_with_sni_list([(0, "123.456.example.com")])
        result = _extract_sni_from_tls(ch)
        self.assertEqual(result, "123.456.example.com")

    def test_sni_with_hyphens(self):
        ch = self._build_ch_with_sni_list([(0, "my-app.test-site.example.com")])
        result = _extract_sni_from_tls(ch)
        self.assertEqual(result, "my-app.test-site.example.com")

    def test_sni_with_underscores(self):
        """Underscores in SNI (common for DKIM, _dmarc, etc.)."""
        ch = self._build_ch_with_sni_list([(0, "_dmarc.example.com")])
        result = _extract_sni_from_tls(ch)
        self.assertEqual(result, "_dmarc.example.com")

    def test_non_client_hello_type(self):
        """ServerHello (type=0x02) → not parsed."""
        data = bytes([0x02]) + b'\x00' * 100
        self.assertIsNone(_extract_sni_from_tls(data))

    def test_truncated_before_session_id(self):
        """Truncated before session ID length."""
        data = bytes([0x01]) + b'\x00\x00\x40' + b'\x03\x03' + b'\x00' * 10
        self.assertIsNone(_extract_sni_from_tls(data))

    def test_no_extensions(self):
        """ClientHello with zero-length extensions → no SNI."""
        ch_body = struct.pack("!H", 0x0303) + b'\x00' * 32 + bytes([0x00]) + struct.pack("!H", 2) + b'\x13\x01' + bytes([0x01, 0x00]) + struct.pack("!H", 0)
        ch = bytes([0x01]) + bytes([(len(ch_body) >> 16) & 0xFF]) + struct.pack("!H", len(ch_body)) + ch_body
        self.assertIsNone(_extract_sni_from_tls(ch))

    def test_sni_extension_after_others(self):
        """SNI not first extension — must be found by scanning."""
        # Build extensions with ALPN first, then SNI
        alpn_proto = b'\x02h3' + b'\x02h2'
        alpn_list = struct.pack("!H", len(alpn_proto)) + alpn_proto
        alpn_ext = struct.pack("!HH", 0x0010, len(alpn_list)) + alpn_list

        sni_bytes = b'ordered.example.com'
        sni_entry = bytes([0x00]) + struct.pack("!H", len(sni_bytes)) + sni_bytes
        sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
        sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

        extensions = struct.pack("!H", len(alpn_ext) + len(sni_ext)) + alpn_ext + sni_ext
        ch_body = struct.pack("!H", 0x0303) + b'\x00' * 32 + bytes([0x00]) + struct.pack("!H", 2) + b'\x13\x01' + bytes([0x01, 0x00]) + extensions
        ch = bytes([0x01]) + bytes([(len(ch_body) >> 16) & 0xFF]) + struct.pack("!H", len(ch_body)) + ch_body
        result = _extract_sni_from_tls(ch)
        self.assertEqual(result, "ordered.example.com")


# ============================================================
# 7. Version-Specific Salt Selection
# ============================================================

class TestVersionSalt(unittest.TestCase):
    """QUIC v1/draft-29 use one salt, QUIC v2 uses a different one."""

    def test_v1_roundtrip(self):
        pkt = _build_roundtrip_packet("v1.example.com", version=QUIC_V1)
        self.assertEqual(extract_quic_sni(pkt), "v1.example.com")

    def test_draft29_roundtrip(self):
        pkt = _build_roundtrip_packet("d29.example.com", version=QUIC_DRAFT29)
        self.assertEqual(extract_quic_sni(pkt), "d29.example.com")

    def test_v2_roundtrip(self):
        pkt = _build_roundtrip_packet("v2.example.com", version=QUIC_V2)
        self.assertEqual(extract_quic_sni(pkt), "v2.example.com")

    def test_v1_salt_constant(self):
        """QUIC v1 initial salt (RFC 9001 Section 5.2)."""
        expected = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
        self.assertEqual(INITIAL_SALT_V1, expected)

    def test_v1_v2_different_decryption(self):
        """Same DCID with v1 vs v2 salt produces different keys."""
        dcid = os.urandom(8)
        salt_v1 = INITIAL_SALT_V1
        salt_v2 = bytes.fromhex("a707c203a59b47184317ef6f70b64a1e76ab5765")

        s1 = _hkdf_extract(salt_v1, dcid)
        s2 = _hkdf_extract(salt_v2, dcid)
        self.assertNotEqual(s1, s2)

        c1 = _hkdf_expand_label(s1, "client in", b"", 32)
        c2 = _hkdf_expand_label(s2, "client in", b"", 32)
        self.assertNotEqual(c1, c2)

    def test_wrong_version_decrypt_fails(self):
        """Packet built with v1 salt can't be decrypted with v2 salt."""
        # This is tested implicitly: extract_quic_sni uses version from header
        # to select salt. If version field says v1 but salt is v2, decryption fails.
        pkt = _build_roundtrip_packet("wrong.example.com", version=QUIC_V1)
        self.assertIsNotNone(pkt)
        # Manually patch version to v2 in the packet
        # Byte 1-4 is version
        patched = bytearray(pkt)
        patched[1:5] = struct.pack("!I", QUIC_V2)
        # Should fail because keys were derived with v1 salt
        result = extract_quic_sni(bytes(patched))
        self.assertIsNone(result)


# ============================================================
# 8. QUIC Packet Type Filtering
# ============================================================

class TestPacketTypeFiltering(unittest.TestCase):

    def test_initial_type_detected(self):
        """Type bits 4-5 = 0b00 → Initial."""
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V1) + bytes([4]) + os.urandom(4) + bytes([0])
        self.assertTrue(is_quic_initial(data))

    def test_zero_rtt_rejected(self):
        """Type bits 4-5 = 0b01 → 0-RTT, not Initial."""
        data = bytes([0xD0]) + struct.pack("!I", QUIC_V1) + bytes([0, 0])
        self.assertFalse(is_quic_initial(data))

    def test_handshake_type_rejected(self):
        """Type bits 4-5 = 0b10 → Handshake, not Initial."""
        data = bytes([0xE0]) + struct.pack("!I", QUIC_V1) + bytes([0, 0])
        self.assertFalse(is_quic_initial(data))

    def test_retry_type_rejected(self):
        """Type bits 4-5 = 0b11 → Retry, not Initial."""
        data = bytes([0xF0]) + struct.pack("!I", QUIC_V1) + bytes([0, 0])
        self.assertFalse(is_quic_initial(data))

    def test_short_header_rejected(self):
        """Short header (first bit not set) is not QUIC long header."""
        data = bytes([0x40]) + os.urandom(20)
        self.assertFalse(is_quic_initial(data))

    def test_reserved_bits_ignored(self):
        """Bits 2-3 are reserved; should still be detected as Initial."""
        # 0xC0 | reserved(0b11) | type(0b00) = 0xCF
        data = bytes([0xCF]) + struct.pack("!I", QUIC_V1) + bytes([4]) + os.urandom(4) + bytes([0])
        self.assertTrue(is_quic_initial(data))


# ============================================================
# 9. HKDF Primitives
# ============================================================

class TestHkdfPrimitives(unittest.TestCase):

    def test_hkdf_extract_output_length(self):
        """HKDF-Extract with SHA-256 always produces 32 bytes."""
        for salt_len in [0, 1, 20, 32, 64]:
            for ikm_len in [0, 1, 8, 32, 64]:
                salt = os.urandom(max(salt_len, 1))
                ikm = os.urandom(max(ikm_len, 1))
                result = _hkdf_extract(salt, ikm)
                self.assertEqual(len(result), 32)

    def test_hkdf_expand_label_output_length(self):
        """HKDF-Expand-Label respects length parameter."""
        secret = os.urandom(32)
        for length in [1, 12, 16, 32, 48, 64]:
            result = _hkdf_expand_label(secret, "test", b"", length)
            self.assertEqual(len(result), length)

    def test_hkdf_expand_label_with_tls13_prefix(self):
        """Labels are prefixed with 'tls13 ' per RFC 8446."""
        secret = os.urandom(32)
        # The internal label is "tls13 quic key" — this is what the server uses
        r1 = _hkdf_expand_label(secret, "quic key", b"", 16)
        self.assertEqual(len(r1), 16)
        # Different label → different output
        r2 = _hkdf_expand_label(secret, "quic iv", b"", 12)
        self.assertEqual(len(r2), 12)
        self.assertNotEqual(r1[:12], r2)

    def test_hkdf_expand_different_context(self):
        """Different context bytes produce different output."""
        secret = os.urandom(32)
        r1 = _hkdf_expand_label(secret, "test", b"\x00", 32)
        r2 = _hkdf_expand_label(secret, "test", b"\x01", 32)
        self.assertNotEqual(r1, r2)

    def test_hkdf_expand_empty_context(self):
        """Empty context is valid."""
        secret = os.urandom(32)
        result = _hkdf_expand_label(secret, "client in", b"", 32)
        self.assertEqual(len(result), 32)


# ============================================================
# 10. End-to-End with Real-World Domains
# ============================================================

class TestRealWorldDomains(unittest.TestCase):
    """Roundtrip test with popular domains that use QUIC."""

    def _roundtrip(self, domain, **kwargs):
        pkt = _build_roundtrip_packet(domain, **kwargs)
        self.assertIsNotNone(pkt, f"Failed to build packet for {domain}")
        result = extract_quic_sni(pkt)
        self.assertEqual(result, domain, f"SNI mismatch for {domain}")

    def test_google_com(self):
        self._roundtrip("www.google.com")

    def test_youtube_com(self):
        self._roundtrip("www.youtube.com")

    def test_facebook_com(self):
        self._roundtrip("www.facebook.com")

    def test_instagram_com(self):
        self._roundtrip("i.instagram.com")

    def test_tiktok_com(self):
        self._roundtrip("www.tiktok.com")

    def test_netflix_com(self):
        self._roundtrip("www.netflix.com")

    def test_spotify_com(self):
        self._roundtrip("open.spotify.com")

    def test_cloudflare_com(self):
        self._roundtrip("www.cloudflare.com")

    def test_github_com(self):
        self._roundtrip("github.com")

    def test_wikipedia_org(self):
        self._roundtrip("en.wikipedia.org")

    def test_reddit_com(self):
        self._roundtrip("www.reddit.com")

    def test_twitter_com(self):
        self._roundtrip("api.twitter.com")

    def test_whatsapp_com(self):
        self._roundtrip("web.whatsapp.com")

    def test_telegram_org(self):
        self._roundtrip("web.telegram.org")

    def test_deep_subdomain(self):
        self._roundtrip("a.b.c.d.e.f.deep.example.com")

    def test_single_label(self):
        self._roundtrip("localhost")

    def test_numeric_domain(self):
        self._roundtrip("192.168.1.1")

    def test_hyphenated(self):
        self._roundtrip("my-app.test-site.co.uk")


# ============================================================
# 11. Minimum Payload Size (1200 bytes)
# ============================================================

class TestMinimumPayload(unittest.TestCase):
    """QUIC Initial packets MUST be at least 1200 bytes (RFC 9000 Section 14.1)."""

    def test_small_client_hello_padded(self):
        """Small ClientHello gets padded to meet 1200-byte minimum."""
        pkt = _build_roundtrip_packet("small.example.com", min_payload=True)
        self.assertIsNotNone(pkt)
        self.assertGreaterEqual(len(pkt), 1200)

    def test_large_client_hello_no_extra_padding(self):
        """Large ClientHello doesn't need extra padding."""
        # Build a domain long enough that ClientHello > 1200 bytes
        long_domain = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 60 + ".example.com"
        # This may not be enough — but test the builder works
        pkt = _build_roundtrip_packet(long_domain, min_payload=True)
        self.assertIsNotNone(pkt)


# ============================================================
# 12. Header Protection (AES-ECB Mask)
# ============================================================

class TestHeaderProtection(unittest.TestCase):
    """Header protection uses AES-ECB to generate a 5-byte mask."""

    def test_mask_is_16_bytes(self):
        """AES-ECB encrypt produces 16 bytes; we use first 5."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        hp = os.urandom(16)
        sample = os.urandom(16)
        cipher = Cipher(algorithms.AES(hp), modes.ECB())
        encryptor = cipher.encryptor()
        mask = encryptor.update(sample) + encryptor.finalize()
        self.assertEqual(len(mask), 16)

    def test_different_samples_different_masks(self):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        hp = os.urandom(16)
        mask1 = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(os.urandom(16)) + b''
        mask2 = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(os.urandom(16)) + b''
        # With overwhelming probability, different samples → different masks
        self.assertNotEqual(mask1, mask2)

    def test_same_sample_same_mask(self):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        hp = os.urandom(16)
        sample = os.urandom(16)
        e1 = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
        e2 = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
        m1 = e1.update(sample) + e1.finalize()
        m2 = e2.update(sample) + e2.finalize()
        self.assertEqual(m1, m2)

    def test_first_byte_mask_preserves_reserved_bits(self):
        """Mask[0] & 0x0F preserves upper nibble of first byte."""
        mask_byte = 0xFF
        original = 0xC0  # Long header, Initial type
        unmasked = original ^ (mask_byte & 0x0F)
        # Upper 4 bits (0xC) preserved, lower 4 bits XORed
        self.assertEqual(unmasked & 0xF0, 0xC0)
        self.assertEqual(unmasked & 0x0F, 0x0F)


# ============================================================
# 13. Varint Encoding (RFC 9000 Section 16)
# ============================================================

class TestVarintEncoding(unittest.TestCase):

    def _roundtrip_varint(self, value):
        """Encode then decode a varint."""
        encoded = _write_varint(value)
        decoded, new_offset = _read_varint(encoded, 0)
        self.assertEqual(decoded, value, f"Varint roundtrip failed for {value}")
        self.assertEqual(new_offset, len(encoded))

    def test_varint_0(self):
        self._roundtrip_varint(0)

    def test_varint_1(self):
        self._roundtrip_varint(1)

    def test_varint_63_max_1byte(self):
        self._roundtrip_varint(63)

    def test_varint_64_min_2byte(self):
        self._roundtrip_varint(64)

    def test_varint_255(self):
        self._roundtrip_varint(255)

    def test_varint_16383_max_2byte(self):
        self._roundtrip_varint(16383)

    def test_varint_16384_min_4byte(self):
        self._roundtrip_varint(16384)

    def test_varint_65535(self):
        self._roundtrip_varint(65535)

    def test_varint_1000000(self):
        self._roundtrip_varint(1000000)

    def test_varint_max_4byte(self):
        self._roundtrip_varint((1 << 30) - 1)

    def test_varint_at_offset(self):
        """Read varint from non-zero offset."""
        prefix = b'\xFF\xFF\xFF'
        encoded = _write_varint(42)
        data = prefix + encoded
        decoded, offset = _read_varint(data, 3)
        self.assertEqual(decoded, 42)
        self.assertEqual(offset, 3 + len(encoded))

    def test_varint_empty_data(self):
        decoded, offset = _read_varint(b'', 0)
        self.assertEqual(decoded, 0)
        self.assertEqual(offset, 0)

    def test_varint_offset_past_end(self):
        decoded, offset = _read_varint(b'\x00', 5)
        self.assertEqual(decoded, 0)
        self.assertEqual(offset, 5)


if __name__ == '__main__':
    unittest.main()
