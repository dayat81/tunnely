"""
Extended QUIC SNI extraction tests with real packet construction.

Tests the full pipeline by constructing QUIC Initial packets manually
with proper encryption, then verifying the parser can decrypt and extract SNI.
"""

import struct
import unittest
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from quic_sni import (
    extract_quic_sni, is_quic_initial,
    _parse_quic_header, _decrypt_initial, _parse_crypto_frame,
    _extract_sni_from_tls, _hkdf_extract, _hkdf_expand_label,
    _read_varint,
    QUIC_V1, QUIC_DRAFT29, QUIC_V2, INITIAL_SALT_V1,
)


# ============================================================
# Helper: Build properly encrypted QUIC Initial packet
# ============================================================

def _build_tls_client_hello(sni: str) -> bytes:
    """Build a minimal TLS 1.3 ClientHello with SNI."""
    sni_bytes = sni.encode('ascii')
    sni_entry = bytes([0x00]) + struct.pack("!H", len(sni_bytes)) + sni_bytes
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
    sv_ext = struct.pack("!HH", 0x002b, 3) + b'\x02\x03\x04'
    sg_ext = struct.pack("!HH", 0x000a, 4) + b'\x00\x02\x00\x1d'
    sa_ext = struct.pack("!HH", 0x000d, 4) + b'\x00\x02\x04\x03'
    extensions = struct.pack("!H", len(sni_ext) + len(sv_ext) + len(sg_ext) + len(sa_ext))
    extensions += sni_ext + sv_ext + sg_ext + sa_ext
    ch_body = (struct.pack("!H", 0x0303) + b'\x00' * 32 + bytes([0x00]) +
               struct.pack("!H", 2) + b'\x13\x01' + bytes([0x01, 0x00]) + extensions)
    return (bytes([0x01]) + bytes([(len(ch_body) >> 16) & 0xFF]) +
            struct.pack("!H", len(ch_body)) + ch_body)


def _build_crypto_frame(data: bytes, offset: int = 0) -> bytes:
    """Build QUIC CRYPTO frame with proper varint encoding."""
    def encode_varint(val: int) -> bytes:
        if val < 64:
            return bytes([val])
        elif val < 16384:
            return struct.pack("!H", 0x4000 | val)
        elif val < 1073741824:
            return struct.pack("!I", 0x80000000 | val)
        else:
            return struct.pack("!Q", 0xC000000000000000 | val)
    
    frame = bytes([0x06])  # CRYPTO type
    frame += encode_varint(offset)
    frame += encode_varint(len(data))
    frame += data
    return frame


def _build_encrypted_quic_initial(
    sni: str,
    dcid: bytes = b'\x01\x02\x03\x04\x05\x06\x07\x08',
    scid: bytes = b'\x0A\x0B\x0C\x0D',
    version: int = QUIC_V1,
    packet_number: int = 0,
    pad_to: int = 1200,
) -> bytes:
    """Build a properly encrypted QUIC Initial packet with TLS ClientHello."""
    # Select salt
    salt = INITIAL_SALT_V1 if version != QUIC_V2 else bytes.fromhex(
        "a707c203a59b47184317ef6f70b64a1e76ab5765")

    # Derive keys (RFC 9001 Section 5.2 — must go through "client in" first)
    initial_secret = _hkdf_extract(salt, dcid)
    client_initial_secret = _hkdf_expand_label(initial_secret, "client in", b"", 32)
    key = _hkdf_expand_label(client_initial_secret, "quic key", b"", 16)
    iv = _hkdf_expand_label(client_initial_secret, "quic iv", b"", 12)
    hp = _hkdf_expand_label(client_initial_secret, "quic hp", b"", 16)

    # Build TLS ClientHello → CRYPTO frame → payload
    ch = _build_tls_client_hello(sni)
    crypto = _build_crypto_frame(ch)
    payload = crypto + b'\x00' * max(0, pad_to - len(crypto))  # PADDING

    # Packet number
    pn_len = 1
    pn_bytes = packet_number.to_bytes(pn_len, 'big')

    # Build unprotected header
    header = bytearray()
    header.append(0xC0 | (pn_len - 1))  # Initial type, pn_length=1
    header.extend(struct.pack("!I", version))
    header.extend(bytes([len(dcid)]) + dcid)
    header.extend(bytes([len(scid)]) + scid)
    header.extend(bytes([0x00]))  # token length = 0

    # Payload length = encrypted payload + GCM tag + PN
    enc_total = len(payload) + 16 + pn_len
    if enc_total < 64:
        header.append(enc_total)
    elif enc_total < 16384:
        header.extend(struct.pack("!H", 0x4000 | enc_total))

    header_bytes = bytes(header)

    # Nonce = IV XOR packet_number (padded to 12 bytes)
    nonce = bytearray(iv)
    pn_padded = packet_number.to_bytes(12, 'big')
    for i in range(12):
        nonce[i] ^= pn_padded[i]

    # Encrypt: AAD = header + PN (both unprotected)
    aad = header_bytes + pn_bytes
    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(bytes(nonce), payload, aad)

    # Header protection: sample starts 4 bytes after PN field start
    # In encrypted payload, that's at offset (4 - pn_len)
    sample_start = 4 - pn_len
    sample = encrypted[sample_start:sample_start + 16]
    cipher = Cipher(algorithms.AES(hp), modes.ECB())
    enc = cipher.encryptor()
    mask = enc.update(sample) + enc.finalize()

    # Protect first byte
    protected = bytearray(header_bytes)
    protected[0] ^= (mask[0] & 0x0F)
    # Protect packet number
    protected_pn = bytearray(pn_bytes)
    for i in range(pn_len):
        protected_pn[i] ^= mask[1 + i]

    return bytes(protected) + bytes(protected_pn) + encrypted


# ============================================================
# Test: Full Round-Trip QUIC Initial Packet
# ============================================================

class TestFullRoundTrip(unittest.TestCase):
    """Test full QUIC Initial packet → decrypt → extract SNI."""

    def _roundtrip(self, sni: str, **kwargs) -> Optional[str]:
        packet = _build_encrypted_quic_initial(sni, **kwargs)
        return extract_quic_sni(packet)

    def test_roundtrip_google(self):
        self.assertEqual(self._roundtrip("google.com"), "google.com")

    def test_roundtrip_facebook(self):
        self.assertEqual(self._roundtrip("www.facebook.com"), "www.facebook.com")

    def test_roundtrip_youtube(self):
        self.assertEqual(self._roundtrip("youtube.com"), "youtube.com")

    def test_roundtrip_deep_subdomain(self):
        self.assertEqual(self._roundtrip("api.v2.internal.example.com"),
                        "api.v2.internal.example.com")

    def test_roundtrip_minimal_dcid(self):
        self.assertEqual(self._roundtrip("test.com", dcid=b'\x42'), "test.com")

    def test_roundtrip_max_dcid(self):
        self.assertEqual(self._roundtrip("max.com", dcid=b'\xAB' * 20), "max.com")

    def test_roundtrip_empty_scid(self):
        self.assertEqual(self._roundtrip("noscid.com", scid=b''), "noscid.com")

    def test_roundtrip_draft29(self):
        self.assertEqual(self._roundtrip("draft29.com", version=QUIC_DRAFT29), "draft29.com")

    def test_roundtrip_v2(self):
        self.assertEqual(self._roundtrip("quicv2.com", version=QUIC_V2), "quicv2.com")

    def test_roundtrip_packet_number_255(self):
        self.assertEqual(self._roundtrip("pn255.com", packet_number=255), "pn255.com")

    def test_roundtrip_with_padding(self):
        """Padded to 1200 bytes (QUIC minimum Initial size)."""
        packet = _build_encrypted_quic_initial("padded.com", pad_to=1200)
        self.assertTrue(len(packet) >= 1200)
        self.assertEqual(extract_quic_sni(packet), "padded.com")

    def test_roundtrip_minimal_padding(self):
        """Minimal padding (no extra padding)."""
        packet = _build_encrypted_quic_initial("minpad.com", pad_to=50)
        self.assertEqual(extract_quic_sni(packet), "minpad.com")


# ============================================================
# Test: CRYPTO Frame Parsing
# ============================================================

class TestCryptoFrameParsing(unittest.TestCase):
    """Test CRYPTO frame extraction."""

    def test_basic_crypto_frame(self):
        data = b'\x01\x02\x03\x04\x05'
        frame = _build_crypto_frame(data)
        self.assertEqual(_parse_crypto_frame(frame), data)

    def test_crypto_frame_with_offset(self):
        data = b'\xAA\xBB\xCC'
        # offset=10 needs 2-byte varint
        frame = bytes([0x06, 0x40, 0x0A, len(data)]) + data
        self.assertEqual(_parse_crypto_frame(frame), data)

    def test_crypto_frame_with_padding(self):
        data = b'\x04\x05\x06'
        frame = bytes([0x00, 0x00, 0x00]) + _build_crypto_frame(data)  # PADDING + CRYPTO
        self.assertEqual(_parse_crypto_frame(frame), data)

    def test_crypto_frame_with_ping(self):
        data = b'\x07\x08'
        frame = bytes([0x01]) + _build_crypto_frame(data)  # PING + CRYPTO
        self.assertEqual(_parse_crypto_frame(frame), data)

    def test_no_crypto_frame(self):
        self.assertIsNone(_parse_crypto_frame(bytes([0x00, 0x00, 0x00])))

    def test_crypto_frame_tls_client_hello(self):
        ch = _build_tls_client_hello("test.com")
        frame = _build_crypto_frame(ch)
        result = _parse_crypto_frame(frame)
        self.assertEqual(result, ch)
        self.assertEqual(_extract_sni_from_tls(result), "test.com")

    def test_crypto_frame_large(self):
        data = b'\xAB' * 400
        frame = bytes([0x06])  # CRYPTO
        frame += struct.pack("!H", 0x4000 | 0)  # offset=0 as 2-byte varint
        frame += struct.pack("!H", 0x4000 | len(data))  # length as 2-byte varint
        frame += data
        self.assertEqual(_parse_crypto_frame(frame), data)


# ============================================================
# Test: TLS SNI Extraction
# ============================================================

class TestTlsSniExtraction(unittest.TestCase):
    """Test SNI extraction from TLS ClientHello."""

    def test_basic_sni(self):
        ch = _build_tls_client_hello("example.com")
        self.assertEqual(_extract_sni_from_tls(ch), "example.com")

    def test_google_sni(self):
        ch = _build_tls_client_hello("google.com")
        self.assertEqual(_extract_sni_from_tls(ch), "google.com")

    def test_subdomain_sni(self):
        ch = _build_tls_client_hello("api.v2.example.com")
        self.assertEqual(_extract_sni_from_tls(ch), "api.v2.example.com")

    def test_non_client_hello(self):
        self.assertIsNone(_extract_sni_from_tls(bytes([0x02]) + b'\x00' * 50))

    def test_truncated(self):
        self.assertIsNone(_extract_sni_from_tls(bytes([0x01, 0x00, 0x00])))

    def test_empty(self):
        self.assertIsNone(_extract_sni_from_tls(b''))


# ============================================================
# Test: Domain Formats in QUIC
# ============================================================

class TestDomainFormatsInQuic(unittest.TestCase):
    """Test various domain formats through full QUIC pipeline."""

    def _roundtrip(self, sni: str) -> Optional[str]:
        return extract_quic_sni(_build_encrypted_quic_initial(sni))

    def test_hyphens(self):
        self.assertEqual(self._roundtrip("my-app.example.com"), "my-app.example.com")

    def test_numbers(self):
        self.assertEqual(self._roundtrip("api123.v2.example.com"), "api123.v2.example.com")

    def test_single_label(self):
        self.assertEqual(self._roundtrip("localhost"), "localhost")

    def test_two_labels(self):
        self.assertEqual(self._roundtrip("example.com"), "example.com")

    def test_deep_subdomain(self):
        self.assertEqual(self._roundtrip("a.b.c.d.e.example.com"), "a.b.c.d.e.example.com")

    def test_max_length(self):
        d = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 60 + ".com"
        self.assertEqual(self._roundtrip(d), d)

    def test_numeric_only(self):
        self.assertEqual(self._roundtrip("12345"), "12345")

    def test_google_services(self):
        for domain in ["google.com", "youtube.com", "ytimg.com",
                       "gstatic.com", "googlevideo.com", "ggpht.com"]:
            self.assertEqual(self._roundtrip(domain), domain)

    def test_cloudflare(self):
        self.assertEqual(self._roundtrip("cdnjs.cloudflare.com"), "cdnjs.cloudflare.com")

    def test_facebook_cdn(self):
        self.assertEqual(self._roundtrip("external.fsub1-1.fna.fbcdn.net"),
                        "external.fsub1-1.fna.fbcdn.net")

    def test_spotify(self):
        self.assertEqual(self._roundtrip("spclient.wg.spotify.com"),
                        "spclient.wg.spotify.com")

    def test_xiaomi(self):
        self.assertEqual(self._roundtrip("api.ad.intl.xiaomi.com"),
                        "api.ad.intl.xiaomi.com")


# ============================================================
# Test: Non-QUIC Packets
# ============================================================

class TestNonQuicPackets(unittest.TestCase):
    """Ensure non-QUIC packets return None."""

    def test_dns(self):
        dns = (b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
               b'\x03www\x07example\x03com\x00\x00\x01\x00\x01')
        self.assertIsNone(extract_quic_sni(dns))

    def test_stun(self):
        stun = b'\x00\x01\x00\x00\x21\x12\xa4\x42' + b'\x00' * 12
        self.assertIsNone(extract_quic_sni(stun))

    def test_wireguard(self):
        wg = b'\x01\x00\x00\x00' + b'\x00' * 100
        self.assertIsNone(extract_quic_sni(wg))

    def test_dtls(self):
        dtls = b'\x16\xFE\xFD\x00\x00\x00\x00\x00\x00\x00\x00' + b'\x00' * 20
        self.assertIsNone(extract_quic_sni(dtls))

    def test_tcp_tls(self):
        tcp_tls = b'\x16\x03\x01\x00\x05' + b'\x00' * 100
        self.assertIsNone(extract_quic_sni(tcp_tls))

    def test_empty(self):
        self.assertIsNone(extract_quic_sni(b''))

    def test_zeros(self):
        self.assertIsNone(extract_quic_sni(b'\x00' * 200))


# ============================================================
# Test: Corrupted Packets
# ============================================================

class TestCorruptedPackets(unittest.TestCase):
    """Corrupted packets should return None, not crash."""

    def test_corrupted_payload(self):
        packet = bytearray(_build_encrypted_quic_initial("test.com"))
        if len(packet) > 50:
            packet[45] ^= 0xFF
            packet[46] ^= 0xFF
        self.assertIsNone(extract_quic_sni(bytes(packet)))

    def test_truncated(self):
        packet = _build_encrypted_quic_initial("test.com")
        self.assertIsNone(extract_quic_sni(packet[:20]))

    def test_zero_length_dcid(self):
        data = bytes([0xC0]) + struct.pack("!I", QUIC_V1) + bytes([0, 0, 0, 10]) + b'\x00' * 20
        header = _parse_quic_header(data)
        self.assertIsNotNone(header)

    def test_random_bytes(self):
        import random
        random.seed(42)
        data = bytes([random.randint(0, 255) for _ in range(200)])
        result = extract_quic_sni(data)
        self.assertIsInstance(result, (str, type(None)))


# ============================================================
# Test: Key Derivation
# ============================================================

class TestKeyDerivation(unittest.TestCase):
    """Test QUIC key derivation."""

    def test_key_is_valid_aes128(self):
        secret = _hkdf_extract(INITIAL_SALT_V1, b'\x01\x02\x03\x04')
        key = _hkdf_expand_label(secret, "quic key", b"", 16)
        self.assertEqual(len(key), 16)
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        cipher.encryptor().update(b'\x00' * 16)

    def test_different_dcids_different_keys(self):
        s1 = _hkdf_extract(INITIAL_SALT_V1, b'\x01\x02')
        s2 = _hkdf_extract(INITIAL_SALT_V1, b'\x03\x04')
        k1 = _hkdf_expand_label(s1, "quic key", b"", 16)
        k2 = _hkdf_expand_label(s2, "quic key", b"", 16)
        self.assertNotEqual(k1, k2)

    def test_iv_is_12_bytes(self):
        secret = _hkdf_extract(INITIAL_SALT_V1, b'\x01\x02')
        iv = _hkdf_expand_label(secret, "quic iv", b"", 12)
        self.assertEqual(len(iv), 12)

    def test_hp_is_16_bytes(self):
        secret = _hkdf_extract(INITIAL_SALT_V1, b'\x01\x02')
        hp = _hkdf_expand_label(secret, "quic hp", b"", 16)
        self.assertEqual(len(hp), 16)

    def test_v2_different_salt(self):
        dcid = b'\x01\x02\x03\x04'
        s1 = _hkdf_extract(INITIAL_SALT_V1, dcid)
        s2 = _hkdf_extract(bytes.fromhex("a707c203a59b47184317ef6f70b64a1e76ab5765"), dcid)
        self.assertNotEqual(s1, s2)

    def test_deterministic(self):
        dcid = b'\x01\x02\x03\x04'
        for _ in range(5):
            s = _hkdf_extract(INITIAL_SALT_V1, dcid)
            k = _hkdf_expand_label(s, "quic key", b"", 16)
            self.assertEqual(len(k), 16)


# ============================================================
# Test: Header Protection
# ============================================================

class TestHeaderProtection(unittest.TestCase):
    """Test AES-ECB header protection mask."""

    def test_mask_16_bytes(self):
        hp = b'\x00' * 16
        sample = b'\x00' * 16
        cipher = Cipher(algorithms.AES(hp), modes.ECB())
        mask = cipher.encryptor().update(sample) + cipher.encryptor().finalize()
        self.assertEqual(len(mask), 16)

    def test_xor_reversibility(self):
        original = b'\xAB\xCD\xEF\x12'
        mask = b'\x11\x22\x33\x44'
        masked = bytes(a ^ b for a, b in zip(original, mask))
        unmasked = bytes(a ^ b for a, b in zip(masked, mask))
        self.assertEqual(original, unmasked)

    def test_different_samples_different_masks(self):
        hp = b'\x11' * 16
        c1 = Cipher(algorithms.AES(hp), modes.ECB())
        m1 = c1.encryptor().update(b'\x00' * 16)
        c2 = Cipher(algorithms.AES(hp), modes.ECB())
        m2 = c2.encryptor().update(b'\xFF' * 16)
        self.assertNotEqual(m1[:5], m2[:5])


# ============================================================
# Test: Varint Parsing
# ============================================================

class TestVarint(unittest.TestCase):
    def test_1byte(self):
        self.assertEqual(_read_varint(bytes([0x05]), 0), (5, 1))

    def test_1byte_max(self):
        self.assertEqual(_read_varint(bytes([0x3F]), 0), (63, 1))

    def test_2byte(self):
        val, pos = _read_varint(struct.pack("!H", 0x4000 | 300), 0)
        self.assertEqual(val, 300)
        self.assertEqual(pos, 2)

    def test_4byte(self):
        val, pos = _read_varint(struct.pack("!I", 0x80000000 | 70000), 0)
        self.assertEqual(val, 70000)
        self.assertEqual(pos, 4)

    def test_offset(self):
        self.assertEqual(_read_varint(b'\x00\x00\x05', 2), (5, 3))

    def test_empty(self):
        self.assertEqual(_read_varint(b'', 0), (0, 0))


if __name__ == '__main__':
    unittest.main()
