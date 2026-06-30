"""
QUIC Initial Packet SNI Extractor

Decrypts QUIC Initial packets (RFC 9001) to extract TLS 1.3 ClientHello SNI.
Only processes Initial packets — all other QUIC packet types are skipped.

QUIC v1 Initial packet structure:
  Byte 0: 0xC0 | type(2) | reserved(2) | pn_length(2)  → 0b110000xx
  Version: 4 bytes (0x00000001 for QUIC v1)
  DCID len: 1 byte
  DCID: 0-20 bytes
  SCID len: 1 byte  
  SCID: 0-20 bytes
  Token len: variable int
  Token: variable
  Length: variable int
  Packet Number: 1-4 bytes (encrypted)
  Payload: encrypted with AES-128-GCM

Decryption:
  1. Derive initial_secret = HKDF-Expand-Label(initial_salt, "", DCID, 32)
  2. Derive key = HKDF-Expand-Label(initial_secret, "quic key", "", 16)
  3. Derive iv  = HKDF-Expand-Label(initial_secret, "quic iv", "", 12)
  4. Derive hp  = HKDF-Expand-Label(initial_secret, "quic hp", "", 16)
  5. Unmask packet number using AES-ECB(hp, sample)
  6. Decrypt payload with AES-GCM(key, nonce, aad)
  7. Parse CRYPTO frame → TLS ClientHello → SNI extension
"""

import struct
import socket
from typing import Optional, Tuple

# ============================================================
# QUIC v1 constants
# ============================================================

QUIC_V1 = 0x00000001
QUIC_DRAFT29 = 0xff00001d
QUIC_V2 = 0x6b3343cf

# Initial salt for QUIC v1 (RFC 9001 Section 5.2)
INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

# TLS 1.3 handshake types
CLIENT_HELLO = 0x01

# TLS extension types
SNI_EXTENSION = 0x0000


# ============================================================
# HKDF / Crypto helpers
# ============================================================

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract (RFC 5869)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives import hmac as crypto_hmac
    h = crypto_hmac.HMAC(salt, hashes.SHA256())
    h.update(ikm)
    return h.finalize()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand (RFC 5869)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives import hmac as crypto_hmac
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        h = crypto_hmac.HMAC(prk, hashes.SHA256())
        h.update(t + info + bytes([counter]))
        t = h.finalize()
        okm += t
        counter += 1
    return okm[:length]


def _hkdf_expand_label(secret: bytes, label: str, context: bytes, length: int) -> bytes:
    """HKDF-Expand-Label (RFC 8446 Section 7.1)."""
    full_label = "tls13 " + label
    label_bytes = full_label.encode('ascii')
    # struct: length(2) + label_len(1) + label + context_len(1) + context
    hkdf_label = struct.pack("!H", length) + bytes([len(label_bytes)]) + label_bytes + bytes([len(context)]) + context
    return _hkdf_expand(secret, hkdf_label, length)


# ============================================================
# Variable-length integer (RFC 9000 Section 16)
# ============================================================

def _read_varint(data: bytes, offset: int) -> Tuple[int, int]:
    """Read QUIC variable-length integer. Returns (value, new_offset)."""
    if offset >= len(data):
        return 0, offset
    first = data[offset]
    length = 1 << ((first & 0xC0) >> 6)
    if offset + length > len(data):
        return 0, offset
    if length == 1:
        return first & 0x3F, offset + 1
    elif length == 2:
        return struct.unpack("!H", data[offset:offset+2])[0] & 0x3FFF, offset + 2
    elif length == 4:
        return struct.unpack("!I", data[offset:offset+4])[0] & 0x3FFFFFFF, offset + 4
    else:  # length == 8
        return struct.unpack("!Q", data[offset:offset+8])[0] & 0x3FFFFFFFFFFFFFFF, offset + 8


# ============================================================
# QUIC packet parsing
# ============================================================

def _is_quic_initial(data: bytes) -> bool:
    """Check if packet is a QUIC Initial packet."""
    if len(data) < 6:
        return False
    # Long header: first bit set
    if not (data[0] & 0x80):
        return False
    # Fixed bit set
    if not (data[0] & 0x40):
        return False
    # Packet type = Initial (bits 4-5 = 0b00)
    if (data[0] & 0x30) != 0x00:
        return False
    # Version check
    version = struct.unpack("!I", data[1:5])[0]
    return version in (QUIC_V1, QUIC_DRAFT29, QUIC_V2)


def _parse_quic_header(data: bytes) -> Optional[dict]:
    """Parse QUIC Initial packet header. Returns None if not valid."""
    if not _is_quic_initial(data):
        return None

    pos = 0
    first_byte = data[pos]; pos += 1
    pn_length = (first_byte & 0x03) + 1  # 1-4 bytes

    version = struct.unpack("!I", data[pos:pos+4])[0]
    pos += 4

    # Destination Connection ID
    dcid_len = data[pos]; pos += 1
    if dcid_len > 20:
        return None
    dcid = data[pos:pos+dcid_len]; pos += dcid_len

    # Source Connection ID
    scid_len = data[pos]; pos += 1
    if scid_len > 20:
        return None
    scid = data[pos:pos+scid_len]; pos += scid_len

    # Token (Initial packets only)
    token_len, pos = _read_varint(data, pos)
    token = data[pos:pos+token_len]; pos += token_len

    # Length (protected payload + packet number)
    payload_length, pos = _read_varint(data, pos)

    return {
        "first_byte": first_byte,
        "version": version,
        "dcid": dcid,
        "scid": scid,
        "token": token,
        "pn_length": pn_length,
        "payload_length": payload_length,
        "header_end": pos,
    }


def _decrypt_initial(data: bytes, header: dict) -> Optional[bytes]:
    """Decrypt QUIC Initial packet payload. Returns decrypted bytes or None."""
    dcid = header["dcid"]
    version = header["version"]

    # Select salt based on version
    if version == QUIC_V1:
        salt = INITIAL_SALT_V1
    elif version == QUIC_DRAFT29:
        salt = INITIAL_SALT_V1  # Same salt for draft-29
    elif version == QUIC_V2:
        # QUIC v2 uses different salt
        salt = bytes.fromhex("a707c203a59b47184317ef6f70b64a1e76ab5765")
    else:
        return None

    # Step 1: Derive initial_secret from DCID
    initial_secret = _hkdf_extract(salt, dcid)

    # Step 2: Derive keys
    client_key = _hkdf_expand_label(initial_secret, "quic key", b"", 16)
    client_iv = _hkdf_expand_label(initial_secret, "quic iv", b"", 12)
    client_hp = _hkdf_expand_label(initial_secret, "quic hp", b"", 16)

    header_end = header["header_end"]
    pn_length = header["pn_length"]

    # Step 3: Sample for header protection (16 bytes, 4 bytes before packet number)
    sample_offset = header_end + 4
    if sample_offset + 16 > len(data):
        return None
    sample = data[sample_offset:sample_offset + 16]

    # Step 4: Unmask packet number using AES-ECB
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    cipher = Cipher(algorithms.AES(client_hp), modes.ECB())
    encryptor = cipher.encryptor()
    mask = encryptor.update(sample) + encryptor.finalize()

    # Unmask first byte
    if pn_length == 1:
        first_byte = data[0] ^ (mask[0] & 0x0F)
    else:
        first_byte = data[0] ^ (mask[0] & 0x0F)

    # Unmask packet number
    pn_bytes = bytearray(data[header_end:header_end + pn_length])
    for i in range(pn_length):
        pn_bytes[i] ^= mask[1 + i]
    packet_number = int.from_bytes(pn_bytes, 'big')

    # Step 5: Construct nonce = IV XOR packet_number (padded to 12 bytes)
    nonce = bytearray(client_iv)
    pn_padded = packet_number.to_bytes(12, 'big')
    for i in range(12):
        nonce[i] ^= pn_padded[i]

    # Step 6: Decrypt payload with AES-GCM
    payload_start = header_end + pn_length
    payload_end = payload_start + header["payload_length"] - pn_length
    if payload_end > len(data):
        payload_end = len(data)

    # AAD = header (everything before encrypted part)
    aad = data[:header_end] + data[header_end:header_end + pn_length]
    # Actually AAD = full header including packet number
    # But packet number is stored encrypted, so we use the unmasked version
    aad = bytearray(data[:header_end])
    aad.append(first_byte)
    aad.extend(pn_bytes)

    # Actually, AAD = original header bytes (before decryption)
    # The first byte and packet number bytes are in their encrypted form in AAD
    aad = data[:payload_start]

    encrypted_payload = data[payload_start:payload_end]
    # Last 16 bytes are the authentication tag
    if len(encrypted_payload) < 16:
        return None

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(client_key)
        # nonce must be bytes, aad can be bytes
        decrypted = aesgcm.decrypt(bytes(nonce), bytes(encrypted_payload), bytes(aad))
        return decrypted
    except Exception:
        return None


# ============================================================
# CRYPTO frame → TLS ClientHello → SNI extraction
# ============================================================

def _parse_crypto_frame(payload: bytes) -> Optional[bytes]:
    """Extract TLS ClientHello from QUIC CRYPTO frame."""
    pos = 0
    while pos < len(payload):
        if pos >= len(payload):
            break
        frame_type = payload[pos]; pos += 1

        if frame_type == 0x06:  # CRYPTO frame
            offset, pos = _read_varint(payload, pos)
            length, pos = _read_varint(payload, pos)
            if pos + length > len(payload):
                return None
            crypto_data = payload[pos:pos + length]
            return crypto_data
        elif frame_type == 0x00:  # PADDING
            continue
        elif frame_type == 0x01:  # PING
            continue
        elif frame_type == 0x02 or frame_type == 0x03:  # ACK
            # Skip ACK frame
            _, pos = _read_varint(payload, pos)  # largest acknowledged
            _, pos = _read_varint(payload, pos)  # ack delay
            ack_range_count, pos = _read_varint(payload, pos)
            _, pos = _read_varint(payload, pos)  # first ack range
            for _ in range(ack_range_count):
                _, pos = _read_varint(payload, pos)  # gap
                _, pos = _read_varint(payload, pos)  # ack range
        else:
            # Unknown frame — skip (may have length field)
            break

    return None


def _extract_sni_from_tls(data: bytes) -> Optional[str]:
    """Extract SNI from TLS 1.3 ClientHello."""
    if len(data) < 6:
        return None
    if data[0] != CLIENT_HELLO:
        return None

    # Handshake length
    ch_length = (data[1] << 16) | struct.unpack("!H", data[2:4])[0]

    pos = 4
    # Client version
    if pos + 2 > len(data):
        return None
    pos += 2

    # Random (32 bytes)
    pos += 32

    # Session ID
    if pos + 1 > len(data):
        return None
    session_id_len = data[pos]; pos += 1
    pos += session_id_len

    # Cipher Suites
    if pos + 2 > len(data):
        return None
    cs_len = struct.unpack("!H", data[pos:pos+2])[0]; pos += 2
    pos += cs_len

    # Compression
    if pos + 1 > len(data):
        return None
    comp_len = data[pos]; pos += 1
    pos += comp_len

    # Extensions
    if pos + 2 > len(data):
        return None
    ext_total_len = struct.unpack("!H", data[pos:pos+2])[0]; pos += 2
    ext_end = pos + ext_total_len

    while pos + 4 <= ext_end and pos + 4 <= len(data):
        ext_type = struct.unpack("!H", data[pos:pos+2])[0]
        ext_data_len = struct.unpack("!H", data[pos+2:pos+4])[0]
        pos += 4

        if ext_type == SNI_EXTENSION:
            # Parse SNI extension
            if pos + 2 > len(data):
                return None
            sni_list_len = struct.unpack("!H", data[pos:pos+2])[0]
            sni_pos = pos + 2
            if sni_pos + 3 <= len(data):
                name_type = data[sni_pos]
                name_len = struct.unpack("!H", data[sni_pos+1:sni_pos+3])[0]
                sni_pos += 3
                if name_type == 0 and sni_pos + name_len <= len(data):
                    try:
                        return data[sni_pos:sni_pos+name_len].decode('ascii')
                    except UnicodeDecodeError:
                        return None
            return None

        pos += ext_data_len

    return None


# ============================================================
# Public API
# ============================================================

def extract_quic_sni(data: bytes) -> Optional[str]:
    """
    Extract SNI from a QUIC Initial packet.
    
    Works for QUIC v1 (RFC 9000), draft-29, and QUIC v2.
    Returns the SNI hostname or None if not extractable.
    
    This handles:
    - QUIC header parsing
    - Initial packet decryption (AES-128-GCM)
    - Header protection removal (AES-ECB)
    - CRYPTO frame extraction
    - TLS 1.3 ClientHello SNI parsing
    """
    header = _parse_quic_header(data)
    if header is None:
        return None

    decrypted = _decrypt_initial(data, header)
    if decrypted is None:
        return None

    crypto_data = _parse_crypto_frame(decrypted)
    if crypto_data is None:
        return None

    return _extract_sni_from_tls(crypto_data)


def is_quic_initial(data: bytes) -> bool:
    """Check if a UDP packet is a QUIC Initial packet."""
    return _is_quic_initial(data)
