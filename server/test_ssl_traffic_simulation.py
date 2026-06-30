#!/usr/bin/env python3
"""
SSL/TLS Traffic Simulation for SNI Pipeline Testing.

Simulates realistic browser traffic patterns through the VPN:
- DNS queries (UDP :53)
- TCP 3-way handshake (SYN, SYN-ACK, ACK)
- TLS ClientHello with SNI extension
- TLS ServerHello response
- Application data transfer
- Multiple concurrent connections (tabs, API calls, CDN)
- Edge cases: fragmented handshakes, non-standard ports, QUIC

Tests the full pipeline: packet → SNI extraction → domain cache → flow display
Mirrors what PacketFlowTracker + SniParser do on Android.
"""

import struct
import socket
import unittest
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple
import time
import threading


# ============================================================
# SNI Parser (Python equivalent of SniParser.kt)
# ============================================================

TLS_HANDSHAKE = 0x16
CLIENT_HELLO = 0x01
SNI_EXTENSION = 0x0000
SNI_HOST_NAME = 0x00


def extract_sni(packet: bytes) -> Optional[str]:
    """Extract SNI domain from a raw IP packet. Mirrors SniParser.kt."""
    if len(packet) < 20:
        return None

    version = (packet[0] & 0xF0) >> 4
    if version != 4:
        return None

    ihl = (packet[0] & 0x0F) * 4
    if ihl < 20 or len(packet) < ihl:
        return None

    protocol = packet[9] & 0xFF
    if protocol != 6:  # TCP only
        return None

    if len(packet) < ihl + 12:
        return None
    data_offset = ((packet[ihl + 12] & 0xF0) >> 4) * 4

    payload_start = ihl + data_offset
    if len(packet) < payload_start + 5:
        return None

    tls_content_type = packet[payload_start]
    if tls_content_type != TLS_HANDSHAKE:
        return None

    handshake_type = packet[payload_start + 5]
    if handshake_type != CLIENT_HELLO:
        return None

    return _parse_client_hello(packet, payload_start + 5)


def _parse_client_hello(data: bytes, offset: int) -> Optional[str]:
    """Parse TLS ClientHello to extract SNI extension."""
    if len(data) < offset + 34:
        return None

    # Skip: handshake type(1) + length(3) + version(2) + random(32)
    pos = offset + 38

    # Session ID
    if pos >= len(data):
        return None
    session_id_len = data[pos] & 0xFF
    pos += 1 + session_id_len

    # Cipher Suites
    if pos + 2 > len(data):
        return None
    cipher_suites_len = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF)
    pos += 2 + cipher_suites_len

    # Compression Methods
    if pos >= len(data):
        return None
    compression_len = data[pos] & 0xFF
    pos += 1 + compression_len

    # Extensions
    if pos + 2 > len(data):
        return None
    extensions_len = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF)
    pos += 2

    extensions_end = pos + extensions_len
    if extensions_end > len(data):
        return None

    while pos + 4 <= extensions_end:
        ext_type = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF)
        ext_len = ((data[pos + 2] & 0xFF) << 8) | (data[pos + 3] & 0xFF)
        pos += 4

        if ext_type == SNI_EXTENSION:
            return _parse_sni_extension(data, pos, ext_len)

        pos += ext_len

    return None


def _parse_sni_extension(data: bytes, offset: int, length: int) -> Optional[str]:
    """Parse SNI extension to extract hostname."""
    if offset + 2 > len(data):
        return None

    end = offset + length
    pos = offset + 2  # Skip SNI list length

    while pos + 3 <= end:
        name_type = data[pos]
        name_len = ((data[pos + 1] & 0xFF) << 8) | (data[pos + 2] & 0xFF)
        pos += 3

        if name_type == SNI_HOST_NAME and pos + name_len <= end:
            try:
                return data[pos:pos + name_len].decode('ascii')
            except UnicodeDecodeError:
                return None

        pos += name_len

    return None


# ============================================================
# Packet Builder — builds realistic IP/TCP/TLS packets
# ============================================================

def build_ip_header(src_ip: str, dst_ip: str, protocol: int, payload_len: int,
                    ihl: int = 5) -> bytes:
    """Build a minimal IPv4 header."""
    total_len = (ihl * 4) + payload_len
    header = bytearray(ihl * 4)
    header[0] = (4 << 4) | ihl  # version + IHL
    header[1] = 0  # DSCP/ECN
    struct.pack_into('!H', header, 2, total_len)
    struct.pack_into('!H', header, 4, 0x1234)  # identification
    struct.pack_into('!H', header, 6, 0x4000)  # flags (DF)
    header[8] = 64  # TTL
    header[9] = protocol
    # checksum = 0 (compute later)
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    header[12:16] = src_bytes
    header[16:20] = dst_bytes
    # Compute checksum
    csum = _ip_checksum(bytes(header))
    struct.pack_into('!H', header, 10, csum)
    return bytes(header)


def _ip_checksum(data: bytes) -> int:
    """Compute IP header checksum."""
    s = 0
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            w = (data[i] << 8) + data[i + 1]
        else:
            w = data[i] << 8
        s += w
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def build_tcp_header(src_port: int, dst_port: int, seq: int, ack: int,
                     flags: int, payload: bytes = b'',
                     data_offset: int = 5) -> bytes:
    """Build a TCP header."""
    tcp_len = data_offset * 4
    header = bytearray(tcp_len)
    struct.pack_into('!H', header, 0, src_port)
    struct.pack_into('!H', header, 2, dst_port)
    struct.pack_into('!I', header, 4, seq)
    struct.pack_into('!I', header, 8, ack)
    header[12] = (data_offset << 4)
    header[13] = flags
    struct.pack_into('!H', header, 14, 65535)  # window
    return bytes(header) + payload


def build_tls_client_hello(sni_hostname: str,
                           session_id: bytes = b'',
                           cipher_suites: List[int] = None,
                           extra_extensions: List[Tuple[int, bytes]] = None,
                           ) -> bytes:
    """Build a TLS ClientHello with SNI extension."""
    if cipher_suites is None:
        cipher_suites = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02c, 0xcca9, 0x00ff]

    if extra_extensions is None:
        extra_extensions = []

    if not session_id:
        session_id = bytes(32)  # 32-byte session ID

    # Random (32 bytes)
    random = b'\x00' * 32

    # Cipher suites (2-byte length + data)
    cs_data = b''
    for cs in cipher_suites:
        cs_data += struct.pack('!H', cs)

    # Compression methods
    compression = b'\x01\x00'  # null compression

    # SNI extension
    sni_bytes = sni_hostname.encode('ascii')
    sni_ext_data = (
        struct.pack('!H', 1 + 2 + len(sni_bytes)) +  # SNI list length
        bytes([SNI_HOST_NAME]) +                       # name type
        struct.pack('!H', len(sni_bytes)) +            # name length
        sni_bytes                                       # hostname
    )
    sni_extension = struct.pack('!HH', SNI_EXTENSION, len(sni_ext_data)) + sni_ext_data

    # Other typical extensions (simplified)
    supported_versions = struct.pack('!HH', 0x002b, 4) + b'\x00\x02\x03\x04'  # TLS 1.3
    supported_groups = struct.pack('!HH', 0x000a, 4) + b'\x00\x02\x00\x1d'   # x25519
    sig_algorithms = struct.pack('!HH', 0x000d, 4) + b'\x00\x02\x04\x03'     # ecdsa_secp256r1

    extensions = sni_extension + supported_versions + supported_groups + sig_algorithms
    for ext_type, ext_data in extra_extensions:
        extensions += struct.pack('!HH', ext_type, len(ext_data)) + ext_data

    # ClientHello body
    client_hello = (
        bytes([CLIENT_HELLO]) +           # handshake type
        b'\x00' +                         # length placeholder (3 bytes)
        struct.pack('!H', 0) +            # will be filled
        struct.pack('!H', 0x0303) +       # TLS 1.2 (legacy version)
        random +
        bytes([len(session_id)]) + session_id +
        struct.pack('!H', len(cs_data)) + cs_data +
        compression +
        struct.pack('!H', len(extensions)) + extensions
    )

    # Fix ClientHello length
    ch_len = len(client_hello) - 4  # exclude type + 3-byte length
    client_hello = (
        client_hello[:1] +
        bytes([(ch_len >> 16) & 0xFF, (ch_len >> 8) & 0xFF, ch_len & 0xFF]) +
        client_hello[4:]
    )

    # TLS record
    tls_record = (
        bytes([TLS_HANDSHAKE]) +          # content type
        struct.pack('!H', 0x0301) +       # TLS 1.0 (legacy record version)
        struct.pack('!H', len(client_hello)) +
        client_hello
    )

    return tls_record


def build_syn_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                     seq: int) -> bytes:
    """Build TCP SYN packet."""
    ip = build_ip_header(src_ip, dst_ip, 6, 20)
    tcp = build_tcp_header(src_port, dst_port, seq, 0, 0x02)  # SYN
    return ip + tcp


def build_syn_ack_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                         seq: int, ack: int) -> bytes:
    """Build TCP SYN-ACK packet."""
    ip = build_ip_header(src_ip, dst_ip, 6, 20)
    tcp = build_tcp_header(src_port, dst_port, seq, ack, 0x12)  # SYN+ACK
    return ip + tcp


def build_ack_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                     seq: int, ack: int) -> bytes:
    """Build TCP ACK packet."""
    ip = build_ip_header(src_ip, dst_ip, 6, 20)
    tcp = build_tcp_header(src_port, dst_port, seq, ack, 0x10)  # ACK
    return ip + tcp


def build_data_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                      seq: int, ack: int, payload: bytes, flags: int = 0x18) -> bytes:
    """Build TCP packet with payload (PSH+ACK by default)."""
    ip = build_ip_header(src_ip, dst_ip, 6, 20 + len(payload))
    tcp = build_tcp_header(src_port, dst_port, seq, ack, flags, payload)
    return ip + tcp


def build_udp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                     payload: bytes) -> bytes:
    """Build UDP packet."""
    udp_header = struct.pack('!HHHH', src_port, dst_port, 8 + len(payload), 0)
    ip = build_ip_header(src_ip, dst_ip, 17, 8 + len(payload))
    return ip + udp_header + payload


def build_tls_server_hello() -> bytes:
    """Build a minimal TLS ServerHello (no SNI)."""
    server_hello_body = (
        struct.pack('!H', 0x0303) +   # TLS 1.2
        b'\x00' * 32 +                # random
        b'\x00' +                     # session ID length
        struct.pack('!H', 0x1301) +   # cipher suite
        b'\x00' +                     # compression
        b'\x00\x00'                   # extensions length (empty)
    )
    handshake = (
        bytes([0x02]) +               # ServerHello
        bytes([(len(server_hello_body) >> 16) & 0xFF]) +
        struct.pack('!H', len(server_hello_body)) +
        server_hello_body
    )
    tls_record = (
        bytes([TLS_HANDSHAKE]) +
        struct.pack('!H', 0x0303) +
        struct.pack('!H', len(handshake)) +
        handshake
    )
    return tls_record


def build_dns_query(domain: str) -> bytes:
    """Build a DNS query packet (UDP)."""
    # DNS header
    dns = struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
    # Question
    for label in domain.split('.'):
        dns += bytes([len(label)]) + label.encode()
    dns += b'\x00'  # root label
    dns += struct.pack('!HH', 1, 1)  # A record, IN class
    return dns


# ============================================================
# Flow Tracker (Python equivalent of PacketFlowTracker.kt)
# ============================================================

@dataclass
class FlowStats:
    remote_ip: str
    remote_port: int
    protocol: str
    domain: Optional[str] = None
    uplink_bytes: int = 0
    downlink_bytes: int = 0
    last_seen: float = field(default_factory=time.time)


class DomainCache:
    """Python equivalent of DomainCache.kt."""
    MAX_ENTRIES = 1000

    def __init__(self):
        self._cache: Dict[str, str] = {}

    def get_domain(self, ip: str) -> Optional[str]:
        return self._cache.get(ip)

    def put_domain(self, ip: str, domain: str):
        self._cache[ip] = domain.lower()
        if len(self._cache) > self.MAX_ENTRIES:
            # Evict oldest (simple FIFO for testing)
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]

    def clear(self):
        self._cache.clear()

    def size(self) -> int:
        return len(self._cache)


class PacketFlowTracker:
    """Python equivalent of PacketFlowTracker.kt."""
    MAX_FLOWS = 500
    FLOW_TIMEOUT = 300  # 5 min

    def __init__(self):
        self.flows: Dict[str, FlowStats] = {}
        self.domain_cache = DomainCache()
        self.total_packets = 0
        self.uplink_tcp = 0
        self.sni_extracted = 0
        self.cache_hits = 0

    def clear(self):
        self.flows.clear()
        self.domain_cache.clear()
        self.total_packets = 0
        self.uplink_tcp = 0
        self.sni_extracted = 0
        self.cache_hits = 0

    def get_debug_stats(self) -> str:
        return (f"packets={self.total_packets}, uplinkTcp={self.uplink_tcp}, "
                f"sniExtracted={self.sni_extracted}, cacheHits={self.cache_hits}, "
                f"flows={len(self.flows)}, cacheSize={self.domain_cache.size()}")

    def process_packet(self, packet: bytes, is_uplink: bool):
        """Process a raw IP packet. Mirrors processPacket() in Kotlin."""
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

        # Extract SNI from uplink TCP packets
        domain = None
        if is_uplink and proto_name == "TCP":
            self.uplink_tcp += 1
            domain = extract_sni(packet)
            if domain is not None:
                self.sni_extracted += 1
                self.domain_cache.put_domain(remote_ip, domain)

        # Cache lookup for non-SNI packets
        if domain is None:
            cached = self.domain_cache.get_domain(remote_ip)
            if cached is not None:
                domain = cached
                self.cache_hits += 1

        # Normalize domain to lowercase (mirrors DomainCache.putDomain)
        if domain is not None:
            domain = domain.lower()

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
            if len(self.flows) >= self.MAX_FLOWS:
                oldest_key = min(self.flows, key=lambda k: self.flows[k].last_seen)
                del self.flows[oldest_key]
            self.flows[key] = FlowStats(
                remote_ip=remote_ip,
                remote_port=remote_port,
                protocol=proto_name,
                domain=domain,
                uplink_bytes=packet_len if is_uplink else 0,
                downlink_bytes=0 if is_uplink else packet_len,
                last_seen=now
            )

    def get_flows(self) -> List[FlowStats]:
        now = time.time()
        self.flows = {k: v for k, v in self.flows.items()
                      if now - v.last_seen < self.FLOW_TIMEOUT}
        return sorted(self.flows.values(),
                      key=lambda f: f.uplink_bytes + f.downlink_bytes,
                      reverse=True)

    @staticmethod
    def _ip_to_string(packet: bytes, offset: int) -> str:
        return f"{packet[offset] & 0xFF}.{packet[offset+1] & 0xFF}." \
               f"{packet[offset+2] & 0xFF}.{packet[offset+3] & 0xFF}"


# ============================================================
# Traffic Simulation — realistic browser traffic patterns
# ============================================================

CLIENT_IP = "10.20.0.2"
SERVER_IP = "142.250.185.78"  # google.com
CDN_IP = "151.101.1.140"      # reddit CDN
API_IP = "104.18.10.45"       # random API
LOCAL_DNS = "10.20.0.3"       # VPN DNS


class TrafficSimulator:
    """Simulates realistic browser traffic through VPN."""

    def __init__(self):
        self.tracker = PacketFlowTracker()
        self.seq_counters: Dict[str, int] = {}

    def _next_seq(self, key: str) -> int:
        seq = self.seq_counters.get(key, 1000)
        self.seq_counters[key] = seq + 100
        return seq

    def simulate_dns_query(self, domain: str):
        """Simulate DNS lookup through VPN."""
        dns_payload = build_dns_query(domain)
        pkt = build_udp_packet(CLIENT_IP, LOCAL_DNS, 54321, 53, dns_payload)
        self.tracker.process_packet(pkt, is_uplink=True)

    def simulate_tls_connection(self, dst_ip: str, hostname: str,
                                dst_port: int = 443) -> dict:
        """Simulate a full TLS connection: SYN → SYN-ACK → ACK → ClientHello → ServerHello → Data."""
        src_port = 30000 + (hash(dst_ip) % 30000)
        seq_key = f"{dst_ip}:{dst_port}"
        client_seq = self._next_seq(seq_key)
        server_seq = 100000

        result = {}

        # 1. DNS (if not already resolved)
        self.simulate_dns_query(hostname)

        # 2. SYN (uplink)
        syn = build_syn_packet(CLIENT_IP, dst_ip, src_port, dst_port, client_seq)
        self.tracker.process_packet(syn, is_uplink=True)
        result['syn'] = True

        # 3. SYN-ACK (downlink)
        syn_ack = build_syn_ack_packet(dst_ip, CLIENT_IP, dst_port, src_port,
                                        server_seq, client_seq + 1)
        self.tracker.process_packet(syn_ack, is_uplink=False)
        result['syn_ack'] = True

        # 4. ACK (uplink)
        ack = build_ack_packet(CLIENT_IP, dst_ip, src_port, dst_port,
                               client_seq + 1, server_seq + 1)
        self.tracker.process_packet(ack, is_uplink=True)
        result['ack'] = True

        # 5. ClientHello with SNI (uplink) — THE KEY PACKET
        client_hello = build_tls_client_hello(hostname)
        ch_pkt = build_data_packet(CLIENT_IP, dst_ip, src_port, dst_port,
                                   client_seq + 1, server_seq + 1, client_hello)
        self.tracker.process_packet(ch_pkt, is_uplink=True)
        result['client_hello'] = True
        result['client_hello_len'] = len(client_hello)

        # 6. ServerHello (downlink)
        server_hello = build_tls_server_hello()
        sh_pkt = build_data_packet(dst_ip, CLIENT_IP, dst_port, src_port,
                                   server_seq + 1, client_seq + 1 + len(client_hello),
                                   server_hello)
        self.tracker.process_packet(sh_pkt, is_uplink=False)
        result['server_hello'] = True

        # 7. Application data (bidirectional)
        app_req = b'GET / HTTP/1.1\r\nHost: ' + hostname.encode() + b'\r\n\r\n'
        req_pkt = build_data_packet(CLIENT_IP, dst_ip, src_port, dst_port,
                                    client_seq + 1 + len(client_hello),
                                    server_seq + 1 + len(server_hello),
                                    app_req)
        self.tracker.process_packet(req_pkt, is_uplink=True)

        app_resp = b'HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n' + b'x' * 1000
        resp_pkt = build_data_packet(dst_ip, CLIENT_IP, dst_port, src_port,
                                     server_seq + 1 + len(server_hello),
                                     client_seq + 1 + len(client_hello) + len(app_req),
                                     app_resp)
        self.tracker.process_packet(resp_pkt, is_uplink=False)
        result['data_transferred'] = len(app_req) + len(app_resp)

        return result

    def simulate_non_tls_traffic(self, dst_ip: str, dst_port: int, payload: bytes):
        """Simulate non-TLS TCP traffic (no SNI)."""
        src_port = 40000 + (hash(dst_ip + str(dst_port)) % 20000)
        seq_key = f"{dst_ip}:{dst_port}"
        client_seq = self._next_seq(seq_key)

        # SYN
        syn = build_syn_packet(CLIENT_IP, dst_ip, src_port, dst_port, client_seq)
        self.tracker.process_packet(syn, is_uplink=True)

        # ACK
        ack = build_ack_packet(CLIENT_IP, dst_ip, src_port, dst_port,
                               client_seq + 1, 10000)
        self.tracker.process_packet(ack, is_uplink=True)

        # Data
        data_pkt = build_data_packet(CLIENT_IP, dst_ip, src_port, dst_port,
                                     client_seq + 1, 10000, payload)
        self.tracker.process_packet(data_pkt, is_uplink=True)

    def simulate_udp_traffic(self, dst_ip: str, dst_port: int, payload: bytes):
        """Simulate UDP traffic (DNS, QUIC, etc.)."""
        src_port = 50000 + (hash(dst_ip) % 10000)
        pkt = build_udp_packet(CLIENT_IP, dst_ip, src_port, dst_port, payload)
        self.tracker.process_packet(pkt, is_uplink=True)

    def simulate_browser_tab(self, hostname: str, dst_ip: str) -> dict:
        """Simulate a full browser tab lifecycle: DNS + TLS + multiple requests."""
        results = {}

        # DNS resolution
        self.simulate_dns_query(hostname)

        # TLS handshake
        tls_result = self.simulate_tls_connection(dst_ip, hostname)
        results['tls'] = tls_result

        # Follow-up requests (keep-alive, sub-resources)
        for path in ['/style.css', '/script.js', '/api/data']:
            req = f'GET {path} HTTP/1.1\r\nHost: {hostname}\r\n\r\n'.encode()
            src_port = 30000 + (hash(dst_ip) % 30000)
            data_pkt = build_data_packet(CLIENT_IP, dst_ip, src_port, 443,
                                         5000, 5000, req)
            self.tracker.process_packet(data_pkt, is_uplink=True)

        results['sub_requests'] = 3
        return results

    def simulate_background_noise(self):
        """Simulate background traffic: mDNS, NTP, push notifications."""
        # mDNS (UDP 5353)
        mdns = build_udp_packet(CLIENT_IP, "224.0.0.251", 5353, 5353,
                                b'\x00\x00\x01\x00\x00\x01')
        self.tracker.process_packet(mdns, is_uplink=True)

        # NTP (UDP 123)
        ntp = build_udp_packet(CLIENT_IP, "169.254.169.254", 12345, 123,
                               b'\x00' * 48)
        self.tracker.process_packet(ntp, is_uplink=True)

        # Push notification (GCM/FCM on TCP 5228)
        self.simulate_non_tls_traffic("74.125.200.188", 5228,
                                      b'\x00\x01\x00\x00')


# ============================================================
# Tests
# ============================================================

class TestSniParser(unittest.TestCase):
    """Test the SNI parser directly with crafted packets."""

    def test_basic_sni_extraction(self):
        """Extract SNI from a standard ClientHello."""
        client_hello = build_tls_client_hello("google.com")
        # Wrap in IP+TCP
        pkt = build_data_packet("10.20.0.2", "142.250.185.78", 43210, 443,
                                100, 200, client_hello)
        domain = extract_sni(pkt)
        self.assertEqual(domain, "google.com")

    def test_sni_with_subdomain(self):
        """Extract SNI with subdomain."""
        pkt = build_data_packet("10.20.0.2", "104.18.10.45", 43210, 443,
                                100, 200,
                                build_tls_client_hello("api.example.com"))
        self.assertEqual(extract_sni(pkt), "api.example.com")

    def test_sni_with_long_domain(self):
        """Extract SNI with a long domain name."""
        hostname = "very-long-subdomain.name.example.co.uk"
        pkt = build_data_packet("10.20.0.2", "1.2.3.4", 43210, 443,
                                100, 200,
                                build_tls_client_hello(hostname))
        self.assertEqual(extract_sni(pkt), hostname)

    def test_no_sni_in_syn(self):
        """SYN packet has no TLS payload."""
        syn = build_syn_packet("10.20.0.2", "142.250.185.78", 43210, 443, 100)
        self.assertIsNone(extract_sni(syn))

    def test_no_sni_in_syn_ack(self):
        """SYN-ACK packet has no TLS payload."""
        syn_ack = build_syn_ack_packet("142.250.185.78", "10.20.0.2", 443, 43210, 200, 101)
        self.assertIsNone(extract_sni(syn_ack))

    def test_no_sni_in_ack(self):
        """Pure ACK packet has no TLS payload."""
        ack = build_ack_packet("10.20.0.2", "142.250.185.78", 43210, 443, 101, 201)
        self.assertIsNone(extract_sni(ack))

    def test_no_sni_in_server_hello(self):
        """ServerHello doesn't contain SNI."""
        server_hello = build_tls_server_hello()
        pkt = build_data_packet("142.250.185.78", "10.20.0.2", 443, 43210,
                                201, 101, server_hello)
        # ServerHello is downlink, but extract_sni doesn't check direction
        # It should still find TLS Handshake but not ClientHello
        self.assertIsNone(extract_sni(pkt))

    def test_no_sni_in_udp(self):
        """UDP packets are ignored."""
        pkt = build_udp_packet("10.20.0.2", "8.8.8.8", 54321, 53, b'\x00' * 20)
        self.assertIsNone(extract_sni(pkt))

    def test_no_sni_in_non_tls_tcp(self):
        """Non-TLS TCP payload is ignored."""
        pkt = build_data_packet("10.20.0.2", "142.250.185.78", 43210, 80,
                                100, 200,
                                b'GET / HTTP/1.1\r\nHost: google.com\r\n\r\n')
        self.assertIsNone(extract_sni(pkt))

    def test_sni_non_standard_port(self):
        """SNI extracted from non-443 port."""
        pkt = build_data_packet("10.20.0.2", "1.2.3.4", 43210, 8443,
                                100, 200,
                                build_tls_client_hello("cdn.example.com"))
        self.assertEqual(extract_sni(pkt), "cdn.example.com")

    def test_sni_port_993(self):
        """SNI extracted from IMAPS port."""
        pkt = build_data_packet("10.20.0.2", "1.2.3.4", 43210, 993,
                                100, 200,
                                build_tls_client_hello("imap.gmail.com"))
        self.assertEqual(extract_sni(pkt), "imap.gmail.com")

    def test_sni_port_465(self):
        """SNI extracted from SMTPS port."""
        pkt = build_data_packet("10.20.0.2", "1.2.3.4", 43210, 465,
                                100, 200,
                                build_tls_client_hello("smtp.gmail.com"))
        self.assertEqual(extract_sni(pkt), "smtp.gmail.com")

    def test_sni_ip_only(self):
        """SNI with IP literal (some clients send this)."""
        pkt = build_data_packet("10.20.0.2", "1.2.3.4", 43210, 443,
                                100, 200,
                                build_tls_client_hello("1.2.3.4"))
        self.assertEqual(extract_sni(pkt), "1.2.3.4")

    def test_empty_packet(self):
        """Empty packet returns None."""
        self.assertIsNone(extract_sni(b''))

    def test_tiny_packet(self):
        """Packet too small for IP header."""
        self.assertIsNone(extract_sni(b'\x45'))

    def test_ipv6_ignored(self):
        """IPv6 packets ignored."""
        pkt = bytearray(b'\x60' + b'\x00' * 39)
        self.assertIsNone(extract_sni(bytes(pkt)))


class TestFlowTracker(unittest.TestCase):
    """Test the flow tracker with simulated traffic."""

    def setUp(self):
        self.tracker = PacketFlowTracker()

    def test_dns_tracked_as_udp(self):
        """DNS queries show as UDP flows."""
        dns = build_udp_packet(CLIENT_IP, LOCAL_DNS, 54321, 53,
                               build_dns_query("google.com"))
        self.tracker.process_packet(dns, is_uplink=True)

        flows = self.tracker.get_flows()
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].protocol, "UDP")
        self.assertEqual(flows[0].remote_port, 53)
        self.assertIsNone(flows[0].domain)  # DNS is UDP, no SNI

    def test_tls_handshake_creates_flow_with_domain(self):
        """Full TLS handshake results in flow with domain."""
        sim = TrafficSimulator()
        sim.tracker = self.tracker
        sim.simulate_tls_connection("142.250.185.78", "google.com")

        flows = self.tracker.get_flows()
        # Find the TLS flow
        tls_flows = [f for f in flows if f.protocol == "TCP" and f.remote_port == 443]
        self.assertTrue(len(tls_flows) > 0, "No TLS flow found")

        tls_flow = tls_flows[0]
        self.assertEqual(tls_flow.domain, "google.com")
        self.assertEqual(tls_flow.remote_ip, "142.250.185.78")

    def test_sni_counter_increments(self):
        """Debug counter tracks SNI extractions."""
        sim = TrafficSimulator()
        sim.tracker = self.tracker

        sim.simulate_tls_connection("142.250.185.78", "google.com")
        self.assertEqual(self.tracker.sni_extracted, 1)

        sim.simulate_tls_connection("151.101.1.140", "reddit.com")
        self.assertEqual(self.tracker.sni_extracted, 2)

    def test_cache_hit_on_downlink(self):
        """Downlink packets get domain from cache."""
        sim = TrafficSimulator()
        sim.tracker = self.tracker

        # First: uplink with ClientHello
        sim.simulate_tls_connection("142.250.185.78", "google.com")
        cache_before = self.tracker.cache_hits

        # Then: another downlink packet for same IP
        downlink = build_data_packet("142.250.185.78", CLIENT_IP, 443, 30000,
                                     5000, 5000, b'\x17\x03\x03' + b'\x00' * 100)
        self.tracker.process_packet(downlink, is_uplink=False)

        self.assertGreater(self.tracker.cache_hits, cache_before)

    def test_domain_propagates_to_existing_flow(self):
        """Domain set on first flow creation propagates correctly."""
        # Create flow without domain (SYN only)
        syn = build_syn_packet(CLIENT_IP, "142.250.185.78", 30000, 443, 1000)
        self.tracker.process_packet(syn, is_uplink=True)

        flows = self.tracker.get_flows()
        self.assertEqual(len(flows), 1)
        self.assertIsNone(flows[0].domain)

        # Now send ClientHello — should update the existing flow
        client_hello = build_tls_client_hello("google.com")
        ch_pkt = build_data_packet(CLIENT_IP, "142.250.185.78", 30000, 443,
                                   1001, 2000, client_hello)
        self.tracker.process_packet(ch_pkt, is_uplink=True)

        flows = self.tracker.get_flows()
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].domain, "google.com")

    def test_multiple_concurrent_connections(self):
        """Multiple TLS connections all get their domains."""
        sim = TrafficSimulator()
        sim.tracker = self.tracker

        domains = [
            ("142.250.185.78", "google.com"),
            ("151.101.1.140", "reddit.com"),
            ("104.18.10.45", "api.example.com"),
            ("13.107.42.14", "teams.microsoft.com"),
            ("31.13.65.36", "www.facebook.com"),
        ]

        for ip, domain in domains:
            sim.simulate_tls_connection(ip, domain)

        flows = self.tracker.get_flows()
        tls_flows = [f for f in flows if f.protocol == "TCP" and f.remote_port == 443]
        found_domains = {f.domain for f in tls_flows if f.domain}

        for _, domain in domains:
            self.assertIn(domain, found_domains,
                          f"Domain {domain} not found in flows")

    def test_clear_resets_everything(self):
        """Clear() resets flows, cache, and counters."""
        sim = TrafficSimulator()
        sim.tracker = self.tracker

        sim.simulate_tls_connection("142.250.185.78", "google.com")
        self.assertGreater(len(self.tracker.flows), 0)
        self.assertGreater(self.tracker.total_packets, 0)
        self.assertGreater(self.tracker.sni_extracted, 0)

        self.tracker.clear()

        self.assertEqual(len(self.tracker.flows), 0)
        self.assertEqual(self.tracker.total_packets, 0)
        self.assertEqual(self.tracker.sni_extracted, 0)
        self.assertEqual(self.tracker.cache_hits, 0)
        self.assertEqual(self.tracker.domain_cache.size(), 0)

    def test_debug_stats_format(self):
        """Debug stats string contains all counters."""
        sim = TrafficSimulator()
        sim.tracker = self.tracker
        sim.simulate_tls_connection("142.250.185.78", "google.com")

        stats = self.tracker.get_debug_stats()
        self.assertIn("packets=", stats)
        self.assertIn("uplinkTcp=", stats)
        self.assertIn("sniExtracted=", stats)
        self.assertIn("cacheHits=", stats)
        self.assertIn("flows=", stats)
        self.assertIn("cacheSize=", stats)


class TestTrafficSimulation(unittest.TestCase):
    """Test realistic traffic simulation scenarios."""

    def setUp(self):
        self.sim = TrafficSimulator()

    def test_full_browser_session(self):
        """Simulate a full browsing session: 5 sites + background noise."""
        sites = [
            ("142.250.185.78", "www.google.com"),
            ("151.101.1.140", "www.reddit.com"),
            ("104.18.10.45", "api.github.com"),
            ("13.107.42.14", "teams.microsoft.com"),
            ("31.13.65.36", "www.facebook.com"),
        ]

        for ip, hostname in sites:
            self.sim.simulate_browser_tab(hostname, ip)

        self.sim.simulate_background_noise()

        tracker = self.sim.tracker
        flows = tracker.get_flows()

        # Should have flows for all sites
        self.assertGreater(len(flows), 0)

        # Check domains are extracted
        domains_found = {f.domain for f in flows if f.domain}
        for _, hostname in sites:
            self.assertIn(hostname, domains_found,
                          f"Domain {hostname} not found after browsing session")

        # Debug stats should show progress
        self.assertGreater(tracker.sni_extracted, 0)
        self.assertGreater(tracker.cache_hits, 0)
        self.assertGreater(tracker.total_packets, 0)

        print(f"\n=== Browser Session Results ===")
        print(f"Flows: {len(flows)}")
        print(f"Domains found: {domains_found}")
        print(f"Debug: {tracker.get_debug_stats()}")

    def test_heavy_tab_scenario(self):
        """Simulate 10+ tabs opening simultaneously."""
        domains = [
            ("142.250.185.78", "www.google.com"),
            ("151.101.1.140", "www.reddit.com"),
            ("104.18.10.45", "api.github.com"),
            ("13.107.42.14", "teams.microsoft.com"),
            ("31.13.65.36", "www.facebook.com"),
            ("151.101.65.69", "www.nytimes.com"),
            ("104.16.132.229", "blog.cloudflare.com"),
            ("172.217.14.206", "accounts.youtube.com"),
            ("20.190.151.68", "login.live.com"),
            ("52.96.108.18", "outlook.office365.com"),
        ]

        # Open all tabs in quick succession
        for ip, hostname in domains:
            self.sim.simulate_browser_tab(hostname, ip)

        flows = self.sim.tracker.get_flows()
        tls_flows = [f for f in flows if f.protocol == "TCP" and f.domain]

        print(f"\n=== Heavy Tab Results ===")
        print(f"Total flows: {len(flows)}")
        print(f"TLS flows with domains: {len(tls_flows)}")
        for f in tls_flows:
            print(f"  🔒 {f.domain} ({f.remote_ip}:{f.remote_port}) "
                  f"↑{f.uplink_bytes}B ↓{f.downlink_bytes}B")
        print(f"Debug: {self.sim.tracker.get_debug_stats()}")

        # All TLS flows should have domains
        for f in flows:
            if f.protocol == "TCP" and f.remote_port == 443:
                self.assertIsNotNone(f.domain,
                    f"Flow {f.remote_ip}:{f.remote_port} missing domain!")

    def test_non_tls_traffic_no_domain(self):
        """Non-TLS traffic should show IP:port, not domain."""
        # HTTP (port 80) — no TLS
        self.sim.simulate_non_tls_traffic("93.184.216.34", 80,
                                          b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n')
        # SSH (port 22)
        self.sim.simulate_non_tls_traffic("192.168.1.1", 22, b'\x00' * 50)

        flows = self.sim.tracker.get_flows()
        for f in flows:
            self.assertIsNone(f.domain,
                f"Non-TLS flow {f.remote_ip}:{f.remote_port} should not have domain")

    def test_udp_traffic_no_domain(self):
        """UDP flows (DNS, QUIC-like) have no SNI domain."""
        self.sim.simulate_dns_query("google.com")
        self.sim.simulate_udp_traffic("142.250.185.78", 443,
                                      b'\x00' * 100)  # QUIC-like

        flows = self.sim.tracker.get_flows()
        for f in flows:
            if f.protocol == "UDP":
                self.assertIsNone(f.domain)

    def test_mixed_traffic_stats(self):
        """Mixed traffic produces correct aggregate stats."""
        # 3 TLS connections
        self.sim.simulate_tls_connection("142.250.185.78", "google.com")
        self.sim.simulate_tls_connection("151.101.1.140", "reddit.com")
        self.sim.simulate_tls_connection("104.18.10.45", "api.github.com")

        # 2 DNS queries
        self.sim.simulate_dns_query("google.com")
        self.sim.simulate_dns_query("reddit.com")

        # 1 non-TLS TCP
        self.sim.simulate_non_tls_traffic("93.184.216.34", 80,
                                          b'GET / HTTP/1.1\r\n\r\n')

        tracker = self.sim.tracker
        flows = tracker.get_flows()

        # Verify composition
        tcp_flows = [f for f in flows if f.protocol == "TCP"]
        udp_flows = [f for f in flows if f.protocol == "UDP"]
        tls_flows = [f for f in tcp_flows if f.remote_port == 443]
        domains_found = {f.domain for f in tls_flows if f.domain}

        print(f"\n=== Mixed Traffic Stats ===")
        print(f"Total flows: {len(flows)}")
        print(f"TCP: {len(tcp_flows)}, UDP: {len(udp_flows)}")
        print(f"TLS with domains: {len(tls_flows)} → {domains_found}")
        print(f"Packets: {tracker.total_packets}")
        print(f"SNI extracted: {tracker.sni_extracted}")
        print(f"Cache hits: {tracker.cache_hits}")

        self.assertEqual(len(tls_flows), 3)
        self.assertEqual(domains_found, {"google.com", "reddit.com", "api.github.com"})

    def test_domain_cache_prevents_re_extraction(self):
        """Once a domain is cached, subsequent packets use cache."""
        # First connection extracts SNI — this also generates cache hits
        # from downlink packets within the same connection (SYN-ACK, ServerHello, data)
        self.sim.simulate_tls_connection("142.250.185.78", "google.com")
        self.assertEqual(self.sim.tracker.sni_extracted, 1)
        initial_sni = self.sim.tracker.sni_extracted
        initial_cache = self.sim.tracker.cache_hits
        self.assertGreater(initial_cache, 0)  # Downlink packets used cache

        # Now send MORE downlink packets to same IP — all should use cache
        for _ in range(5):
            downlink = build_data_packet("142.250.185.78", CLIENT_IP, 443, 30000,
                                         5000, 5000, b'\x17\x03\x03' + b'\x00' * 100)
            self.sim.tracker.process_packet(downlink, is_uplink=False)

        # No new SNI extractions, but more cache hits
        self.assertEqual(self.sim.tracker.sni_extracted, initial_sni)
        self.assertGreater(self.sim.tracker.cache_hits, initial_cache)


class TestEdgeCases(unittest.TestCase):
    """Edge cases and stress tests."""

    def test_fragmented_client_hello(self):
        """ClientHello split across TCP segments — first segment may not have full SNI."""
        # Build a ClientHello
        client_hello = build_tls_client_hello("google.com")

        # Split it: first 10 bytes of TLS in first packet, rest in second
        split_point = 10
        first_segment = client_hello[:split_point]
        second_segment = client_hello[split_point:]

        # First segment — too small for SNI
        pkt1 = build_data_packet("10.20.0.2", "142.250.185.78", 30000, 443,
                                 100, 200, first_segment)
        self.assertIsNone(extract_sni(pkt1))

        # Second segment — not a valid TLS record start
        pkt2 = build_data_packet("10.20.0.2", "142.250.185.78", 30000, 443,
                                 100 + split_point, 200, second_segment)
        # This won't extract SNI because it doesn't start with TLS record header
        # In real TCP, the kernel reassembles before TUN sees it, so this is expected
        self.assertIsNone(extract_sni(pkt2))

    def test_many_unique_domains(self):
        """500 unique domains don't crash the tracker."""
        tracker = PacketFlowTracker()
        for i in range(500):
            ip = f"10.0.{i // 256}.{i % 256}"
            domain = f"site{i}.example.com"
            pkt = build_data_packet(CLIENT_IP, ip, 30000 + i, 443,
                                    100, 200,
                                    build_tls_client_hello(domain))
            tracker.process_packet(pkt, is_uplink=True)

        flows = tracker.get_flows()
        self.assertEqual(len(flows), 500)
        domains = {f.domain for f in flows if f.domain}
        self.assertEqual(len(domains), 500)

    def test_same_ip_different_ports(self):
        """Same IP, different ports = different flows."""
        tracker = PacketFlowTracker()
        for port in [443, 8443, 9443]:
            domain = f"port{port}.example.com"
            pkt = build_data_packet(CLIENT_IP, "1.2.3.4", 30000 + port, port,
                                    100, 200,
                                    build_tls_client_hello(domain))
            tracker.process_packet(pkt, is_uplink=True)

        flows = tracker.get_flows()
        self.assertEqual(len(flows), 3)
        for f in flows:
            self.assertIsNotNone(f.domain)

    def test_domain_lowercase_normalized(self):
        """Domains are stored in lowercase."""
        tracker = PacketFlowTracker()
        pkt = build_data_packet(CLIENT_IP, "1.2.3.4", 30000, 443,
                                100, 200,
                                build_tls_client_hello("GOOGLE.COM"))
        tracker.process_packet(pkt, is_uplink=True)

        flows = tracker.get_flows()
        self.assertEqual(flows[0].domain, "google.com")

    def test_flow_eviction_at_capacity(self):
        """Oldest flow evicted when MAX_FLOWS reached."""
        tracker = PacketFlowTracker()
        tracker.MAX_FLOWS = 5  # Small for testing

        for i in range(10):
            ip = f"10.0.0.{i + 1}"
            pkt = build_syn_packet(CLIENT_IP, ip, 30000 + i, 443, 100)
            tracker.process_packet(pkt, is_uplink=True)

        self.assertLessEqual(len(tracker.flows), 5)


class TestConcurrentAccess(unittest.TestCase):
    """Test thread safety of the flow tracker."""

    def test_concurrent_writes_and_reads(self):
        """Multiple threads writing/reading simultaneously."""
        tracker = PacketFlowTracker()
        errors = []

        def writer_thread(thread_id: int, domain: str, ip: str):
            try:
                for _ in range(50):
                    pkt = build_data_packet(CLIENT_IP, ip, 30000 + thread_id, 443,
                                            100, 200,
                                            build_tls_client_hello(domain))
                    tracker.process_packet(pkt, is_uplink=True)
                    time.sleep(0.001)
            except Exception as e:
                errors.append(f"Writer {thread_id}: {e}")

        def reader_thread():
            try:
                for _ in range(100):
                    flows = tracker.get_flows()
                    stats = tracker.get_debug_stats()
                    _ = tracker.domain_cache.size()
                    time.sleep(0.001)
            except Exception as e:
                errors.append(f"Reader: {e}")

        threads = []
        # 5 writer threads
        for i in range(5):
            t = threading.Thread(target=writer_thread,
                                args=(i, f"site{i}.example.com", f"10.0.0.{i}"))
            threads.append(t)
        # 3 reader threads
        for _ in range(3):
            t = threading.Thread(target=reader_thread)
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        self.assertEqual(errors, [], f"Concurrent access errors: {errors}")
        self.assertGreater(len(tracker.flows), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
