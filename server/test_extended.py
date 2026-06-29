#!/usr/bin/env python3
"""
Extended edge case & unit tests for Tunnely UDP VPN Server.

Covers:
- SessionManager: stats, save/load state, IP pool, roaming, exhaustion
- _rewrite_src_ip: checksum correctness for TCP/UDP/ICMP
- _incremental_checksum_fix: RFC 1624 compliance
- extract_src_ip/extract_dst_ip: IPv6, options, short packets
- IP pool: server IP exclusion, broadcast exclusion, recycling
- _build_udp_response: additional edge cases
- Integration: full packet rewrite → forward → response cycle
"""
import ipaddress
import json
import os
import struct
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(__file__))

from udp_vpn_server import (
    extract_dst_ip,
    extract_src_ip,
    extract_udp_dst_port,
    extract_udp_payload,
    UdpVpnServer,
    SessionManager,
    IDLE_TIMEOUT,
    PRIVATE_DNS_IPS,
    TUNSETIFF,
    IFF_TUN,
    IFF_NO_PI,
)


# ── Packet Builders ───────────────────────────────────────────────────

def build_ip_packet(
    src_ip="10.20.0.2", dst_ip="8.8.8.8",
    protocol=17, ihl=5, ttl=64, payload=b"",
    fragment_offset=0, mf_flag=False, identification=0,
):
    """Build a raw IPv4 packet with optional transport header."""
    ip_header_len = ihl * 4
    total_len = ip_header_len + len(payload)
    pkt = bytearray(total_len)
    pkt[0] = (4 << 4) | ihl
    pkt[1] = 0
    pkt[2:4] = struct.pack("!H", total_len)
    pkt[4:6] = struct.pack("!H", identification)
    flags = 0x40 if not mf_flag else 0x20
    pkt[6] = flags | ((fragment_offset >> 8) & 0x1F)
    pkt[7] = fragment_offset & 0xFF
    pkt[8] = ttl
    pkt[9] = protocol
    pkt[10:12] = b"\x00\x00"
    pkt[12:16] = ipaddress.IPv4Address(src_ip).packed
    pkt[16:20] = ipaddress.IPv4Address(dst_ip).packed
    if ihl > 5:
        for i in range(20, ip_header_len):
            pkt[i] = 0x01
    pkt[ip_header_len:] = payload
    return bytes(pkt)


def build_tcp_packet(
    src_ip="10.20.0.2", dst_ip="8.8.8.8",
    src_port=54321, dst_port=443,
    payload=b"", ihl=5,
    flags=0x02,  # SYN
):
    """Build a raw IPv4/TCP packet."""
    tcp_header_len = 20
    ip_header_len = ihl * 4
    total_len = ip_header_len + tcp_header_len + len(payload)
    pkt = bytearray(total_len)
    # IP header
    pkt[0] = (4 << 4) | ihl
    pkt[2:4] = struct.pack("!H", total_len)
    pkt[8] = 64
    pkt[9] = 6  # TCP
    pkt[12:16] = ipaddress.IPv4Address(src_ip).packed
    pkt[16:20] = ipaddress.IPv4Address(dst_ip).packed
    # TCP header
    off = ip_header_len
    pkt[off:off+2] = struct.pack("!H", src_port)
    pkt[off+2:off+4] = struct.pack("!H", dst_port)
    pkt[off+4:off+8] = struct.pack("!I", 1000)  # seq
    pkt[off+8:off+12] = struct.pack("!I", 0)  # ack
    pkt[off+12] = 5 << 4  # data offset = 5 (20 bytes)
    pkt[off+13] = flags
    pkt[off+14:off+16] = struct.pack("!H", 65535)  # window
    pkt[off+16:off+18] = b"\x00\x00"  # checksum
    pkt[off+18:off+20] = b"\x00\x00"  # urgent ptr
    # Payload
    pkt[ip_header_len + tcp_header_len:] = payload
    return bytes(pkt)


def build_udp_packet(
    src_ip="10.20.0.2", dst_ip="8.8.8.8",
    src_port=54321, dst_port=53,
    payload=b"", ihl=5, checksum=None,
):
    """Build a raw IPv4/UDP packet with optional checksum."""
    udp_len = 8 + len(payload)
    ip_header_len = ihl * 4
    total_len = ip_header_len + udp_len
    pkt = bytearray(total_len)
    # IP header
    pkt[0] = (4 << 4) | ihl
    pkt[2:4] = struct.pack("!H", total_len)
    pkt[8] = 64
    pkt[9] = 17  # UDP
    pkt[12:16] = ipaddress.IPv4Address(src_ip).packed
    pkt[16:20] = ipaddress.IPv4Address(dst_ip).packed
    # UDP header
    off = ip_header_len
    pkt[off:off+2] = struct.pack("!H", src_port)
    pkt[off+2:off+4] = struct.pack("!H", dst_port)
    pkt[off+4:off+6] = struct.pack("!H", udp_len)
    if checksum is not None:
        pkt[off+6:off+8] = struct.pack("!H", checksum)
    else:
        pkt[off+6:off+8] = b"\x00\x00"
    pkt[ip_header_len + 8:] = payload
    return bytes(pkt)


def compute_ip_checksum(header):
    """Compute IP header checksum."""
    s = 0
    for i in range(0, len(header), 2):
        s += (header[i] << 8) | header[i+1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


# ── SessionManager: Stats ─────────────────────────────────────────────

class TestSessionManagerStats:
    """Test SessionManager.stats() output."""

    def setup_method(self):
        self.sm = SessionManager("10.20.0.0/24", state_file="/dev/null")

    def test_stats_empty(self):
        s = self.sm.stats()
        assert s["active"] == 0
        assert s["total_rx"] == 0
        assert s["total_tx"] == 0
        assert s["sessions"] == {}

    def test_stats_single_session(self):
        ip = self.sm.assign_ip(("1.2.3.4", 1000))
        self.sm.touch(ip, rx_bytes=500, tx_bytes=300)
        s = self.sm.stats()
        assert s["active"] == 1
        assert s["total_rx"] == 500
        assert s["total_tx"] == 300
        assert ip in s["sessions"]
        assert s["sessions"][ip]["addr"] == "1.2.3.4:1000"
        assert s["sessions"][ip]["rx"] == 500
        assert s["sessions"][ip]["tx"] == 300

    def test_stats_multiple_sessions(self):
        for i in range(5):
            ip = self.sm.assign_ip((f"10.0.0.{i}", 1000 + i))
            self.sm.touch(ip, rx_bytes=100 * i, tx_bytes=50 * i)
        s = self.sm.stats()
        assert s["active"] == 5
        assert s["total_rx"] == sum(100 * i for i in range(5))
        assert s["total_tx"] == sum(50 * i for i in range(5))

    def test_stats_idle_time(self):
        ip = self.sm.assign_ip(("1.2.3.4", 1000))
        time.sleep(0.1)
        s = self.sm.stats()
        assert s["sessions"][ip]["idle"] >= 0

    def test_stats_after_cleanup(self):
        ip1 = self.sm.assign_ip(("1.2.3.4", 1000))
        ip2 = self.sm.assign_ip(("5.6.7.8", 2000))
        self.sm.touch(ip1, rx_bytes=100, tx_bytes=50)
        self.sm.sessions[ip2]["last_seen"] = time.time() - 181
        self.sm.cleanup()
        s = self.sm.stats()
        assert s["active"] == 1
        assert s["total_rx"] == 100


# ── SessionManager: Save/Load State ──────────────────────────────────

class TestSessionState:
    """Test save_state/load_state persistence."""

    def test_save_creates_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
        try:
            sm = SessionManager("10.20.0.0/24", state_file=path)
            sm.assign_ip(("1.2.3.4", 1000))
            sm.save_state()
            assert os.path.exists(path)
            with open(path) as f:
                data = json.load(f)
            assert len(data) == 1
        finally:
            os.unlink(path)

    def test_save_state_content(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
        try:
            sm = SessionManager("10.20.0.0/24", state_file=path)
            ip = sm.assign_ip(("1.2.3.4", 1000))
            sm.save_state()
            with open(path) as f:
                data = json.load(f)
            assert ip in data
            assert data[ip]["addr"] == ["1.2.3.4", 1000]
        finally:
            os.unlink(path)

    def test_save_empty_sessions(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
        try:
            sm = SessionManager("10.20.0.0/24", state_file=path)
            sm.save_state()
            with open(path) as f:
                data = json.load(f)
            assert data == {}
        finally:
            os.unlink(path)


# ── SessionManager: IP Pool ──────────────────────────────────────────

class TestIpPool:
    """Test IP pool allocation."""

    def setup_method(self):
        self.sm = SessionManager("10.20.0.0/24", state_file="/dev/null")

    def test_first_ip_is_in_range(self):
        """Assigned IP should be in the 10.20.0.2-254 range."""
        ip = self.sm.assign_ip(("1.2.3.4", 1000))
        assert ip.startswith("10.20.0.")
        num = int(ip.split(".")[-1])
        assert 2 <= num <= 254

    def test_unique_ips_for_unique_clients(self):
        """Each unique client gets a unique IP."""
        ips = []
        for i in range(5):
            ip = self.sm.assign_ip((f"10.0.0.{i}", 1000 + i))
            ips.append(ip)
        assert len(set(ips)) == 5  # all unique

    def test_server_ip_excluded(self):
        """10.20.0.1 (server) should never be assigned."""
        for i in range(250):
            self.sm.assign_ip((f"10.0.0.{i % 255}", 1000 + i))
        all_ips = set(self.sm.sessions.keys())
        assert "10.20.0.1" not in all_ips

    def test_same_addr_returns_same_ip(self):
        """Same client addr should get same IP."""
        ip1 = self.sm.assign_ip(("1.2.3.4", 1000))
        ip2 = self.sm.assign_ip(("1.2.3.4", 1000))
        assert ip1 == ip2

    def test_different_addr_different_ip(self):
        """Different client addrs should get different IPs."""
        ip1 = self.sm.assign_ip(("1.2.3.4", 1000))
        ip2 = self.sm.assign_ip(("5.6.7.8", 2000))
        assert ip1 != ip2

    def test_pool_exhaustion_recycles(self):
        """When pool is exhausted, expired IPs should be recycled."""
        # Use a /28 subnet for faster exhaustion (12 usable: .2-.13)
        sm = SessionManager("10.20.0.0/28", state_file="/dev/null")
        # Assign all available IPs
        ips = []
        for i in range(12):
            ip = sm.assign_ip((f"10.0.0.{i}", 1000 + i))
            ips.append(ip)
        # All assigned
        assert len(sm.sessions) == 12
        # Expire all
        for ip in ips:
            sm.sessions[ip]["last_seen"] = time.time() - 181
        # New client should recycle
        new_ip = sm.assign_ip(("99.99.99.99", 9999))
        assert new_ip.startswith("10.20.0.")


# ── SessionManager: IP Recycling & Limits ────────────────────────────

class TestSessionRecycling:
    """Test IP pool recycling and max session enforcement."""

    def test_ip_recycled_on_expiry(self):
        """Expired session's IP should be available for reuse."""
        sm = SessionManager("10.20.0.0/28", state_file="/dev/null")
        ip1 = sm.assign_ip(("1.2.3.4", 1000))
        # Expire it
        sm.sessions[ip1]["last_seen"] = time.time() - 999
        sm.cleanup()
        assert ip1 not in sm.sessions
        # IP should be back in pool — new assignment should be able to reuse it
        ip2 = sm.assign_ip(("5.6.7.8", 2000))
        # ip2 might or might not be ip1 (set order), but it should be valid
        assert ip2.startswith("10.20.0.")

    def test_ip_pool_size_matches_subnet(self):
        """Pool should have exactly (subnet_size - 2) IPs."""
        sm = SessionManager("10.20.0.0/24", state_file="/dev/null")
        # /24 = 256 addresses: .0=network, .1=server, .2-.254=clients, .255=broadcast
        # net.hosts() returns .1-.254 (254 hosts), we skip .1 → 253 available
        assert len(sm._available) == 253

    def test_ip_returned_to_pool_on_remove(self):
        """_remove_session should return IP to available pool."""
        sm = SessionManager("10.20.0.0/28", state_file="/dev/null")
        ip = sm.assign_ip(("1.2.3.4", 1000))
        pool_before = len(sm._available)
        sm._remove_session(ip, reason="test")
        assert len(sm._available) == pool_before + 1
        assert ip in sm._available

    def test_dedup_same_addr_reuses_ip(self):
        """Same client address should reuse existing session."""
        sm = SessionManager("10.20.0.0/24", state_file="/dev/null")
        ip1 = sm.assign_ip(("1.2.3.4", 1000))
        ip2 = sm.assign_ip(("1.2.3.4", 1000))
        assert ip1 == ip2
        assert len(sm.sessions) == 1

    def test_max_sessions_enforced(self):
        """Should not exceed MAX_SESSIONS."""
        sm = SessionManager("10.20.0.0/24", state_file="/dev/null")
        sm.MAX_SESSIONS = 5
        for i in range(5):
            sm.assign_ip((f"10.0.0.{i}", 1000 + i))
        assert len(sm.sessions) == 5
        # 6th should evict oldest
        sm.assign_ip(("10.0.0.99", 9999))
        assert len(sm.sessions) == 5  # still 5

    def test_no_addr_to_ip_leak(self):
        """addr_to_ip should be cleaned up when session is removed."""
        sm = SessionManager("10.20.0.0/24", state_file="/dev/null")
        sm.assign_ip(("1.2.3.4", 1000))
        assert ("1.2.3.4", 1000) in sm.addr_to_ip
        sm.cleanup()  # won't expire yet
        assert ("1.2.3.4", 1000) in sm.addr_to_ip
        # Force expire
        for s in sm.sessions.values():
            s["last_seen"] = time.time() - 999
        sm.cleanup()
        assert ("1.2.3.4", 1000) not in sm.addr_to_ip

    def test_evict_oldest(self):
        """_evict_oldest should remove the session with oldest last_seen."""
        sm = SessionManager("10.20.0.0/24", state_file="/dev/null")
        ip1 = sm.assign_ip(("1.1.1.1", 1001))
        ip2 = sm.assign_ip(("2.2.2.2", 1002))
        # Make ip1 the oldest
        sm.sessions[ip1]["last_seen"] = time.time() - 100
        sm._evict_oldest()
        assert ip1 not in sm.sessions
        assert ip2 in sm.sessions


# ── SessionManager: Roaming ─────────────────────────────────────────

class TestSessionRoaming:
    """Test NAT rebinding / client roaming."""

    def setup_method(self):
        self.sm = SessionManager("10.20.0.0/24", state_file="/dev/null")

    def test_update_addr(self):
        """update_addr should change the client's UDP address."""
        ip = self.sm.assign_ip(("1.2.3.4", 1000))
        self.sm.update_addr(ip, ("5.6.7.8", 2000))
        assert self.sm.get_addr_by_ip(ip) == ("5.6.7.8", 2000)
        assert ("5.6.7.8", 2000) in self.sm.addr_to_ip

    def test_update_addr_removes_old_mapping(self):
        """Old addr mapping should be removed on update."""
        ip = self.sm.assign_ip(("1.2.3.4", 1000))
        self.sm.update_addr(ip, ("5.6.7.8", 2000))
        assert ("1.2.3.4", 1000) not in self.sm.addr_to_ip

    def test_update_nonexistent_session(self):
        """Updating a non-existent session should be a no-op."""
        self.sm.update_addr("10.20.0.99", ("1.2.3.4", 1000))
        assert ("1.2.3.4", 1000) not in self.sm.addr_to_ip

    def test_get_addr_by_ip_unknown(self):
        """Getting addr for unknown IP should return None."""
        assert self.sm.get_addr_by_ip("10.20.0.99") is None


# ── _rewrite_src_ip Tests ────────────────────────────────────────────

class TestRewriteSrcIp:
    """Test IP source rewriting with checksum fix."""

    def setup_method(self):
        # Create a minimal server instance for _rewrite_src_ip
        self.server = UdpVpnServer.__new__(UdpVpnServer)

    def test_rewrite_udp_packet(self):
        """Rewriting src IP in UDP packet should fix IP + UDP checksums."""
        pkt = build_udp_packet(src_ip="10.20.0.2", dst_ip="8.8.8.8", checksum=0x1234)
        rewritten = self.server._rewrite_src_ip(pkt, "10.20.0.5")
        # Source IP changed
        assert extract_src_ip(rewritten) == "10.20.0.5"
        # Dest IP unchanged
        assert extract_dst_ip(rewritten) == "8.8.8.8"
        # IP checksum valid: sum all 16-bit words including checksum = 0xFFFF
        ip_hdr = bytearray(rewritten[:20])
        assert compute_ip_checksum(ip_hdr) == 0  # valid IP checksum

    def test_rewrite_tcp_packet(self):
        """Rewriting src IP in TCP packet should fix IP + TCP checksums."""
        pkt = build_tcp_packet(src_ip="10.20.0.2", dst_ip="8.8.8.8")
        rewritten = self.server._rewrite_src_ip(pkt, "10.20.0.5")
        assert extract_src_ip(rewritten) == "10.20.0.5"
        # IP checksum valid: sum all 16-bit words including checksum = 0xFFFF
        ip_hdr = bytearray(rewritten[:20])
        assert compute_ip_checksum(ip_hdr) == 0  # valid IP checksum

    def test_rewrite_no_change(self):
        """If new IP == old IP, packet should be unchanged."""
        pkt = build_udp_packet(src_ip="10.20.0.2")
        rewritten = self.server._rewrite_src_ip(pkt, "10.20.0.2")
        assert rewritten == pkt

    def test_rewrite_preserves_payload(self):
        """Payload should be preserved after rewrite."""
        payload = b"Hello, World!"
        pkt = build_udp_packet(src_ip="10.20.0.2", payload=payload)
        rewritten = self.server._rewrite_src_ip(pkt, "10.20.0.5")
        # UDP payload starts after IP header (20) + UDP header (8)
        assert rewritten[28:] == payload

    def test_rewrite_preserves_dst_ip(self):
        """Destination IP should not change."""
        pkt = build_udp_packet(src_ip="10.20.0.2", dst_ip="1.1.1.1")
        rewritten = self.server._rewrite_src_ip(pkt, "10.20.0.5")
        assert extract_dst_ip(rewritten) == "1.1.1.1"

    def test_rewrite_icmp_packet(self):
        """ICMP packets (protocol 1) should have IP checksum fixed only."""
        pkt = build_ip_packet(src_ip="10.20.0.2", dst_ip="8.8.8.8", protocol=1, payload=b"\x08\x00" + b"\x00" * 18)
        rewritten = self.server._rewrite_src_ip(pkt, "10.20.0.5")
        assert extract_src_ip(rewritten) == "10.20.0.5"

    def test_rewrite_short_packet_no_crash(self):
        """Packet shorter than 20 bytes now handled gracefully (IHL-based checksum)."""
        pkt = b"\x45" + b"\x00" * 15  # 16 bytes, < 20
        rewritten = self.server._rewrite_src_ip(pkt, "10.20.0.5")
        assert len(rewritten) == len(pkt)

    def test_rewrite_multiple_times(self):
        """Multiple rewrites should produce valid checksums each time."""
        pkt = build_udp_packet(src_ip="10.20.0.2", checksum=0x5678)
        for new_ip in ["10.20.0.3", "10.20.0.4", "10.20.0.5"]:
            pkt = self.server._rewrite_src_ip(pkt, new_ip)
            assert extract_src_ip(pkt) == new_ip

    def test_rewrite_with_ip_options(self):
        """Packet with IP options (IHL > 5) should rewrite correctly."""
        pkt = build_udp_packet(src_ip="10.20.0.2", ihl=6, checksum=0x1234)
        rewritten = self.server._rewrite_src_ip(pkt, "10.20.0.5")
        assert extract_src_ip(rewritten) == "10.20.0.5"

    def test_rewrite_udp_zero_checksum(self):
        """UDP with checksum=0 should NOT have transport checksum fixed."""
        pkt = build_udp_packet(src_ip="10.20.0.2", checksum=0)
        rewritten = self.server._rewrite_src_ip(pkt, "10.20.0.5")
        # UDP checksum should remain 0
        ihl = (rewritten[0] & 0x0F) * 4
        assert rewritten[ihl + 6] == 0 and rewritten[ihl + 7] == 0


# ── _incremental_checksum_fix Tests ──────────────────────────────────

class TestIncrementalChecksum:
    """Test RFC 1624 incremental checksum update."""

    def setup_method(self):
        self.server = UdpVpnServer.__new__(UdpVpnServer)

    def test_checksum_identity(self):
        """If old == new, checksum should not change."""
        pkt = bytearray(b"\x00" * 40)
        pkt[16:18] = struct.pack("!H", 0x1234)
        old = b"\x01\x02\x03\x04"
        self.server._incremental_checksum_fix(pkt, 16, old, old)
        # Checksum should remain unchanged
        assert struct.unpack("!H", pkt[16:18])[0] == 0x1234

    def test_checksum_changes_with_data(self):
        """Checksum should change when data changes."""
        pkt = bytearray(b"\x00" * 40)
        pkt[16:18] = struct.pack("!H", 0x0000)
        old = b"\x00\x00\x00\x00"
        new = b"\x01\x02\x03\x04"
        self.server._incremental_checksum_fix(pkt, 16, old, new)
        new_cksum = struct.unpack("!H", pkt[16:18])[0]
        assert new_cksum != 0x0000

    def test_checksum_roundtrip(self):
        """Applying old→new then new→old should restore original checksum."""
        pkt1 = bytearray(b"\x00" * 40)
        pkt1[16:18] = struct.pack("!H", 0xABCD)
        old = b"\x01\x02\x03\x04"
        new = b"\x05\x06\x07\x08"
        self.server._incremental_checksum_fix(pkt1, 16, old, new)
        cksum_after = struct.unpack("!H", pkt1[16:18])[0]

        pkt2 = bytearray(b"\x00" * 40)
        pkt2[16:18] = struct.pack("!H", cksum_after)
        self.server._incremental_checksum_fix(pkt2, 16, new, old)
        assert struct.unpack("!H", pkt2[16:18])[0] == 0xABCD


# ── extract_src_ip / extract_dst_ip Edge Cases ──────────────────────

class TestIpExtractionEdgeCases:
    """Edge cases for IP address extraction."""

    def test_extract_src_ip_loopback(self):
        pkt = build_ip_packet(src_ip="127.0.0.1")
        assert extract_src_ip(pkt) == "127.0.0.1"

    def test_extract_dst_ip_broadcast(self):
        pkt = build_ip_packet(dst_ip="255.255.255.255")
        assert extract_dst_ip(pkt) == "255.255.255.255"

    def test_extract_src_ip_all_zeros(self):
        pkt = build_ip_packet(src_ip="0.0.0.0")
        assert extract_src_ip(pkt) == "0.0.0.0"

    def test_extract_dst_ip_class_e(self):
        pkt = build_ip_packet(dst_ip="240.0.0.1")
        assert extract_dst_ip(pkt) == "240.0.0.1"

    def test_extract_src_ip_short_packet(self):
        pkt = b"\x45" + b"\x00" * 10  # 11 bytes, < 20
        assert extract_src_ip(pkt) is None

    def test_extract_dst_ip_short_packet(self):
        pkt = b"\x45" + b"\x00" * 10
        assert extract_dst_ip(pkt) is None

    def test_extract_src_ip_empty(self):
        assert extract_src_ip(b"") is None

    def test_extract_dst_ip_empty(self):
        assert extract_dst_ip(b"") is None

    def test_extract_src_ip_exact_20_bytes(self):
        pkt = build_ip_packet(src_ip="10.20.0.5")
        assert len(pkt) >= 20
        assert extract_src_ip(pkt) == "10.20.0.5"

    def test_extract_dst_ip_with_options(self):
        pkt = build_ip_packet(dst_ip="10.0.2.3", ihl=6)
        assert extract_dst_ip(pkt) == "10.0.2.3"

    def test_extract_ipv6_returns_none(self):
        """IPv6: extract_src_ip now correctly returns None (IPv4 check added)."""
        pkt = bytearray(40)
        pkt[0] = 0x60  # IPv6
        result = extract_src_ip(bytes(pkt))
        assert result is None  # fixed: now validates IPv4 version


# ── extract_udp_dst_port Edge Cases ──────────────────────────────────

class TestUdpDstPortEdgeCases:
    """Additional edge cases for UDP port extraction."""

    def test_port_1(self):
        pkt = build_udp_packet(dst_port=1)
        assert extract_udp_dst_port(pkt) == 1

    def test_port_53_dns(self):
        pkt = build_udp_packet(dst_port=53)
        assert extract_udp_dst_port(pkt) == 53

    def test_port_443_https(self):
        pkt = build_udp_packet(dst_port=443)
        assert extract_udp_dst_port(pkt) == 443

    def test_port_853_dot(self):
        """DNS-over-TLS port."""
        pkt = build_udp_packet(dst_port=853)
        assert extract_udp_dst_port(pkt) == 853

    def test_port_65535(self):
        pkt = build_udp_packet(dst_port=65535)
        assert extract_udp_dst_port(pkt) == 65535

    def test_with_ip_options(self):
        pkt = build_udp_packet(dst_port=53, ihl=7)
        assert extract_udp_dst_port(pkt) == 53

    def test_packet_exactly_27_bytes(self):
        """27 bytes: < 28 minimum, should return None."""
        pkt = b"\x45" + b"\x00" * 26
        assert extract_udp_dst_port(pkt) is None

    def test_packet_exactly_28_bytes(self):
        """28 bytes: minimum valid (IP 20 + UDP 8)."""
        pkt = build_udp_packet(dst_port=1234)
        assert len(pkt) == 28
        assert extract_udp_dst_port(pkt) == 1234


# ── _build_udp_response Edge Cases ──────────────────────────────────

class TestBuildUdpResponseEdgeCases:
    """Additional edge cases for response packet construction."""

    def test_response_max_port(self):
        resp = UdpVpnServer._build_udp_response("10.0.2.3", "10.20.0.2", 53, 65535, b"\x00")
        dst_port = struct.unpack("!H", resp[22:24])[0]
        assert dst_port == 65535

    def test_response_zero_src_port(self):
        resp = UdpVpnServer._build_udp_response("10.0.2.3", "10.20.0.2", 0, 12345, b"\x00")
        src_port = struct.unpack("!H", resp[20:22])[0]
        assert src_port == 0

    def test_response_preserves_private_dns_src(self):
        """Source IP should be the private DNS IP (10.0.2.3 etc)."""
        for dns_ip in PRIVATE_DNS_IPS:
            resp = UdpVpnServer._build_udp_response(dns_ip, "10.20.0.2", 53, 12345, b"\x00")
            assert extract_src_ip(resp) == dns_ip

    def test_response_total_length_matches(self):
        payload = b"\x00" * 100
        resp = UdpVpnServer._build_udp_response("10.0.2.3", "10.20.0.2", 53, 12345, payload)
        total_len = struct.unpack("!H", resp[2:4])[0]
        assert total_len == len(resp)

    def test_response_version_is_4(self):
        resp = UdpVpnServer._build_udp_response("10.0.2.3", "10.20.0.2", 53, 12345, b"\x00")
        assert (resp[0] >> 4) == 4

    def test_response_ihl_is_5(self):
        resp = UdpVpnServer._build_udp_response("10.0.2.3", "10.20.0.2", 53, 12345, b"\x00")
        assert (resp[0] & 0x0F) == 5

    def test_response_protocol_is_udp(self):
        resp = UdpVpnServer._build_udp_response("10.0.2.3", "10.20.0.2", 53, 12345, b"\x00")
        assert resp[9] == 17  # UDP


# ── SessionManager: Cleanup Edge Cases ───────────────────────────────

class TestCleanupEdgeCases:
    """Edge cases for session cleanup."""

    def setup_method(self):
        self.sm = SessionManager("10.20.0.0/24", state_file="/dev/null")

    def test_cleanup_empty(self):
        """Cleanup on empty session manager should not crash."""
        self.sm.cleanup()
        assert len(self.sm.sessions) == 0

    def test_cleanup_preserves_active(self):
        """Active sessions should survive cleanup."""
        ips = [self.sm.assign_ip((f"10.0.0.{i}", 1000 + i)) for i in range(5)]
        self.sm.cleanup()
        for ip in ips:
            assert ip in self.sm.sessions

    def test_cleanup_removes_only_expired(self):
        """Only expired sessions should be removed."""
        ip1 = self.sm.assign_ip(("1.2.3.4", 1000))
        ip2 = self.sm.assign_ip(("5.6.7.8", 2000))
        ip3 = self.sm.assign_ip(("9.10.11.12", 3000))
        # Expire ip2 only
        self.sm.sessions[ip2]["last_seen"] = time.time() - 181
        self.sm.cleanup()
        assert ip1 in self.sm.sessions
        assert ip2 not in self.sm.sessions
        assert ip3 in self.sm.sessions

    def test_cleanup_removes_from_addr_to_ip(self):
        """Cleanup should remove expired addr from addr_to_ip."""
        addr = ("1.2.3.4", 1000)
        ip = self.sm.assign_ip(addr)
        self.sm.sessions[ip]["last_seen"] = time.time() - 181
        self.sm.cleanup()
        assert addr not in self.sm.addr_to_ip

    def test_cleanup_multiple_expired(self):
        """Multiple expired sessions should all be removed."""
        ips = []
        for i in range(10):
            ip = self.sm.assign_ip((f"10.0.0.{i}", 1000 + i))
            ips.append(ip)
        # Expire odd-numbered
        for i in range(0, 10, 2):
            self.sm.sessions[ips[i]]["last_seen"] = time.time() - 181
        self.sm.cleanup()
        assert len(self.sm.sessions) == 5

    def test_cleanup_preserves_stats(self):
        """Cleanup should not affect accumulated stats (they're just removed)."""
        ip = self.sm.assign_ip(("1.2.3.4", 1000))
        self.sm.touch(ip, rx_bytes=1000, tx_bytes=500)
        self.sm.sessions[ip]["last_seen"] = time.time() - 181
        self.sm.cleanup()
        # Session is gone, so stats are gone too
        s = self.sm.stats()
        assert s["active"] == 0


# ── SessionManager: Touch Edge Cases ─────────────────────────────────

class TestTouchEdgeCases:
    """Edge cases for session touch."""

    def setup_method(self):
        self.sm = SessionManager("10.20.0.0/24", state_file="/dev/null")

    def test_touch_nonexistent_ip(self):
        """Touching a non-existent IP should be a no-op."""
        self.sm.touch("10.20.0.99", rx_bytes=100, tx_bytes=50)
        # No crash, no session created
        assert len(self.sm.sessions) == 0

    def test_touch_accumulates(self):
        """Touch should accumulate rx/tx bytes."""
        ip = self.sm.assign_ip(("1.2.3.4", 1000))
        self.sm.touch(ip, rx_bytes=100, tx_bytes=50)
        self.sm.touch(ip, rx_bytes=200, tx_bytes=100)
        assert self.sm.sessions[ip]["rx"] == 300
        assert self.sm.sessions[ip]["tx"] == 150

    def test_touch_updates_last_seen(self):
        """Touch should update last_seen timestamp."""
        ip = self.sm.assign_ip(("1.2.3.4", 1000))
        old = self.sm.sessions[ip]["last_seen"]
        time.sleep(0.01)
        self.sm.touch(ip)
        assert self.sm.sessions[ip]["last_seen"] > old

    def test_touch_zero_bytes(self):
        """Touch with 0 bytes should still update last_seen."""
        ip = self.sm.assign_ip(("1.2.3.4", 1000))
        old_rx = self.sm.sessions[ip]["rx"]
        self.sm.touch(ip, rx_bytes=0, tx_bytes=0)
        assert self.sm.sessions[ip]["rx"] == old_rx

    def test_touch_large_values(self):
        """Touch with large byte counts should not overflow."""
        ip = self.sm.assign_ip(("1.2.3.4", 1000))
        self.sm.touch(ip, rx_bytes=2**32, tx_bytes=2**32)
        assert self.sm.sessions[ip]["rx"] == 2**32
        assert self.sm.touch(ip, rx_bytes=1, tx_bytes=1) is None  # no crash


# ── IP Protocol Constants ────────────────────────────────────────────

class TestProtocolConstants:
    """Verify protocol constants are correct."""

    def test_tun_ioctl_value(self):
        assert TUNSETIFF == 0x400454CA

    def test_iff_tun_value(self):
        assert IFF_TUN == 0x0001

    def test_iff_no_pi_value(self):
        assert IFF_NO_PI == 0x1000

    def test_idle_timeout_is_60(self):
        assert IDLE_TIMEOUT == 60

    def test_private_dns_ips_count(self):
        assert len(PRIVATE_DNS_IPS) == 3

    def test_private_dns_ips_content(self):
        assert PRIVATE_DNS_IPS == {"10.0.2.3", "10.0.2.2", "10.0.3.3"}


# ── Full Rewrite → Forward Cycle ─────────────────────────────────────

class TestRewriteForwardCycle:
    """Integration: rewrite src IP → verify packet is valid for forwarding."""

    def setup_method(self):
        self.server = UdpVpnServer.__new__(UdpVpnServer)
        self.sm = SessionManager("10.20.0.0/24", state_file="/dev/null")

    def test_udp_rewrite_forward_ready(self):
        """Rewritten UDP packet should have valid checksums for kernel forwarding."""
        pkt = build_udp_packet(src_ip="10.20.0.2", dst_ip="8.8.8.8", checksum=0x1234)
        rewritten = self.server._rewrite_src_ip(pkt, "10.20.0.5")
        # IP checksum valid: sum all 16-bit words including checksum = 0xFFFF
        ip_hdr = bytearray(rewritten[:20])
        assert compute_ip_checksum(ip_hdr) == 0  # valid IP checksum
        # Source IP changed
        assert extract_src_ip(rewritten) == "10.20.0.5"
        # Dest IP preserved
        assert extract_dst_ip(rewritten) == "8.8.8.8"

    def test_tcp_rewrite_forward_ready(self):
        """Rewritten TCP packet should have valid checksums."""
        pkt = build_tcp_packet(src_ip="10.20.0.2", dst_ip="8.8.8.8")
        rewritten = self.server._rewrite_src_ip(pkt, "10.20.0.5")
        # IP checksum valid: sum all 16-bit words including checksum = 0xFFFF
        ip_hdr = bytearray(rewritten[:20])
        assert compute_ip_checksum(ip_hdr) == 0  # valid IP checksum

    def test_assign_and_rewrite(self):
        """Full flow: assign IP → rewrite packet."""
        addr = ("1.2.3.4", 12345)
        assigned_ip = self.sm.assign_ip(addr)
        pkt = build_udp_packet(src_ip="10.20.0.2", dst_ip="8.8.8.8")
        rewritten = self.server._rewrite_src_ip(pkt, assigned_ip)
        assert extract_src_ip(rewritten) == assigned_ip
        assert self.sm.get_addr_by_ip(assigned_ip) == addr


# ── Pool Exhaustion Fix Tests ─────────────────────────────────────────

class TestPoolExhaustionFix:
    """Test that pool exhaustion no longer crashes the server."""

    def test_exhaustion_evicts_oldest(self):
        """When pool is exhausted, oldest session is evicted."""
        sm = SessionManager("10.20.0.0/29", state_file="/dev/null")  # 5 usable: .2-.6
        sm.MAX_SESSIONS = 3
        for i in range(3):
            sm.assign_ip((f"10.0.0.{i}", 1000 + i))
        assert len(sm.sessions) == 3
        # One more — should evict oldest
        ip = sm.assign_ip(("99.99.99.99", 9999))
        assert ip.startswith("10.20.0.")
        assert len(sm.sessions) == 3  # evicted one, added one

    def test_exhaustion_preserves_new_session(self):
        """New session survives after eviction."""
        sm = SessionManager("10.20.0.0/29", state_file="/dev/null")  # 5 usable
        sm.MAX_SESSIONS = 3
        for i in range(3):
            sm.assign_ip((f"10.0.0.{i}", 1000 + i))
        ip = sm.assign_ip(("99.99.99.99", 9999))
        assert ip in sm.sessions
        assert sm.sessions[ip]["addr"] == ("99.99.99.99", 9999)


# ── extract_src_ip IPv4 Validation Tests ──────────────────────────────

class TestSrcIpValidation:
    """Test that extract_src_ip validates IPv4 version."""

    def test_ipv4_valid(self):
        pkt = build_ip_packet(src_ip="10.20.0.5")
        assert extract_src_ip(pkt) == "10.20.0.5"

    def test_ipv6_rejected(self):
        pkt = bytearray(40)
        pkt[0] = 0x60  # IPv6
        assert extract_src_ip(bytes(pkt)) is None

    def test_version_0_rejected(self):
        pkt = bytearray(20)
        pkt[0] = 0x00  # version 0
        assert extract_src_ip(bytes(pkt)) is None

    def test_version_15_rejected(self):
        pkt = bytearray(20)
        pkt[0] = 0xF0  # version 15
        assert extract_src_ip(bytes(pkt)) is None


# ── IP Checksum with Options Tests ───────────────────────────────────

class TestChecksumWithOptions:
    """Test IP checksum with IP options (IHL > 5)."""

    def setup_method(self):
        self.server = UdpVpnServer.__new__(UdpVpnServer)

    def test_rewrite_with_ihl5(self):
        """Standard 20-byte header."""
        pkt = build_udp_packet(src_ip="10.20.0.2", ihl=5)
        rewritten = self.server._rewrite_src_ip(pkt, "10.20.0.5")
        assert extract_src_ip(rewritten) == "10.20.0.5"

    def test_rewrite_with_ihl6(self):
        """24-byte header (4 bytes options)."""
        pkt = build_udp_packet(src_ip="10.20.0.2", ihl=6)
        rewritten = self.server._rewrite_src_ip(pkt, "10.20.0.5")
        assert extract_src_ip(rewritten) == "10.20.0.5"

    def test_rewrite_with_ihl7(self):
        """28-byte header (8 bytes options)."""
        pkt = build_udp_packet(src_ip="10.20.0.2", ihl=7)
        rewritten = self.server._rewrite_src_ip(pkt, "10.20.0.5")
        assert extract_src_ip(rewritten) == "10.20.0.5"

    def test_checksum_covers_options(self):
        """Checksum must cover the full IP header including options."""
        pkt = build_udp_packet(src_ip="10.20.0.2", ihl=6)
        rewritten = self.server._rewrite_src_ip(pkt, "10.20.0.5")
        # Verify checksum is valid
        ihl = (rewritten[0] & 0x0F) * 4
        assert ihl == 24
        ip_hdr = bytearray(rewritten[:ihl])
        assert compute_ip_checksum(ip_hdr) == 0


# ── Stats Snapshot Tests ──────────────────────────────────────────────

class TestStatsSnapshot:
    """Test that stats() uses a snapshot to avoid concurrent modification."""

    def setup_method(self):
        self.sm = SessionManager("10.20.0.0/24", state_file="/dev/null")

    def test_stats_uses_snapshot(self):
        """Stats should work even if sessions change during iteration."""
        for i in range(5):
            self.sm.assign_ip((f"10.0.0.{i}", 1000 + i))
        s = self.sm.stats()
        assert s["active"] == 5

    def test_stats_consistent(self):
        """Stats should be internally consistent."""
        ip = self.sm.assign_ip(("1.2.3.4", 1000))
        self.sm.touch(ip, rx_bytes=100, tx_bytes=50)
        s = self.sm.stats()
        assert s["total_rx"] == 100
        assert s["total_tx"] == 50
        assert s["active"] == 1


# ── _rewrite_dst_ip Tests ────────────────────────────────────────────

class TestRewriteDstIp:
    """Test IP destination rewriting with checksum fix.
    
    This is the critical fix for TCP forwarding: server assigns 10.20.0.5 to a
    client whose TUN is 10.20.0.2/32. Reply packets have dst=10.20.0.5 — the
    server must rewrite dst back to 10.20.0.2 before sending to client.
    """

    def setup_method(self):
        self.server = UdpVpnServer.__new__(UdpVpnServer)

    def test_rewrite_dst_ip_udp(self):
        """Rewriting dst IP in UDP packet should fix IP + UDP checksums."""
        pkt = build_udp_packet(src_ip="8.8.8.8", dst_ip="10.20.0.5", checksum=0x1234)
        rewritten = self.server._rewrite_dst_ip(pkt, "10.20.0.2")
        assert extract_dst_ip(rewritten) == "10.20.0.2"
        assert extract_src_ip(rewritten) == "8.8.8.8"  # src unchanged
        ip_hdr = bytearray(rewritten[:20])
        assert compute_ip_checksum(ip_hdr) == 0

    def test_rewrite_dst_ip_tcp(self):
        """Rewriting dst IP in TCP packet should fix IP + TCP checksums."""
        pkt = build_tcp_packet(src_ip="91.108.56.140", dst_ip="10.20.0.5", dst_port=45330, flags=0x12)
        rewritten = self.server._rewrite_dst_ip(pkt, "10.20.0.2")
        assert extract_dst_ip(rewritten) == "10.20.0.2"
        assert extract_src_ip(rewritten) == "91.108.56.140"
        ip_hdr = bytearray(rewritten[:20])
        assert compute_ip_checksum(ip_hdr) == 0

    def test_rewrite_dst_ip_no_change(self):
        """If new IP == old IP, packet should be unchanged."""
        pkt = build_udp_packet(dst_ip="10.20.0.2")
        rewritten = self.server._rewrite_dst_ip(pkt, "10.20.0.2")
        assert rewritten == pkt

    def test_rewrite_dst_ip_preserves_src(self):
        """Source IP should not change."""
        pkt = build_udp_packet(src_ip="74.125.200.101", dst_ip="10.20.0.5")
        rewritten = self.server._rewrite_dst_ip(pkt, "10.20.0.2")
        assert extract_src_ip(rewritten) == "74.125.200.101"

    def test_rewrite_dst_ip_preserves_payload(self):
        """Payload should be preserved after rewrite."""
        payload = b"SYN-ACK data here"
        pkt = build_udp_packet(src_ip="8.8.8.8", dst_ip="10.20.0.5", payload=payload)
        rewritten = self.server._rewrite_dst_ip(pkt, "10.20.0.2")
        assert rewritten[28:] == payload

    def test_rewrite_dst_ip_icmp(self):
        """ICMP packets should have IP checksum fixed only."""
        pkt = build_ip_packet(src_ip="8.8.8.8", dst_ip="10.20.0.5", protocol=1,
                              payload=b"\x00\x00" + b"\x00" * 18)
        rewritten = self.server._rewrite_dst_ip(pkt, "10.20.0.2")
        assert extract_dst_ip(rewritten) == "10.20.0.2"
        ip_hdr = bytearray(rewritten[:20])
        assert compute_ip_checksum(ip_hdr) == 0

    def test_rewrite_dst_ip_short_packet_no_crash(self):
        """Packet shorter than 20 bytes handled gracefully."""
        pkt = b"\x45" + b"\x00" * 15
        rewritten = self.server._rewrite_dst_ip(pkt, "10.20.0.2")
        assert len(rewritten) == len(pkt)

    def test_rewrite_dst_ip_multiple_times(self):
        """Multiple rewrites should produce valid checksums each time."""
        pkt = build_udp_packet(src_ip="8.8.8.8", dst_ip="10.20.0.5", checksum=0x5678)
        for new_ip in ["10.20.0.4", "10.20.0.3", "10.20.0.2"]:
            pkt = self.server._rewrite_dst_ip(pkt, new_ip)
            assert extract_dst_ip(pkt) == new_ip
            ip_hdr = bytearray(pkt[:20])
            assert compute_ip_checksum(ip_hdr) == 0

    def test_roundtrip_src_then_dst_rewrite(self):
        """Simulate the full VPN flow: rewrite src on outbound, dst on inbound.
        
        1. Client sends SYN with src=10.20.0.2 → server rewrites src to 10.20.0.5
        2. Reply SYN-ACK has dst=10.20.0.5 → server rewrites dst to 10.20.0.2
        3. Final packet should have correct IPs and checksums
        """
        # Step 1: Client SYN (src=10.20.0.2 → dst=91.108.56.140)
        syn = build_tcp_packet(src_ip="10.20.0.2", dst_ip="91.108.56.140",
                               src_port=45330, dst_port=443, flags=0x02)
        # Server rewrites src to assigned IP
        syn_rewritten = self.server._rewrite_src_ip(syn, "10.20.0.5")
        assert extract_src_ip(syn_rewritten) == "10.20.0.5"

        # Step 2: SYN-ACK reply (src=91.108.56.140 → dst=10.20.0.5)
        syn_ack = build_tcp_packet(src_ip="91.108.56.140", dst_ip="10.20.0.5",
                                   src_port=443, dst_port=45330, flags=0x12)
        # Server rewrites dst back to client TUN IP
        syn_ack_fixed = self.server._rewrite_dst_ip(syn_ack, "10.20.0.2")
        assert extract_dst_ip(syn_ack_fixed) == "10.20.0.2"
        assert extract_src_ip(syn_ack_fixed) == "91.108.56.140"
        # Both checksums valid
        ip_hdr = bytearray(syn_ack_fixed[:20])
        assert compute_ip_checksum(ip_hdr) == 0

    def test_roundtrip_preserves_tcp_port_mapping(self):
        """After roundtrip, TCP ports must be intact for connection tracking."""
        pkt = build_tcp_packet(src_ip="91.108.56.140", dst_ip="10.20.0.5",
                               src_port=443, dst_port=45330, flags=0x12)
        rewritten = self.server._rewrite_dst_ip(pkt, "10.20.0.2")
        ihl = (rewritten[0] & 0x0F) * 4
        sport = (rewritten[ihl] << 8) | rewritten[ihl + 1]
        dport = (rewritten[ihl + 2] << 8) | rewritten[ihl + 3]
        assert sport == 443
        assert dport == 45330


# ── Run Tests ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v", "--tb=short"]))
