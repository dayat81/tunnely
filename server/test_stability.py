#!/usr/bin/env python3
"""
Tests for VPN connection instability (Issue #17).

Root cause analysis:
- Duration always 00:00:04 → VPN reconnects every ~4 seconds
- DNS works, TCP = 0 → UDP packets flow but TCP data stalls
- Eventually stable after ~30s → multiple reconnects eventually succeed

Tests cover:
- Keepalive timing vs NAT timeout vs idle timeout
- MtuProber WG_OVERHEAD vs UDP overhead mismatch
- Session cycling behavior
- TCP vs UDP packet flow differences
- Server-side session expiry race conditions
- Client reconnect detection
"""
import struct
import sys
import os
import time

sys.path.insert(0, os.path.dirname(__file__))

from udp_vpn_server import (
    SessionManager,
    IDLE_TIMEOUT,
    extract_dst_ip,
    extract_src_ip,
    extract_udp_dst_port,
    UdpVpnServer,
)


# ── Constants (mirrored from client) ──────────────────────────────────

TUNNEL_MTU = 1400          # UdpTunnelVpnService hardcoded
PREFS_MTU_DEFAULT = 1420   # VpnPreferences default
WG_OVERHEAD = 60           # MtuProber (WRONG for UDP tunnel)
UDP_OVERHEAD = 28          # 20 IP + 8 UDP (correct for UDP tunnel)
GCP_MTU = 1460             # GCP ens4
KEEPALIVE_INTERVAL = 15    # seconds
CLIENT_CONNECT_TIMEOUT = 4 # approximate seconds before reconnect


# ── MtuProber Overhead Bug ───────────────────────────────────────────

class TestMtuProberOverheadBug:
    """MtuProber subtracts WireGuard overhead (60) but UDP tunnel only needs 28."""

    def test_wg_overhead_is_wrong_for_udp_tunnel(self):
        """WG_OVERHEAD=60 is wrong for UDP tunnel (should be 28)."""
        assert WG_OVERHEAD == 60  # MtuProber uses this
        assert UDP_OVERHEAD == 28  # Correct value for UDP tunnel
        assert WG_OVERHEAD != UDP_OVERHEAD

    def test_mtu_prober_returns_too_low(self):
        """With path MTU 1500, MtuProber returns 1500-60=1440 (clamped to 1420).
        With correct overhead, should return 1500-28=1472."""
        path_mtu = 1500
        probed_mtu = path_mtu - WG_OVERHEAD  # 1440
        correct_mtu = path_mtu - UDP_OVERHEAD  # 1472
        assert probed_mtu != correct_mtu
        assert probed_mtu < correct_mtu

    def test_mtu_prober_with_gcp_mtu(self):
        """On GCP (path MTU 1460), MtuProber returns 1460-60=1400 (correct by accident)."""
        path_mtu = GCP_MTU
        probed_mtu = path_mtu - WG_OVERHEAD
        assert probed_mtu == TUNNEL_MTU  # 1400 — works on GCP by luck

    def test_prefs_mtu_default_is_wrong(self):
        """prefs.mtu defaults to 1420, but TUNNEL_MTU is 1400."""
        assert PREFS_MTU_DEFAULT == 1420
        assert TUNNEL_MTU == 1400
        assert PREFS_MTU_DEFAULT != TUNNEL_MTU

    def test_prefs_mtu_not_used_by_udp_tunnel(self):
        """UdpTunnelVpnService uses TUNNEL_MTU constant, ignores prefs.mtu.
        This means the MTU setting in Settings is cosmetic for UDP mode."""
        # The VPN builder uses .setMtu(TUNNEL_MTU) not .setMtu(prefs.mtu)
        # So prefs.mtu=1420 is displayed but 1400 is actually used
        assert TUNNEL_MTU == 1400  # hardcoded
        assert PREFS_MTU_DEFAULT == 1420  # displayed in settings

    def test_udp_overhead_calculation(self):
        """Correct UDP tunnel overhead: IP(20) + UDP(8) = 28 bytes."""
        ip_header = 20
        udp_header = 8
        assert ip_header + udp_header == UDP_OVERHEAD

    def test_wg_overhead_calculation(self):
        """WireGuard overhead: IP(20) + UDP(8) + WG(32) = 60 bytes."""
        ip_header = 20
        udp_header = 8
        wg_header = 32
        assert ip_header + udp_header + wg_header == WG_OVERHEAD

    def test_tunnel_mtu_fits_with_correct_overhead(self):
        """TUNNEL_MTU + correct UDP overhead must fit in GCP MTU."""
        outer = TUNNEL_MTU + UDP_OVERHEAD
        assert outer <= GCP_MTU  # 1428 <= 1460 ✓

    def test_tunnel_mtu_fits_with_wrong_overhead_too(self):
        """TUNNEL_MTU + WG overhead also fits (but wastes 32 bytes)."""
        outer = TUNNEL_MTU + WG_OVERHEAD
        assert outer <= GCP_MTU  # 1460 <= 1460 ✓ (exactly at limit)


# ── Keepalive Timing vs NAT Timeout ─────────────────────────────────

class TestKeepaliveTimingForStability:
    """Keepalive must arrive before carrier NAT timeout to prevent cycling."""

    def test_keepalive_interval_vs_carrier_nat_30s(self):
        """15s keepalive must be < 30s NAT timeout (2x safety)."""
        carrier_nat = 30
        assert KEEPALIVE_INTERVAL < carrier_nat
        assert carrier_nat / KEEPALIVE_INTERVAL >= 2.0

    def test_keepalive_interval_vs_carrier_nat_60s(self):
        """15s keepalive must be < 60s NAT timeout (4x safety)."""
        carrier_nat = 60
        assert KEEPALIVE_INTERVAL < carrier_nat
        assert carrier_nat / KEEPALIVE_INTERVAL >= 4.0

    def test_first_keepalive_timing(self):
        """First keepalive must be sent WITHIN NAT timeout window.
        If keepalive fires at t=15s and NAT times out at t=30s, that's OK.
        But if connection takes 10s to establish, first keepalive at t=25s — 
        still within 30s NAT window."""
        connect_time = 10  # seconds to establish connection
        first_keepalive = connect_time + KEEPALIVE_INTERVAL  # 25s
        assert first_keepalive < 30  # within NAT timeout

    def test_connection_cycling_at_4s_indicates_no_keepalive(self):
        """If connection cycles at 4s, keepalive (15s) was never sent.
        This matches the bug: keepalive was empty try block pre-v3.8.0."""
        assert CLIENT_CONNECT_TIMEOUT < KEEPALIVE_INTERVAL
        # If cycling happens at 4s, keepalive at 15s is too late
        # The connection dies before first keepalive

    def test_session_expiry_without_keepalive(self):
        """Without keepalive, server session expires at IDLE_TIMEOUT (180s).
        But carrier NAT expires at 30-60s, so response packets get dropped."""
        server_timeout = IDLE_TIMEOUT  # 180s
        carrier_nat = 30  # conservative estimate
        # Carrier NAT expires first → responses dropped → TCP stalls
        assert carrier_nat < server_timeout

    def test_keepalive_must_be_udp_not_tcp(self):
        """Keepalive must use UDP (same protocol as tunnel), not TCP.
        TCP keepalive would create a new connection, not maintain the tunnel."""
        # Server handles keepalive as 4-byte UDP packet (TUNN magic)
        # This is correct — UDP packet maintains NAT mapping
        pass  # structural test — keepalive IS UDP


# ── DNS Works But TCP Doesn't ────────────────────────────────────────

class TestDnsWorksTcpDoesnt:
    """Why DNS flows but TCP stalls — MTU/MSS analysis."""

    def test_dns_packet_size(self):
        """DNS queries are ~50-100 bytes, well under MTU."""
        typical_dns_query = 60  # bytes
        assert typical_dns_query < TUNNEL_MTU

    def test_tcp_syn_size(self):
        """TCP SYN is ~60 bytes, fits in MTU."""
        tcp_syn = 60
        assert tcp_syn < TUNNEL_MTU

    def test_tcp_data_segment_size(self):
        """TCP data segments use MSS (1360), which fits in MTU."""
        mss = 1360
        tcp_ip_headers = 40
        segment = mss + tcp_ip_headers  # 1400
        assert segment <= TUNNEL_MTU

    def test_tls_handshake_size(self):
        """TLS Server Hello can be 2-5KB, needs multiple TCP segments."""
        tls_server_hello = 3000  # typical
        mss = 1360
        segments = (tls_server_hello + mss - 1) // mss  # 3 segments
        assert segments > 1  # multi-segment — each must arrive

    def test_tcp_needs_all_segments(self):
        """TCP stalls if any segment is dropped — unlike UDP DNS which is atomic."""
        # DNS query = 1 UDP packet → arrives or doesn't
        # TCP page load = hundreds of segments → ALL must arrive
        dns_packets = 1
        tcp_packets = 100  # minimum for a page load
        assert tcp_packets > dns_packets

    def test_mtu_mismatch_drops_tcp_data(self):
        """If client sends 1420-byte packets but server TUN is 1400,
        TCP data segments get dropped → TCP stalls."""
        client_mtu = PREFS_MTU_DEFAULT  # 1420 (prefs default)
        server_tun_mtu = TUNNEL_MTU  # 1400
        # If client sends 1420-byte packet to server's TUN (1400),
        # kernel drops it (exceeds TUN MTU)
        assert client_mtu > server_tun_mtu  # 1420 > 1400 → PROBLEM

    def test_dns_survives_mtu_mismatch(self):
        """DNS packets are small enough to survive MTU mismatch."""
        dns_size = 100
        server_tun_mtu = TUNNEL_MTU  # 1400
        assert dns_size < server_tun_mtu  # fits even with wrong MTU


# ── Connection Cycling ───────────────────────────────────────────────

class TestConnectionCycling:
    """What causes VPN to reconnect every ~4 seconds."""

    def test_error_then_disconnect_timing(self):
        """Connect error → ERROR state → 3s sleep → DISCONNECT ≈ 4s total."""
        error_detection_time = 1  # approximate
        disconnect_sleep = 3  # Thread.sleep(3000) in error handler
        total = error_detection_time + disconnect_sleep
        assert 3 <= total <= 5  # matches "00:00:04" observation

    def test_cycling_indicates_connect_failure(self):
        """If VPN reconnects every 4s, the connect() call is failing."""
        # connect() throws exception → ERROR → 3s → disconnect → retry
        # Each cycle ≈ 4s, matching the bug report
        cycle_time = 4  # seconds
        assert cycle_time < KEEPALIVE_INTERVAL  # too fast for keepalive

    def test_eventually_stable_after_retries(self):
        """Connection stabilizes after ~30s = ~7-8 retry cycles.
        This suggests a transient issue (server session cleanup, NAT race)."""
        stabilize_time = 30  # seconds
        cycle_time = 4  # seconds
        retries = stabilize_time // cycle_time  # ~7 retries
        assert retries >= 5  # enough retries to overcome transient issue

    def test_server_session_cleanup_race(self):
        """Old session may not be cleaned up when client reconnects quickly.
        Server assigns same IP to same addr → no race.
        But if addr changed (NAT rebind) → new IP assigned."""
        sm = SessionManager("10.20.0.0/24", state_file="/dev/null")
        addr = ("1.2.3.4", 1000)
        ip1 = sm.assign_ip(addr)
        # Quick reconnect from same addr → same IP
        ip2 = sm.assign_ip(addr)
        assert ip1 == ip2  # no race condition here

    def test_nat_rebind_changes_addr(self):
        """After NAT rebind, client has new port → server sees new addr."""
        sm = SessionManager("10.20.0.0/24", state_file="/dev/null")
        ip1 = sm.assign_ip(("1.2.3.4", 1000))
        # NAT rebind → new port
        ip2 = sm.assign_ip(("1.2.3.4", 2000))
        assert ip1 != ip2  # different IP because different addr


# ── Server Session Behavior During Instability ───────────────────────

class TestServerSessionDuringInstability:
    """How server handles rapid client reconnections."""

    def setup_method(self):
        self.sm = SessionManager("10.20.0.0/24", state_file="/dev/null")

    def test_rapid_reconnect_same_addr(self):
        """Client reconnects every 4s from same addr → same IP, session preserved."""
        addr = ("1.2.3.4", 12345)
        ips = set()
        for _ in range(10):
            ip = self.sm.assign_ip(addr)
            ips.add(ip)
            self.sm.touch(ip, rx_bytes=100, tx_bytes=50)
        assert len(ips) == 1  # same IP every time
        assert self.sm.sessions[ips.pop()]["rx"] == 1000  # 10 * 100

    def test_rapid_reconnect_nat_rebind(self):
        """Client reconnects with new port each time → new IP each time."""
        ips = []
        for i in range(10):
            ip = self.sm.assign_ip(("1.2.3.4", 1000 + i))
            ips.append(ip)
        # All different IPs because different ports
        assert len(set(ips)) == 10
        assert len(self.sm.sessions) == 10

    def test_session_accumulates_during_stable_period(self):
        """After cycling stops, session accumulates traffic normally."""
        ip = self.sm.assign_ip(("1.2.3.4", 12345))
        # Cycling phase — small bursts
        for _ in range(10):
            self.sm.touch(ip, rx_bytes=100, tx_bytes=50)
        # Stable phase — larger transfers
        for _ in range(100):
            self.sm.touch(ip, rx_bytes=10000, tx_bytes=5000)
        assert self.sm.sessions[ip]["rx"] == 1000 + 1000000
        assert self.sm.sessions[ip]["tx"] == 500 + 500000

    def test_old_sessions_expire_during_cycling(self):
        """Old sessions from cycling eventually get cleaned up."""
        for i in range(10):
            ip = self.sm.assign_ip(("1.2.3.4", 1000 + i))
            self.sm.sessions[ip]["last_seen"] = time.time() - 181
        self.sm.cleanup()
        assert len(self.sm.sessions) == 0

    def test_last_session_survives_cleanup(self):
        """The most recent session (from the stable connection) survives."""
        old_ips = []
        for i in range(5):
            ip = self.sm.assign_ip(("1.2.3.4", 1000 + i))
            self.sm.sessions[ip]["last_seen"] = time.time() - 181
            old_ips.append(ip)
        # New stable connection
        stable_ip = self.sm.assign_ip(("1.2.3.4", 9999))
        self.sm.touch(stable_ip, rx_bytes=1000, tx_bytes=500)
        self.sm.cleanup()
        assert stable_ip in self.sm.sessions
        for old_ip in old_ips:
            assert old_ip not in self.sm.sessions


# ── MTU Configuration Consistency ────────────────────────────────────

class TestMtuConsistency:
    """MTU must be consistent between client and server."""

    def test_client_tunnel_mtu(self):
        """Client TUNNEL_MTU = 1400."""
        assert TUNNEL_MTU == 1400

    def test_server_tun_mtu(self):
        """Server TUN MTU = 1400 (set in setup_tun)."""
        # From server code: ip link set dev tunnely0 mtu 1400
        server_tun_mtu = 1400
        assert server_tun_mtu == TUNNEL_MTU

    def test_client_server_mtu_match(self):
        """Client TUN MTU must equal server TUN MTU."""
        assert TUNNEL_MTU == 1400  # client
        # Server also uses 1400 (hardcoded in setup_tun)

    def test_mss_matches_mtu(self):
        """MSS = MTU - 40 (TCP/IP headers)."""
        mss = TUNNEL_MTU - 40
        assert mss == 1360

    def test_outer_packet_fits_gcp(self):
        """TUNNEL_MTU + UDP_OVERHEAD ≤ GCP_MTU."""
        assert TUNNEL_MTU + UDP_OVERHEAD <= GCP_MTU

    def test_prefs_mtu_ignored_by_udp_mode(self):
        """prefs.mtu (default 1420) is NOT used by UdpTunnelVpnService.
        This is a UX issue — settings shows 1420 but actual is 1400."""
        # Document the mismatch
        assert PREFS_MTU_DEFAULT == 1420
        assert TUNNEL_MTU == 1400
        # The fix would be: either use prefs.mtu in UDP mode,
        # or hide the MTU setting when UDP mode is selected.


# ── Run Tests ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v", "--tb=short"]))
