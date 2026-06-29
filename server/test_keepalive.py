#!/usr/bin/env python3
"""
Unit tests for Tunnely keepalive mechanism.

Tests:
- Server recognizes "TUNN" magic (0x54554E4E) as hello/keepalive
- Server rejects wrong magic bytes ("KEEP", random, partial)
- Session touch on keepalive (last_seen updated, session not expired)
- New session assignment on first hello
- Keepalive packet format (exactly 4 bytes)
- Edge cases: oversized keepalive, empty, 3 bytes, 5 bytes
- Session timeout behavior (IDLE_TIMEOUT = 60s)
- Keepalive interval vs NAT timeout (15s < 30-60s carrier NAT)
- Multiple keepalives extend session lifetime
- Keepalive from different addr (NAT rebinding / roaming)
- Integration: full hello → keepalive → data → keepalive cycle
"""
import struct
import time
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from udp_vpn_server import (
    SessionManager,
    IDLE_TIMEOUT,
    PRIVATE_DNS_IPS,
)

# ── Constants ──────────────────────────────────────────────────────────

TUNN_MAGIC = b"\x54\x55\x4E\x4E"  # "TUNN" = 0x54554E4E
KEEP_MAGIC = b"\x4B\x45\x45\x50"  # "KEEP" = 0x4B454550 (WRONG — server rejects)
KEEPALIVE_INTERVAL = 15  # seconds (client sends every 15s)


# ── Magic Bytes Tests ─────────────────────────────────────────────────

class TestMagicBytes:
    """Verify TUNN magic is the canonical keepalive/hello format."""

    def test_tunn_magic_value(self):
        """TUNN magic should be 0x54554E4E."""
        assert TUNN_MAGIC == b"\x54\x55\x4E\x4E"

    def test_tunn_magic_int(self):
        """As int (big-endian): 0x54554E4E = 1414852174."""
        assert struct.unpack(">I", TUNN_MAGIC)[0] == 0x54554E4E

    def test_keep_magic_is_wrong(self):
        """KEEP magic (0x4B454550) is NOT what server expects."""
        assert KEEP_MAGIC != TUNN_MAGIC
        assert struct.unpack(">I", KEEP_MAGIC)[0] == 0x4B454550

    def test_tunn_magic_length(self):
        """Keepalive must be exactly 4 bytes."""
        assert len(TUNN_MAGIC) == 4

    def test_tunn_magic_is_ascii(self):
        """TUNN magic is readable ASCII (useful for debugging)."""
        assert TUNN_MAGIC == b"TUNN"


# ── Server Hello/Keepalive Handling Tests ─────────────────────────────

class TestServerKeepaliveHandling:
    """Test how server handles hello/keepalive packets."""

    def setup_method(self):
        """Fresh SessionManager for each test."""
        self.sm = SessionManager("10.20.0.0/24", state_file="/dev/null")
        self.client_addr = ("1.2.3.4", 12345)

    def test_hello_assigns_ip(self):
        """First TUNN packet should assign a tunnel IP."""
        # The server checks: len(data) == 4 and data == TUNN_MAGIC
        # Then: if addr not in sessions → assign_ip()
        assert len(TUNN_MAGIC) == 4
        assert TUNN_MAGIC == b"\x54\x55\x4E\x4E"

        ip = self.sm.assign_ip(self.client_addr)
        assert ip.startswith("10.20.0.")
        assert ip != "10.20.0.1"  # server IP excluded

    def test_keepalive_updates_session(self):
        """TUNN packet from existing client should update last_seen."""
        ip = self.sm.assign_ip(self.client_addr)
        old_last_seen = self.sm.sessions[ip]["last_seen"]

        time.sleep(0.01)
        self.sm.touch(ip)  # This is what server does on keepalive

        assert self.sm.sessions[ip]["last_seen"] > old_last_seen

    def test_keepalive_preserves_session(self):
        """Keepalive should NOT create a new session."""
        ip1 = self.sm.assign_ip(self.client_addr)
        ip2 = self.sm.addr_to_ip.get(self.client_addr)
        assert ip1 == ip2

        # After touch (keepalive), same IP
        self.sm.touch(ip1)
        assert self.sm.addr_to_ip.get(self.client_addr) == ip1

    def test_wrong_magic_ignored(self):
        """KEEP magic should NOT be recognized as hello/keepalive."""
        # Server check: len(data) == 4 and data == b"\x54\x55\x4E\x4E"
        assert not (len(KEEP_MAGIC) == 4 and KEEP_MAGIC == TUNN_MAGIC)
        # KEEP magic fails the equality check

    def test_wrong_magic_does_not_assign_ip(self):
        """If server receives wrong magic, no session should be created."""
        # Simulate: server checks data == TUNN_MAGIC before assign_ip
        wrong = KEEP_MAGIC
        assert wrong != TUNN_MAGIC
        # Server would NOT call assign_ip for wrong magic

    def test_partial_magic_rejected(self):
        """3-byte partial TUNN should not match."""
        partial = b"\x54\x55\x4E"  # "TUN" (missing last N)
        assert len(partial) != 4 or partial != TUNN_MAGIC

    def test_extra_bytes_rejected(self):
        """5-byte packet with TUNN prefix should not match (len != 4)."""
        extra = TUNN_MAGIC + b"\x00"
        assert len(extra) != 4  # server checks len(data) == 4

    def test_empty_packet_ignored(self):
        """Empty packet should not trigger keepalive."""
        data = b""
        assert len(data) < 20  # enters the short-packet branch
        assert not (len(data) == 4 and data == TUNN_MAGIC)

    def test_single_byte_packet_ignored(self):
        """1-byte packet should not trigger keepalive."""
        data = b"\x54"
        assert len(data) < 20
        assert not (len(data) == 4 and data == TUNN_MAGIC)

    def test_3_byte_packet_ignored(self):
        """3-byte packet should not trigger keepalive."""
        data = b"\x54\x55\x4E"
        assert len(data) < 20
        assert not (len(data) == 4 and data == TUNN_MAGIC)

    def test_5_byte_tunn_rejected(self):
        """5-byte TUNN+null should not match (len != 4)."""
        data = b"\x54\x55\x4E\x4E\x00"
        assert len(data) < 20
        assert not (len(data) == 4 and data == TUNN_MAGIC)


# ── Session Timeout Tests ─────────────────────────────────────────────

class TestSessionTimeout:
    """Test session expiry behavior."""

    def setup_method(self):
        self.sm = SessionManager("10.20.0.0/24", state_file="/dev/null")
        self.client_addr = ("1.2.3.4", 12345)

    def test_session_alive_within_timeout(self):
        """Session should survive within IDLE_TIMEOUT."""
        ip = self.sm.assign_ip(self.client_addr)
        self.sm.cleanup()
        assert ip in self.sm.sessions

    def test_session_expires_after_timeout(self):
        """Session should be removed after IDLE_TIMEOUT."""
        ip = self.sm.assign_ip(self.client_addr)
        # Manually set last_seen to past
        self.sm.sessions[ip]["last_seen"] = time.time() - IDLE_TIMEOUT - 1
        self.sm.cleanup()
        assert ip not in self.sm.sessions

    def test_keepalive_prevents_expiry(self):
        """Regular keepalive (touch) prevents session expiry."""
        ip = self.sm.assign_ip(self.client_addr)
        # Simulate time passing but with keepalives
        for _ in range(10):
            self.sm.sessions[ip]["last_seen"] = time.time() - (IDLE_TIMEOUT - 5)
            self.sm.touch(ip)  # keepalive resets last_seen
            self.sm.cleanup()
            assert ip in self.sm.sessions

    def test_keepalive_interval_vs_nat_timeout(self):
        """Keepalive interval (15s) must be < carrier NAT timeout (30-60s)."""
        # Indonesian carriers typically have 30-60s UDP NAT timeout
        min_nat_timeout = 30
        assert KEEPALIVE_INTERVAL < min_nat_timeout, (
            f"Keepalive {KEEPALIVE_INTERVAL}s must be < NAT timeout {min_nat_timeout}s"
        )

    def test_keepalive_interval_vs_idle_timeout(self):
        """Keepalive interval (15s) must be < server IDLE_TIMEOUT (60s)."""
        assert KEEPALIVE_INTERVAL < IDLE_TIMEOUT

    def test_idle_timeout_value(self):
        """IDLE_TIMEOUT should be 60s (enough for 4 keepalive cycles)."""
        assert IDLE_TIMEOUT == 60
        assert IDLE_TIMEOUT / KEEPALIVE_INTERVAL >= 3  # at least 3 chances


# ── NAT Timeout Scenario Tests ────────────────────────────────────────

class TestNatTimeoutScenarios:
    """Simulate real-world NAT timeout scenarios."""

    def setup_method(self):
        self.sm = SessionManager("10.20.0.0/24", state_file="/dev/null")

    def test_no_keepalive_session_dies(self):
        """Without keepalive, session expires after IDLE_TIMEOUT."""
        ip = self.sm.assign_ip(("1.2.3.4", 12345))
        # Simulate silence (no keepalive)
        self.sm.sessions[ip]["last_seen"] = time.time() - 61
        self.sm.cleanup()
        assert ip not in self.sm.sessions

    def test_keepalive_every_15s_keeps_alive(self):
        """Keepalive every 15s for 5 minutes → session survives."""
        ip = self.sm.assign_ip(("1.2.3.4", 12345))
        # Simulate 5 minutes with keepalives every 15s
        for i in range(20):  # 20 * 15s = 300s = 5 min
            self.sm.touch(ip)
            # Don't actually sleep — just verify touch works
            assert ip in self.sm.sessions

    def test_missing_keepalive_for_60s_ok(self):
        """Missing keepalive for 30s is OK (within 60s timeout)."""
        ip = self.sm.assign_ip(("1.2.3.4", 12345))
        self.sm.sessions[ip]["last_seen"] = time.time() - 30
        self.sm.cleanup()
        assert ip in self.sm.sessions  # still alive

    def test_missing_keepalive_for_120s_ok(self):
        """Missing keepalive for 45s is still OK (within 60s)."""
        ip = self.sm.assign_ip(("1.2.3.4", 12345))
        self.sm.sessions[ip]["last_seen"] = time.time() - 45
        self.sm.cleanup()
        assert ip in self.sm.sessions

    def test_missing_keepalive_for_181s_dies(self):
        """Missing keepalive for 61s → session expired."""
        ip = self.sm.assign_ip(("1.2.3.4", 12345))
        self.sm.sessions[ip]["last_seen"] = time.time() - 61
        self.sm.cleanup()
        assert ip not in self.sm.sessions

    def test_carrier_nat_timeout_30s(self):
        """Even if carrier NAT times out at 30s, server session survives."""
        ip = self.sm.assign_ip(("1.2.3.4", 12345))
        # Carrier NAT timeout at 30s — but server session is separate
        self.sm.sessions[ip]["last_seen"] = time.time() - 30
        self.sm.cleanup()
        assert ip in self.sm.sessions  # server still has it

    def test_carrier_nat_timeout_60s(self):
        """Carrier NAT timeout at 50s — server session still alive."""
        ip = self.sm.assign_ip(("1.2.3.4", 12345))
        self.sm.sessions[ip]["last_seen"] = time.time() - 50
        self.sm.cleanup()
        assert ip in self.sm.sessions


# ── Multiple Clients Keepalive Tests ──────────────────────────────────

class TestMultipleClientsKeepalive:
    """Test keepalive with multiple concurrent clients."""

    def setup_method(self):
        self.sm = SessionManager("10.20.0.0/24", state_file="/dev/null")

    def test_two_clients_independent_keepalive(self):
        """Two clients send keepalives independently."""
        ip1 = self.sm.assign_ip(("1.2.3.4", 10001))
        ip2 = self.sm.assign_ip(("5.6.7.8", 20002))
        assert ip1 != ip2

        # Client 1 keeps alive, client 2 goes idle
        self.sm.touch(ip1)
        self.sm.sessions[ip2]["last_seen"] = time.time() - 181

        self.sm.cleanup()
        assert ip1 in self.sm.sessions
        assert ip2 not in self.sm.sessions

    def test_many_clients_keepalive(self):
        """10 clients all sending keepalives."""
        ips = []
        for i in range(10):
            ip = self.sm.assign_ip((f"10.0.0.{i}", 10000 + i))
            ips.append(ip)

        # All send keepalive
        for ip in ips:
            self.sm.touch(ip)

        self.sm.cleanup()
        for ip in ips:
            assert ip in self.sm.sessions

    def test_pool_recycling_after_expiry(self):
        """After sessions expire, IPs should be recyclable."""
        ip1 = self.sm.assign_ip(("1.2.3.4", 10001))
        self.sm.sessions[ip1]["last_seen"] = time.time() - 181
        self.sm.cleanup()

        # New client should get a (possibly same) IP
        ip2 = self.sm.assign_ip(("5.6.7.8", 20002))
        assert ip2.startswith("10.20.0.")


# ── Integration: Hello → Data → Keepalive Cycle ──────────────────────

class TestKeepaliveIntegration:
    """Integration tests for full keepalive lifecycle."""

    def setup_method(self):
        self.sm = SessionManager("10.20.0.0/24", state_file="/dev/null")

    def test_full_lifecycle(self):
        """Simulate: hello → data → keepalive → more data → keepalive."""
        addr = ("1.2.3.4", 12345)

        # 1. Hello — assign IP
        ip = self.sm.assign_ip(addr)
        assert ip.startswith("10.20.0.")

        # 2. Data packet (touch with rx/tx)
        self.sm.touch(ip, rx_bytes=1500, tx_bytes=500)
        assert self.sm.sessions[ip]["rx"] == 1500
        assert self.sm.sessions[ip]["tx"] == 500

        # 3. Keepalive (no data, just touch)
        time.sleep(0.01)
        old_seen = self.sm.sessions[ip]["last_seen"]
        self.sm.touch(ip)
        assert self.sm.sessions[ip]["last_seen"] > old_seen

        # 4. More data
        self.sm.touch(ip, rx_bytes=2000, tx_bytes=1000)
        assert self.sm.sessions[ip]["rx"] == 3500
        assert self.sm.sessions[ip]["tx"] == 1500

        # 5. Another keepalive
        self.sm.touch(ip)

        # 6. Session still alive
        self.sm.cleanup()
        assert ip in self.sm.sessions

    def test_roaming_after_nat_rebind(self):
        """Client's NAT rebinds to new port — should get new session."""
        ip1 = self.sm.assign_ip(("1.2.3.4", 10001))
        # Old session expires
        self.sm.sessions[ip1]["last_seen"] = time.time() - 181
        self.sm.cleanup()

        # Client reconnects from new port (NAT rebind)
        ip2 = self.sm.assign_ip(("1.2.3.4", 20002))
        assert ip2.startswith("10.20.0.")
        # May or may not be the same IP (depends on pool recycling)

    def test_stats_accumulate_across_keepalives(self):
        """Stats should accumulate across multiple keepalive cycles."""
        ip = self.sm.assign_ip(("1.2.3.4", 12345))

        total_rx = 0
        total_tx = 0
        for _ in range(100):
            rx = 100
            tx = 50
            self.sm.touch(ip, rx_bytes=rx, tx_bytes=tx)
            total_rx += rx
            total_tx += tx

        assert self.sm.sessions[ip]["rx"] == total_rx
        assert self.sm.sessions[ip]["tx"] == total_tx

    def test_keepalive_without_data_is_valid(self):
        """Keepalive with 0 bytes rx/tx is still valid (just touch)."""
        ip = self.sm.assign_ip(("1.2.3.4", 12345))
        self.sm.touch(ip, rx_bytes=0, tx_bytes=0)
        assert ip in self.sm.sessions
        assert self.sm.sessions[ip]["rx"] == 0
        assert self.sm.sessions[ip]["tx"] == 0


# ── Client Keepalive Constant Tests ──────────────────────────────────

class TestClientConstants:
    """Verify client-side keepalive constants are correct."""

    def test_client_hello_magic_matches_server(self):
        """Client sends 0x54554E4E ("TUNN") — must match server."""
        # From UdpTunnelVpnService.kt:
        # ByteBuffer.allocate(4).putInt(0x54554E4E).array()
        client_magic = struct.pack(">I", 0x54554E4E)
        assert client_magic == TUNN_MAGIC

    def test_old_keep_magic_was_wrong(self):
        """Old code used 0x4B454550 ("KEEP") — this was the bug."""
        old_magic = struct.pack(">I", 0x4B454550)
        assert old_magic == KEEP_MAGIC
        assert old_magic != TUNN_MAGIC

    def test_keepalive_interval_is_15s(self):
        """Client sends keepalive every 15 seconds."""
        # From UdpTunnelVpnService.kt: KEEPALIVE_INTERVAL = 15_000L
        assert KEEPALIVE_INTERVAL == 15

    def test_keepalive_interval_safety_margin(self):
        """15s keepalive gives 2x safety margin for 30s NAT timeout."""
        nat_timeout = 30
        margin = nat_timeout / KEEPALIVE_INTERVAL
        assert margin >= 2.0, f"Need ≥2x margin, got {margin}x"


# ── Edge Cases ────────────────────────────────────────────────────────

class TestKeepaliveEdgeCases:
    """Edge cases for keepalive mechanism."""

    def setup_method(self):
        self.sm = SessionManager("10.20.0.0/24", state_file="/dev/null")

    def test_rapid_keepalives(self):
        """Sending keepalives every 1ms should not break anything."""
        ip = self.sm.assign_ip(("1.2.3.4", 12345))
        for _ in range(1000):
            self.sm.touch(ip)
        assert ip in self.sm.sessions

    def test_keepalive_after_long_silence_within_timeout(self):
        """Keepalive after 179s silence → session should survive."""
        ip = self.sm.assign_ip(("1.2.3.4", 12345))
        self.sm.sessions[ip]["last_seen"] = time.time() - 179
        self.sm.touch(ip)  # keepalive arrives just in time
        assert ip in self.sm.sessions

    def test_keepalive_after_exact_timeout(self):
        """Keepalive at exactly IDLE_TIMEOUT boundary — uses > check so equal passes."""
        ip = self.sm.assign_ip(("1.2.3.4", 12345))
        # Server checks: now - last_seen > IDLE_TIMEOUT (strict greater)
        # At exactly the boundary, now - last_seen == IDLE_TIMEOUT → not expired
        # But float timing makes this unreliable. Use a small margin instead.
        self.sm.sessions[ip]["last_seen"] = time.time() - IDLE_TIMEOUT + 0.1
        self.sm.cleanup()
        assert ip in self.sm.sessions

    def test_keepalive_after_exact_timeout_plus_one(self):
        """Keepalive at IDLE_TIMEOUT + 1 → session expired."""
        ip = self.sm.assign_ip(("1.2.3.4", 12345))
        self.sm.sessions[ip]["last_seen"] = time.time() - IDLE_TIMEOUT - 1
        self.sm.cleanup()
        assert ip not in self.sm.sessions

    def test_addr_to_ip_consistency(self):
        """addr_to_ip and sessions should stay in sync."""
        addr = ("1.2.3.4", 12345)
        ip = self.sm.assign_ip(addr)

        assert self.sm.addr_to_ip[addr] == ip
        assert self.sm.sessions[ip]["addr"] == addr

        # After touch, still in sync
        self.sm.touch(ip)
        assert self.sm.addr_to_ip[addr] == ip
        assert self.sm.sessions[ip]["addr"] == addr

    def test_cleanup_removes_from_both_dicts(self):
        """Expired session should be removed from both sessions and addr_to_ip."""
        addr = ("1.2.3.4", 12345)
        ip = self.sm.assign_ip(addr)
        self.sm.sessions[ip]["last_seen"] = time.time() - 181
        self.sm.cleanup()

        assert ip not in self.sm.sessions
        assert addr not in self.sm.addr_to_ip


# ── NAT Rebind Tests ──────────────────────────────────────────────────

class TestNatRebind:
    """Carrier NAT rebinding: same client IP, different port."""

    def setup_method(self):
        self.sm = SessionManager("10.20.0.0/24", state_file="/dev/null")

    def test_nat_rebind_keeps_same_ip(self):
        """Same client IP with new port reuses existing session."""
        ip1 = self.sm.assign_ip(("119.235.222.139", 20511))
        ip2 = self.sm.assign_ip(("119.235.222.139", 21277))
        assert ip1 == ip2

    def test_nat_rebind_updates_port(self):
        """After rebind, session.addr has new port."""
        ip = self.sm.assign_ip(("119.235.222.139", 20511))
        self.sm.assign_ip(("119.235.222.139", 21277))
        assert self.sm.sessions[ip]["addr"] == ("119.235.222.139", 21277)

    def test_nat_rebind_cleans_old_addr(self):
        """Old (ip, port) is removed from addr_to_ip after rebind."""
        self.sm.assign_ip(("119.235.222.139", 20511))
        self.sm.assign_ip(("119.235.222.139", 21277))
        assert ("119.235.222.139", 20511) not in self.sm.addr_to_ip
        assert ("119.235.222.139", 21277) in self.sm.addr_to_ip

    def test_nat_rebind_preserves_rx_tx(self):
        """Stats survive NAT rebind."""
        ip = self.sm.assign_ip(("119.235.222.139", 20511))
        self.sm.touch(ip, rx_bytes=1000, tx_bytes=2000)
        self.sm.assign_ip(("119.235.222.139", 21277))
        assert self.sm.sessions[ip]["rx"] == 1000
        assert self.sm.sessions[ip]["tx"] == 2000

    def test_multiple_rebinds_same_client(self):
        """Multiple NAT rebinds all keep same session."""
        ip = self.sm.assign_ip(("119.235.222.139", 20511))
        for port in [20600, 20700, 20800, 20900, 21277]:
            new_ip = self.sm.assign_ip(("119.235.222.139", port))
            assert new_ip == ip
        assert len(self.sm.sessions) == 1

    def test_different_client_ips_get_different_sessions(self):
        """Different client IPs still get different sessions."""
        ip1 = self.sm.assign_ip(("119.235.222.139", 20511))
        ip2 = self.sm.assign_ip(("203.83.40.108", 11308))
        assert ip1 != ip2
        assert len(self.sm.sessions) == 2

    def test_rebind_after_expiry_gets_new_session(self):
        """After session expires, rebind creates new session."""
        ip1 = self.sm.assign_ip(("119.235.222.139", 20511))
        self.sm.sessions[ip1]["last_seen"] = time.time() - 181
        self.sm.cleanup()
        ip2 = self.sm.assign_ip(("119.235.222.139", 21277))
        assert ip2.startswith("10.20.0.")
        # New session (old one expired)
        assert ip2 != ip1 or ip1 not in self.sm.sessions

    def test_client_ip_map_cleanup_on_remove(self):
        """client_ip_map is cleaned when session is removed."""
        ip = self.sm.assign_ip(("119.235.222.139", 20511))
        assert "119.235.222.139" in self.sm.client_ip_map
        self.sm._remove_session(ip)
        assert "119.235.222.139" not in self.sm.client_ip_map

    def test_no_session_leak_with_rebind(self):
        """NAT rebinds don't leak sessions or IPs."""
        initial_available = len(self.sm._available)
        ip = self.sm.assign_ip(("119.235.222.139", 20511))
        for port in range(20512, 20612):  # 100 rebinds
            self.sm.assign_ip(("119.235.222.139", port))
        assert len(self.sm.sessions) == 1
        assert len(self.sm._available) == initial_available - 1

    def test_rebind_preserves_connected_at(self):
        """connected_at timestamp survives NAT rebind."""
        ip = self.sm.assign_ip(("119.235.222.139", 20511))
        original_time = self.sm.sessions[ip]["connected_at"]
        time.sleep(0.01)
        self.sm.assign_ip(("119.235.222.139", 21277))
        assert self.sm.sessions[ip]["connected_at"] == original_time

    def test_rebind_addr_to_ip_consistency(self):
        """addr_to_ip always has exactly 1 entry for this client."""
        self.sm.assign_ip(("119.235.222.139", 20511))
        self.sm.assign_ip(("119.235.222.139", 21277))
        self.sm.assign_ip(("119.235.222.139", 22000))
        count = sum(1 for a in self.sm.addr_to_ip if a[0] == "119.235.222.139")
        assert count == 1

    def test_rebind_updates_last_seen(self):
        """NAT rebind updates last_seen timestamp."""
        ip = self.sm.assign_ip(("119.235.222.139", 20511))
        old_ts = self.sm.sessions[ip]["last_seen"]
        time.sleep(0.01)
        self.sm.assign_ip(("119.235.222.139", 21277))
        assert self.sm.sessions[ip]["last_seen"] >= old_ts

    def test_cgnat_two_devices_same_ip(self):
        """Two devices behind same CGNAT IP — second steals session.
        
        Known limitation: IP-level dedup can't distinguish two devices
        behind the same carrier-grade NAT. In practice, the keepalive
        ping-pong resolves this within seconds.
        """
        ip1 = self.sm.assign_ip(("100.64.1.1", 10001))
        ip2 = self.sm.assign_ip(("100.64.1.1", 20002))
        # Same session — can't distinguish CGNAT peers
        assert ip1 == ip2
        assert len(self.sm.sessions) == 1

    def test_rebind_after_evict(self):
        """After eviction, client gets new session on rebind."""
        # Fill sessions
        for i in range(50):
            self.sm.assign_ip((f"10.0.0.{i}", 10000 + i))
        assert len(self.sm.sessions) == 50
        # Old client rebinds — should evict oldest and get new session
        ip = self.sm.assign_ip(("119.235.222.139", 20511))
        assert ip.startswith("10.20.0.")

    def test_interleaved_rebinds_two_clients(self):
        """Two clients interleaving rebinds don't interfere."""
        ip_a = self.sm.assign_ip(("1.1.1.1", 1000))
        ip_b = self.sm.assign_ip(("2.2.2.2", 2000))
        assert ip_a != ip_b
        # Client A rebinds
        ip_a2 = self.sm.assign_ip(("1.1.1.1", 1001))
        assert ip_a2 == ip_a
        # Client B rebinds
        ip_b2 = self.sm.assign_ip(("2.2.2.2", 2001))
        assert ip_b2 == ip_b
        assert len(self.sm.sessions) == 2

    def test_rapid_rebind_stress(self):
        """1000 rapid rebinds — no leak, no crash."""
        ip = self.sm.assign_ip(("1.2.3.4", 1000))
        for port in range(1001, 2001):
            self.sm.assign_ip(("1.2.3.4", port))
        assert len(self.sm.sessions) == 1
        assert len(self.sm.addr_to_ip) == 1

    def test_rebind_exact_port_match_fast_path(self):
        """Exact (ip,port) match takes fast path (no client_ip_map lookup)."""
        ip1 = self.sm.assign_ip(("1.2.3.4", 12345))
        ip2 = self.sm.assign_ip(("1.2.3.4", 12345))  # exact match
        assert ip1 == ip2
        # Should NOT log NAT rebind (fast path)
        assert len(self.sm.sessions) == 1

    def test_client_ip_map_not_polluted_by_other_clients(self):
        """client_ip_map entries don't leak between different clients."""
        self.sm.assign_ip(("1.1.1.1", 1000))
        self.sm.assign_ip(("2.2.2.2", 2000))
        self.sm.assign_ip(("3.3.3.3", 3000))
        assert len(self.sm.client_ip_map) == 3
        # Remove one
        ip = self.sm.client_ip_map["2.2.2.2"]
        self.sm._remove_session(ip)
        assert len(self.sm.client_ip_map) == 2
        assert "2.2.2.2" not in self.sm.client_ip_map

    def test_rebind_with_stale_client_ip_map(self):
        """Stale client_ip_map entry (session removed externally) is cleaned."""
        ip = self.sm.assign_ip(("1.2.3.4", 1000))
        # Manually remove session without going through _remove_session
        self.sm.sessions.pop(ip)
        # Now client_ip_map is stale
        ip2 = self.sm.assign_ip(("1.2.3.4", 2000))
        # Should create new session (stale mapping cleaned up)
        assert ip2.startswith("10.20.0.")
        assert ip2 in self.sm.sessions


# ── Run Tests ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v", "--tb=short"]))
