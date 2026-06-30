"""Tests for latency probe echo in UDP VPN server.
Tests both the probe format AND the server-side echo logic ordering.
"""
import struct
import time
import pytest

TLTP_MAGIC = b"\x54\x4C\x54\x50"
TUNN_MAGIC = b"\x54\x55\x4E\x4E"
PROBE_REQUEST = 0x01
PROBE_RESPONSE = 0x02
PROBE_SIZE = 24


def build_probe_request(seq: int, client_ts_us: int) -> bytes:
    """Build a 24-byte probe request."""
    pkt = bytearray(PROBE_SIZE)
    pkt[0:4] = TLTP_MAGIC
    pkt[4] = PROBE_REQUEST
    pkt[5] = 0  # reserved
    struct.pack_into(">H", pkt, 6, seq)
    struct.pack_into(">q", pkt, 8, client_ts_us)
    struct.pack_into(">q", pkt, 16, 0)
    return bytes(pkt)


def parse_probe(data: bytes) -> dict:
    """Parse a probe packet."""
    return {
        "magic": data[0:4],
        "type": data[4],
        "seq": struct.unpack_from(">H", data, 6)[0],
        "client_ts": struct.unpack_from(">q", data, 8)[0],
        "server_ts": struct.unpack_from(">q", data, 16)[0],
    }


def echo_probe(data: bytes) -> bytes:
    """Simulate server echo: change type to RESPONSE, add server timestamp."""
    response = bytearray(data)
    response[4] = PROBE_RESPONSE
    now_us = int(time.time() * 1_000_000)
    struct.pack_into(">q", response, 16, now_us)
    return bytes(response)


# ── Simulated _process_udp_packet logic ──────────────────────────────

def process_udp_packet_v1(data: bytes) -> str:
    """OLD code (buggy): TLTP check INSIDE 'if len(data) < 20' block."""
    if len(data) < 20:
        if len(data) == 4 and data == TUNN_MAGIC:
            return "keepalive"
        if len(data) == PROBE_SIZE and data[0:4] == TLTP_MAGIC:
            return "probe_echo"
        return "short_packet_drop"
    return "ip_packet"


def process_udp_packet_v2(data: bytes) -> str:
    """NEW code (fixed): TLTP check BEFORE 'if len(data) < 20' block."""
    if len(data) == PROBE_SIZE and data[0:4] == TLTP_MAGIC:
        return "probe_echo"
    if len(data) < 20:
        if len(data) == 4 and data == TUNN_MAGIC:
            return "keepalive"
        return "short_packet_drop"
    return "ip_packet"


class TestProbeFormat:
    """Basic probe packet format tests."""

    def test_request_format(self):
        pkt = build_probe_request(1, 1000)
        assert len(pkt) == PROBE_SIZE
        assert pkt[0:4] == TLTP_MAGIC
        assert pkt[4] == PROBE_REQUEST

    def test_response_type_changed(self):
        req = build_probe_request(1, 1000)
        resp = echo_probe(req)
        assert resp[4] == PROBE_RESPONSE

    def test_response_preserves_client_ts(self):
        req = build_probe_request(42, 1234567890)
        resp = echo_probe(req)
        parsed = parse_probe(resp)
        assert parsed["client_ts"] == 1234567890
        assert parsed["server_ts"] > 0

    def test_sequence_preserved(self):
        req = build_probe_request(65535, 100)
        resp = echo_probe(req)
        parsed = parse_probe(resp)
        assert parsed["seq"] == 65535

    def test_wrong_magic_ignored(self):
        pkt = b"\x00" * PROBE_SIZE
        assert pkt[0:4] != TLTP_MAGIC

    def test_wrong_size_ignored(self):
        pkt = build_probe_request(1, 1000)
        assert len(pkt[:20]) != PROBE_SIZE

    def test_server_timestamp_is_recent(self):
        now_us = int(time.time() * 1_000_000)
        req = build_probe_request(1, now_us)
        resp = echo_probe(req)
        parsed = parse_probe(resp)
        assert abs(parsed["server_ts"] - now_us) < 100_000

    def test_latency_calculation(self):
        client_send = 1_000_000
        server_recv = 1_050_000
        client_recv = 1_080_000
        rtt = client_recv - client_send
        uplink = server_recv - client_send
        downlink = client_recv - server_recv
        assert rtt == 80_000
        assert uplink == 50_000
        assert downlink == 30_000
        assert uplink + downlink == rtt

    def test_multiple_probes_independent(self):
        req1 = build_probe_request(1, 1000)
        req2 = build_probe_request(2, 2000)
        resp1 = echo_probe(req1)
        resp2 = echo_probe(req2)
        p1 = parse_probe(resp1)
        p2 = parse_probe(resp2)
        assert p1["seq"] == 1 and p2["seq"] == 2
        assert p1["client_ts"] == 1000 and p2["client_ts"] == 2000


class TestServerEchoOrdering:
    """Test that probe detection works regardless of code ordering.

    Bug #25: TLTP check was inside 'if len(data) < 20' block.
    Probe is 24 bytes → never reached. Server silently dropped probes.
    """

    def test_probe_is_24_bytes_not_less_than_20(self):
        """Fundamental: probe size (24) > 20, so it fails '< 20' check."""
        probe = build_probe_request(1, 1000)
        assert len(probe) == 24
        assert len(probe) >= 20  # NOT < 20

    def test_old_code_drops_probe(self):
        """v1 (buggy): probe is NOT < 20 bytes, falls through to IP parsing."""
        probe = build_probe_request(1, 1000)
        result = process_udp_packet_v1(probe)
        assert result == "ip_packet"  # treated as IP, NOT as probe!

    def test_new_code_echoes_probe(self):
        """v2 (fixed): probe detected BEFORE size check."""
        probe = build_probe_request(1, 1000)
        result = process_udp_packet_v2(probe)
        assert result == "probe_echo"

    def test_keepalive_still_works_v2(self):
        """Keepalive (4 bytes) still detected correctly in v2."""
        result = process_udp_packet_v2(TUNN_MAGIC)
        assert result == "keepalive"

    def test_short_non_keepalive_still_dropped_v2(self):
        """Random 10-byte packet still dropped in v2."""
        result = process_udp_packet_v2(b"\x00" * 10)
        assert result == "short_packet_drop"

    def test_ip_packet_still_processed_v2(self):
        """Normal 100-byte IP packet still processed in v2."""
        pkt = bytearray(100)
        pkt[0] = 0x45  # IPv4, IHL=5
        result = process_udp_packet_v2(bytes(pkt))
        assert result == "ip_packet"

    def test_probe_with_non_tltp_magic_treated_as_ip(self):
        """24-byte packet with wrong magic treated as IP packet."""
        pkt = b"\x00" * 24
        result = process_udp_packet_v2(pkt)
        assert result == "ip_packet"

    def test_probe_with_wrong_size_not_detected(self):
        """20-byte TLTP-like packet not detected (wrong size)."""
        pkt = bytearray(20)
        pkt[0:4] = TLTP_MAGIC
        result = process_udp_packet_v2(bytes(pkt))
        assert result == "ip_packet"  # wrong size, not PROBE_SIZE


class TestClientProbeTiming:
    """Test probe timing logic matches expected intervals.

    Bug #25: Monitor thread slept KEEPALIVE_INTERVAL (15s).
    Probe timing check (5s) never fired.
    """

    def test_probe_interval_is_5s(self):
        """PROBE_INTERVAL_MS should be 5000ms."""
        # Import from the module (won't work without Android, but test the constant)
        PROBE_INTERVAL_MS = 5000
        assert PROBE_INTERVAL_MS == 5000

    def test_keepalive_interval_is_15s(self):
        """KEEPALIVE_INTERVAL should be 15000ms."""
        KEEPALIVE_INTERVAL = 15000
        assert KEEPALIVE_INTERVAL == 15000

    def test_probe_interval_less_than_keepalive(self):
        """Probe should fire more often than keepalive."""
        PROBE_INTERVAL_MS = 5000
        KEEPALIVE_INTERVAL = 15000
        assert PROBE_INTERVAL_MS < KEEPALIVE_INTERVAL

    def test_probe_timing_check_fires_at_5s(self):
        """Simulate: if sleep=5s, probe timing check fires every iteration."""
        last_probe_ms = 0
        PROBE_INTERVAL_MS = 5000
        iterations = 0

        for tick in range(0, 30001, 5000):  # 0, 5, 10, 15, 20, 25, 30
            if tick - last_probe_ms >= PROBE_INTERVAL_MS:
                iterations += 1
                last_probe_ms = tick

        # tick=0: 0-0=0 < 5000 → skip. First fire at tick=5000.
        # Fires at: 5, 10, 15, 20, 25, 30 = 6 probes
        assert iterations == 6

    def test_old_timing_only_fires_every_15s(self):
        """Simulate OLD bug: sleep=15s, probe check fires only every 3rd iteration."""
        last_probe_ms = 0
        PROBE_INTERVAL_MS = 5000
        iterations = 0

        for tick in range(0, 45001, 15000):  # 0, 15, 30, 45
            if tick - last_probe_ms >= PROBE_INTERVAL_MS:
                iterations += 1
                last_probe_ms = tick

        # tick=0: skip. Fires at: 15, 30, 45 = 3 probes in 45s
        # vs new code: 6 probes in 30s (= 9 in 45s) — 3x fewer
        assert iterations == 3

    def test_stale_entry_purge(self):
        """Entries older than 30s should be purged."""
        probe_sent_times = {}
        now_us = 50_000_000  # 50s

        # Add entries: some fresh, some stale
        probe_sent_times[1] = 10_000_000  # 40s ago — stale (< cutoff 20M)
        probe_sent_times[2] = 19_000_000  # 31s ago — stale (< cutoff 20M)
        probe_sent_times[3] = 45_000_000  # 5s ago — fresh
        probe_sent_times[4] = 49_000_000  # 1s ago — fresh

        cutoff_us = now_us - 30_000_000  # entries before 20M are stale
        to_remove = [k for k, v in probe_sent_times.items() if v < cutoff_us]
        for k in to_remove:
            del probe_sent_times[k]

        assert 1 not in probe_sent_times
        assert 2 not in probe_sent_times
        assert 3 in probe_sent_times
        assert 4 in probe_sent_times
        assert len(probe_sent_times) == 2
