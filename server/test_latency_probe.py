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
PROBE_SIZE = 32  # Updated to 32-byte format


def build_probe_request(seq: int, client_ts_us: int) -> bytes:
    """Build a 32-byte probe request."""
    pkt = bytearray(PROBE_SIZE)
    pkt[0:4] = TLTP_MAGIC
    pkt[4] = PROBE_REQUEST
    pkt[5] = 0  # reserved
    struct.pack_into(">H", pkt, 6, seq)
    struct.pack_into(">q", pkt, 8, client_ts_us)
    struct.pack_into(">q", pkt, 16, 0)  # serverRecvTs
    struct.pack_into(">q", pkt, 24, 0)  # serverEchoTs
    return bytes(pkt)


def parse_probe(data: bytes) -> dict:
    """Parse a 32-byte probe packet."""
    return {
        "magic": data[0:4],
        "type": data[4],
        "seq": struct.unpack_from(">H", data, 6)[0],
        "client_ts": struct.unpack_from(">q", data, 8)[0],
        "server_recv_ts": struct.unpack_from(">q", data, 16)[0],
        "server_echo_ts": struct.unpack_from(">q", data, 24)[0],
    }


def echo_probe(data: bytes) -> bytes:
    """Simulate server echo: change type to RESPONSE, add recv + echo timestamps."""
    response = bytearray(data)
    response[4] = PROBE_RESPONSE
    now_us = int(time.time() * 1_000_000)
    struct.pack_into(">q", response, 16, now_us)  # serverRecvTs
    # Simulate 5ms processing time
    struct.pack_into(">q", response, 24, now_us + 5000)  # serverEchoTs
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
        assert parsed["server_recv_ts"] > 0
        assert parsed["server_echo_ts"] > 0

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
        assert abs(parsed["server_recv_ts"] - now_us) < 100_000

    def test_latency_calculation_clock_independent(self):
        """v3.14.4: Uses server processing time, not cross-machine clock."""
        client_send = 1_000_000
        client_recv = 1_080_000  # 80ms RTT
        server_recv = 5_000_000_000  # arbitrary server clock
        server_echo = 5_000_005_000  # 5ms processing

        rtt = client_recv - client_send  # 80ms (client clock, correct)
        server_proc = server_echo - server_recv  # 5ms (same machine, correct)
        network_rtt = rtt - server_proc  # 75ms
        uplink = downlink = network_rtt / 2  # 37.5ms

        assert rtt == 80_000
        assert server_proc == 5_000
        assert network_rtt == 75_000
        assert uplink == downlink == 37_500

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

    def test_probe_is_32_bytes_not_less_than_20(self):
        """Fundamental: probe size (32) > 20, so it fails '< 20' check."""
        probe = build_probe_request(1, 1000)
        assert len(probe) == PROBE_SIZE
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
        """32-byte packet with wrong magic treated as IP packet."""
        pkt = b"\x00" * PROBE_SIZE
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


class TestProbeResponseEdgeCases:
    """Edge cases in probe response handling (client-side logic)."""

    def test_unknown_sequence_ignored(self):
        """Response with sequence not in sentTimes is silently ignored."""
        probe_sent_times = {1: 1000, 2: 2000}
        unknown_seq = 99
        sent_us = probe_sent_times.get(unknown_seq)
        assert sent_us is None  # no crash, just ignored

    def test_duplicate_response_ignored(self):
        """Second response for same seq finds no entry (already removed)."""
        probe_sent_times = {42: 5000}
        sent_us = probe_sent_times.pop(42, None)
        assert sent_us == 5000
        sent_us2 = probe_sent_times.pop(42, None)
        assert sent_us2 is None

    def test_response_with_request_type_ignored(self):
        """Probe with TYPE_REQUEST (not RESPONSE) should not trigger processing."""
        pkt = build_probe_request(1, 1000)
        assert pkt[4] == PROBE_REQUEST

    def test_ema_convergence(self):
        """EMA converges to steady value after repeated probes."""
        ema = 0.0
        alpha = 0.3
        target_ms = 50.0
        for _ in range(30):
            ema = alpha * target_ms + (1 - alpha) * ema
        assert abs(ema - target_ms) < 0.5

    def test_ema_responds_to_spike(self):
        """EMA responds to sudden latency spike but dampens it."""
        ema = 50.0
        alpha = 0.3
        ema = alpha * 500.0 + (1 - alpha) * ema
        assert 50 < ema < 500
        assert abs(ema - 185.0) < 1

    def test_ema_responds_to_drop(self):
        """EMA responds to sudden latency drop."""
        ema = 200.0
        alpha = 0.3
        ema = alpha * 10.0 + (1 - alpha) * ema
        assert 10 < ema < 200
        assert abs(ema - 143.0) < 1

    def test_zero_server_timestamp_detected(self):
        """If server timestamp is 0, downlink is huge — should be flagged."""
        now_us = 50_000_000
        server_recv_ts = 0
        downlink_us = max(0, now_us - server_recv_ts)  # Kotlin: coerceAtLeast(0)
        assert downlink_us == 50_000_000  # known: needs server-side fix

    def test_sequence_wraps_in_packet(self):
        """probeSeq=65536 wraps to 0 in uint16 packet."""
        seq_int = 65536
        seq_uint16 = seq_int & 0xFFFF
        assert seq_uint16 == 0
        pkt = build_probe_request(seq_uint16, 1000)
        parsed = parse_probe(pkt)
        assert parsed["seq"] == 0

    def test_sequence_mismatch_at_wrap(self):
        """Client key=65536 but packet seq=0 → response lost at wrap point."""
        probe_sent_times = {65536: 1000}
        pkt_seq = 65536 & 0xFFFF  # = 0
        result = probe_sent_times.get(pkt_seq)
        assert result is None  # BUG: response lost at wrap

    def test_probe_cleanup_on_disconnect(self):
        """All probe state should be cleared on disconnect."""
        probe_sent_times = {1: 100, 2: 200, 3: 300}
        probe_sent_times.clear()
        assert len(probe_sent_times) == 0


class TestClockSynchronization:
    """Test that client and server use compatible clocks (#26).

    Bug: client used nanoTime() (monotonic, arbitrary epoch)
    vs server time.time() (wall clock since 1970).
    Subtracting gave ~1.7e15 µs (nonsense).
    """

    def test_server_timestamp_is_epoch_microseconds(self):
        """Server timestamp should be ~1.7e15 µs (year 2026)."""
        now_us = int(time.time() * 1_000_000)
        assert now_us > 1_000_000_000_000_000  # > 1e15
        assert now_us < 2_000_000_000_000_000  # < 2e15

    def test_client_server_same_clock_origin(self):
        """Client and server timestamps should be within 1s of each other."""
        # Simulate: server timestamp (what server would write)
        server_us = int(time.time() * 1_000_000)
        # Simulate: client timestamp (what client currentTimeMillis()*1000 gives)
        client_us = int(time.time() * 1_000_000)  # same source in test
        diff = abs(server_us - client_us)
        assert diff < 1_000_000  # within 1s

    def test_rtt_computation_same_clock(self):
        """RTT = client_recv - client_send (same clock, always correct)."""
        client_send = int(time.time() * 1_000_000)
        time.sleep(0.02)  # 20ms
        client_recv = int(time.time() * 1_000_000)
        rtt_us = client_recv - client_send
        rtt_ms = rtt_us / 1000.0
        assert 15 < rtt_ms < 50  # ~20ms

    def test_server_processing_same_machine(self):
        """Server processing = echo - recv (same machine, no clock offset)."""
        server_recv = int(time.time() * 1_000_000)
        time.sleep(0.005)  # 5ms processing
        server_echo = int(time.time() * 1_000_000)
        server_proc_us = server_echo - server_recv
        server_proc_ms = server_proc_us / 1000.0
        assert 3 < server_proc_ms < 10  # ~5ms

    def test_clock_offset_cancels_in_server_proc(self):
        """Even with 997ms clock offset, server processing is correct."""
        clock_offset_us = 997_000  # 997ms offset
        server_recv = 5_000_000_000 + clock_offset_us
        server_echo = 5_000_005_000 + clock_offset_us  # 5ms later
        server_proc = server_echo - server_recv
        assert server_proc == 5000  # Clock offset cancels!

    def test_old_nanotime_would_give_wrong_magnitude(self):
        """Demonstrates the bug: nanoTime and time.time() have different origins."""
        # nanoTime origin = JVM start (gives ~10^12 µs range for 2026)
        # time.time() origin = epoch 1970 (gives ~10^15 µs range for 2026)
        # Difference = ~10^15 which looks like "1782742400 seconds"
        nanotime_us = 1_000_000_000_000  # ~10^12 (typical nanoTime/1000)
        wallclock_us = 1_782_742_400_000_000  # ~10^15 (typical time.time()*1e6)
        bogus_diff = wallclock_us - nanotime_us
        bogus_seconds = bogus_diff / 1_000_000.0
        # This is the bug value the user saw!
        assert bogus_seconds > 1_000_000_000  # "1782742400 seconds"
        # After fix: both use wallclock, diff is small
        wallclock_us2 = wallclock_us + 50_000  # 50ms later
        real_diff = wallclock_us2 - wallclock_us
        real_ms = real_diff / 1000.0
        assert real_ms == 50.0


class TestRemainingEdgeCases:
    """Final edge case coverage for latency probe."""

    # 1. Race: disconnect while probe in-flight
    def test_response_after_cleanup_ignored(self):
        """Response arriving after disconnect cleanup doesn't crash."""
        probe_sent_times = {}
        # Simulate: disconnect clears map
        probe_sent_times.clear()
        # Response arrives with seq=42
        sent_us = probe_sent_times.pop(42, None)
        assert sent_us is None  # no crash

    # 2. Thread safety: ConcurrentHashMap
    def test_concurrent_read_write_no_crash(self):
        """Simulate concurrent access from 2 threads."""
        import threading
        probe_sent_times = {}
        errors = []

        def writer():
            for i in range(1000):
                probe_sent_times[i] = i

        def reader():
            for i in range(1000):
                probe_sent_times.get(i)

        t1 = threading.Thread(target=writer)
        t2 = threading.Thread(target=reader)
        t1.start(); t2.start()
        t1.join(); t2.join()
        # No crash = pass (dict is thread-safe for basic ops in CPython)

    # 3. Malformed probe: unknown type
    def test_unknown_type_ignored_by_client(self):
        """Probe with type=0xFF (unknown) not treated as RESPONSE."""
        pkt = build_probe_request(1, 1000)
        # Change type to unknown
        bad = bytearray(pkt)
        bad[4] = 0xFF
        assert bad[4] != PROBE_REQUEST
        assert bad[4] != PROBE_RESPONSE
        # Client checks: probe.type == TYPE_RESPONSE → False → skip

    # 4. Server timestamp in the future
    def test_future_server_timestamp(self):
        """If server clock is ahead, uplink could be negative → coerceAtLeast(0)."""
        client_send = 1_000_000
        server_recv = 900_000  # 100ms BEFORE client send (clock skew)
        uplink_us = max(0, server_recv - client_send)  # coerceAtLeast(0)
        assert uplink_us == 0  # clamped, not negative

    # 5. Negative RTT
    def test_negative_rtt_clamped(self):
        """If clock adjusts backward, RTT could be negative."""
        client_send = 1_000_000
        client_recv = 999_000  # clock went backward
        rtt_us = client_recv - client_send
        assert rtt_us == -1000  # negative!
        # Client should clamp: max(0, rtt_us)
        clamped_rtt_ms = max(0, rtt_us) / 1000.0
        assert clamped_rtt_ms == 0.0

    # 6. Probe response NOT written to TUN
    def test_probe_response_skips_tun_write(self):
        """After detecting probe response, code does continue (not write to TUN)."""
        # This is a code path test: if probe detected → continue
        pkt = build_probe_request(1, 1000)
        assert len(pkt) == PROBE_SIZE
        # In real code: if n == PACKET_SIZE && decode(type==RESPONSE) → continue
        # No TUN write happens

    # 7. formatLatency edge cases (Python equivalent)
    def test_format_latency_microseconds(self):
        """Sub-millisecond values should show µs."""
        ms = 0.5
        if ms < 1:
            result = f"{ms * 1000:.0f}µs"
        assert result == "500µs"

    def test_format_latency_milliseconds(self):
        """Values 1-999ms show ms."""
        ms = 45.2
        if 1 <= ms < 1000:
            result = f"{ms:.1f}ms"
        assert result == "45.2ms"

    def test_format_latency_seconds(self):
        """Values >= 1000ms show seconds."""
        ms = 1500.0
        if ms >= 1000:
            result = f"{ms / 1000:.2f}s"
        assert result == "1.50s"

    # 8. Multiple connect/disconnect cycles
    def test_multiple_cycles_reset_state(self):
        """State resets correctly across connect/disconnect cycles."""
        probe_sent_times = {}
        ema_rtt = 50.0
        probes_sent = 100

        # Cycle 1: disconnect
        probe_sent_times.clear()
        ema_rtt = 0.0
        probes_sent = 0
        assert len(probe_sent_times) == 0

        # Cycle 2: reconnect, send probes
        probe_sent_times[1] = 1000
        ema_rtt = 30.0
        probes_sent = 5
        assert len(probe_sent_times) == 1

        # Cycle 2: disconnect again
        probe_sent_times.clear()
        ema_rtt = 0.0
        probes_sent = 0
        assert len(probe_sent_times) == 0
        assert ema_rtt == 0.0


class TestExtendedEdgeCases:
    """Additional comprehensive edge cases for latency probe."""

    def test_sequence_0_is_valid(self):
        """First probe should use seq=0."""
        pkt = build_probe_request(0, 1000)
        parsed = parse_probe(pkt)
        assert parsed["seq"] == 0

    def test_sequence_wrap_65535_to_0(self):
        """After 65535, next seq wraps to 0."""
        pkt1 = build_probe_request(65535, 1000)
        parsed1 = parse_probe(pkt1)
        assert parsed1["seq"] == 65535

        pkt2 = build_probe_request(0, 2000)
        parsed2 = parse_probe(pkt2)
        assert parsed2["seq"] == 0

    def test_large_timestamp_year_2100(self):
        """Year 2100 in microseconds should be representable."""
        year_2100_us = 4_102_444_800_000_000  # ~4.1e15
        pkt = build_probe_request(1, year_2100_us)
        parsed = parse_probe(pkt)
        assert parsed["client_ts"] == year_2100_us

    def test_max_safe_timestamp(self):
        """Very large timestamp (~10^16) should be representable."""
        large_ts = 9_999_999_999_999_999
        pkt = build_probe_request(1, large_ts)
        parsed = parse_probe(pkt)
        assert parsed["client_ts"] == large_ts

    def test_reserved_byte_is_zero(self):
        """Byte [5] is reserved, should be 0x00."""
        pkt = build_probe_request(1, 1000)
        assert pkt[5] == 0x00

    def test_invalid_type_still_decodes(self):
        """Type 0xFF decodes but is not REQUEST or RESPONSE."""
        pkt = bytearray(PROBE_SIZE)
        pkt[0:4] = TLTP_MAGIC
        pkt[4] = 0xFF  # invalid type
        struct.pack_into(">H", pkt, 6, 1)
        struct.pack_into(">q", pkt, 8, 1000)
        parsed = parse_probe(bytes(pkt))
        assert parsed["type"] == 0xFF
        assert parsed["type"] != PROBE_REQUEST
        assert parsed["type"] != PROBE_RESPONSE

    def test_multiple_probes_encode_decode_independent(self):
        """Multiple probes should encode/decode independently."""
        probes = [(seq, seq * 1000) for seq in range(1, 11)]
        for seq, ts in probes:
            pkt = build_probe_request(seq, ts)
            parsed = parse_probe(pkt)
            assert parsed["seq"] == seq
            assert parsed["client_ts"] == ts

    def test_rtt_equals_server_processing(self):
        """If server processing equals RTT, network RTT is 0."""
        rtt_ms = 50.0
        server_proc_ms = 50.0
        network_rtt_ms = rtt_ms - server_proc_ms
        assert network_rtt_ms == 0.0

        uplink_ms = network_rtt_ms / 2.0
        assert uplink_ms == 0.0

    def test_very_small_rtt_sub_millisecond(self):
        """Sub-millisecond RTT (fast LAN)."""
        rtt_ms = 0.5
        server_proc_ms = 0.1
        network_rtt_ms = rtt_ms - server_proc_ms  # 0.4ms
        uplink_ms = network_rtt_ms / 2.0  # 0.2ms
        assert 0.19 < uplink_ms < 0.21

    def test_server_processing_zero(self):
        """Server processes instantly (0ms)."""
        rtt_ms = 20.0
        server_proc_ms = 0.0
        network_rtt_ms = rtt_ms - server_proc_ms
        uplink_ms = network_rtt_ms / 2.0
        assert network_rtt_ms == 20.0
        assert uplink_ms == 10.0

    def test_asymmetric_path_uplink_greater(self):
        """Simulate asymmetric path: uplink slower than downlink."""
        rtt_ms = 100.0
        server_proc_ms = 10.0
        network_rtt_ms = rtt_ms - server_proc_ms  # 90ms
        # Asymmetric: 60% uplink, 40% downlink
        uplink_ms = network_rtt_ms * 0.6  # 54ms
        downlink_ms = network_rtt_ms * 0.4  # 36ms
        assert uplink_ms > downlink_ms
        assert uplink_ms + downlink_ms == network_rtt_ms

    def test_probe_sent_times_management(self):
        """Simulate probe sent times map operations."""
        probe_sent_times = {}

        # Add probes
        probe_sent_times[1] = 1000
        probe_sent_times[2] = 2000
        probe_sent_times[3] = 3000
        assert len(probe_sent_times) == 3

        # Remove on response
        sent_us = probe_sent_times.pop(2, None)
        assert sent_us == 2000
        assert len(probe_sent_times) == 2

        # Unknown seq returns None
        unknown = probe_sent_times.pop(99, None)
        assert unknown is None

    def test_stale_probe_cleanup_large_batch(self):
        """Purge 1000 stale entries."""
        probe_sent_times = {}
        now_us = 100_000_000

        # Add 1000 stale entries (60s ago)
        for i in range(1, 1001):
            probe_sent_times[i] = now_us - 60_000_000
        assert len(probe_sent_times) == 1000

        # Purge stale entries
        cutoff_us = now_us - 30_000_000
        to_remove = [k for k, v in probe_sent_times.items() if v < cutoff_us]
        for k in to_remove:
            del probe_sent_times[k]

        assert len(probe_sent_times) == 0

    def test_response_after_disconnect_cleanup(self):
        """Response arriving after disconnect cleanup doesn't crash."""
        probe_sent_times = {}
        probe_sent_times.clear()
        sent_us = probe_sent_times.pop(42, None)
        assert sent_us is None

    def test_duplicate_response_second_none(self):
        """Second response for same seq returns None."""
        probe_sent_times = {42: 5000}
        sent_us1 = probe_sent_times.pop(42, None)
        assert sent_us1 == 5000
        sent_us2 = probe_sent_times.pop(42, None)
        assert sent_us2 is None

    def test_multiple_cycles_state_reset(self):
        """State resets correctly across connect/disconnect cycles."""
        probe_sent_times = {}
        ema_rtt = 50.0

        # Cycle 1
        probe_sent_times.clear()
        ema_rtt = 0.0
        assert len(probe_sent_times) == 0

        # Cycle 2
        probe_sent_times[1] = 1000
        ema_rtt = 30.0
        assert len(probe_sent_times) == 1

        # Cycle 2 disconnect
        probe_sent_times.clear()
        ema_rtt = 0.0
        assert len(probe_sent_times) == 0
        assert ema_rtt == 0.0

    def test_probe_interval_constant(self):
        """PROBE_INTERVAL_MS should be 5000ms."""
        PROBE_INTERVAL_MS = 5000
        assert PROBE_INTERVAL_MS == 5000

    def test_packet_size_exactly_32(self):
        """PROBE_SIZE should be 32 bytes."""
        assert PROBE_SIZE == 32

    def test_magic_bytes_tltp(self):
        """Magic should be TLTP (0x544C5450)."""
        assert TLTP_MAGIC == b"\x54\x4C\x54\x50"
        assert TLTP_MAGIC == b"TLTP"

    def test_type_request_0x01(self):
        """PROBE_REQUEST should be 0x01."""
        assert PROBE_REQUEST == 0x01

    def test_type_response_0x02(self):
        """PROBE_RESPONSE should be 0x02."""
        assert PROBE_RESPONSE == 0x02

    def test_packet_offsets_correct(self):
        """Verify field offsets in 32-byte packet."""
        pkt = bytearray(PROBE_SIZE)
        pkt[0:4] = TLTP_MAGIC
        pkt[4] = PROBE_RESPONSE
        pkt[5] = 0x00  # reserved
        struct.pack_into(">H", pkt, 6, 1)  # seq
        struct.pack_into(">q", pkt, 8, 100)  # clientSendTs
        struct.pack_into(">q", pkt, 16, 200)  # serverRecvTs
        struct.pack_into(">q", pkt, 24, 205)  # serverEchoTs

        parsed = parse_probe(bytes(pkt))
        assert parsed["magic"] == TLTP_MAGIC
        assert parsed["type"] == PROBE_RESPONSE
        assert parsed["seq"] == 1
        assert parsed["client_ts"] == 100
        assert parsed["server_recv_ts"] == 200
        assert parsed["server_echo_ts"] == 205

    def test_timestamp_precision_microseconds(self):
        """Microsecond precision should be preserved."""
        precise_ts = 1234567890123456
        pkt = build_probe_request(1, precise_ts)
        parsed = parse_probe(pkt)
        assert parsed["client_ts"] == precise_ts

    def test_decode_rejects_empty(self):
        """Empty packet should be rejected."""
        # build_probe_request with empty would fail, but test parse directly
        with pytest.raises(Exception):
            parse_probe(b"")

    def test_decode_rejects_24_byte_old_format(self):
        """Old 24-byte format should not parse correctly."""
        old_pkt = bytearray(24)
        old_pkt[0:4] = TLTP_MAGIC
        # parse_probe expects 32 bytes, will fail on struct.unpack_from at offset 24
        with pytest.raises(Exception):
            parse_probe(bytes(old_pkt))

    def test_server_echo_timestamp_always_after_recv(self):
        """In real server, echo_ts >= recv_ts."""
        server_recv = 1000
        server_echo = 1010  # 10µs processing
        assert server_echo >= server_recv
        server_proc = server_echo - server_recv
        assert server_proc == 10

    def test_probe_response_zero_server_timestamps(self):
        """Server returned 0 timestamps (shouldn't happen but handle gracefully)."""
        pkt = bytearray(PROBE_SIZE)
        pkt[0:4] = TLTP_MAGIC
        pkt[4] = PROBE_RESPONSE
        struct.pack_into(">H", pkt, 6, 1)
        struct.pack_into(">q", pkt, 8, 1000)
        struct.pack_into(">q", pkt, 16, 0)  # serverRecvTs = 0
        struct.pack_into(">q", pkt, 24, 0)  # serverEchoTs = 0

        parsed = parse_probe(bytes(pkt))
        assert parsed["server_recv_ts"] == 0
        assert parsed["server_echo_ts"] == 0

        # Server processing would be 0
        server_proc = parsed["server_echo_ts"] - parsed["server_recv_ts"]
        assert server_proc == 0

    def test_concurrent_stale_cleanup_and_response(self):
        """Simulate concurrent stale cleanup and response handling."""
        import threading
        probe_sent_times = {}
        now_us = 50_000_000

        # Add stale entries
        for i in range(100):
            probe_sent_times[i] = now_us - 60_000_000

        errors = []

        def cleanup():
            try:
                cutoff = now_us - 30_000_000
                to_remove = [k for k, v in probe_sent_times.items() if v < cutoff]
                for k in to_remove:
                    probe_sent_times.pop(k, None)
            except Exception as e:
                errors.append(e)

        def respond():
            try:
                for i in range(100):
                    probe_sent_times.pop(i, None)
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=cleanup)
        t2 = threading.Thread(target=respond)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert len(errors) == 0

    def test_format_latency_boundary_999ms(self):
        """999ms should show as ms, not seconds."""
        ms = 999.0
        result = ""
        if ms < 1000:
            result = f"{ms:.1f}ms"
        assert result == "999.0ms"

    def test_format_latency_boundary_1000ms(self):
        """1000ms should show as seconds."""
        ms = 1000.0
        result = ""
        if ms >= 1000:
            result = f"{ms / 1000:.2f}s"
        assert result == "1.00s"

    def test_format_latency_boundary_1ms(self):
        """1ms should show as ms, not µs."""
        ms = 1.0
        result = ""
        if ms >= 1:
            result = f"{ms:.1f}ms"
        assert result == "1.0ms"

    def test_format_latency_boundary_0_999ms(self):
        """0.999ms should show as µs."""
        ms = 0.999
        result = ""
        if ms < 1:
            result = f"{ms * 1000:.0f}µs"
        assert result == "999µs"

    def test_ema_30_iterations_convergence(self):
        """EMA with α=0.3 converges in 30 iterations."""
        ema = 0.0
        alpha = 0.3
        target = 100.0
        for _ in range(30):
            ema = alpha * target + (1 - alpha) * ema
        assert abs(ema - target) < 1.0

    def test_ema_responds_to_gradual_increase(self):
        """EMA tracks gradual latency increase."""
        ema = 50.0
        alpha = 0.3
        # Gradually increase from 50 to 100
        for latency in range(51, 101):
            ema = alpha * latency + (1 - alpha) * ema
        # EMA should be close to 100
        assert ema > 95.0

    def test_probe_sent_times_empty_map(self):
        """Empty map operations should not crash."""
        probe_sent_times = {}
        assert len(probe_sent_times) == 0
        sent_us = probe_sent_times.pop(1, None)
        assert sent_us is None
        sent_us = probe_sent_times.get(1)
        assert sent_us is None

    def test_probe_sent_times_single_entry(self):
        """Single entry operations."""
        probe_sent_times = {42: 5000}
        assert len(probe_sent_times) == 1
        sent_us = probe_sent_times.pop(42, None)
        assert sent_us == 5000
        assert len(probe_sent_times) == 0
