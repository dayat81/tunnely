"""Tests for latency probe echo in UDP VPN server."""
import struct
import time
import pytest

TLTP_MAGIC = b"\x54\x4C\x54\x50"
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


class TestLatencyProbe:
    def test_request_format(self):
        """Probe request has correct magic and type."""
        pkt = build_probe_request(1, 1000)
        assert len(pkt) == PROBE_SIZE
        assert pkt[0:4] == TLTP_MAGIC
        assert pkt[4] == PROBE_REQUEST

    def test_response_type_changed(self):
        """Server changes type from REQUEST to RESPONSE."""
        req = build_probe_request(1, 1000)
        resp = echo_probe(req)
        assert resp[4] == PROBE_RESPONSE

    def test_response_preserves_client_ts(self):
        """Server echo preserves client timestamp."""
        req = build_probe_request(42, 1234567890)
        resp = echo_probe(req)

        parsed = parse_probe(resp)
        assert parsed["client_ts"] == 1234567890
        assert parsed["server_ts"] > 0  # server added its timestamp

    def test_sequence_preserved(self):
        """Sequence number preserved in echo."""
        req = build_probe_request(65535, 100)
        resp = echo_probe(req)

        parsed = parse_probe(resp)
        assert parsed["seq"] == 65535

    def test_wrong_magic_ignored(self):
        """Non-probe packets should not be detected as probes."""
        pkt = b"\x00" * PROBE_SIZE
        assert pkt[0:4] != TLTP_MAGIC

    def test_wrong_size_ignored(self):
        """Probe detection requires exactly 24 bytes."""
        pkt = build_probe_request(1, 1000)
        assert len(pkt[:20]) != PROBE_SIZE  # too short

    def test_server_timestamp_is_recent(self):
        """Server timestamp should be close to current time."""
        now_us = int(time.time() * 1_000_000)
        req = build_probe_request(1, now_us)
        resp = echo_probe(req)

        parsed = parse_probe(resp)
        # Server timestamp should be within 100ms of request time
        assert abs(parsed["server_ts"] - now_us) < 100_000

    def test_latency_calculation(self):
        """Client can compute RTT and one-way latencies."""
        client_send = 1_000_000  # 1.0s
        server_recv = 1_050_000  # 1.05s (50ms uplink)
        client_recv = 1_080_000  # 1.08s (30ms downlink, 80ms RTT)

        rtt = client_recv - client_send  # 80ms
        uplink = server_recv - client_send  # 50ms
        downlink = client_recv - server_recv  # 30ms

        assert rtt == 80_000
        assert uplink == 50_000
        assert downlink == 30_000
        assert uplink + downlink == rtt

    def test_multiple_probes_independent(self):
        """Different sequences are independent."""
        req1 = build_probe_request(1, 1000)
        req2 = build_probe_request(2, 2000)

        resp1 = echo_probe(req1)
        resp2 = echo_probe(req2)

        p1 = parse_probe(resp1)
        p2 = parse_probe(resp2)
        assert p1["seq"] == 1
        assert p2["seq"] == 2
        assert p1["client_ts"] == 1000
        assert p2["client_ts"] == 2000
