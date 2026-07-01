"""
Minimal SNTP client for Tunnely server.
Syncs clock offset from pool.ntp.org on startup + periodically.
"""
import socket
import struct
import time
import threading

NTP_PORT = 123
NTP_PACKET_SIZE = 48
NTP_EPOCH_OFFSET = 2208988800  # seconds from 1900 to 1970
NTP_SERVERS = [
    "0.pool.ntp.org",
    "1.pool.ntp.org",
    "2.pool.ntp.org",
    "time.google.com",
]


def _query_single(server: str, timeout_s: float = 3.0) -> float | None:
    """Query one NTP server, return offset in seconds (positive = local ahead).
    Returns None on failure."""
    try:
        addr = socket.getaddrinfo(server, NTP_PORT, socket.AF_INET)[0][4]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout_s)
        try:
            # Build NTP request (LI=0, VN=3, Mode=3=client)
            pkt = bytearray(NTP_PACKET_SIZE)
            pkt[0] = 0x1B

            # T1: local send time (seconds since 1900)
            t1 = time.time() + NTP_EPOCH_OFFSET
            t1_sec = int(t1)
            t1_frac = int((t1 - t1_sec) * (1 << 32))
            struct.pack_into(">II", pkt, 24, t1_sec, t1_frac)

            sock.sendto(bytes(pkt), addr)

            # Receive
            data, _ = sock.recvfrom(NTP_PACKET_SIZE)
            t4 = time.time()  # local receive time

            if len(data) < NTP_PACKET_SIZE:
                return None

            # Parse T2 (server recv) and T3 (server xmit)
            t2_sec, t2_frac = struct.unpack_from(">II", data, 32)
            t3_sec, t3_frac = struct.unpack_from(">II", data, 40)

            t2 = (t2_sec - NTP_EPOCH_OFFSET) + t2_frac / (1 << 32)
            t3 = (t3_sec - NTP_EPOCH_OFFSET) + t3_frac / (1 << 32)

            # NTP offset = ((T2-T1) + (T3-T4)) / 2
            # But here T1/T4 are in unix epoch, T2/T3 in NTP epoch (already converted)
            t1_unix = t1 - NTP_EPOCH_OFFSET
            offset = ((t2 - t1_unix) + (t3 - t4)) / 2
            return offset
        finally:
            sock.close()
    except Exception:
        return None


def query_ntp(servers: list[str] | None = None, timeout_s: float = 3.0) -> float | None:
    """Query multiple NTP servers, return median offset in seconds.
    Returns None if all servers fail."""
    if servers is None:
        servers = NTP_SERVERS

    offsets = []
    for server in servers:
        off = _query_single(server, timeout_s)
        if off is not None:
            offsets.append(off)

    if not offsets:
        return None

    offsets.sort()
    n = len(offsets)
    if n % 2 == 1:
        return offsets[n // 2]
    else:
        return (offsets[n // 2 - 1] + offsets[n // 2]) / 2


class NtpSync:
    """Background NTP sync — keeps a running clock offset estimate."""

    def __init__(self, sync_interval_s: float = 300.0):
        self.offset_us: int = 0  # microseconds (positive = NTP server ahead / local behind)
        self.last_sync: float = 0
        self.sync_interval_s = sync_interval_s
        self._lock = threading.Lock()
        self._running = False

    def start(self):
        """Sync once, then start background re-sync thread."""
        self._do_sync()
        self._running = True
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            time.sleep(self.sync_interval_s)
            if self._running:
                self._do_sync()

    def _do_sync(self):
        offset_s = query_ntp(timeout_s=5.0)
        if offset_s is not None:
            with self._lock:
                self.offset_us = int(offset_s * 1_000_000)
                self.last_sync = time.time()
            print(f"[NTP] synced: offset={self.offset_us}µs ({offset_s*1000:.1f}ms)", flush=True)
        else:
            print("[NTP] sync failed, keeping previous offset", flush=True)

    def now_micros(self) -> int:
        """Current time in microseconds, corrected by NTP offset.
        NTP_time = local_time + offset (offset positive = NTP ahead of local)."""
        return int(time.time() * 1_000_000) + self.offset_us

    @property
    def synced(self) -> bool:
        return self.last_sync > 0
