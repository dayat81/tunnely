#!/usr/bin/env python3
"""
Tunnely UDP VPN Server v3.5.1
===============================
Lightweight UDP tunnel daemon — no WireGuard, no crypto, no key management.

Architecture:
  Android (VpnService TUN) ←─ UDP ──→ Server (TUN + NAT) → Internet

Protocol:
  Client→Server: raw IP packet inside UDP (first packet = auto-register)
  Server→Client: raw IP packet inside UDP (routed by dst IP → client session)

Usage:
  sudo python3 udp_vpn_server.py --port 5555
  sudo python3 udp_vpn_server.py --port 5555 --subnet 10.20.0.0/24

Requires: root (TUN device + iptables NAT)
"""
import fcntl
import os
import socket
import struct
import subprocess
import sys
import time
import signal
import argparse
import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import ipaddress
import select
from concurrent.futures import ThreadPoolExecutor
from ntp_sync import NtpSync

# QUIC SNI extraction
try:
    from quic_sni import extract_quic_sni, is_quic_initial, _parse_quic_header
    QUIC_SNI_AVAILABLE = True
except ImportError:
    QUIC_SNI_AVAILABLE = False

# ── Constants ──────────────────────────────────────────────────────────────

__version__ = "3.26.0"

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000  # no packet info header

IDLE_TIMEOUT = 60  # seconds — clean stale sessions fast
BUFFER_SIZE = 65535
MAX_BATCH = 64  # max packets to drain per fd per select()
STATS_INTERVAL = 30

# Pre-packed bytes for common IPs (avoid ipaddress in hot path)
_DNS_8888 = socket.inet_aton("8.8.8.8")
PRIVATE_DNS_IP_BYTES = frozenset({
    socket.inet_aton(ip) for ip in ("10.0.2.3", "10.0.2.2", "10.0.3.3")
})

# Private DNS IPs that clients may try to reach (e.g., emulator 10.0.2.3)
# These are intercepted and forwarded to 8.8.8.8 instead of routing through TUN.
PRIVATE_DNS_IPS = {"10.0.2.3", "10.0.2.2", "10.0.3.3"}
# Latency probe constants
TLTP_MAGIC = b"\x54\x4C\x54\x50"  # "TLTP" = Tunnely Latency Test Packet
PROBE_REQUEST = 0x01
PROBE_RESPONSE = 0x02
PROBE_SIZE = 32

STATE_FILE = "/var/lib/tunnely/sessions.json"
LOG_FILE = "/var/log/tunnely-udp-vpn.log"


# ── Logging ────────────────────────────────────────────────────────────────

def log(msg, level="INFO"):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [{level}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


# ── TUN Device ─────────────────────────────────────────────────────────────

def create_tun(name: str = "tun0") -> int:
    """Create a TUN interface, return file descriptor."""
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    return fd


def setup_interface(name: str, server_ip: str, prefix_len: int):
    """Configure IP address and bring interface up."""
    subprocess.run(["ip", "addr", "flush", "dev", name], check=True)
    subprocess.run(
        ["ip", "addr", "add", f"{server_ip}/{prefix_len}", "dev", name], check=True
    )
    subprocess.run(["ip", "link", "set", "dev", name, "mtu", "1400", "up"], check=True)


def setup_nat(tun_name: str, iface: str = "ens4"):
    """Enable IP forwarding and NAT (MASQUERADE) for tunnel traffic."""
    # Enable forwarding
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1")

    # NAT rule (idempotent — delete first, then add)
    subprocess.run(
        ["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"],
        capture_output=True,
    )
    subprocess.run(
        ["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"],
        check=True,
    )

    # Allow forwarding from/to tunnel
    subprocess.run(["iptables", "-A", "FORWARD", "-i", tun_name, "-j", "ACCEPT"], capture_output=True)
    subprocess.run(["iptables", "-A", "FORWARD", "-o", tun_name, "-j", "ACCEPT"], capture_output=True)

    # MSS clamping — critical for TCP over tunnel (prevents fragmentation)
    # Tunnel MTU = 1400, TCP MSS = 1400 - 40 (TCP+IP headers) = 1360
    # Must account for UDP encapsulation overhead (28 bytes)
    # Delete old rules first (idempotent)
    subprocess.run(
        ["iptables", "-t", "mangle", "-D", "FORWARD", "-p", "tcp",
         "--tcp-flags", "SYN,RST", "SYN", "-i", tun_name, "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
        capture_output=True,
    )
    subprocess.run(
        ["iptables", "-t", "mangle", "-A", "FORWARD", "-p", "tcp",
         "--tcp-flags", "SYN,RST", "SYN", "-i", tun_name, "-j", "TCPMSS", "--set-mss", "1360"],
        capture_output=True,
    )
    # Also clamp responses going back to tunnel
    subprocess.run(
        ["iptables", "-t", "mangle", "-D", "FORWARD", "-p", "tcp",
         "--tcp-flags", "SYN,RST", "SYN", "-o", tun_name, "-j", "TCPMSS", "--set-mss", "1360"],
        capture_output=True,
    )
    subprocess.run(
        ["iptables", "-t", "mangle", "-A", "FORWARD", "-p", "tcp",
         "--tcp-flags", "SYN,RST", "SYN", "-o", tun_name, "-j", "TCPMSS", "--set-mss", "1360"],
        capture_output=True,
    )

    log(f"NAT configured: {tun_name} → {iface} MASQUERADE")


def teardown_nat(tun_name: str, iface: str = "ens4"):
    """Clean up NAT rules on shutdown."""
    subprocess.run(
        ["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"],
        capture_output=True,
    )
    subprocess.run(["iptables", "-D", "FORWARD", "-i", tun_name, "-j", "ACCEPT"], capture_output=True)
    subprocess.run(["iptables", "-D", "FORWARD", "-o", tun_name, "-j", "ACCEPT"], capture_output=True)
    # Clean up MSS clamping rules (both directions)
    for flag in ["-i", "-o"]:
        subprocess.run(
            ["iptables", "-t", "mangle", "-D", "FORWARD", "-p", "tcp",
             "--tcp-flags", "SYN,RST", "SYN", flag, tun_name, "-j", "TCPMSS", "--set-mss", "1360"],
            capture_output=True,
        )
        subprocess.run(
            ["iptables", "-t", "mangle", "-D", "FORWARD", "-p", "tcp",
             "--tcp-flags", "SYN,RST", "SYN", flag, tun_name, "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
            capture_output=True,
        )


# ── Session Management ────────────────────────────────────────────────────

class SessionManager:
    """Manages client IP assignment and NAT mapping.
    
    Improvements over v3.6:
    - IP pool uses a set (O(1) alloc/free) instead of iterator
    - IPs are recycled immediately on session expiry
    - Client dedup: same (ip,port) reuses existing session
    - Max session limit prevents pool exhaustion
    - Roaming: same IP but different port = update, not new session
    - **IP-level dedup**: carrier NAT rebinding (same client IP, new port)
      reuses existing session instead of creating a new one
    """

    MAX_SESSIONS = 50  # hard limit

    def __init__(self, network: str, state_file: str = STATE_FILE):
        net = ipaddress.ip_network(network, strict=False)
        self.network = net
        self.subnet_prefix = str(net.network_address)
        # Available IPs: .2 through .254 (skip .1=server)
        # net.hosts() already excludes .0 (network) and .255 (broadcast)
        all_hosts = list(net.hosts())
        self._available = set(str(ip) for ip in all_hosts[1:])  # skip .1 only
        # ip (str) → {addr: (ip, port), last_seen: float, rx: int, tx: int, connected_at: float}
        self.sessions = {}
        # addr tuple → ip str (reverse lookup)
        self.addr_to_ip = {}
        # client IP (str, no port) → assigned tunnel IP (str)
        # Key fix: carrier NAT rebinding changes port, not client IP
        self.client_ip_map = {}
        self.state_file = state_file

    def assign_ip(self, client_addr) -> str:
        """Assign or return existing IP for a client address.
        
        Dedup priority:
        1. Exact (ip, port) match → reuse (fast path)
        2. Same client IP, different port → update port (NAT rebinding / roaming)
        3. New client → allocate from pool
        """
        # Dedup 1: exact (ip, port) match
        if client_addr in self.addr_to_ip:
            ip = self.addr_to_ip[client_addr]
            self.sessions[ip]["last_seen"] = time.time()
            return ip

        # Dedup 2: same client IP but different port (carrier NAT rebinding)
        client_ip = client_addr[0]
        if client_ip in self.client_ip_map:
            assigned_ip = self.client_ip_map[client_ip]
            if assigned_ip in self.sessions:
                old_addr = self.sessions[assigned_ip]["addr"]
                # Update port mapping
                if old_addr in self.addr_to_ip:
                    del self.addr_to_ip[old_addr]
                self.sessions[assigned_ip]["addr"] = client_addr
                self.sessions[assigned_ip]["last_seen"] = time.time()
                self.addr_to_ip[client_addr] = assigned_ip
                log(f"NAT rebind: {client_ip}:{old_addr[1]}→{client_addr[1]} keeps {assigned_ip}")
                return assigned_ip
            else:
                # Stale mapping — session was cleaned up
                del self.client_ip_map[client_ip]

        # Dedup 3: new client → allocate
        # Enforce max sessions
        if len(self.sessions) >= self.MAX_SESSIONS:
            self.cleanup()
            if len(self.sessions) >= self.MAX_SESSIONS:
                self._evict_oldest()

        # Get an IP from the pool
        if not self._available:
            self.cleanup()
            if not self._available:
                self._evict_oldest()

        if not self._available:
            raise RuntimeError("IP pool exhausted and no sessions to evict")

        ip = self._available.pop()

        self.sessions[ip] = {
            "addr": client_addr,
            "last_seen": time.time(),
            "rx": 0,
            "tx": 0,
            "connected_at": time.time(),
        }
        self.addr_to_ip[client_addr] = ip
        self.client_ip_map[client_ip] = ip
        log(f"Session assigned: {client_addr[0]}:{client_addr[1]} → {ip}")
        return ip

    def get_addr_by_ip(self, ip: str):
        """Find client address by tunnel IP (for TUN→UDP routing)."""
        s = self.sessions.get(ip)
        return s["addr"] if s else None

    def update_addr(self, ip: str, new_addr):
        """Update client address (NAT/roaming)."""
        old = self.sessions.get(ip)
        if old:
            if old["addr"] in self.addr_to_ip:
                del self.addr_to_ip[old["addr"]]
            old["addr"] = new_addr
            self.addr_to_ip[new_addr] = ip
            self.client_ip_map[new_addr[0]] = ip
            log(f"Session updated: {ip} → {new_addr[0]}:{new_addr[1]} (roaming)")

    def touch(self, ip: str, rx_bytes: int = 0, tx_bytes: int = 0):
        """Update session stats."""
        s = self.sessions.get(ip)
        if s:
            s["last_seen"] = time.time()
            s["rx"] += rx_bytes
            s["tx"] += tx_bytes

    def _evict_oldest(self):
        """Force-expire the session with the oldest last_seen."""
        if not self.sessions:
            return
        oldest_ip = min(self.sessions, key=lambda k: self.sessions[k]["last_seen"])
        self._remove_session(oldest_ip, reason="evicted (oldest)")

    def _remove_session(self, ip: str, reason: str = "expired"):
        """Remove a session and return its IP to the pool."""
        s = self.sessions.pop(ip, None)
        if s:
            addr = s["addr"]
            if addr in self.addr_to_ip:
                del self.addr_to_ip[addr]
            # Clean up client_ip_map
            client_ip = addr[0]
            if self.client_ip_map.get(client_ip) == ip:
                del self.client_ip_map[client_ip]
            duration = int(time.time() - s["connected_at"])
            log(f"Session {reason}: {ip} ({addr[0]}:{addr[1]}) after {duration}s")
        self._available.add(ip)

    def cleanup(self):
        """Remove expired sessions and return IPs to pool."""
        now = time.time()
        expired = [
            ip for ip, s in self.sessions.items()
            if now - s["last_seen"] > IDLE_TIMEOUT
        ]
        for ip in expired:
            self._remove_session(ip, reason="expired")

    def stats(self) -> dict:
        # Iterate over a snapshot to avoid RuntimeError from concurrent modification
        snapshot = dict(self.sessions)
        total_rx = sum(s["rx"] for s in snapshot.values())
        total_tx = sum(s["tx"] for s in snapshot.values())
        return {
            "active": len(snapshot),
            "total_rx": total_rx,
            "total_tx": total_tx,
            "sessions": {
                ip: {
                    "addr": f"{s['addr'][0]}:{s['addr'][1]}",
                    "rx": s["rx"],
                    "tx": s["tx"],
                    "idle": int(time.time() - s["last_seen"]),
                }
                for ip, s in snapshot.items()
            },
        }

    def save_state(self):
        """Persist sessions to disk (for restart recovery)."""
        try:
            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
            data = {
                ip: {"addr": list(s["addr"]), "last_seen": s["last_seen"]}
                for ip, s in self.sessions.items()
            }
            with open(self.state_file, "w") as f:
                json.dump(data, f)
        except Exception as e:
            log(f"State save failed: {e}", "WARN")


# ── Packet Parsing ─────────────────────────────────────────────────────────

def _ntoa(raw: bytes) -> str:
    """Fast IP bytes → string (replaces ipaddress.IPv4Address)."""
    return f"{raw[0]}.{raw[1]}.{raw[2]}.{raw[3]}"

def _aton(ip_str: str) -> bytes:
    """Fast IP string → bytes."""
    return socket.inet_aton(ip_str)

def extract_dst_ip(packet: bytes) -> str | None:
    """Extract destination IPv4 address from raw IP packet."""
    if len(packet) < 20:
        return None
    if (packet[0] >> 4) != 4:
        return None
    return _ntoa(packet[16:20])


def extract_src_ip(packet: bytes) -> str | None:
    """Extract source IPv4 address from raw IP packet."""
    if len(packet) < 20:
        return None
    if (packet[0] >> 4) != 4:
        return None
    return _ntoa(packet[12:16])


def extract_dst_ip_raw(packet: bytes) -> bytes | None:
    """Extract destination IP as raw 4 bytes (zero-alloc hot path)."""
    if len(packet) < 20 or (packet[0] >> 4) != 4:
        return None
    return packet[16:20]


def extract_src_ip_raw(packet: bytes) -> bytes | None:
    """Extract source IP as raw 4 bytes (zero-alloc hot path)."""
    if len(packet) < 20 or (packet[0] >> 4) != 4:
        return None
    return packet[12:16]


def extract_udp_dst_port(packet: bytes) -> int | None:
    """Extract UDP destination port from raw IPv4/UDP packet."""
    if len(packet) < 28:  # 20 IP + 8 UDP
        return None
    if (packet[0] >> 4) != 4:
        return None
    if packet[9] != 17:  # UDP
        return None
    ihl = (packet[0] & 0x0F) * 4
    if len(packet) < ihl + 4:  # need at least 4 bytes of UDP header
        return None
    return (packet[ihl + 2] << 8) | packet[ihl + 3]


def extract_udp_payload(packet: bytes) -> bytes | None:
    """Extract UDP payload from raw IPv4/UDP packet."""
    if len(packet) < 28:
        return None
    if (packet[0] >> 4) != 4 or packet[9] != 17:
        return None
    ihl = (packet[0] & 0x0F) * 4
    return packet[ihl + 8:]


# ── Main Daemon ────────────────────────────────────────────────────────────

class UdpVpnServer:
    def __init__(self, port: int, subnet: str, tun_name: str = "tun0", ext_iface: str = "ens4"):
        self.port = port
        self.subnet = subnet
        self.tun_name = tun_name
        self.ext_iface = ext_iface
        self.running = True

        net = ipaddress.ip_network(subnet, strict=False)
        self.server_ip = str(list(net.hosts())[0])  # .1
        self.prefix_len = net.prefixlen
        self.sessions = SessionManager(subnet)

        self.tun_fd = -1
        self.sock: socket.socket | None = None
        self.dns_sock: socket.socket | None = None  # for forwarding private DNS
        self.dns_tracks: dict = {}  # src_port → (client_ip, client_addr)
        self.dns_ip_map: dict = {}  # ip → domain (from DNS A record responses)
        self.dns_query_names: dict = {}  # src_port → queried domain name
        self._ptr_cache: dict = {}  # ip → domain (from reverse DNS PTR lookups)
        self._ptr_pending: set = set()  # IPs with in-flight PTR lookups
        self._ptr_executor = ThreadPoolExecutor(max_workers=4)
        self.start_time = time.time()
        self.last_stats = 0
        self.last_save = 0
        self._last_stats_rx = 0
        self._last_stats_tx = 0
        self.ntp = NtpSync(sync_interval_s=300.0)

    def start(self):
        log("=" * 60)
        log(f"Tunnely UDP VPN Server v{__version__} starting...")
        log(f"  Subnet:    {self.subnet}")
        log(f"  Server IP: {self.server_ip}")
        log(f"  TUN:       {self.tun_name}")
        log(f"  UDP port:  {self.port}")
        log(f"  NAT iface: {self.ext_iface}")
        log("=" * 60)

        # Create TUN
        self.tun_fd = create_tun(self.tun_name)
        setup_interface(self.tun_name, self.server_ip, self.prefix_len)
        setup_nat(self.tun_name, self.ext_iface)

        # Create UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        self.sock.bind(("0.0.0.0", self.port))

        # Create DNS forwarding socket (for private DNS proxy: 10.0.2.3 → 8.8.8.8)
        self.dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.dns_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.dns_sock.bind(("0.0.0.0", 0))  # random port
        log(f"DNS forwarder on :{self.dns_sock.getsockname()[1]}")

        # Start NTP sync (for accurate probe timestamps)
        self.ntp.start()
        log(f"NTP sync: offset={self.ntp.offset_us}µs")

        log(f"Listening on UDP :{self.port}")
        log(f"Dashboard: http://0.0.0.0:{self.port + 1}/")
        log("Ready for connections.\n")

        # Start HTTP stats server in background thread
        self._start_http_server()

        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        try:
            self._loop()
        finally:
            self.shutdown()

    def _signal_handler(self, sig, frame):
        log(f"Signal {sig} received, shutting down...")
        self.running = False

    def _start_http_server(self):
        """Start HTTP stats server on UDP port + 1."""
        http_port = self.port + 1
        try:
            StatsHttpHandler.server_ref = self
            httpd = HTTPServer(("0.0.0.0", http_port), StatsHttpHandler)
            httpd.timeout = 1
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            log(f"HTTP stats server on :{http_port}")
        except Exception as e:
            log(f"HTTP stats server failed: {e}", "WARN")

    def _loop(self):
        """Main event loop: TUN fd ↔ UDP socket ↔ DNS forwarder.
        
        Optimizations:
        - epoll on Linux (O(1) for active fds vs O(n) for select)
        - Batch-drain each fd (up to MAX_BATCH packets per wake)
        - Cached timestamp (one time.time() per iteration)
        """
        # Use epoll on Linux, fall back to select
        use_epoll = hasattr(select, 'epoll')
        if use_epoll:
            ep = select.epoll()
            ep.register(self.tun_fd, select.EPOLLIN)
            ep.register(self.sock.fileno(), select.EPOLLIN)
            ep.register(self.dns_sock.fileno(), select.EPOLLIN)
            fd_map = {
                self.tun_fd: 'tun',
                self.sock.fileno(): 'udp',
                self.dns_sock.fileno(): 'dns',
            }
        else:
            watch_fds = [self.tun_fd, self.sock, self.dns_sock]

        while self.running:
            try:
                if use_epoll:
                    events = ep.poll(1.0)
                    readable = [fd for fd, ev in events]
                else:
                    readable, _, _ = select.select(watch_fds, [], [], 1.0)
            except (ValueError, OSError):
                # fd closed after shutdown
                break

            now = time.time()

            # Periodic tasks
            if now - self.last_stats >= STATS_INTERVAL:
                self._print_stats()
                self.sessions.cleanup()  # cleanup with every stats print
                self.last_stats = now
            if now - self.last_save >= 60:
                self.sessions.save_state()
                self.last_save = now

            for fd in readable:
                if use_epoll:
                    kind = fd_map.get(fd)
                    if kind == 'udp':
                        self._batch_handle_udp()
                    elif kind == 'tun':
                        self._batch_handle_tun()
                    elif kind == 'dns':
                        self._handle_dns_response()
                else:
                    if fd == self.sock:
                        self._batch_handle_udp()
                    elif fd == self.tun_fd:
                        self._batch_handle_tun()
                    elif fd == self.dns_sock:
                        self._handle_dns_response()

        if use_epoll:
            ep.close()

    def _batch_handle_udp(self):
        """Drain all pending UDP packets (up to MAX_BATCH)."""
        for _ in range(MAX_BATCH):
            # Check if more data is available without blocking
            ready, _, _ = select.select([self.sock], [], [], 0)
            if not ready:
                return
            try:
                data, addr = self.sock.recvfrom(BUFFER_SIZE)
            except socket.error:
                return
            self._process_udp_packet(data, addr)

    def _batch_handle_tun(self):
        """Drain all pending TUN packets (up to MAX_BATCH)."""
        for _ in range(MAX_BATCH):
            ready, _, _ = select.select([self.tun_fd], [], [], 0)
            if not ready:
                return
            try:
                data = os.read(self.tun_fd, BUFFER_SIZE)
            except OSError:
                return
            self._process_tun_packet(data)

    def _process_udp_packet(self, data: bytes, addr):
        """Process a single UDP packet from client → write to TUN."""

        # Handle latency probe (magic "TLTP" = 0x544C5450) — 32 bytes
        if len(data) == PROBE_SIZE and data[0:4] == TLTP_MAGIC:
            probe_type = data[4]
            if probe_type == PROBE_REQUEST:
                recv_us = self.ntp.now_micros()  # NTP-corrected timestamp
                response = bytearray(data)
                response[4] = PROBE_RESPONSE
                struct.pack_into(">q", response, 16, recv_us)  # server recv timestamp
                echo_us = self.ntp.now_micros()  # NTP-corrected timestamp
                struct.pack_into(">q", response, 24, echo_us)  # server echo timestamp
                try:
                    self.sock.sendto(bytes(response), addr)
                except socket.error:
                    pass
            return

        if len(data) < 20:
            # Handle hello/keepalive packets (magic "TUNN" = 0x54554E4E)
            if len(data) == 4 and data == b"\x54\x55\x4E\x4E":
                if addr not in self.sessions.addr_to_ip:
                    assigned_ip = self.sessions.assign_ip(addr)
                    log(f"Hello packet from {addr[0]}:{addr[1]} → {assigned_ip}")
                else:
                    self.sessions.touch(self.sessions.addr_to_ip[addr])
            return  # Not a valid IP packet

        src_ip = extract_src_ip(data)
        if not src_ip:
            return

        # Check if this client has a session
        if addr in self.sessions.addr_to_ip:
            assigned_ip = self.sessions.addr_to_ip[addr]
            # Handle roaming: client IP in packet should match assigned IP
            # If src_ip != assigned_ip, client may have reconnected with new key
            if src_ip != assigned_ip:
                # Update the source IP in the packet to match assignment
                # (client doesn't know its assigned IP on first connect)
                data = self._rewrite_src_ip(data, assigned_ip)
            self.sessions.touch(assigned_ip, rx_bytes=len(data))
        else:
            # New client — auto-assign IP
            assigned_ip = self.sessions.assign_ip(addr)
            # Rewrite source IP to assigned IP
            data = self._rewrite_src_ip(data, assigned_ip)
            self.sessions.touch(assigned_ip, rx_bytes=len(data))

        # Write to TUN device (kernel routes it)
        # BUT: intercept DNS to private IPs (10.0.2.3 etc) — forward to 8.8.8.8
        dst_ip = extract_dst_ip(data)
        dst_port = extract_udp_dst_port(data)
        # Fast path: check raw bytes instead of string conversion
        dst_raw = data[16:20] if len(data) >= 20 else None
        if dst_raw and dst_raw in PRIVATE_DNS_IP_BYTES and dst_port == 53:
            self._forward_dns(data, dst_ip, assigned_ip, addr)
            return

        # Log protocol breakdown (sampled)
        proto = data[9] if len(data) > 9 else -1
        proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, f"P{proto}")
        if self._should_debug_log():
            log(f"  [RX] {assigned_ip}→{dst_ip} {proto_name} {len(data)}B")

        # Track TCP/TLS for debugging
        if proto == 6:  # TCP
            self._track_tcp_flow(data, assigned_ip, dst_ip)

        # Track QUIC SNI for UDP port 443
        if proto == 17 and QUIC_SNI_AVAILABLE and dst_port == 443:
            self._track_quic_sni(data, assigned_ip, dst_ip)

        try:
            os.write(self.tun_fd, data)
        except OSError as e:
            log(f"TUN write error: {e}", "WARN")

    def _process_tun_packet(self, data: bytes):
        """Process a single TUN packet → route to client via UDP."""

        dst_ip = extract_dst_ip(data)
        if not dst_ip:
            return

        client_addr = self.sessions.get_addr_by_ip(dst_ip)
        if client_addr:
            # Track TX using the ORIGINAL assigned IP (session key), before rewriting
            assigned_ip = dst_ip

            # Rewrite dst IP from assigned IP back to client's TUN IP (10.20.0.2)
            # Without this, the client kernel drops packets with dst != 10.20.0.2
            CLIENT_TUN_IP = "10.20.0.2"
            if dst_ip != CLIENT_TUN_IP:
                data = self._rewrite_dst_ip(data, CLIENT_TUN_IP)
                dst_ip = CLIENT_TUN_IP

            # Debug: log response packets (sampled)
            src_ip = extract_src_ip(data)
            proto = data[9] if len(data) > 9 else -1
            proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, f"P{proto}")
            if self._should_debug_log():
                log(f"  [TX] {src_ip}→{dst_ip} {proto_name} {len(data)}B")

            try:
                self.sock.sendto(data, client_addr)
                self.sessions.touch(assigned_ip, tx_bytes=len(data))
            except socket.error as e:
                log(f"UDP send error to {dst_ip}: {e}", "WARN")
        else:
            # No client for this TUN packet — log it
            src_ip = extract_src_ip(data)
            proto = data[9] if len(data) > 9 else -1
            proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, f"P{proto}")
            log(f"  [ORPHAN] {src_ip}→{dst_ip} {proto_name} {len(data)}B (no client)", "WARN")

    _debug_counter = 0
    def _should_debug_log(self) -> bool:
        """Log every 50th packet to avoid spam."""
        self._debug_counter += 1
        if self._debug_counter >= 50:
            self._debug_counter = 0
            return True
        return False

    # TCP/TLS flow tracking for debugging
    _tcp_tracker = {}  # client_ip -> {dst_ip:port -> {syn, established, tls_hello, sni}}
    _tls_sni_log = []  # recent SNI domains seen

    def _track_tcp_flow(self, data: bytes, client_ip: str, dst_ip: str):
        """Track TCP connection state and TLS ClientHello/SNI."""
        if len(data) < 40:  # IP(20) + TCP(20) minimum
            return

        ihl = (data[0] & 0x0F) * 4
        if len(data) < ihl + 14:  # need at least TCP flags
            return

        tcp_flags = data[ihl + 13] & 0x3F
        dst_port = ((data[ihl + 2] & 0xFF) << 8) | (data[ihl + 3] & 0xFF)
        flow_key = f"{dst_ip}:{dst_port}"

        # Get or create client tracker
        if client_ip not in self._tcp_tracker:
            self._tcp_tracker[client_ip] = {}

        client_flows = self._tcp_tracker[client_ip]
        if flow_key not in client_flows:
            client_flows[flow_key] = {"syn": 0, "established": False, "tls_hello": 0, "sni": None}

        flow = client_flows[flow_key]

        # SYN flag (bit 1)
        if tcp_flags & 0x02:
            flow["syn"] += 1

        # Check for TLS ClientHello in TCP payload
        payload_start = ihl + ((data[ihl + 12] & 0xF0) >> 2)  # data offset
        if len(data) > payload_start + 5:
            tls_content_type = data[payload_start]
            tls_version = ((data[payload_start + 1] & 0xFF) << 8) | (data[payload_start + 2] & 0xFF)
            # TLS Handshake (0x16) with version >= TLS 1.0 (0x0301)
            if tls_content_type == 0x16 and tls_version >= 0x0301:
                handshake_type = data[payload_start + 5] if len(data) > payload_start + 5 else -1
                if handshake_type == 0x01:  # ClientHello
                    flow["tls_hello"] += 1
                    # Try to extract SNI
                    sni = self._extract_sni_from_payload(data, payload_start + 5)
                    if sni:
                        flow["sni"] = sni
                        self._tls_sni_log.append(f"{client_ip}→{dst_ip}:{dst_port} = {sni}")
                        # Keep only last 50 entries
                        if len(self._tls_sni_log) > 50:
                            self._tls_sni_log.pop(0)
                        log(f"  [TLS] {client_ip}→{dst_ip}:{dst_port} SNI={sni}")

        # Mark established on SYN-ACK (from server) or ACK after SYN
        if tcp_flags & 0x10:  # ACK
            flow["established"] = True

    # QUIC SNI tracking (UDP port 443)
    _quic_sni_cache = {}  # dst_ip -> domain (dedup, avoid re-parsing)
    _quic_initial_seen = 0  # total QUIC Initial packets seen
    _quic_sni_extracted = 0  # successful QUIC SNI extractions
    _quic_sni_failed = 0  # failed QUIC SNI extractions (Initial but no SNI)

    def _track_quic_sni(self, data: bytes, client_ip: str, dst_ip: str):
        """Extract SNI from QUIC Initial packets (UDP :443)."""
        # Skip if already know this IP's domain
        if dst_ip in self._quic_sni_cache:
            return

        # IP header offset
        ihl = (data[0] & 0x0F) * 4 if len(data) >= 20 else 0
        # UDP header is 8 bytes after IP header
        udp_payload_start = ihl + 8
        if len(data) <= udp_payload_start:
            return

        udp_payload = data[udp_payload_start:]
        if not is_quic_initial(udp_payload):
            return

        self._quic_initial_seen += 1
        sni = extract_quic_sni(udp_payload)
        if sni:
            self._quic_sni_extracted += 1
            self._quic_sni_cache[dst_ip] = sni
            # Add to tcp_tracker so it appears in sni_domain_map
            if client_ip not in self._tcp_tracker:
                self._tcp_tracker[client_ip] = {}
            flow_key = f"{dst_ip}:443"
            self._tcp_tracker[client_ip][flow_key] = {
                "syn": 0, "established": True, "tls_hello": 1, "sni": sni
            }
            self._tls_sni_log.append(f"{client_ip}→{dst_ip}:443 = {sni}")
            if len(self._tls_sni_log) > 50:
                self._tls_sni_log.pop(0)
            log(f"  [QUIC] {client_ip}→{dst_ip}:443 SNI={sni}")
        else:
            # DNS fallback: if we know this IP from a prior DNS query, use that domain
            dns_domain = self.dns_ip_map.get(dst_ip)
            if dns_domain:
                self._quic_sni_extracted += 1  # count as success (DNS-resolved)
                self._quic_sni_cache[dst_ip] = dns_domain
                if client_ip not in self._tcp_tracker:
                    self._tcp_tracker[client_ip] = {}
                flow_key = f"{dst_ip}:443"
                self._tcp_tracker[client_ip][flow_key] = {
                    "syn": 0, "established": True, "tls_hello": 1, "sni": dns_domain
                }
                self._tls_sni_log.append(f"{client_ip}→{dst_ip}:443 = {dns_domain} [dns]")
                if len(self._tls_sni_log) > 50:
                    self._tls_sni_log.pop(0)
                log(f"  [QUIC-DNS] {client_ip}→{dst_ip}:443 SNI={dns_domain}")
            else:
                # PTR fallback: try reverse DNS lookup for unknown IPs
                if dst_ip in self._ptr_cache:
                    ptr_domain = self._ptr_cache[dst_ip]
                    if ptr_domain:
                        self._quic_sni_extracted += 1
                        self._quic_sni_cache[dst_ip] = ptr_domain
                        if client_ip not in self._tcp_tracker:
                            self._tcp_tracker[client_ip] = {}
                        flow_key = f"{dst_ip}:443"
                        self._tcp_tracker[client_ip][flow_key] = {
                            "syn": 0, "established": True, "tls_hello": 1, "sni": ptr_domain
                        }
                        self._tls_sni_log.append(f"{client_ip}→{dst_ip}:443 = {ptr_domain} [ptr]")
                        if len(self._tls_sni_log) > 50:
                            self._tls_sni_log.pop(0)
                        log(f"  [QUIC-PTR] {client_ip}→{dst_ip}:443 SNI={ptr_domain}")
                    # else: PTR returned None — skip, don't re-lookup
                elif dst_ip not in self._ptr_pending and len(self._ptr_pending) < 100:
                    # Schedule async PTR lookup for this IP (non-blocking)
                    self._ptr_pending.add(dst_ip)
                    self._ptr_executor.submit(self._do_ptr_lookup, dst_ip)
                    # Debug: log failed QUIC extraction (sampled 1/5)
                    if self._quic_initial_seen % 5 == 1:
                        hdr = _parse_quic_header(udp_payload)
                        if hdr:
                            log(f"  [QUIC-FAIL] {dst_ip} ver=0x{hdr['version']:08x} dcid={hdr['dcid'].hex()[:8]}.. len={len(udp_payload)}")
                        else:
                            log(f"  [QUIC-FAIL] {dst_ip} len={len(udp_payload)} hdr=None")

    def _extract_sni_from_payload(self, data: bytes, ch_offset: int) -> str:
        """Extract SNI from TLS ClientHello at given offset."""
        try:
            if len(data) < ch_offset + 38:
                return None
            # Skip: handshake type(1) + length(3) + version(2) + random(32) = 38
            pos = ch_offset + 38
            # Session ID
            if pos >= len(data):
                return None
            session_id_len = data[pos] & 0xFF
            pos += 1 + session_id_len
            # Cipher Suites
            if pos + 2 > len(data):
                return None
            cs_len = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF)
            pos += 2 + cs_len
            # Compression
            if pos >= len(data):
                return None
            comp_len = data[pos] & 0xFF
            pos += 1 + comp_len
            # Extensions
            if pos + 2 > len(data):
                return None
            ext_len = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF)
            pos += 2
            ext_end = pos + ext_len
            if ext_end > len(data):
                return None
            # Find SNI extension (type 0x0000)
            while pos + 4 <= ext_end:
                ext_type = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF)
                ext_data_len = ((data[pos + 2] & 0xFF) << 8) | (data[pos + 3] & 0xFF)
                pos += 4
                if ext_type == 0x0000:  # SNI
                    if pos + 2 > len(data):
                        return None
                    sni_list_len = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF)
                    pos += 2
                    if pos + 3 > len(data):
                        return None
                    name_type = data[pos]
                    name_len = ((data[pos + 1] & 0xFF) << 8) | (data[pos + 2] & 0xFF)
                    pos += 3
                    if name_type == 0x00 and pos + name_len <= len(data):
                        return data[pos:pos + name_len].decode('ascii', errors='ignore')
                pos += ext_data_len
        except Exception:
            pass
        return None

    def get_tcp_debug_summary(self) -> dict:
        """Get summary of TCP/TLS/QUIC flows for HTTP stats."""
        total_tls = 0
        total_sni = 0
        recent_snis = list(self._tls_sni_log[-10:])
        # Build comprehensive IP→domain map from ALL tracked flows
        sni_domain_map = {}
        for client_flows in self._tcp_tracker.values():
            for flow_key, flow in client_flows.items():
                if flow["tls_hello"] > 0:
                    total_tls += 1
                if flow["sni"]:
                    total_sni += 1
                    # flow_key = "dst_ip:dst_port" — extract IP
                    colon_idx = flow_key.rfind(':')
                    remote_ip = flow_key[:colon_idx] if colon_idx > 0 else flow_key
                    sni_domain_map[remote_ip] = flow["sni"]

        # QUIC SNI data
        quic_sni_count = len(self._quic_sni_cache)
        quic_sni_map = dict(self._quic_sni_cache)

        # DNS IP→domain map (from DNS response A records)
        dns_map = dict(self.dns_ip_map)

        # PTR reverse DNS map (filter out None/misses)
        ptr_map = {k: v for k, v in self._ptr_cache.items() if v is not None}

        # Combined: TCP + QUIC + DNS + PTR (priority: QUIC > TCP > DNS > PTR)
        combined_map = {**ptr_map, **dns_map, **sni_domain_map, **quic_sni_map}
        combined_sni = len(combined_map)

        # Also enrich TCP flows without SNI using DNS map
        dns_enriched = 0
        for client_flows in self._tcp_tracker.values():
            for flow_key, flow in client_flows.items():
                if not flow["sni"]:
                    colon_idx = flow_key.rfind(':')
                    remote_ip = flow_key[:colon_idx] if colon_idx > 0 else flow_key
                    if remote_ip in self.dns_ip_map:
                        flow["sni"] = self.dns_ip_map[remote_ip]
                        dns_enriched += 1
                        total_sni += 1

        return {
            "tcp_flows": sum(len(f) for f in self._tcp_tracker.values()),
            "tls_handshakes": total_tls,
            "sni_domains": total_sni,
            "recent_snis": recent_snis,
            "sni_domain_map": sni_domain_map,
            "quic_initial_seen": self._quic_initial_seen,
            "quic_sni_extracted": self._quic_sni_extracted,
            "quic_sni_failed": self._quic_initial_seen - self._quic_sni_extracted,
            "quic_sni_domains": quic_sni_count,
            "quic_sni_map": quic_sni_map,
            "dns_domains": len(dns_map),
            "dns_enriched": dns_enriched,
            "dns_ip_map": dns_map,
            "ptr_domains": len(ptr_map),
            "ptr_pending": len(self._ptr_pending),
            "ptr_map": ptr_map,
            "combined_sni_domains": combined_sni,
            "combined_sni_map": combined_map,
        }

    def _forward_dns(self, packet: bytes, orig_dns_ip: str, client_ip: str, client_addr):
        """Forward DNS query to 8.8.8.8, track for response rewriting."""
        payload = extract_udp_payload(packet)
        if not payload or len(payload) < 12:
            return

        # Extract src port from IP/UDP packet (at UDP header offset 0)
        ihl = (packet[0] & 0x0F) * 4
        src_port = (packet[ihl] << 8) | packet[ihl + 1]

        # Track: response for this src_port goes back to this client
        self.dns_tracks[src_port] = (orig_dns_ip, client_ip, client_addr, time.time())
        
        # Parse DNS question to extract queried domain name
        try:
            if len(payload) > 12:
                qname = self._parse_dns_qname(payload, 12)
                if qname:
                    self.dns_query_names[src_port] = qname.lower()
        except Exception:
            pass  # non-fatal

        # Forward to real DNS server
        try:
            self.dns_sock.sendto(payload, ("8.8.8.8", 53))
        except socket.error as e:
            log(f"DNS forward error: {e}", "WARN")
            self.dns_tracks.pop(src_port, None)

    def _handle_dns_response(self):
        """Receive DNS response from 8.8.8.8, rewrite, send to client."""
        try:
            data, _ = self.dns_sock.recvfrom(BUFFER_SIZE)
        except socket.error:
            return

        if len(data) < 12:  # minimum DNS header
            return

        # Extract dst port from DNS response (our original src port)
        # DNS doesn't have ports — we need to find the src_port from the original query.
        # The dst port in the UDP response matches our dns_sock's ephemeral port,
        # NOT our src_port tracking key. We need to match by DNS transaction ID instead.
        # Actually, the response comes to dns_sock bound on a random port.
        # The remote addr (8.8.8.8:53) sends to our dns_sock port.
        # We can't distinguish which query this response belongs to from the UDP alone.
        #
        # Solution: parse DNS header to get transaction ID, but we didn't store it.
        # Simpler: use the UDP source port from the ORIGINAL query packet.
        # Since we can't get it from the response, we'll match by scanning dns_tracks.
        # In practice, only ONE query is in-flight at a time per src_port.
        #
        # Better approach: match by DNS question section. But that's complex.
        # Simplest: just scan dns_tracks and use the first match.
        # For correct matching, we need to store the DNS transaction ID.
        #
        # Actually, we CAN get the original src port! The DNS response's dst port
        # is our dns_sock's local port (ephemeral). But we can get the ORIGINAL
        # src port from the DNS response itself... no, DNS doesn't carry ports.
        #
        # Real solution: store transaction ID → src_port mapping.
        # Or: use one dns_sock per query. Too expensive.
        # Or: match by scanning all tracked entries (small dict, fast).
        #
        # Since responses are fast (<100ms) and we have few concurrent queries,
        # just use the OLDEST unmatched entry. This works for the common case.
        if not self.dns_tracks:
            return

        # Find the oldest entry (FIFO)
        oldest_port = min(self.dns_tracks, key=lambda k: self.dns_tracks[k][3])
        orig_dns_ip, client_ip, client_addr, _ = self.dns_tracks.pop(oldest_port)
        
        # Extract A records from DNS response → dns_ip_map
        qname = self.dns_query_names.pop(oldest_port, None)
        if qname:
            try:
                a_records = self._parse_dns_a_records(data)
                for ip in a_records:
                    self.dns_ip_map[ip] = qname
                if a_records:
                    log(f"  [DNS] {qname} → {', '.join(a_records[:3])}")
            except Exception:
                pass  # non-fatal
        
        # Cap dns_ip_map size (LRU-like: just purge oldest half when too big)
        if len(self.dns_ip_map) > 5000:
            keys = list(self.dns_ip_map.keys())
            for k in keys[:len(keys)//2]:
                del self.dns_ip_map[k]

        # Build response IP/UDP packet with src=original_private_dns
        resp = self._build_udp_response(orig_dns_ip, client_ip, 53, oldest_port, data)

        try:
            os.write(self.tun_fd, resp)
            self.sessions.touch(client_ip, tx_bytes=len(resp))
        except OSError as e:
            log(f"DNS response TUN write error: {e}", "WARN")

    def _do_ptr_lookup(self, ip: str):
        """Reverse DNS lookup (PTR record). Runs in thread pool — non-blocking."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            # Filter out generic/meaningless PTR names
            if hostname and hostname != ip and not hostname.startswith("unknown"):
                self._ptr_cache[ip] = hostname.lower()
                log(f"  [PTR] {ip} → {hostname}")
            else:
                self._ptr_cache[ip] = None
        except (socket.herror, socket.gaierror, OSError):
            self._ptr_cache[ip] = None
        finally:
            self._ptr_pending.discard(ip)

    @staticmethod
    def _parse_dns_qname(data: bytes, offset: int) -> str | None:
        """Parse DNS QNAME from packet starting at offset. Returns domain string."""
        labels = []
        jumped = False
        jump_limit = 10
        while jump_limit > 0:
            if offset >= len(data):
                return None
            length = data[offset]
            if length == 0:
                offset += 1
                break
            # Pointer (compression)
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data):
                    return None
                if not jumped:
                    # Save position after pointer for final offset
                    pass
                offset = ((length & 0x3F) << 8) | data[offset + 1]
                jumped = True
                jump_limit -= 1
                continue
            offset += 1
            if offset + length > len(data):
                return None
            labels.append(data[offset:offset + length].decode('ascii', errors='ignore'))
            offset += length
        return '.'.join(labels) if labels else None

    @staticmethod
    def _parse_dns_a_records(data: bytes) -> list[str]:
        """Parse DNS response and extract A record IP addresses."""
        if len(data) < 12:
            return []
        # Header: ID(2) FLAGS(2) QDCOUNT(2) ANCOUNT(2) ...
        qdcount = (data[4] << 8) | data[5]
        ancount = (data[6] << 8) | data[7]
        if ancount == 0:
            return []

        # Skip question section
        offset = 12
        for _ in range(qdcount):
            # Skip QNAME
            limit = 10
            while limit > 0 and offset < len(data):
                length = data[offset]
                if length == 0:
                    offset += 1
                    break
                if (length & 0xC0) == 0xC0:
                    offset += 2
                    break
                offset += 1 + length
                limit -= 1
            offset += 4  # QTYPE(2) + QCLASS(2)

        # Parse answer section
        ips = []
        for _ in range(ancount):
            if offset >= len(data):
                break
            # Skip NAME (may be pointer)
            if (data[offset] & 0xC0) == 0xC0:
                offset += 2
            else:
                limit = 10
                while limit > 0 and offset < len(data):
                    length = data[offset]
                    if length == 0:
                        offset += 1
                        break
                    if (length & 0xC0) == 0xC0:
                        offset += 2
                        break
                    offset += 1 + length
                    limit -= 1

            if offset + 10 > len(data):
                break
            rtype = (data[offset] << 8) | data[offset + 1]
            rdlength = (data[offset + 8] << 8) | data[offset + 9]
            offset += 10  # TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)

            if rtype == 1 and rdlength == 4 and offset + 4 <= len(data):  # A record
                ip = f"{data[offset]}.{data[offset+1]}.{data[offset+2]}.{data[offset+3]}"
                ips.append(ip)
            offset += rdlength

        return ips

    @staticmethod
    def _build_udp_response(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
        """Build a raw IP/UDP packet for DNS response."""
        ip_len = 20
        udp_len = 8 + len(payload)
        total_len = ip_len + udp_len
        pkt = bytearray(total_len)

        # IP header
        pkt[0] = 0x45
        pkt[2] = (total_len >> 8) & 0xFF
        pkt[3] = total_len & 0xFF
        pkt[6] = 0x40  # DF
        pkt[8] = 64    # TTL
        pkt[9] = 17    # UDP
        # IP checksum = 0 (kernel recalculates on TUN write)
        src = _aton(src_ip)
        dst = _aton(dst_ip)
        pkt[12:16] = src
        pkt[16:20] = dst

        # UDP header
        pkt[20] = (src_port >> 8) & 0xFF
        pkt[21] = src_port & 0xFF
        pkt[22] = (dst_port >> 8) & 0xFF
        pkt[23] = dst_port & 0xFF
        pkt[24] = (udp_len >> 8) & 0xFF
        pkt[25] = udp_len & 0xFF
        # UDP checksum = 0 (valid per RFC 768)
        pkt[26] = 0
        pkt[27] = 0

        pkt[28:] = payload
        return bytes(pkt)

    def _rewrite_src_ip(self, packet: bytes, new_ip: str) -> bytes:
        """Rewrite source IP and fix ALL checksums (IP header + TCP/UDP transport).
        
        Without fixing transport checksums, the kernel silently drops TCP packets
        because the pseudo-header checksum no longer matches.
        """
        pkt = bytearray(packet)
        new_ip_bytes = _aton(new_ip)
        old_src = bytes(pkt[12:16])

        # Skip if no change needed
        if old_src == new_ip_bytes:
            return bytes(pkt)

        # ── Fix IP header checksum ──
        pkt[10:12] = b"\x00\x00"
        pkt[12:16] = new_ip_bytes
        ihl = (pkt[0] & 0x0F) * 4  # actual IP header length (may include options)
        ip_sum = 0
        for i in range(0, min(ihl, len(pkt)), 2):
            ip_sum += pkt[i] << 8 | pkt[i + 1]
        while ip_sum >> 16:
            ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16)
        pkt[10:12] = (~ip_sum & 0xFFFF).to_bytes(2, "big")

        # ── Fix transport checksum (TCP/UDP) using RFC 1624 incremental update ──
        if len(pkt) >= 20:
            protocol = pkt[9]
            ihl = (pkt[0] & 0x0F) * 4  # IP header length

            if protocol == 6 and len(pkt) >= ihl + 18:
                # TCP: checksum at offset 16 from TCP header
                self._incremental_checksum_fix(pkt, ihl + 16, old_src, new_ip_bytes)
            elif protocol == 17 and len(pkt) >= ihl + 8:
                # UDP: checksum at offset 6 from UDP header (skip if 0 = no checksum)
                udp_cksum_off = ihl + 6
                if pkt[udp_cksum_off] != 0 or pkt[udp_cksum_off + 1] != 0:
                    self._incremental_checksum_fix(pkt, udp_cksum_off, old_src, new_ip_bytes)

        return bytes(pkt)

    def _rewrite_dst_ip(self, packet: bytes, new_ip: str) -> bytes:
        """Rewrite destination IP and fix ALL checksums (IP header + TCP/UDP transport).
        
        Used to rewrite reply packets from assigned IP back to client's TUN IP (10.20.0.2).
        """
        if len(packet) < 20:
            return packet  # too short to have a dst IP field

        pkt = bytearray(packet)
        new_ip_bytes = _aton(new_ip)
        old_dst = bytes(pkt[16:20])

        # Skip if no change needed
        if old_dst == new_ip_bytes:
            return bytes(pkt)

        # ── Fix IP header checksum ──
        pkt[10:12] = b"\x00\x00"
        pkt[16:20] = new_ip_bytes
        ihl = (pkt[0] & 0x0F) * 4
        ip_sum = 0
        for i in range(0, min(ihl, len(pkt)), 2):
            ip_sum += pkt[i] << 8 | pkt[i + 1]
        while ip_sum >> 16:
            ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16)
        pkt[10:12] = (~ip_sum & 0xFFFF).to_bytes(2, "big")

        # ── Fix transport checksum (TCP/UDP) using RFC 1624 incremental update ──
        if len(pkt) >= 20:
            protocol = pkt[9]
            ihl = (pkt[0] & 0x0F) * 4

            if protocol == 6 and len(pkt) >= ihl + 18:
                # TCP: checksum at offset 16 from TCP header
                self._incremental_checksum_fix(pkt, ihl + 16, old_dst, new_ip_bytes)
            elif protocol == 17 and len(pkt) >= ihl + 8:
                # UDP: checksum at offset 6 from UDP header (skip if 0 = no checksum)
                udp_cksum_off = ihl + 6
                if pkt[udp_cksum_off] != 0 or pkt[udp_cksum_off + 1] != 0:
                    self._incremental_checksum_fix(pkt, udp_cksum_off, old_dst, new_ip_bytes)

        return bytes(pkt)

    @staticmethod
    def _incremental_checksum_fix(pkt: bytearray, cksum_off: int, old_bytes: bytes, new_bytes: bytes):
        """RFC 1624 incremental checksum update for changed source IP.
        
        HC' = ~(~HC + ~m + m')
        where HC = old checksum, m = old bytes, m' = new bytes
        """
        # Read current transport checksum
        cksum = (pkt[cksum_off] << 8) | pkt[cksum_off + 1]

        # Compute: sum = ~HC + ~old + new (for each 16-bit word)
        s = (~cksum & 0xFFFF)
        for i in range(0, len(old_bytes), 2):
            old_word = (old_bytes[i] << 8) | old_bytes[i + 1]
            s += (~old_word & 0xFFFF)
        for i in range(0, len(new_bytes), 2):
            new_word = (new_bytes[i] << 8) | new_bytes[i + 1]
            s += new_word

        # Fold carries (ones' complement)
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)

        # Result is complement of sum
        new_cksum = ~s & 0xFFFF
        pkt[cksum_off] = (new_cksum >> 8) & 0xFF
        pkt[cksum_off + 1] = new_cksum & 0xFF

    def _print_stats(self):
        s = self.sessions.stats()
        rx_mb = s["total_rx"] / 1024 / 1024
        tx_mb = s["total_tx"] / 1024 / 1024
        # Rate = delta since last stats print (not cumulative)
        delta_rx = s["total_rx"] - self._last_stats_rx
        delta_tx = s["total_tx"] - self._last_stats_tx
        self._last_stats_rx = s["total_rx"]
        self._last_stats_tx = s["total_tx"]
        log(
            f"[stats] sessions={s['active']}  "
            f"rx={rx_mb:.2f}MB  tx={tx_mb:.2f}MB  "
            f"rate={delta_rx / STATS_INTERVAL / 1024:.0f}KB/s↓ "
            f"{delta_tx / STATS_INTERVAL / 1024:.0f}KB/s↑"
        )
        for ip, info in s["sessions"].items():
            log(
                f"  {ip} → {info['addr']}  "
                f"rx={info['rx']:,}B  tx={info['tx']:,}B  "
                f"idle={info['idle']}s"
            )

    def shutdown(self):
        log("Shutting down...")
        self.sessions.save_state()
        teardown_nat(self.tun_name, self.ext_iface)

        if self.sock:
            self.sock.close()
        if self.dns_sock:
            self.dns_sock.close()
        if self.tun_fd >= 0:
            try:
                os.close(self.tun_fd)
            except OSError:
                pass

        # Remove TUN interface
        subprocess.run(["ip", "link", "del", self.tun_name], capture_output=True)
        log("Server stopped.")


# ── Status API (optional, for monitoring) ──────────────────────────────────
# Stats are logged to stdout + /var/log/tunnely-udp-vpn.log.
# For HTTP status, query the /api/tunnel/status endpoint on the main API server.


# ── CLI ────────────────────────────────────────────────────────────────────

# ── HTTP Stats Dashboard ─────────────────────────────────────────────

DASHBOARD_HTML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")


class StatsHttpHandler(BaseHTTPRequestHandler):
    """HTTP handler for stats API and dashboard."""

    server_ref: object = None  # Set by UdpVpnServer before starting

    def do_GET(self):
        if self.path == "/api/stats" or self.path == "/api/vpn/stats":
            self._serve_stats()
        elif self.path == "/" or self.path == "/dashboard":
            self._serve_dashboard()
        else:
            self.send_error(404)

    def do_HEAD(self):
        self.do_GET()

    def _serve_stats(self):
        srv = self.server_ref
        if not srv:
            self.send_error(503)
            return

        stats = srv.sessions.stats()
        tcp_debug = srv.get_tcp_debug_summary()
        data = {
            "version": __version__,
            "uptime_seconds": int(time.time() - srv.start_time),
            "active_sessions": stats["active"],
            "total_rx": stats["total_rx"],
            "total_tx": stats["total_tx"],
            "sessions": stats["sessions"],
            "subnet": srv.subnet,
            "tun_name": srv.tun_name,
            "ext_iface": srv.ext_iface,
            "udp_port": srv.port,
            "dns_forwarder_port": srv.dns_sock.getsockname()[1] if srv.dns_sock else None,
            "tcp_debug": tcp_debug,
        }
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_dashboard(self):
        try:
            with open(DASHBOARD_HTML_PATH, "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except FileNotFoundError:
            self.send_error(404, "Dashboard not found")

    def log_message(self, format, *args):
        pass  # Suppress HTTP access logs


def main():
    parser = argparse.ArgumentParser(description="Tunnely UDP VPN Server")
    parser.add_argument("--port", type=int, default=5555, help="UDP listen port")
    parser.add_argument("--subnet", default="10.20.0.0/24", help="Client IP subnet")
    parser.add_argument("--tun-name", default="tun0", help="TUN interface name")
    parser.add_argument("--ext-iface", default="ens4", help="External interface for NAT")
    parser.add_argument("--no-nat", action="store_true", help="Skip iptables NAT setup")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("ERROR: Must run as root (need TUN device + iptables)")
        sys.exit(1)

    server = UdpVpnServer(
        port=args.port,
        subnet=args.subnet,
        tun_name=args.tun_name,
        ext_iface=args.ext_iface,
    )
    server.start()


if __name__ == "__main__":
    main()
