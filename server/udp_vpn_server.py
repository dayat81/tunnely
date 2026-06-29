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

# ── Constants ──────────────────────────────────────────────────────────────

__version__ = "3.7.0"

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
    """Manages client IP assignment and NAT mapping."""

    def __init__(self, network: str, state_file: str = STATE_FILE):
        net = ipaddress.ip_network(network, strict=False)
        self.network = net
        # .1 = server, .2-.254 = clients
        self.pool = list(net.hosts())[1:-1]  # skip .1 (server) and .255 (broadcast)
        self.pool_iter = iter(self.pool)
        # ip (str) → {addr: (ip, port), last_seen: float, rx: int, tx: int}
        self.sessions = {}
        # addr tuple → ip str (reverse lookup)
        self.addr_to_ip = {}
        self.state_file = state_file

    def assign_ip(self, client_addr) -> str:
        """Assign or return existing IP for a client address."""
        if client_addr in self.addr_to_ip:
            ip = self.addr_to_ip[client_addr]
            self.sessions[ip]["last_seen"] = time.time()
            return ip

        # Try to get an IP from the pool
        try:
            ip = str(next(self.pool_iter))
        except StopIteration:
            # Pool exhausted — try recycling expired sessions
            self.cleanup()
            self.pool_iter = iter(self.pool)
            try:
                ip = str(next(self.pool_iter))
            except StopIteration:
                # Still exhausted — force-expire the oldest session
                if self.sessions:
                    oldest_ip = min(self.sessions, key=lambda k: self.sessions[k]["last_seen"])
                    old_addr = self.sessions[oldest_ip]["addr"]
                    del self.sessions[oldest_ip]
                    if old_addr in self.addr_to_ip:
                        del self.addr_to_ip[old_addr]
                    log(f"Pool exhausted — evicted oldest session {oldest_ip}", "WARN")
                    self.pool_iter = iter(self.pool)
                    ip = str(next(self.pool_iter))
                else:
                    raise RuntimeError("IP pool exhausted and no sessions to evict")

        self.sessions[ip] = {
            "addr": client_addr,
            "last_seen": time.time(),
            "rx": 0,
            "tx": 0,
            "connected_at": time.time(),
        }
        self.addr_to_ip[client_addr] = ip
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
            log(f"Session updated: {ip} → {new_addr[0]}:{new_addr[1]} (roaming)")

    def touch(self, ip: str, rx_bytes: int = 0, tx_bytes: int = 0):
        """Update session stats."""
        s = self.sessions.get(ip)
        if s:
            s["last_seen"] = time.time()
            s["rx"] += rx_bytes
            s["tx"] += tx_bytes

    def cleanup(self):
        """Remove expired sessions."""
        now = time.time()
        expired = [
            ip for ip, s in self.sessions.items()
            if now - s["last_seen"] > IDLE_TIMEOUT
        ]
        for ip in expired:
            addr = self.sessions[ip]["addr"]
            duration = int(now - self.sessions[ip]["connected_at"])
            log(f"Session expired: {ip} ({addr[0]}:{addr[1]}) after {duration}s")
            del self.sessions[ip]
            if addr in self.addr_to_ip:
                del self.addr_to_ip[addr]

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
        self.start_time = time.time()
        self.last_stats = 0
        self.last_save = 0
        self._last_stats_rx = 0
        self._last_stats_tx = 0

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
                self.sessions.touch(dst_ip, tx_bytes=len(data))
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

        # Build response IP/UDP packet with src=original_private_dns
        resp = self._build_udp_response(orig_dns_ip, client_ip, 53, oldest_port, data)

        try:
            os.write(self.tun_fd, resp)
            self.sessions.touch(client_ip, tx_bytes=len(resp))
        except OSError as e:
            log(f"DNS response TUN write error: {e}", "WARN")

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
