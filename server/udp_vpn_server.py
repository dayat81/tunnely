#!/usr/bin/env python3
"""
Tunnely UDP VPN Server
=======================
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
import select
import socket
import struct
import subprocess
import sys
import time
import signal
import ipaddress
import argparse
import json

# ── Constants ──────────────────────────────────────────────────────────────

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000  # no packet info header

IDLE_TIMEOUT = 180  # seconds before session cleanup
BUFFER_SIZE = 65535
STATS_INTERVAL = 30

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
    subprocess.run(["ip", "link", "set", "dev", name, "up"], check=True)


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
    # ens4 MTU is 1460 on GCP; tunnel MTU is 1500; TCP MSS must be clamped
    subprocess.run(
        ["iptables", "-t", "mangle", "-A", "FORWARD", "-p", "tcp",
         "--tcp-flags", "SYN,RST", "SYN", "-i", tun_name, "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
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
        # Check if already registered by addr
        if client_addr in self.addr_to_ip:
            ip = self.addr_to_ip[client_addr]
            self.sessions[ip]["last_seen"] = time.time()
            return ip

        # Check state file for re-registration (same addr, different port = roaming)
        # Assign new IP
        try:
            ip = str(next(self.pool_iter))
        except StopIteration:
            # Recycle expired IPs
            self.cleanup()
            self.pool_iter = iter(self.pool)
            ip = str(next(self.pool_iter))

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
        total_rx = sum(s["rx"] for s in self.sessions.values())
        total_tx = sum(s["tx"] for s in self.sessions.values())
        return {
            "active": len(self.sessions),
            "total_rx": total_rx,
            "total_tx": total_tx,
            "sessions": {
                ip: {
                    "addr": f"{s['addr'][0]}:{s['addr'][1]}",
                    "rx": s["rx"],
                    "tx": s["tx"],
                    "idle": int(time.time() - s["last_seen"]),
                }
                for ip, s in self.sessions.items()
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

def extract_dst_ip(packet: bytes) -> str | None:
    """Extract destination IPv4 address from raw IP packet."""
    if len(packet) < 20:
        return None
    version = (packet[0] >> 4) & 0xF
    if version != 4:
        return None
    return str(ipaddress.IPv4Address(packet[16:20]))


def extract_src_ip(packet: bytes) -> str | None:
    """Extract source IPv4 address from raw IP packet."""
    if len(packet) < 20:
        return None
    return str(ipaddress.IPv4Address(packet[12:16]))


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
        self.last_stats = 0
        self.last_save = 0

    def start(self):
        log("=" * 60)
        log("Tunnely UDP VPN Server starting...")
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

        log(f"Listening on UDP :{self.port}")
        log("Ready for connections.\n")

        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        try:
            self._loop()
        finally:
            self.shutdown()

    def _signal_handler(self, sig, frame):
        log(f"Signal {sig} received, shutting down...")
        self.running = False

    def _loop(self):
        """Main select() loop: TUN fd ↔ UDP socket."""
        while self.running:
            readable, _, _ = select.select([self.tun_fd, self.sock], [], [], 1.0)
            now = time.time()

            # Periodic tasks
            if now - self.last_stats >= STATS_INTERVAL:
                self._print_stats()
                self.last_stats = now
            if now - self.last_save >= 60:
                self.sessions.cleanup()
                self.sessions.save_state()
                self.last_save = now

            for fd in readable:
                if fd == self.sock:
                    self._handle_udp()
                elif fd == self.tun_fd:
                    self._handle_tun()

    def _handle_udp(self):
        """Packet from client → write to TUN."""
        try:
            data, addr = self.sock.recvfrom(BUFFER_SIZE)
        except socket.error:
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
        try:
            os.write(self.tun_fd, data)
        except OSError as e:
            log(f"TUN write error: {e}", "WARN")

    def _handle_tun(self):
        """Packet from TUN → route to client via UDP."""
        try:
            data = os.read(self.tun_fd, BUFFER_SIZE)
        except OSError:
            return

        dst_ip = extract_dst_ip(data)
        if not dst_ip:
            return

        client_addr = self.sessions.get_addr_by_ip(dst_ip)
        if client_addr:
            try:
                self.sock.sendto(data, client_addr)
                self.sessions.touch(dst_ip, tx_bytes=len(data))
            except socket.error as e:
                log(f"UDP send error to {dst_ip}: {e}", "WARN")

    def _rewrite_src_ip(self, packet: bytes, new_ip: str) -> bytes:
        """Rewrite source IP and fix ALL checksums (IP header + TCP/UDP transport).
        
        Without fixing transport checksums, the kernel silently drops TCP packets
        because the pseudo-header checksum no longer matches.
        """
        pkt = bytearray(packet)
        new_ip_bytes = ipaddress.IPv4Address(new_ip).packed
        old_src = bytes(pkt[12:16])

        # Skip if no change needed
        if old_src == new_ip_bytes:
            return bytes(pkt)

        # ── Fix IP header checksum ──
        pkt[10:12] = b"\x00\x00"
        pkt[12:16] = new_ip_bytes
        ip_sum = 0
        for i in range(0, 20, 2):
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
        log(
            f"[stats] sessions={s['active']}  "
            f"rx={rx_mb:.2f}MB  tx={tx_mb:.2f}MB  "
            f"rate={s['total_rx'] / STATS_INTERVAL / 1024:.0f}KB/s↓ "
            f"{s['total_tx'] / STATS_INTERVAL / 1024:.0f}KB/s↑"
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
