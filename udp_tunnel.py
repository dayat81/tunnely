#!/usr/bin/env python3
"""
Simple UDP Tunnel / Relay
Forwards UDP packets bidirectionally between clients and a remote server.

Usage:
  python3 udp_tunnel.py <local_port> <remote_host> <remote_port>
  python3 udp_tunnel.py 5000 8.8.8.8 53        # DNS relay
  python3 udp_tunnel.py 51820 35.219.34.37 51820  # WG relay

Features:
  - Multi-client session tracking (NAT-aware)
  - Bidirectional packet forwarding
  - Idle session timeout (5 min)
  - Stats logging every 30s
"""
import socket
import sys
import select
import time
import signal

IDLE_TIMEOUT = 300  # seconds before stale session cleanup
STATS_INTERVAL = 30  # seconds between stats logs


def resolve_host(host: str) -> str:
    """Resolve hostname to IP once at startup."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as e:
        print(f"[-] Cannot resolve {host}: {e}")
        sys.exit(1)


def tunnel(local_port: int, remote_host: str, remote_port: int):
    remote_ip = resolve_host(remote_host)
    remote_addr = (remote_ip, remote_port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", local_port))
    # Increase buffer size for high-throughput
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)

    # Session map: client_addr -> {last_seen, rx_bytes, tx_bytes}
    sessions = {}

    print(f"[+] UDP tunnel ready")
    print(f"    Listen:  0.0.0.0:{local_port}")
    print(f"    Remote:  {remote_ip}:{remote_port} ({remote_host})")
    print(f"    Timeout: {IDLE_TIMEOUT}s idle")
    print(f"    Ctrl+C to stop\n")

    last_stats = time.time()
    total_c2s = 0  # client → server bytes
    total_s2c = 0  # server → client bytes

    def cleanup_stale():
        now = time.time()
        stale = [a for a, s in sessions.items() if now - s["last_seen"] > IDLE_TIMEOUT]
        for addr in stale:
            print(f"[-] Session expired: {addr[0]}:{addr[1]}")
            del sessions[addr]

    def print_stats():
        active = len(sessions)
        print(
            f"[stats] sessions={active}  "
            f"c→s={total_c2s:,}B  s→c={total_s2c:,}B  "
            f"rate_c2s={total_c2s / STATS_INTERVAL / 1024:.1f}KB/s  "
            f"rate_s2c={total_s2c / STATS_INTERVAL / 1024:.1f}KB/s"
        )

    running = [True]

    def handle_signal(sig, frame):
        running[0] = False

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    while running[0]:
        readable, _, _ = select.select([sock], [], [], 1.0)
        now = time.time()

        # Periodic stats
        if now - last_stats >= STATS_INTERVAL:
            print_stats()
            total_c2s = 0
            total_s2c = 0
            last_stats = now
            cleanup_stale()

        if not readable:
            continue

        try:
            data, addr = sock.recvfrom(65535)
        except socket.error:
            continue

        if addr == remote_addr:
            # Packet FROM remote server → forward to ALL active clients
            # (broadcast mode — or forward to most recent session)
            if sessions:
                # Forward to most recently active client
                newest = max(sessions, key=lambda a: sessions[a]["last_seen"])
                sock.sendto(data, newest)
                sessions[newest]["tx_bytes"] += len(data)
                sessions[newest]["last_seen"] = now
                total_s2c += len(data)
        else:
            # Packet FROM client → forward to remote server
            if addr not in sessions:
                print(f"[+] New session: {addr[0]}:{addr[1]}")
            sessions.setdefault(addr, {"last_seen": now, "rx_bytes": 0, "tx_bytes": 0})
            sessions[addr]["last_seen"] = now
            sessions[addr]["rx_bytes"] += len(data)
            sock.sendto(data, remote_addr)
            total_c2s += len(data)

    print("\n[+] Shutting down...")
    sock.close()


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <local_port> <remote_host> <remote_port>")
        print(f"  e.g: {sys.argv[0]} 5000 8.8.8.8 53")
        sys.exit(1)

    tunnel(int(sys.argv[1]), sys.argv[2], int(sys.argv[3]))
