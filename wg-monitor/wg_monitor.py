#!/usr/bin/env python3
"""WireGuard Monitoring Dashboard - standalone service on port 8870."""

import subprocess
import re
import time
import json
import os
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler

WG_INTERFACE = "wg0"
LISTEN_PORT = 8870
DASHBOARD_HTML = os.path.join(os.path.dirname(__file__), "wg_dashboard.html")


def parse_wg_dump():
    """Parse wg show dump."""
    try:
        result = subprocess.run(
            ["wg", "show", WG_INTERFACE, "dump"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return {"error": result.stderr.strip(), "peers": [], "interface": {}}

        lines = result.stdout.strip().split("\n")
        if not lines:
            return {"error": "empty", "peers": [], "interface": {}}

        iface_parts = lines[0].split("\t")
        interface = {
            "public_key": iface_parts[1] if len(iface_parts) > 1 else "",
            "listen_port": int(iface_parts[2]) if len(iface_parts) > 2 else 0,
        }

        peers = []
        now = int(time.time())
        for line in lines[1:]:
            parts = line.split("\t")
            if len(parts) < 8:
                continue

            pubkey = parts[0]
            endpoint = parts[2] if parts[2] != "(none)" else ""
            allowed_ips = parts[3]
            last_hs = int(parts[4]) if parts[4] != "0" else 0
            rx_bytes = int(parts[5])
            tx_bytes = int(parts[6])
            keepalive = parts[7] if parts[7] != "off" else ""

            ip_match = re.search(r"10\.10\.0\.(\d+)", allowed_ips)
            tunnel_ip = ip_match.group(0) if ip_match else ""
            peer_id = int(ip_match.group(1)) if ip_match else 0

            if last_hs == 0:
                status, ago = "never", None
            elif (now - last_hs) < 180:
                status, ago = "connected", now - last_hs
            elif (now - last_hs) < 300:
                status, ago = "stale", now - last_hs
            else:
                status, ago = "disconnected", now - last_hs

            ep_ip, ep_port = "", 0
            if endpoint:
                m = re.match(r"(.+):(\d+)$", endpoint)
                if m:
                    ep_ip, ep_port = m.group(1), int(m.group(2))

            peers.append({
                "public_key": pubkey[:12] + "…",
                "tunnel_ip": tunnel_ip,
                "peer_id": peer_id,
                "endpoint_ip": ep_ip,
                "endpoint_port": ep_port,
                "last_handshake": last_hs,
                "ago": ago,
                "rx_bytes": rx_bytes,
                "tx_bytes": tx_bytes,
                "rx_mb": round(rx_bytes / (1024 * 1024), 2),
                "tx_mb": round(tx_bytes / (1024 * 1024), 2),
                "status": status,
                "keepalive": keepalive,
            })

        peers.sort(key=lambda p: p["peer_id"])
        return {"interface": interface, "peers": peers, "error": None}
    except Exception as e:
        return {"error": str(e), "peers": [], "interface": {}}


def get_stats():
    """Server stats."""
    s = {}
    try:
        with open("/proc/uptime") as f:
            s["uptime_s"] = int(float(f.read().split()[0]))
        for iface in ["wg0", "ens4"]:
            for metric in ["rx_bytes", "tx_bytes", "rx_packets", "tx_packets"]:
                try:
                    with open(f"/sys/class/net/{iface}/statistics/{metric}") as f:
                        s[f"{iface}_{metric}"] = int(f.read().strip())
                except FileNotFoundError:
                    pass
        try:
            r = subprocess.run(["conntrack", "-C"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                s["conntrack"] = int(r.stdout.strip())
        except Exception:
            pass
        with open("/proc/loadavg") as f:
            p = f.read().split()
            s["load"] = [float(p[0]), float(p[1]), float(p[2])]
        with open("/proc/meminfo") as f:
            mem = {}
            for line in f:
                k = line.split(":")[0]
                if k in ("MemTotal", "MemAvailable"):
                    mem[k] = int(line.split()[1]) * 1024  # kB to bytes
            s["mem_total_gb"] = round(mem.get("MemTotal", 0) / (1024**3), 1)
            s["mem_avail_gb"] = round(mem.get("MemAvailable", 0) / (1024**3), 1)
    except Exception as e:
        s["error"] = str(e)
    return s


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # suppress logs

    def do_GET(self):
        if self.path == "/api/wg/status":
            data = parse_wg_dump()
            stats = get_stats()
            connected = sum(1 for p in data["peers"] if p["status"] == "connected")
            stale = sum(1 for p in data["peers"] if p["status"] == "stale")
            never = sum(1 for p in data["peers"] if p["status"] == "never")
            disc = sum(1 for p in data["peers"] if p["status"] == "disconnected")
            total_rx = sum(p["rx_bytes"] for p in data["peers"])
            total_tx = sum(p["tx_bytes"] for p in data["peers"])
            resp = {
                "server": {"interface": data["interface"], "stats": stats, "ts": int(time.time())},
                "summary": {
                    "total": len(data["peers"]), "connected": connected,
                    "stale": stale, "disconnected": disc, "never": never,
                    "total_rx_mb": round(total_rx / (1024**2), 2),
                    "total_tx_mb": round(total_tx / (1024**2), 2),
                },
                "peers": data["peers"], "error": data["error"],
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(resp).encode())

        elif self.path == "/" or self.path == "/dashboard":
            try:
                with open(DASHBOARD_HTML, "rb") as f:
                    html = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(html)
            except FileNotFoundError:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Dashboard not found")
        else:
            self.send_response(404)
            self.end_headers()


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", LISTEN_PORT), Handler)
    print(f"[wg-monitor] Listening on 127.0.0.1:{LISTEN_PORT}")
    server.serve_forever()


# Also mount on port 8800 (antilemot-api) for Tunnely app
