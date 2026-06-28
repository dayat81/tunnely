#!/bin/bash
# Deploy Tunnely UDP VPN Server to 35.219.34.37
# Usage: bash deploy_server.sh
set -e

SERVER="35.219.34.37"
SSH_USER="root"
REMOTE_DIR="/opt/tunnely"

echo "=== Tunnely UDP VPN Server Deploy ==="
echo "Target: ${SSH_USER}@${SERVER}:${REMOTE_DIR}"
echo ""

# Copy files
echo "[1/4] Copying server files..."
scp udp_vpn_server.py ${SSH_USER}@${SERVER}:${REMOTE_DIR}/
scp tunnely-udp-vpn.service ${SSH_USER}@${SERVER}:/etc/systemd/system/

# Install service
echo "[2/4] Installing systemd service..."
ssh ${SSH_USER}@${SERVER} << 'EOF'
mkdir -p /opt/tunnely /var/lib/tunnely
systemctl daemon-reload
systemctl enable tunnely-udp-vpn

# Open firewall
if command -v ufw &> /dev/null; then
    ufw allow 5555/udp
    echo "Firewall: opened UDP 5555"
fi

# Stop WireGuard if running (optional — both can coexist on different ports)
# systemctl stop wireguard-wg0 2>/dev/null || true
EOF

echo "[3/4] Starting service..."
ssh ${SSH_USER}@${SERVER} "systemctl restart tunnely-udp-vpn && sleep 2 && systemctl status tunnely-udp-vpn --no-pager"

echo "[4/4] Verifying..."
echo ""
echo "Done! Server listening on UDP :5555"
echo "Check logs: ssh ${SSH_USER}@${SERVER} journalctl -u tunnely-udp-vpn -f"
