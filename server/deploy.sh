#!/bin/bash
# Tunnely server deployment script
# Usage: ./deploy.sh
# Run as normal user — uses sudo for /opt/tunnely/ files
set -e

SERVER_DIR="/opt/tunnely"
SOURCE_DIR="$HOME/tunnely/server"

echo "=== Tunnely Server Deploy ==="

# 1. Clear stale .pyc cache (prevents Python from using old bytecode)
echo "[1/5] Clearing __pycache__..."
PYS=$(sudo find "$SERVER_DIR" -name "__pycache__" -type d 2>/dev/null | wc -l)
sudo find "$SERVER_DIR" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find "$SOURCE_DIR" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
echo "  ✓ Removed $PYS __pycache__ dirs"

# 2. Copy source files
echo "[2/5] Copying files..."
sudo cp "$SOURCE_DIR/udp_vpn_server.py" "$SERVER_DIR/"
sudo cp "$SOURCE_DIR/quic_sni.py" "$SERVER_DIR/"
sudo cp "$SOURCE_DIR/ntp_sync.py" "$SERVER_DIR/"
echo "  ✓ Files copied"

# 3. Verify no stale .pyc
echo "[3/5] Verifying..."
PYC_COUNT=$(sudo find "$SERVER_DIR" -name "*.pyc" 2>/dev/null | wc -l)
if [ "$PYC_COUNT" -gt 0 ]; then
    echo "  ⚠ Still have $PYC_COUNT .pyc files, removing..."
    sudo find "$SERVER_DIR" -name "*.pyc" -delete
fi
echo "  ✓ No stale bytecode"

# 4. Verify version
echo "[4/5] Version check..."
DEPLOYED_VER=$(sudo grep -oP '__version__\s*=\s*"\K[^"]+' "$SERVER_DIR/udp_vpn_server.py")
SOURCE_VER=$(grep -oP '__version__\s*=\s*"\K[^"]+' "$SOURCE_DIR/udp_vpn_server.py")
if [ "$DEPLOYED_VER" != "$SOURCE_VER" ]; then
    echo "  ✗ Version mismatch! deployed=$DEPLOYED_VER source=$SOURCE_VER"
    exit 1
fi
echo "  ✓ Version: $DEPLOYED_VER"

# 5. Restart service
echo "[5/5] Restarting service..."
sudo systemctl restart tunnely-udp-vpn
sleep 2
if systemctl is-active --quiet tunnely-udp-vpn; then
    echo "  ✓ Service running"
else
    echo "  ✗ Service failed to start!"
    sudo journalctl -u tunnely-udp-vpn -n 20 --no-pager
    exit 1
fi

echo ""
echo "=== Deployed v$DEPLOYED_VER ✅ ==="
