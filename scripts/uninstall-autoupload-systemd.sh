#!/bin/bash
#
# uninstall-autoupload-systemd.sh - Uninstall uploader auto upload systemd service
#

set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Error: This script must be run as root (use sudo)"
    exit 1
fi

echo "🗑️  Uninstalling Uploader Auto Upload Systemd Service"
echo "====================================================="
echo ""

# Stop service if running
if systemctl is-active --quiet uploader-autoupload.service; then
    echo "⏹️  Stopping service..."
    systemctl stop uploader-autoupload.service
fi

# Disable service
if systemctl is-enabled --quiet uploader-autoupload.service 2>/dev/null; then
    echo "⚙️  Disabling service..."
    systemctl disable uploader-autoupload.service
fi

# Remove service file
if [ -f "/etc/systemd/system/uploader-autoupload.service" ]; then
    echo "🗑️  Removing service file..."
    rm -f /etc/systemd/system/uploader-autoupload.service
fi

# Reload systemd
echo "🔄 Reloading systemd daemon..."
systemctl daemon-reload

echo ""
echo "✅ Uninstallation complete!"
echo ""
