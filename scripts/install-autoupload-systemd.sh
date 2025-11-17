#!/bin/bash
#
# install-autoupload-systemd.sh - Install uploader auto upload as systemd service
#
# Usage: sudo ./install-autoupload-systemd.sh <username>
#   where <username> is the user who owns the watch folder
#

set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Error: This script must be run as root (use sudo)"
    exit 1
fi

# Check if username argument provided
if [ -z "$1" ]; then
    echo "❌ Error: Username is required"
    echo "Usage: sudo $0 <username>"
    echo "Example: sudo $0 dev"
    exit 1
fi

TARGET_USER="$1"

# Check if user exists
if ! id "$TARGET_USER" &>/dev/null; then
    echo "❌ Error: User '$TARGET_USER' does not exist"
    exit 1
fi

echo "🔧 Installing Uploader Auto Upload Systemd Service"
echo "================================================="
echo ""
echo "Target User: $TARGET_USER"
echo ""

# Check if binary exists
if [ ! -f "/usr/local/bin/uploader" ]; then
    echo "❌ Error: /usr/local/bin/uploader not found"
    echo "Please install the uploader binary first with: make install"
    exit 1
fi

# Check if config exists
if [ ! -f "/etc/uploader/config.toml" ]; then
    echo "❌ Error: /etc/uploader/config.toml not found"
    echo "Please create config first"
    exit 1
fi

# Create systemd service file
echo "📝 Creating systemd service file..."
cat > /etc/systemd/system/uploader-autoupload.service << EOF
[Unit]
Description=Uploader Auto Upload Daemon
Documentation=https://github.com/your-username/uploader
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$TARGET_USER
Group=$TARGET_USER

# Working directory - user's home
WorkingDirectory=$(eval echo ~$TARGET_USER)

# Binary and config paths
ExecStart=/usr/local/bin/uploader --config /etc/uploader/config.toml auto-upload

# Restart policy
Restart=always
RestartSec=10
StartLimitInterval=200
StartLimitBurst=5

# Security hardening (less strict for user home access)
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=uploader-autoupload

# Environment
Environment="RUST_LOG=info"
Environment="RUST_BACKTRACE=1"

[Install]
WantedBy=multi-user.target
EOF

echo "✅ Service file created: /etc/systemd/system/uploader-autoupload.service"

# Reload systemd
echo "🔄 Reloading systemd daemon..."
systemctl daemon-reload

# Enable service
echo "⚙️  Enabling service..."
systemctl enable uploader-autoupload.service

echo ""
echo "✅ Installation complete!"
echo ""
echo "📋 Service Information:"
echo "  Service: uploader-autoupload.service"
echo "  User: $TARGET_USER"
echo "  Config: /etc/uploader/config.toml"
echo ""
echo "💡 Next steps:"
echo "  1. Make sure /etc/uploader/config.toml has auto_upload configured"
echo "  2. Start service: sudo systemctl start uploader-autoupload"
echo "  3. Check status: sudo systemctl status uploader-autoupload"
echo "  4. View logs: sudo journalctl -u uploader-autoupload -f"
echo ""
