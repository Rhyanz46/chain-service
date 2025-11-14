#!/bin/bash
# Install uploader as systemd service

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Paths
BINARY_PATH="/usr/local/bin/uploader"
CONFIG_DIR="/etc/uploader"
DATA_DIR="/var/lib/uploader"
LOG_DIR="/var/log/uploader"
SERVICE_FILE="/etc/systemd/system/uploader.service"
MULTI_SERVICE_FILE="/etc/systemd/system/uploader@.service"

log() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    error "This script must be run as root (use sudo)"
    exit 1
fi

# Check if binary exists
if [ ! -f "target/release/uploader" ]; then
    error "Binary not found. Please run: make release"
    exit 1
fi

log "Installing Distributed File Transfer Service..."
echo ""

# 1. Create user and group
log "Creating service user..."
if id "uploader" &>/dev/null; then
    warning "User 'uploader' already exists"
else
    useradd -r -s /bin/false -d "$DATA_DIR" -c "Uploader Service" uploader
    success "User 'uploader' created"
fi

# 2. Create directories
log "Creating directories..."
mkdir -p "$CONFIG_DIR"
mkdir -p "$DATA_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$DATA_DIR/storage"
mkdir -p "$DATA_DIR/certs"

# 3. Copy binary
log "Installing binary..."
cp target/release/uploader "$BINARY_PATH"
chmod +x "$BINARY_PATH"
success "Binary installed to $BINARY_PATH"

# 4. Copy configuration
log "Installing configuration..."
if [ ! -f "$CONFIG_DIR/config.toml" ]; then
    if [ -f "config.toml" ]; then
        cp config.toml "$CONFIG_DIR/config.toml"
    else
        cp config.example.toml "$CONFIG_DIR/config.toml"
    fi
    success "Configuration installed to $CONFIG_DIR/config.toml"
else
    warning "Configuration already exists at $CONFIG_DIR/config.toml"
    echo "    Not overwriting. Backup: $CONFIG_DIR/config.toml.backup"
    cp "$CONFIG_DIR/config.toml" "$CONFIG_DIR/config.toml.backup"
fi

# 5. Update config paths for systemd
log "Updating configuration paths..."
sed -i.bak \
    -e "s|listen_address = \".*\"|listen_address = \"0.0.0.0:50051\"|" \
    -e "s|certificate_path = \".*\"|certificate_path = \"$DATA_DIR/certs/node.crt\"|" \
    -e "s|private_key_path = \".*\"|private_key_path = \"$DATA_DIR/certs/node.key\"|" \
    -e "s|root_dir = \".*\"|root_dir = \"$DATA_DIR/storage\"|" \
    "$CONFIG_DIR/config.toml"

# 6. Set permissions
log "Setting permissions..."
chown -R uploader:uploader "$DATA_DIR"
chown -R uploader:uploader "$LOG_DIR"
chown -R root:root "$CONFIG_DIR"
chmod 755 "$CONFIG_DIR"
chmod 644 "$CONFIG_DIR/config.toml"
success "Permissions set"

# 7. Install systemd service files
log "Installing systemd service files..."
cp systemd/uploader.service "$SERVICE_FILE"
cp systemd/uploader@.service "$MULTI_SERVICE_FILE"
chmod 644 "$SERVICE_FILE"
chmod 644 "$MULTI_SERVICE_FILE"
success "Service files installed"

# 8. Reload systemd
log "Reloading systemd daemon..."
systemctl daemon-reload
success "Systemd reloaded"

# 9. Generate certificate if not exists
if [ ! -f "$DATA_DIR/certs/node.crt" ]; then
    log "Generating certificate..."

    # Get server IP (try to auto-detect)
    SERVER_IP=$(hostname -I | awk '{print $1}')
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP="127.0.0.1"
    fi

    sudo -u uploader "$BINARY_PATH" gen-cert \
        --name "$(hostname)" \
        --address "$SERVER_IP:50051" \
        --cert-out "$DATA_DIR/certs/node.crt" \
        --key-out "$DATA_DIR/certs/node.key"

    success "Certificate generated"
else
    warning "Certificate already exists"
fi

# 10. Enable service (but don't start yet)
log "Enabling service..."
systemctl enable uploader.service
success "Service enabled"

echo ""
echo "=========================================="
echo -e "${GREEN}Installation Complete!${NC}"
echo "=========================================="
echo ""
echo "Configuration:"
echo "  Config:  $CONFIG_DIR/config.toml"
echo "  Data:    $DATA_DIR"
echo "  Logs:    $LOG_DIR"
echo "  Binary:  $BINARY_PATH"
echo ""
echo "Service Management:"
echo "  Start:   sudo systemctl start uploader"
echo "  Stop:    sudo systemctl stop uploader"
echo "  Restart: sudo systemctl restart uploader"
echo "  Status:  sudo systemctl status uploader"
echo "  Logs:    sudo journalctl -u uploader -f"
echo ""
echo "Next Steps:"
echo "1. Review configuration: sudo nano $CONFIG_DIR/config.toml"
echo "2. Start service: sudo systemctl start uploader"
echo "3. Check status: sudo systemctl status uploader"
echo "4. View logs: sudo journalctl -u uploader -f"
echo ""
echo -e "${YELLOW}Note: Edit $CONFIG_DIR/config.toml before starting${NC}"
echo ""
