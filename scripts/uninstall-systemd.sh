#!/bin/bash
# Uninstall uploader systemd service

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

echo ""
warning "This will uninstall the uploader service"
echo ""
echo "The following will be removed:"
echo "  - Binary: $BINARY_PATH"
echo "  - Service files: /etc/systemd/system/uploader*.service"
echo "  - Configuration: $CONFIG_DIR"
echo "  - Data directory: $DATA_DIR"
echo "  - Log directory: $LOG_DIR"
echo "  - System user: uploader"
echo ""
read -p "Are you sure? (y/N) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

log "Uninstalling Distributed File Transfer Service..."
echo ""

# 1. Stop and disable service
if systemctl is-active --quiet uploader.service; then
    log "Stopping service..."
    systemctl stop uploader.service
    success "Service stopped"
fi

# Stop all instances
for instance in $(systemctl list-units --type=service --state=active | grep "uploader@" | awk '{print $1}'); do
    log "Stopping $instance..."
    systemctl stop "$instance"
done

if systemctl is-enabled --quiet uploader.service 2>/dev/null; then
    log "Disabling service..."
    systemctl disable uploader.service
    success "Service disabled"
fi

# 2. Remove service files
log "Removing service files..."
rm -f "$SERVICE_FILE"
rm -f "$MULTI_SERVICE_FILE"
success "Service files removed"

# 3. Reload systemd
log "Reloading systemd daemon..."
systemctl daemon-reload
systemctl reset-failed
success "Systemd reloaded"

# 4. Remove binary
if [ -f "$BINARY_PATH" ]; then
    log "Removing binary..."
    rm -f "$BINARY_PATH"
    success "Binary removed"
fi

# 5. Ask about data
echo ""
read -p "Remove configuration and data? (y/N) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Backup before removal
    BACKUP_DIR="/tmp/uploader-backup-$(date +%Y%m%d-%H%M%S)"
    log "Creating backup at $BACKUP_DIR..."
    mkdir -p "$BACKUP_DIR"

    if [ -d "$CONFIG_DIR" ]; then
        cp -r "$CONFIG_DIR" "$BACKUP_DIR/"
    fi

    if [ -d "$DATA_DIR" ]; then
        cp -r "$DATA_DIR" "$BACKUP_DIR/"
    fi

    success "Backup created at $BACKUP_DIR"

    # Remove directories
    log "Removing directories..."
    rm -rf "$CONFIG_DIR"
    rm -rf "$DATA_DIR"
    rm -rf "$LOG_DIR"
    success "Directories removed"
else
    warning "Configuration and data preserved"
    echo "  Config: $CONFIG_DIR"
    echo "  Data: $DATA_DIR"
    echo "  Logs: $LOG_DIR"
fi

# 6. Remove user
echo ""
read -p "Remove system user 'uploader'? (y/N) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    if id "uploader" &>/dev/null; then
        log "Removing user 'uploader'..."
        userdel uploader 2>/dev/null || true
        success "User removed"
    fi
else
    warning "User 'uploader' preserved"
fi

echo ""
echo "=========================================="
echo -e "${GREEN}Uninstallation Complete!${NC}"
echo "=========================================="
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Backup location: $BACKUP_DIR"
    echo ""
fi

echo "Service has been completely removed."
echo ""
