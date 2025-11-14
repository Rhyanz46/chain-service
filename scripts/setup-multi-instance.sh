#!/bin/bash
# Setup multiple uploader instances on same server

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

# Get number of instances
if [ -z "$1" ]; then
    echo "Usage: $0 <num_instances> [starting_port]"
    echo ""
    echo "Example:"
    echo "  $0 3 50051    # Create 3 instances starting at port 50051"
    echo ""
    echo "This will create:"
    echo "  - Instance 1: port 50051, p2p 9000"
    echo "  - Instance 2: port 50052, p2p 9001"
    echo "  - Instance 3: port 50053, p2p 9002"
    exit 1
fi

NUM_INSTANCES=$1
START_PORT=${2:-50051}
P2P_START_PORT=${3:-9000}

log "Setting up $NUM_INSTANCES instances starting at port $START_PORT..."
echo ""

# Check if binary exists
if [ ! -f "/usr/local/bin/uploader" ]; then
    error "Uploader binary not installed. Run: sudo scripts/install-systemd.sh"
    exit 1
fi

# Check if multi-instance service exists
if [ ! -f "/etc/systemd/system/uploader@.service" ]; then
    error "Multi-instance service not installed. Run: sudo scripts/install-systemd.sh"
    exit 1
fi

# Create instances
for i in $(seq 1 $NUM_INSTANCES); do
    INSTANCE_NAME="node$i"
    PORT=$((START_PORT + i - 1))
    P2P_PORT=$((P2P_START_PORT + i - 1))

    log "Creating instance: $INSTANCE_NAME (port: $PORT, p2p: $P2P_PORT)"

    # Create directories
    mkdir -p "/etc/uploader/$INSTANCE_NAME"
    mkdir -p "/var/lib/uploader/$INSTANCE_NAME/storage"
    mkdir -p "/var/lib/uploader/$INSTANCE_NAME/certs"

    # Create config
    cat > "/etc/uploader/$INSTANCE_NAME/config.toml" <<EOF
[node]
name = "$INSTANCE_NAME"
listen_address = "0.0.0.0:$PORT"
certificate_path = "/var/lib/uploader/$INSTANCE_NAME/certs/node.crt"
private_key_path = "/var/lib/uploader/$INSTANCE_NAME/certs/node.key"

[network]
p2p_port = $P2P_PORT
bootstrap_nodes = []
heartbeat_interval = 30
node_timeout = 300

[storage]
root_dir = "/var/lib/uploader/$INSTANCE_NAME/storage"
max_file_size = 0
chunk_size = 1048576

[security]
allow_self_signed = true
cert_validity_days = 365
require_mtls = true
EOF

    # Create environment file
    cat > "/etc/uploader/$INSTANCE_NAME/environment" <<EOF
RUST_LOG=info
RUST_BACKTRACE=1
NODE_NAME=$INSTANCE_NAME
EOF

    # Generate certificate
    SERVER_IP=$(hostname -I | awk '{print $1}')
    if [ -z "$SERVER_IP" ]; then
        SERVER_IP="127.0.0.1"
    fi

    sudo -u uploader /usr/local/bin/uploader gen-cert \
        --name "$INSTANCE_NAME" \
        --address "$SERVER_IP:$PORT" \
        --cert-out "/var/lib/uploader/$INSTANCE_NAME/certs/node.crt" \
        --key-out "/var/lib/uploader/$INSTANCE_NAME/certs/node.key" \
        > /dev/null 2>&1

    # Set permissions
    chown -R uploader:uploader "/var/lib/uploader/$INSTANCE_NAME"
    chown -R root:root "/etc/uploader/$INSTANCE_NAME"
    chmod 644 "/etc/uploader/$INSTANCE_NAME/config.toml"

    # Enable service
    systemctl enable "uploader@$INSTANCE_NAME.service"

    success "Instance $INSTANCE_NAME created"
done

echo ""
echo "=========================================="
echo -e "${GREEN}Multi-Instance Setup Complete!${NC}"
echo "=========================================="
echo ""
echo "Created $NUM_INSTANCES instances:"
echo ""

for i in $(seq 1 $NUM_INSTANCES); do
    INSTANCE_NAME="node$i"
    PORT=$((START_PORT + i - 1))
    P2P_PORT=$((P2P_START_PORT + i - 1))
    echo "  $INSTANCE_NAME:"
    echo "    gRPC Port:    $PORT"
    echo "    P2P Port:     $P2P_PORT"
    echo "    Config:       /etc/uploader/$INSTANCE_NAME/config.toml"
    echo "    Data:         /var/lib/uploader/$INSTANCE_NAME"
    echo ""
done

echo "Service Management:"
echo ""
echo "  Start all:"
for i in $(seq 1 $NUM_INSTANCES); do
    echo "    sudo systemctl start uploader@node$i"
done
echo ""
echo "  Stop all:"
for i in $(seq 1 $NUM_INSTANCES); do
    echo "    sudo systemctl stop uploader@node$i"
done
echo ""
echo "  Status:"
echo "    sudo systemctl status 'uploader@*'"
echo ""
echo "  Logs (all instances):"
echo "    sudo journalctl -u 'uploader@*' -f"
echo ""
echo "  Logs (specific instance):"
echo "    sudo journalctl -u uploader@node1 -f"
echo ""

echo "Quick start all instances:"
echo "  sudo systemctl start uploader@node{1..$NUM_INSTANCES}"
echo ""
