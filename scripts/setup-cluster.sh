#!/bin/bash
# Setup cluster dengan 3 nodes untuk development/testing

set -e

echo "=== Distributed File Transfer Cluster Setup ==="
echo ""

# Konfigurasi
BINARY="./target/release/uploader"
BASE_PORT=50051
P2P_BASE_PORT=9000
NUM_NODES=3

# Check binary exists
if [ ! -f "$BINARY" ]; then
    echo "Error: Binary not found at $BINARY"
    echo "Please run: cargo build --release"
    exit 1
fi

# Create directories
for i in $(seq 1 $NUM_NODES); do
    mkdir -p "node$i/storage"
    mkdir -p "node$i/certs"
done

# Generate configs
for i in $(seq 1 $NUM_NODES); do
    PORT=$((BASE_PORT + i - 1))
    P2P_PORT=$((P2P_BASE_PORT + i - 1))

    echo "Creating config for node-$i (port: $PORT, p2p: $P2P_PORT)"

    cat > "node$i/config.toml" <<EOF
[node]
name = "node-$i"
listen_address = "127.0.0.1:$PORT"
certificate_path = "./node$i/certs/node.crt"
private_key_path = "./node$i/certs/node.key"

[network]
p2p_port = $P2P_PORT
bootstrap_nodes = []
heartbeat_interval = 30
node_timeout = 300

[storage]
root_dir = "./node$i/storage"
max_file_size = 0
chunk_size = 1048576

[security]
allow_self_signed = true
cert_validity_days = 365
require_mtls = true
EOF

    # Generate certificate
    echo "Generating certificate for node-$i"
    $BINARY gen-cert \
        --name "node-$i" \
        --address "127.0.0.1:$PORT" \
        --cert-out "node$i/certs/node.crt" \
        --key-out "node$i/certs/node.key" \
        > /dev/null 2>&1
done

echo ""
echo "=== Cluster Setup Complete ==="
echo ""
echo "To start nodes:"
echo ""
for i in $(seq 1 $NUM_NODES); do
    PORT=$((BASE_PORT + i - 1))
    echo "  # Node $i (port: $PORT)"
    echo "  $BINARY --config node$i/config.toml server &"
    echo ""
done
echo "To test upload to all nodes:"
echo "  $BINARY upload --file test.txt \\"
for i in $(seq 1 $NUM_NODES); do
    PORT=$((BASE_PORT + i - 1))
    echo "    --servers 127.0.0.1:$PORT \\"
done
echo ""
echo "To stop all nodes:"
echo "  pkill -f uploader"
echo ""
