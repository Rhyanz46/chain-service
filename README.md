# Distributed File Transfer System

Backend service untuk upload dan receive file besar antar VPS dengan authentication menggunakan blockchain-style PKI certificates.

## Features

- **Streaming File Transfer**: gRPC bidirectional streaming untuk transfer file besar yang efisien
- **Blockchain-based Authentication**: Custom PKI dengan certificate chain yang mengandung IP dan port
- **Distributed Registry**: Gossip protocol (libp2p) untuk distributed key registry antar node
- **Network Monitoring**: Real-time tracking semua nodes yang connected di network chain
- **Concurrent Operations**: Upload ke multiple servers dan receive dari multiple clients secara bersamaan
- **IP-based Storage**: File disimpan dengan folder structure berdasarkan client IP
- **Peer-to-Peer Network**: Setiap node bisa menjadi client atau server
- **Auto Node Discovery**: Automatic discovery dan registration nodes baru

## Architecture

### Components

1. **PKI System** (`src/pki/`)
   - Certificate generation dengan IP/port embedded
   - Certificate validation
   - Signature verification

2. **gRPC Service** (`src/grpc/`)
   - Bidirectional streaming untuk upload/download
   - Authentication endpoint
   - File listing

3. **Distributed Registry** (`src/registry/`)
   - libp2p gossipsub untuk node discovery
   - Certificate distribution antar nodes
   - Node health monitoring

4. **Storage Manager** (`src/storage/`)
   - IP-based folder structure
   - Streaming file I/O
   - Checksum verification (SHA-256)

5. **Network Layer** (`src/network/`)
   - Client untuk concurrent uploads
   - Server wrapper untuk gRPC service

## Prerequisites

### macOS
```bash
brew install protobuf
```

### Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install -y protobuf-compiler
```

### Linux (RHEL/CentOS)
```bash
sudo yum install protobuf-compiler
```

### Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Installation

1. Clone repository
```bash
git clone <repository-url>
cd uploader
```

2. Build project
```bash
cargo build --release
```

3. Binary akan tersedia di `target/release/uploader`

## Quick Start

### 1. Generate Configuration

```bash
cargo run -- init-config
```

Ini akan membuat `config.toml` dengan default settings.

### 2. Generate Certificate

```bash
cargo run -- gen-cert \
  --name node1 \
  --address 192.168.1.100:50051 \
  --cert-out node.crt \
  --key-out node.key
```

### 3. Start Server

```bash
cargo run -- server
```

Server akan:
- Listen pada port 50051 untuk gRPC
- Listen pada port 9000 untuk P2P network
- Auto-generate certificate jika belum ada
- Join distributed registry network

### 4. Upload File

Upload ke single server:
```bash
cargo run -- upload \
  --file /path/to/large-file.zip \
  --servers 192.168.1.100:50051
```

Upload ke multiple servers (concurrent):
```bash
cargo run -- upload \
  --file /path/to/large-file.zip \
  --servers 192.168.1.100:50051 \
  --servers 192.168.1.101:50051 \
  --servers 192.168.1.102:50051
```

### 5. List Files

```bash
cargo run -- list \
  --server 192.168.1.100:50051 \
  --page 1 \
  --page-size 20
```

Filter by source IP:
```bash
cargo run -- list \
  --server 192.168.1.100:50051 \
  --source-ip 192.168.1.50
```

### 6. Download File

```bash
cargo run -- download \
  --server 192.168.1.100:50051 \
  --file-id 192.168.1.50/abc123def456 \
  --output downloaded-file.zip
```

### 7. Ping Server

```bash
cargo run -- ping --server 192.168.1.100:50051
```

### 8. List Connected Nodes

Lihat semua nodes yang connected di network chain:

```bash
# List active nodes
cargo run -- list-nodes --server 192.168.1.100:50051

# Include inactive/stale nodes
cargo run -- list-nodes --server 192.168.1.100:50051 --include-stale
```

Output:
```
╔═══════════════════════════════════════════════════════════════╗
║               NETWORK STATUS - CONNECTED NODES                ║
╠═══════════════════════════════════════════════════════════════╣
║ Total Nodes: 3                                                ║
║ Current Node: a3f4c2b1d5e8...                                 ║
║ Address: 192.168.1.100:50051                                  ║
╠═══════════════════════════════════════════════════════════════╣
║                      ACTIVE NODES                             ║
╠═══════════════════════════════════════════════════════════════╣
║ Node #1                                                       ║
║ ├─ ID:      a3f4c2b1...                                       ║
║ ├─ Address: 192.168.1.100:50051                              ║
║ └─ Last Seen: 2024-01-15 10:30:45 UTC                        ║
╚═══════════════════════════════════════════════════════════════╝
```

Lihat [NETWORK.md](NETWORK.md) untuk detail lengkap network monitoring.

## Configuration

File `config.toml` berisi:

```toml
[node]
name = "node-1"
listen_address = "0.0.0.0:50051"
certificate_path = "./certs/node.crt"
private_key_path = "./certs/node.key"

[network]
p2p_port = 9000
bootstrap_nodes = []
heartbeat_interval = 30
node_timeout = 300

[storage]
root_dir = "./storage"
max_file_size = 0  # 0 = unlimited
chunk_size = 1048576  # 1MB

[security]
allow_self_signed = true
cert_validity_days = 365
require_mtls = true
```

### Configuration Options

#### Node Section
- `name`: Nama node (untuk certificate CN)
- `listen_address`: Address untuk gRPC server
- `certificate_path`: Path ke certificate file
- `private_key_path`: Path ke private key file

#### Network Section
- `p2p_port`: Port untuk P2P gossip network
- `bootstrap_nodes`: List node lain untuk initial connection
- `heartbeat_interval`: Interval heartbeat (detik)
- `node_timeout`: Timeout untuk consider node as stale (detik)

#### Storage Section
- `root_dir`: Root directory untuk file storage
- `max_file_size`: Maximum file size (bytes), 0 = unlimited
- `chunk_size`: Chunk size untuk streaming (bytes)

#### Security Section
- `allow_self_signed`: Allow self-signed certificates
- `cert_validity_days`: Certificate validity period
- `require_mtls`: Require mutual TLS authentication

## Multi-Node Setup

### Node 1 (Server)
```bash
# config.toml
[node]
name = "node-1"
listen_address = "192.168.1.100:50051"

[network]
p2p_port = 9000
bootstrap_nodes = []

# Start
cargo run -- server
```

### Node 2 (Server)
```bash
# config.toml
[node]
name = "node-2"
listen_address = "192.168.1.101:50051"

[network]
p2p_port = 9000
bootstrap_nodes = ["192.168.1.100:9000"]

# Start
cargo run -- server
```

### Node 3 (Server)
```bash
# config.toml
[node]
name = "node-3"
listen_address = "192.168.1.102:50051"

[network]
p2p_port = 9000
bootstrap_nodes = ["192.168.1.100:9000", "192.168.1.101:9000"]

# Start
cargo run -- server
```

### Client (Upload to All)
```bash
cargo run -- upload \
  --file video.mp4 \
  --servers 192.168.1.100:50051 \
  --servers 192.168.1.101:50051 \
  --servers 192.168.1.102:50051 \
  --mime-type video/mp4
```

## How It Works

### Authentication Flow

1. Client generates/loads certificate dengan IP:port embedded
2. Client connects ke server via gRPC
3. Client sends certificate + signature (challenge-response)
4. Server validates certificate:
   - Check validity period
   - Verify signature
   - Check IP match
   - Check trusted registry
5. Server adds certificate ke trusted registry
6. Server returns list of known nodes
7. Certificate di-gossip ke other nodes via P2P network

### Upload Flow

1. Client creates streaming request
2. First chunk contains file metadata + first data block
3. Subsequent chunks contain data only
4. Server writes chunks ke disk dengan IP-based folder
5. Server calculates checksum
6. Server stores metadata as JSON
7. Server returns success + file_id

### Download Flow

1. Client requests file dengan file_id (format: source_ip/file_id)
2. Server loads file metadata
3. Server streams file chunks
4. Client writes chunks ke disk
5. Client verifies checksum

### Distributed Registry

1. Nodes connect via libp2p
2. Node join di-broadcast via gossipsub
3. Certificates di-share antar nodes
4. Periodic heartbeats
5. Stale nodes removed after timeout

## File Storage Structure

```
storage/
├── 192.168.1.50/
│   ├── abc123_file1.zip
│   ├── abc123.meta.json
│   ├── def456_file2.pdf
│   └── def456.meta.json
├── 192.168.1.51/
│   ├── xyz789_document.docx
│   └── xyz789.meta.json
└── ...
```

## Security Considerations

1. **Certificate Validation**: All certificates validated before accepting connections
2. **IP Verification**: Certificate IP must match actual connection IP
3. **Signature Verification**: All requests must be signed with private key
4. **Distributed Trust**: Trust propagates via gossip protocol
5. **Checksum Verification**: All files verified with SHA-256

## Performance

- **Streaming**: Files never fully loaded into memory
- **Concurrent**: Multiple uploads/downloads simultaneously
- **Efficient Network**: gRPC HTTP/2 with compression
- **Chunked Transfer**: 1MB default chunk size
- **Zero-copy**: Direct file I/O where possible

## Troubleshooting

### Build Error: protoc not found
Install Protocol Buffers compiler:
```bash
# macOS
brew install protobuf

# Linux
sudo apt install protobuf-compiler
```

### Connection Refused
- Check firewall rules
- Verify server is running
- Check address:port correct

### Certificate Error
- Regenerate certificate
- Check certificate IP matches node IP
- Verify certificate not expired

### P2P Network Issues
- Check p2p_port not blocked
- Verify bootstrap_nodes addresses correct
- Check network connectivity between nodes

## Development

### Run Tests
```bash
cargo test
```

### Run with Verbose Logging
```bash
cargo run -- server --verbose
```

### Set Custom Config
```bash
cargo run --config my-config.toml -- server
```

## API Reference

### gRPC Service

Defined in `proto/file_transfer.proto`:

- `UploadFile(stream FileChunk) → UploadResponse`
- `DownloadFile(DownloadRequest) → stream FileChunk`
- `ListFiles(ListFilesRequest) → ListFilesResponse`
- `Authenticate(AuthRequest) → AuthResponse`
- `Ping(PingRequest) → PingResponse`

## License

[Your License Here]

## Contributing

[Contributing Guidelines]
# chain-service
# chain-service
