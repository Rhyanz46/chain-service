#!/bin/bash
# Automatic backup/sync script untuk upload file ke multiple servers

set -e

# Configuration
UPLOADER="./target/release/uploader"
WATCH_DIR="${WATCH_DIR:-./uploads}"
LOG_FILE="${LOG_FILE:-./sync.log}"

# Server list (edit sesuai kebutuhan)
SERVERS=(
    "192.168.1.100:50051"
    "192.168.1.101:50051"
    "192.168.1.102:50051"
)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

# Check dependencies
if ! command -v inotifywait &> /dev/null; then
    error "inotifywait not found. Install: sudo apt-get install inotify-tools"
    exit 1
fi

if [ ! -f "$UPLOADER" ]; then
    error "Uploader binary not found at $UPLOADER"
    exit 1
fi

# Create watch directory if not exists
mkdir -p "$WATCH_DIR"

log "Starting backup sync service"
log "Watch directory: $WATCH_DIR"
log "Servers: ${SERVERS[*]}"
log "Log file: $LOG_FILE"

# Upload function
upload_file() {
    local filepath="$1"
    local filename=$(basename "$filepath")

    log "Uploading $filename to ${#SERVERS[@]} servers..."

    # Build command
    local cmd="$UPLOADER upload --file \"$filepath\""
    for server in "${SERVERS[@]}"; do
        cmd="$cmd --servers $server"
    done

    # Execute upload
    if eval "$cmd" >> "$LOG_FILE" 2>&1; then
        success "Upload complete: $filename"
        return 0
    else
        error "Upload failed: $filename"
        return 1
    fi
}

# Process existing files on startup
process_existing_files() {
    log "Processing existing files in $WATCH_DIR..."

    local count=0
    while IFS= read -r -d '' file; do
        if [ -f "$file" ]; then
            upload_file "$file"
            ((count++))
        fi
    done < <(find "$WATCH_DIR" -type f -print0)

    log "Processed $count existing files"
}

# Option to process existing files
if [ "$1" == "--process-existing" ]; then
    process_existing_files
fi

# Watch for new files
log "Watching for new files..."

inotifywait -m "$WATCH_DIR" -e create -e moved_to --format '%w%f' |
while read filepath; do
    # Skip if file doesn't exist (race condition)
    if [ ! -f "$filepath" ]; then
        continue
    fi

    # Skip hidden files and temp files
    filename=$(basename "$filepath")
    if [[ "$filename" == .* ]] || [[ "$filename" == *~ ]]; then
        warning "Skipping temporary file: $filename"
        continue
    fi

    # Wait a moment for file to finish writing
    sleep 1

    # Upload file
    upload_file "$filepath"
done
