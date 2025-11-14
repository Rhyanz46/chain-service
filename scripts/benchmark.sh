#!/bin/bash
# Benchmark script untuk testing performance

set -e

# Configuration
UPLOADER="${UPLOADER:-./target/release/uploader}"
SERVER="${SERVER:-127.0.0.1:50051}"
OUTPUT_DIR="${OUTPUT_DIR:-./benchmark-results}"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

mkdir -p "$OUTPUT_DIR"

log() {
    echo -e "${BLUE}[BENCH]${NC} $1"
}

success() {
    echo -e "${GREEN}[DONE]${NC} $1"
}

info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

# Generate test file
generate_test_file() {
    local size="$1"
    local filename="$2"

    log "Generating $size test file: $filename"
    dd if=/dev/urandom of="$filename" bs=1M count="$size" 2>/dev/null
}

# Benchmark upload
benchmark_upload() {
    local filesize="$1"  # in MB
    local iterations="$2"

    log "Benchmarking upload: ${filesize}MB file, $iterations iterations"

    local testfile="$OUTPUT_DIR/test_${filesize}mb.bin"
    generate_test_file "$filesize" "$testfile"

    local total_time=0
    local successful=0

    for i in $(seq 1 "$iterations"); do
        info "Upload iteration $i/$iterations"

        local start=$(date +%s.%N)

        if $UPLOADER upload --file "$testfile" --servers "$SERVER" > /dev/null 2>&1; then
            local end=$(date +%s.%N)
            local duration=$(echo "$end - $start" | bc)
            total_time=$(echo "$total_time + $duration" | bc)
            ((successful++))

            local speed=$(echo "scale=2; $filesize / $duration" | bc)
            echo "  Time: ${duration}s, Speed: ${speed}MB/s"
        else
            echo "  FAILED"
        fi
    done

    # Calculate average
    if [ $successful -gt 0 ]; then
        local avg_time=$(echo "scale=2; $total_time / $successful" | bc)
        local avg_speed=$(echo "scale=2; $filesize / $avg_time" | bc)

        echo ""
        success "Upload Results ($filesize MB):"
        echo "  Successful: $successful/$iterations"
        echo "  Avg Time: ${avg_time}s"
        echo "  Avg Speed: ${avg_speed}MB/s"
        echo ""
    fi

    # Cleanup
    rm -f "$testfile"
}

# Benchmark download
benchmark_download() {
    local filesize="$1"
    local iterations="$2"

    log "Benchmarking download: ${filesize}MB file, $iterations iterations"

    # First upload a test file
    local testfile="$OUTPUT_DIR/test_${filesize}mb.bin"
    generate_test_file "$filesize" "$testfile"

    info "Uploading test file..."
    local upload_output=$($UPLOADER upload --file "$testfile" --servers "$SERVER" 2>&1)
    local file_id=$(echo "$upload_output" | grep "File ID:" | awk '{print $NF}')

    if [ -z "$file_id" ]; then
        echo "ERROR: Failed to upload test file"
        rm -f "$testfile"
        return 1
    fi

    local total_time=0
    local successful=0

    for i in $(seq 1 "$iterations"); do
        info "Download iteration $i/$iterations"

        local download_file="$OUTPUT_DIR/download_${i}.bin"
        local start=$(date +%s.%N)

        if $UPLOADER download \
            --server "$SERVER" \
            --file-id "$file_id" \
            --output "$download_file" > /dev/null 2>&1; then

            local end=$(date +%s.%N)
            local duration=$(echo "$end - $start" | bc)
            total_time=$(echo "$total_time + $duration" | bc)
            ((successful++))

            local speed=$(echo "scale=2; $filesize / $duration" | bc)
            echo "  Time: ${duration}s, Speed: ${speed}MB/s"

            rm -f "$download_file"
        else
            echo "  FAILED"
        fi
    done

    # Calculate average
    if [ $successful -gt 0 ]; then
        local avg_time=$(echo "scale=2; $total_time / $successful" | bc)
        local avg_speed=$(echo "scale=2; $filesize / $avg_time" | bc)

        echo ""
        success "Download Results ($filesize MB):"
        echo "  Successful: $successful/$iterations"
        echo "  Avg Time: ${avg_time}s"
        echo "  Avg Speed: ${avg_speed}MB/s"
        echo ""
    fi

    # Cleanup
    rm -f "$testfile"
}

# Benchmark concurrent uploads
benchmark_concurrent() {
    local filesize="$1"
    local concurrency="$2"

    log "Benchmarking concurrent uploads: ${filesize}MB file, $concurrency concurrent uploads"

    local testfile="$OUTPUT_DIR/test_concurrent_${filesize}mb.bin"
    generate_test_file "$filesize" "$testfile"

    local start=$(date +%s.%N)
    local pids=()

    # Start concurrent uploads
    for i in $(seq 1 "$concurrency"); do
        $UPLOADER upload --file "$testfile" --servers "$SERVER" > /dev/null 2>&1 &
        pids+=($!)
    done

    # Wait for all to complete
    local successful=0
    for pid in "${pids[@]}"; do
        if wait "$pid"; then
            ((successful++))
        fi
    done

    local end=$(date +%s.%N)
    local duration=$(echo "$end - $start" | bc)
    local total_mb=$(echo "$filesize * $successful" | bc)
    local throughput=$(echo "scale=2; $total_mb / $duration" | bc)

    echo ""
    success "Concurrent Upload Results:"
    echo "  Successful: $successful/$concurrency"
    echo "  Total Time: ${duration}s"
    echo "  Total Data: ${total_mb}MB"
    echo "  Throughput: ${throughput}MB/s"
    echo ""

    rm -f "$testfile"
}

# Main benchmark suite
run_benchmark_suite() {
    echo ""
    echo "==================================="
    echo "  File Transfer Benchmark Suite"
    echo "==================================="
    echo "Server: $SERVER"
    echo "Output: $OUTPUT_DIR"
    echo ""

    # Test 1: Small files
    log "Test 1: Small Files (1MB)"
    benchmark_upload 1 5
    benchmark_download 1 5

    # Test 2: Medium files
    log "Test 2: Medium Files (10MB)"
    benchmark_upload 10 5
    benchmark_download 10 5

    # Test 3: Large files
    log "Test 3: Large Files (100MB)"
    benchmark_upload 100 3
    benchmark_download 100 3

    # Test 4: Concurrent uploads
    log "Test 4: Concurrent Uploads (10MB x 5)"
    benchmark_concurrent 10 5

    log "Test 5: Concurrent Uploads (10MB x 10)"
    benchmark_concurrent 10 10

    echo ""
    success "Benchmark suite completed!"
    echo ""
}

# Run stress test
stress_test() {
    local duration="$1"  # in seconds
    local filesize="$2"   # in MB

    log "Running stress test for ${duration}s with ${filesize}MB files"

    local testfile="$OUTPUT_DIR/stress_test_${filesize}mb.bin"
    generate_test_file "$filesize" "$testfile"

    local end_time=$(($(date +%s) + duration))
    local count=0
    local errors=0

    while [ $(date +%s) -lt $end_time ]; do
        ((count++))

        if $UPLOADER upload --file "$testfile" --servers "$SERVER" > /dev/null 2>&1; then
            echo -n "."
        else
            echo -n "X"
            ((errors++))
        fi

        if [ $((count % 50)) -eq 0 ]; then
            echo " [$count]"
        fi
    done

    echo ""
    echo ""
    success "Stress Test Results:"
    echo "  Total Uploads: $count"
    echo "  Successful: $((count - errors))"
    echo "  Failed: $errors"
    echo "  Success Rate: $(echo "scale=2; 100 * ($count - $errors) / $count" | bc)%"
    echo ""

    rm -f "$testfile"
}

# Parse command line arguments
case "${1:-suite}" in
    suite)
        run_benchmark_suite
        ;;
    upload)
        benchmark_upload "${2:-10}" "${3:-5}"
        ;;
    download)
        benchmark_download "${2:-10}" "${3:-5}"
        ;;
    concurrent)
        benchmark_concurrent "${2:-10}" "${3:-5}"
        ;;
    stress)
        stress_test "${2:-60}" "${3:-10}"
        ;;
    *)
        echo "Usage: $0 [suite|upload|download|concurrent|stress] [args...]"
        echo ""
        echo "Commands:"
        echo "  suite                          - Run full benchmark suite"
        echo "  upload <size_mb> <iterations>  - Benchmark upload"
        echo "  download <size_mb> <iterations> - Benchmark download"
        echo "  concurrent <size_mb> <count>   - Benchmark concurrent uploads"
        echo "  stress <duration_s> <size_mb>  - Stress test"
        echo ""
        exit 1
        ;;
esac
