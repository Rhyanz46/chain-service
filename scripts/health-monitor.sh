#!/bin/bash
# Health monitoring script untuk distributed file transfer cluster

set -e

# Configuration
UPLOADER="${UPLOADER:-./target/release/uploader}"
CHECK_INTERVAL="${CHECK_INTERVAL:-60}"
ALERT_EMAIL="${ALERT_EMAIL:-}"
SLACK_WEBHOOK="${SLACK_WEBHOOK:-}"

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
BLUE='\033[0;34m'
NC='\033[0m'

# Status tracking
declare -A LAST_STATUS
declare -A DOWN_COUNT

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

error() {
    echo -e "${RED}✗${NC} $1"
}

success() {
    echo -e "${GREEN}✓${NC} $1"
}

warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Send alert via email
send_email_alert() {
    local server="$1"
    local message="$2"

    if [ -n "$ALERT_EMAIL" ]; then
        echo "$message" | mail -s "[ALERT] File Transfer Server: $server" "$ALERT_EMAIL"
        log "Alert email sent to $ALERT_EMAIL"
    fi
}

# Send alert via Slack
send_slack_alert() {
    local server="$1"
    local message="$2"
    local color="$3"  # good, warning, danger

    if [ -n "$SLACK_WEBHOOK" ]; then
        curl -X POST "$SLACK_WEBHOOK" \
            -H 'Content-Type: application/json' \
            -d '{
                "attachments": [{
                    "color": "'"$color"'",
                    "title": "File Transfer Server Alert",
                    "text": "'"$message"'",
                    "fields": [{
                        "title": "Server",
                        "value": "'"$server"'",
                        "short": true
                    }, {
                        "title": "Time",
                        "value": "'"$(date '+%Y-%m-%d %H:%M:%S')"'",
                        "short": true
                    }]
                }]
            }' > /dev/null 2>&1
        log "Slack alert sent"
    fi
}

# Check server health
check_server() {
    local server="$1"

    if $UPLOADER ping --server "$server" > /dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Get server info
get_server_info() {
    local server="$1"

    local output=$($UPLOADER list --server "$server" --page 1 --page-size 1 2>&1 || echo "ERROR")

    if [[ "$output" != "ERROR" ]]; then
        # Parse file count from output
        local file_count=$(echo "$output" | grep -c "^192" || echo "0")
        echo "$file_count files"
    else
        echo "N/A"
    fi
}

# Monitor loop
monitor() {
    local cycle=0

    while true; do
        ((cycle++))
        echo ""
        echo "=== Health Check #$cycle - $(date '+%Y-%m-%d %H:%M:%S') ==="
        echo ""

        local total=${#SERVERS[@]}
        local healthy=0
        local unhealthy=0

        for server in "${SERVERS[@]}"; do
            if check_server "$server"; then
                local info=$(get_server_info "$server")
                success "$server is UP ($info)"
                ((healthy++))

                # Check if was down before
                if [ "${LAST_STATUS[$server]}" == "DOWN" ]; then
                    warning "$server has RECOVERED"
                    send_email_alert "$server" "Server $server has recovered and is now UP"
                    send_slack_alert "$server" "Server has recovered and is now UP" "good"
                fi

                LAST_STATUS[$server]="UP"
                DOWN_COUNT[$server]=0
            else
                error "$server is DOWN"
                ((unhealthy++))

                # Increment down counter
                local count=${DOWN_COUNT[$server]:-0}
                ((count++))
                DOWN_COUNT[$server]=$count

                # Alert on first failure and every 10th failure
                if [ "${LAST_STATUS[$server]}" != "DOWN" ] || [ $((count % 10)) -eq 0 ]; then
                    if [ "${LAST_STATUS[$server]}" != "DOWN" ]; then
                        warning "$server has GONE DOWN"
                        send_email_alert "$server" "Server $server is DOWN and not responding to ping"
                        send_slack_alert "$server" "Server is DOWN and not responding" "danger"
                    else
                        warning "$server still down (check #$count)"
                    fi
                fi

                LAST_STATUS[$server]="DOWN"
            fi
        done

        echo ""
        echo "Status: $healthy/$total servers healthy"

        if [ $unhealthy -gt 0 ]; then
            warning "$unhealthy server(s) are down"
        else
            success "All servers are healthy"
        fi

        # Wait for next check
        sleep "$CHECK_INTERVAL"
    done
}

# Trap Ctrl+C
trap 'echo ""; log "Monitoring stopped"; exit 0' INT TERM

# Start monitoring
log "Starting health monitoring for ${#SERVERS[@]} servers"
log "Check interval: ${CHECK_INTERVAL}s"

if [ -n "$ALERT_EMAIL" ]; then
    log "Email alerts enabled: $ALERT_EMAIL"
fi

if [ -n "$SLACK_WEBHOOK" ]; then
    log "Slack alerts enabled"
fi

monitor
