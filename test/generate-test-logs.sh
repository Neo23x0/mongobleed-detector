#!/usr/bin/env bash
#
# Generate test data for validating mongobleed-detector
# Generates logs, assert-counts, and mock FTDC data
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/logs"
DATA_DIR="${SCRIPT_DIR}/collected-data"

mkdir -p "$OUTPUT_DIR"
mkdir -p "$DATA_DIR/logs"
mkdir -p "$DATA_DIR/assert-counts"
mkdir -p "$DATA_DIR/ftdc-files"

# Get current timestamp in ISO format
now_epoch=$(date +%s)

iso_date() {
    local epoch="$1"
    date -u -d "@$epoch" '+%Y-%m-%dT%H:%M:%S.000Z' 2>/dev/null || \
    date -u -r "$epoch" '+%Y-%m-%dT%H:%M:%S.000Z'
}

iso_date_short() {
    local epoch="$1"
    date -u -d "@$epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || \
    date -u -r "$epoch" '+%Y-%m-%dT%H:%M:%SZ'
}

echo "Generating test data..."
echo

#
# ============================================================================
# LOG FILES (Module A test data)
# ============================================================================
#

echo "Generating log files in $OUTPUT_DIR..."

#
# Test Case 1: Exploitation Pattern (HIGH risk)
# - 500 connections in 30 seconds
# - 0 metadata events
# - Burst rate: 1000/min
#
echo "  Creating exploit_high.log (HIGH risk pattern)..."
{
    for i in $(seq 1 500); do
        ts=$(iso_date $((now_epoch - 1800 + i/17)))
        port=$((30000 + i))
        cat <<EOF
{"t":{"\$date":"${ts}"},"s":"I","c":"NETWORK","id":22943,"ctx":"listener","msg":"connection accepted","attr":{"session_remote":"10.0.0.99:${port}","session_id":${i},"connectionCount":${i}}}
EOF
    done
} > "$OUTPUT_DIR/exploit_high.log"

#
# Test Case 2: Suspicious Pattern (MEDIUM risk)
# - 200 connections in 10 minutes
# - 5 metadata events (2.5% rate < 10% threshold)
# - Burst rate: 20/min (< 500 threshold)
#
echo "  Creating suspicious_medium.log (MEDIUM risk pattern)..."
{
    for i in $(seq 1 200); do
        ts=$(iso_date $((now_epoch - 1800 + i*3)))
        port=$((40000 + i))
        cat <<EOF
{"t":{"\$date":"${ts}"},"s":"I","c":"NETWORK","id":22943,"ctx":"listener","msg":"connection accepted","attr":{"session_remote":"10.0.0.50:${port}","session_id":${i},"connectionCount":${i}}}
EOF
        # Add metadata for first 5 connections only
        if [[ $i -le 5 ]]; then
            cat <<EOF
{"t":{"\$date":"${ts}"},"s":"I","c":"NETWORK","id":51800,"ctx":"conn${i}","msg":"client metadata","attr":{"remote":"10.0.0.50:${port}","doc":{"driver":{"name":"test-driver"}}}}
EOF
        fi
    done
} > "$OUTPUT_DIR/suspicious_medium.log"

#
# Test Case 3: High Volume Legitimate (LOW risk)
# - 150 connections in 10 minutes
# - 145 metadata events (96.7% rate >= 10% threshold)
#
echo "  Creating highvolume_low.log (LOW risk pattern)..."
{
    for i in $(seq 1 150); do
        ts=$(iso_date $((now_epoch - 1800 + i*4)))
        port=$((50000 + i))
        cat <<EOF
{"t":{"\$date":"${ts}"},"s":"I","c":"NETWORK","id":22943,"ctx":"listener","msg":"connection accepted","attr":{"session_remote":"172.16.0.25:${port}","session_id":${i},"connectionCount":${i}}}
EOF
        # Add metadata for most connections (145 out of 150)
        if [[ $i -le 145 ]]; then
            cat <<EOF
{"t":{"\$date":"${ts}"},"s":"I","c":"NETWORK","id":51800,"ctx":"conn${i}","msg":"client metadata","attr":{"remote":"172.16.0.25:${port}","doc":{"application":{"name":"MongoDB Shell"},"driver":{"name":"MongoDB Internal Client"}}}}
EOF
        fi
    done
} > "$OUTPUT_DIR/highvolume_low.log"

#
# Test Case 4: Normal Traffic (INFO risk)
# - 10 connections with metadata
#
echo "  Creating normal_info.log (INFO risk pattern)..."
{
    for i in $(seq 1 10); do
        ts=$(iso_date $((now_epoch - 1800 + i*60)))
        port=$((60000 + i))
        cat <<EOF
{"t":{"\$date":"${ts}"},"s":"I","c":"NETWORK","id":22943,"ctx":"listener","msg":"connection accepted","attr":{"session_remote":"192.168.1.10:${port}","session_id":${i},"connectionCount":${i}}}
{"t":{"\$date":"${ts}"},"s":"I","c":"NETWORK","id":51800,"ctx":"conn${i}","msg":"client metadata","attr":{"remote":"192.168.1.10:${port}","doc":{"application":{"name":"app-server"},"driver":{"name":"pymongo","version":"4.0.0"}}}}
{"t":{"\$date":"${ts}"},"s":"I","c":"NETWORK","id":22944,"ctx":"conn${i}","msg":"end connection","attr":{"remote":"192.168.1.10:${port}","connectionCount":$((i-1))}}
EOF
    done
} > "$OUTPUT_DIR/normal_info.log"

#
# Test Case 5: IPv6 addresses
#
echo "  Creating ipv6_test.log (IPv6 addresses)..."
{
    for i in $(seq 1 120); do
        ts=$(iso_date $((now_epoch - 1800 + i*2)))
        port=$((10000 + i))
        cat <<EOF
{"t":{"\$date":"${ts}"},"s":"I","c":"NETWORK","id":22943,"ctx":"listener","msg":"connection accepted","attr":{"session_remote":"[2001:db8::1]:${port}","session_id":${i}}}
EOF
        # Low metadata rate (5%)
        if [[ $((i % 20)) -eq 0 ]]; then
            cat <<EOF
{"t":{"\$date":"${ts}"},"s":"I","c":"NETWORK","id":51800,"ctx":"conn${i}","msg":"client metadata","attr":{"remote":"[2001:db8::1]:${port}","doc":{"driver":{"name":"test"}}}}
EOF
        fi
    done
} > "$OUTPUT_DIR/ipv6_test.log"

#
# Test Case 6: Mixed traffic from multiple IPs
#
echo "  Creating mixed_traffic.log (multiple IPs)..."
{
    for ip_suffix in 1 2 3 4 5; do
        ip="192.168.${ip_suffix}.100"
        for i in $(seq 1 20); do
            ts=$(iso_date $((now_epoch - 1800 + ip_suffix*100 + i*5)))
            port=$((20000 + ip_suffix*1000 + i))
            cat <<EOF
{"t":{"\$date":"${ts}"},"s":"I","c":"NETWORK","id":22943,"ctx":"listener","msg":"connection accepted","attr":{"session_remote":"${ip}:${port}","session_id":$((ip_suffix*100 + i))}}
{"t":{"\$date":"${ts}"},"s":"I","c":"NETWORK","id":51800,"ctx":"conn$((ip_suffix*100 + i))","msg":"client metadata","attr":{"remote":"${ip}:${port}","doc":{"driver":{"name":"nodejs-driver"}}}}
EOF
        done
    done
} > "$OUTPUT_DIR/mixed_traffic.log"

#
# Test Case 7: Compressed log file
#
echo "  Creating compressed.log.gz..."
{
    for i in $(seq 1 50); do
        ts=$(iso_date $((now_epoch - 3600 + i*10)))
        cat <<EOF
{"t":{"\$date":"${ts}"},"s":"I","c":"NETWORK","id":22943,"ctx":"listener","msg":"connection accepted","attr":{"session_remote":"10.10.10.10:${i}","session_id":${i}}}
{"t":{"\$date":"${ts}"},"s":"I","c":"NETWORK","id":51800,"ctx":"conn${i}","msg":"client metadata","attr":{"remote":"10.10.10.10:${i}","doc":{"driver":{"name":"gzip-test"}}}}
EOF
    done
} | gzip > "$OUTPUT_DIR/compressed.log.gz"

#
# Test Case 8: Malformed lines mixed with valid
#
echo "  Creating malformed_mixed.log (error tolerance test)..."
{
    echo "This is not JSON"
    echo '{"t":{"$date":"2025-01-15T10:00:00.000Z"},"s":"I","c":"NETWORK","id":22943,"ctx":"listener","msg":"connection accepted","attr":{"session_remote":"1.1.1.1:1111","session_id":1}}'
    echo '{"incomplete json'
    echo '{"t":{"$date":"2025-01-15T10:00:00.100Z"},"s":"I","c":"NETWORK","id":51800,"ctx":"conn1","msg":"client metadata","attr":{"remote":"1.1.1.1:1111","doc":{"driver":{"name":"test"}}}}'
    echo ''
    echo '{"t":{"$date":"2025-01-15T10:00:00.200Z"},"s":"I","c":"NETWORK","id":22944,"ctx":"conn1","msg":"end connection","attr":{"remote":"1.1.1.1:1111"}}'
} > "$OUTPUT_DIR/malformed_mixed.log"

echo

#
# ============================================================================
# COLLECTED-DATA STRUCTURE (Module B test data)
# ============================================================================
#

echo "Generating collected-data structure in $DATA_DIR..."

# Copy exploit log to collected-data/logs for combined testing
echo "  Creating collected-data/logs/..."
cp "$OUTPUT_DIR/exploit_high.log" "$DATA_DIR/logs/"

#
# Assert-counts test data (Module B1)
#

echo "  Creating assert-counts JSON files..."

# Multiple snapshots with a spike
# Snapshot 1: baseline
cat > "$DATA_DIR/assert-counts/asserts-snapshot-1.json" <<EOF
{
  "timestamp": "$(iso_date_short $((now_epoch - 3600)))",
  "hostname": "mongo-test-01",
  "asserts": {
    "regular": 0,
    "warning": 0,
    "msg": 0,
    "user": 100,
    "tripwire": 0,
    "rollovers": 0
  },
  "uptime": 86400
}
EOF

# Snapshot 2: small increase (normal)
cat > "$DATA_DIR/assert-counts/asserts-snapshot-2.json" <<EOF
{
  "timestamp": "$(iso_date_short $((now_epoch - 1800)))",
  "hostname": "mongo-test-01",
  "asserts": {
    "regular": 0,
    "warning": 0,
    "msg": 0,
    "user": 110,
    "tripwire": 0,
    "rollovers": 0
  },
  "uptime": 88200
}
EOF

# Snapshot 3: SPIKE! (exploitation)
cat > "$DATA_DIR/assert-counts/asserts-snapshot-3.json" <<EOF
{
  "timestamp": "$(iso_date_short $((now_epoch - 900)))",
  "hostname": "mongo-test-01",
  "asserts": {
    "regular": 0,
    "warning": 0,
    "msg": 0,
    "user": 850,
    "tripwire": 0,
    "rollovers": 0
  },
  "uptime": 89100
}
EOF

# Snapshot 4: post-spike
cat > "$DATA_DIR/assert-counts/asserts-snapshot-4.json" <<EOF
{
  "timestamp": "$(iso_date_short "$now_epoch")",
  "hostname": "mongo-test-01",
  "asserts": {
    "regular": 0,
    "warning": 0,
    "msg": 0,
    "user": 860,
    "tripwire": 0,
    "rollovers": 0
  },
  "uptime": 90000
}
EOF

#
# Create a separate test case: single snapshot (informational only)
#
mkdir -p "$DATA_DIR-single-snapshot/assert-counts"
cat > "$DATA_DIR-single-snapshot/assert-counts/asserts-only.json" <<EOF
{
  "timestamp": "$(iso_date_short "$now_epoch")",
  "hostname": "mongo-test-02",
  "asserts": {
    "regular": 0,
    "warning": 0,
    "msg": 0,
    "user": 5000,
    "tripwire": 0,
    "rollovers": 0
  },
  "uptime": 864000
}
EOF

#
# Create a separate test case: no spikes (stable system)
# Use small deltas (< 100 threshold) between snapshots
#
mkdir -p "$DATA_DIR-no-spikes/assert-counts"
for i in 1 2 3 4 5; do
    cat > "$DATA_DIR-no-spikes/assert-counts/asserts-${i}.json" <<EOF
{
  "timestamp": "$(iso_date_short $((now_epoch - (5-i)*600)))",
  "hostname": "mongo-stable",
  "asserts": {
    "regular": 0,
    "warning": 0,
    "msg": 0,
    "user": $((1000 + i*10)),
    "tripwire": 0,
    "rollovers": 0
  },
  "uptime": $((86400 + i*600))
}
EOF
done

echo

#
# ============================================================================
# SUMMARY
# ============================================================================
#

echo "Test data generated successfully!"
echo
echo "Log files in $OUTPUT_DIR:"
echo "  HIGH:   exploit_high.log (500 connections, 0% metadata)"
echo "  MEDIUM: suspicious_medium.log (200 connections, 2.5% metadata)"
echo "  MEDIUM: ipv6_test.log (120 connections, 5% metadata, IPv6)"
echo "  LOW:    highvolume_low.log (150 connections, 96.7% metadata)"
echo "  INFO:   normal_info.log, mixed_traffic.log, compressed.log.gz"
echo
echo "Collected-data structures:"
echo "  $DATA_DIR/"
echo "    - logs/exploit_high.log"
echo "    - assert-counts/*.json (4 snapshots with spike)"
echo "  $DATA_DIR-single-snapshot/"
echo "    - assert-counts/asserts-only.json (single snapshot, informational)"
echo "  $DATA_DIR-no-spikes/"
echo "    - assert-counts/*.json (5 snapshots, no spikes)"
echo
echo "Run tests with:"
echo "  # Legacy log-only mode:"
echo "  ../mongobleed-detector.sh --no-default-paths -p '$OUTPUT_DIR/*.log' -t 120"
echo
echo "  # Auto-discovery mode with collected data:"
echo "  ../mongobleed-detector.sh --data-dir '$DATA_DIR' -t 120"
echo
echo "  # Test single snapshot (informational):"
echo "  ../mongobleed-detector.sh --data-dir '$DATA_DIR-single-snapshot' -t 120"
echo
echo "  # Test no spikes (stable system):"
echo "  ../mongobleed-detector.sh --data-dir '$DATA_DIR-no-spikes' -t 120"
