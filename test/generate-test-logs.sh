#!/usr/bin/env bash
#
# Generate test MongoDB logs for validating mongobleed-detector
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/logs"

mkdir -p "$OUTPUT_DIR"

# Get current timestamp in ISO format
now_epoch=$(date +%s)

iso_date() {
    local epoch="$1"
    date -u -d "@$epoch" '+%Y-%m-%dT%H:%M:%S.000Z' 2>/dev/null || \
    date -u -r "$epoch" '+%Y-%m-%dT%H:%M:%S.000Z'
}

echo "Generating test logs in $OUTPUT_DIR..."

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

echo ""
echo "Test logs generated successfully!"
echo ""
echo "Run the detector with:"
echo "  ../mongobleed-detector.sh --no-default-paths -p '$OUTPUT_DIR/*.log' -p '$OUTPUT_DIR/*.log.gz' -t 120"
echo ""
echo "Expected results:"
echo "  HIGH:   10.0.0.99 (500 connections, 0% metadata, high burst)"
echo "  MEDIUM: 10.0.0.50 (200 connections, 2.5% metadata, low burst)"
echo "  MEDIUM: 2001:db8::1 (120 connections, 5% metadata, IPv6)"
echo "  LOW:    172.16.0.25 (150 connections, 96.7% metadata)"
echo "  INFO:   All others (< 100 connections)"

