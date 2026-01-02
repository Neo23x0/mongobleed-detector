#!/usr/bin/env bash
#
# Test suite for mongobleed-detector
#
# Runs the detector against example and generated logs
# and verifies expected detection results.
#

set -uo pipefail
# Note: not using -e because we need to capture non-zero exit codes from the detector

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DETECTOR="$PROJECT_DIR/mongobleed-detector.sh"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
RESET='\033[0m'

TESTS_PASSED=0
TESTS_FAILED=0

pass() {
    echo -e "${GREEN}✓ PASS:${RESET} $1"
    ((TESTS_PASSED++))
}

fail() {
    echo -e "${RED}✗ FAIL:${RESET} $1"
    ((TESTS_FAILED++))
}

info() {
    echo -e "${YELLOW}→${RESET} $1"
}

#
# ============================================================================
# MODULE A TESTS (Log Correlation)
# ============================================================================
#

#
# Test: Example log exploitation detection
#
test_example_log_exploitation() {
    info "Testing: Example log exploitation detection"
    
    local example_log="$PROJECT_DIR/example-data/logs/mongod.log"
    
    if [[ ! -f "$example_log" ]]; then
        fail "Example log not found: $example_log"
        return
    fi
    
    local output
    local exit_code
    
    # Use 30-day lookback to catch older example logs
    output=$(/bin/bash "$DETECTOR" --no-default-paths -p "$example_log" -t 43200 2>&1) || exit_code=$?
    exit_code=${exit_code:-0}
    
    # Should exit with 1 (HIGH or MEDIUM findings)
    if [[ $exit_code -eq 1 ]]; then
        pass "Exit code is 1 (findings detected)"
    else
        fail "Expected exit code 1, got $exit_code"
    fi
    
    # Should detect 137.137.137.137 as suspicious
    if echo "$output" | grep -q "137.137.137.137"; then
        pass "Detected source IP 137.137.137.137"
    else
        fail "Did not detect source IP 137.137.137.137"
    fi
    
    # Should have MEDIUM or HIGH risk level
    if echo "$output" | grep -qE "^(HIGH|MEDIUM)\s+137\.137\.137\.137"; then
        pass "Classified as HIGH or MEDIUM risk"
    else
        fail "Did not classify as HIGH or MEDIUM risk"
    fi
    
    # Should show 0.00% metadata rate
    if echo "$output" | grep -q "0.00%"; then
        pass "Detected 0% metadata rate"
    else
        fail "Did not detect 0% metadata rate"
    fi
    
    # Should show warning about patching
    if echo "$output" | grep -q "patching alone is insufficient"; then
        pass "Shows post-exploitation warning"
    else
        fail "Missing post-exploitation warning"
    fi
}

#
# Test: Generated HIGH risk pattern
#
test_generated_high_risk() {
    info "Testing: Generated HIGH risk pattern"
    
    local test_log="$SCRIPT_DIR/logs/exploit_high.log"
    
    if [[ ! -f "$test_log" ]]; then
        fail "Test log not found: $test_log (run generate-test-logs.sh first)"
        return
    fi
    
    local output
    local exit_code
    
    output=$(/bin/bash "$DETECTOR" --no-default-paths -p "$test_log" -t 4320 2>&1) || exit_code=$?
    exit_code=${exit_code:-0}
    
    if [[ $exit_code -eq 1 ]]; then
        pass "Exit code is 1 (findings detected)"
    else
        fail "Expected exit code 1, got $exit_code"
    fi
    
    if echo "$output" | grep -qE "^HIGH\s+10\.0\.0\.99"; then
        pass "Classified 10.0.0.99 as HIGH risk"
    else
        fail "Did not classify 10.0.0.99 as HIGH risk"
    fi
}

#
# Test: Normal traffic (no findings)
#
test_normal_traffic() {
    info "Testing: Normal traffic (INFO only)"
    
    local test_log="$SCRIPT_DIR/logs/normal_info.log"
    
    if [[ ! -f "$test_log" ]]; then
        fail "Test log not found: $test_log (run generate-test-logs.sh first)"
        return
    fi
    
    local output
    local exit_code
    
    output=$(/bin/bash "$DETECTOR" --no-default-paths -p "$test_log" -t 4320 2>&1) || exit_code=$?
    exit_code=${exit_code:-0}
    
    if [[ $exit_code -eq 0 ]]; then
        pass "Exit code is 0 (no HIGH/MEDIUM findings)"
    else
        fail "Expected exit code 0, got $exit_code"
    fi
    
    if echo "$output" | grep -q "No HIGH or MEDIUM risk findings"; then
        pass "Reports no HIGH/MEDIUM findings"
    else
        fail "Missing 'no findings' message"
    fi
}

#
# Test: IPv6 address handling
#
test_ipv6_handling() {
    info "Testing: IPv6 address handling"
    
    local test_log="$SCRIPT_DIR/logs/ipv6_test.log"
    
    if [[ ! -f "$test_log" ]]; then
        fail "Test log not found: $test_log (run generate-test-logs.sh first)"
        return
    fi
    
    local output
    output=$(/bin/bash "$DETECTOR" --no-default-paths -p "$test_log" -t 4320 2>&1) || true
    
    if echo "$output" | grep -q "2001:db8::1"; then
        pass "Detected IPv6 address 2001:db8::1"
    else
        fail "Did not detect IPv6 address"
    fi
}

#
# Test: Malformed log tolerance
#
test_malformed_tolerance() {
    info "Testing: Malformed log tolerance"
    
    local test_log="$SCRIPT_DIR/logs/malformed_mixed.log"
    
    if [[ ! -f "$test_log" ]]; then
        fail "Test log not found: $test_log (run generate-test-logs.sh first)"
        return
    fi
    
    local output
    local exit_code
    
    # Use very long lookback (1 year) since malformed_mixed.log has old hardcoded timestamps
    output=$(/bin/bash "$DETECTOR" --no-default-paths -p "$test_log" -t 525600 2>&1) || exit_code=$?
    exit_code=${exit_code:-0}
    
    # Should not crash (exit 2 would indicate error)
    if [[ $exit_code -ne 2 ]]; then
        pass "Did not crash on malformed input"
    else
        fail "Crashed on malformed input (exit code 2)"
    fi
    
    # Should still detect the valid entry
    if echo "$output" | grep -q "1.1.1.1"; then
        pass "Detected valid entry among malformed lines"
    else
        fail "Did not detect valid entry"
    fi
}

#
# Test: Help and version
#
test_help_and_version() {
    info "Testing: Help and version output"
    
    local output
    
    output=$(/bin/bash "$DETECTOR" --help 2>&1)
    if echo "$output" | grep -q "CVE-2025-14847"; then
        pass "--help mentions CVE-2025-14847"
    else
        fail "--help does not mention CVE"
    fi
    
    output=$(/bin/bash "$DETECTOR" --version 2>&1)
    if echo "$output" | grep -qE "^mongobleed-detector\.sh v[0-9]+\.[0-9]+"; then
        pass "--version shows version number"
    else
        fail "--version output unexpected"
    fi
}

#
# Test: Custom thresholds
#
test_custom_thresholds() {
    info "Testing: Custom thresholds"
    
    local test_log="$SCRIPT_DIR/logs/highvolume_low.log"
    
    if [[ ! -f "$test_log" ]]; then
        fail "Test log not found: $test_log"
        return
    fi
    
    local output
    
    # With default thresholds (100 connections), should detect
    output=$(/bin/bash "$DETECTOR" --no-default-paths -p "$test_log" -t 4320 2>&1) || true
    
    if echo "$output" | grep -qE "^LOW\s+172\.16\.0\.25"; then
        pass "Default thresholds: detected as LOW"
    else
        fail "Default thresholds: unexpected classification"
    fi
    
    # With higher threshold (200), should be INFO
    output=$(/bin/bash "$DETECTOR" --no-default-paths -p "$test_log" -t 4320 -c 200 2>&1) || true
    
    if echo "$output" | grep -qE "^INFO\s+172\.16\.0\.25"; then
        pass "Higher threshold (200): classified as INFO"
    else
        fail "Higher threshold: unexpected classification"
    fi
}

#
# ============================================================================
# MODULE B1 TESTS (Assert Counts)
# ============================================================================
#

#
# Test: Assert counts with spike detection
#
test_assert_counts_spike() {
    info "Testing: Assert counts spike detection (Module B1)"
    
    local data_dir="$SCRIPT_DIR/collected-data"
    
    if [[ ! -d "$data_dir/assert-counts" ]]; then
        fail "Test data not found: $data_dir (run generate-test-logs.sh first)"
        return
    fi
    
    local output
    local exit_code
    
    output=$(/bin/bash "$DETECTOR" --data-dir "$data_dir" -t 4320 2>&1) || exit_code=$?
    exit_code=${exit_code:-0}
    
    # Should show Module B1 status
    if echo "$output" | grep -q "Module B1"; then
        pass "Shows Module B1 status"
    else
        fail "Missing Module B1 status"
    fi
    
    # Should detect the spike
    if echo "$output" | grep -qi "SPIKE"; then
        pass "Detected assert spike"
    else
        fail "Did not detect assert spike"
    fi
    
    # Should show the delta
    if echo "$output" | grep -q "740"; then
        pass "Shows spike delta (740)"
    else
        fail "Missing spike delta value"
    fi
}

#
# Test: Single snapshot (informational only)
#
test_single_snapshot() {
    info "Testing: Single assert snapshot (informational)"
    
    local data_dir="$SCRIPT_DIR/collected-data-single-snapshot"
    
    if [[ ! -d "$data_dir/assert-counts" ]]; then
        fail "Test data not found: $data_dir (run generate-test-logs.sh first)"
        return
    fi
    
    local output
    
    output=$(/bin/bash "$DETECTOR" --data-dir "$data_dir" -t 4320 2>&1) || true
    
    # Should indicate single snapshot (either "single snapshot" or "1 snapshot")
    if echo "$output" | grep -qi "single snapshot\|informational\|1 snapshot"; then
        pass "Indicates single snapshot"
    else
        fail "Missing single snapshot indication"
    fi
}

#
# Test: No spikes (stable system)
#
test_no_spikes() {
    info "Testing: Stable system with no spikes"
    
    local data_dir="$SCRIPT_DIR/collected-data-no-spikes"
    
    if [[ ! -d "$data_dir/assert-counts" ]]; then
        fail "Test data not found: $data_dir (run generate-test-logs.sh first)"
        return
    fi
    
    local output
    local exit_code
    
    output=$(/bin/bash "$DETECTOR" --data-dir "$data_dir" -t 4320 2>&1) || exit_code=$?
    exit_code=${exit_code:-0}
    
    # Should not detect spikes
    if ! echo "$output" | grep -qi "SPIKE DETECTED"; then
        pass "No spikes detected in stable data"
    else
        fail "Incorrectly detected spikes in stable data"
    fi
    
    # Should exit 0 (no findings)
    if [[ $exit_code -eq 0 ]]; then
        pass "Exit code 0 for stable system"
    else
        fail "Expected exit code 0, got $exit_code"
    fi
}

#
# ============================================================================
# REAL-WORLD DATA TESTS
# ============================================================================
#

#
# Test: Real-world example data (aws-debian attack)
#
test_real_world_example() {
    info "Testing: Real-world example data from aws-debian"
    
    local data_dir="$PROJECT_DIR/example-data"
    
    if [[ ! -d "$data_dir" ]]; then
        fail "Example data not found: $data_dir"
        return
    fi
    
    local output
    local exit_code
    
    # Use 30-day lookback for older logs
    output=$(/bin/bash "$DETECTOR" --data-dir "$data_dir" -t 43200 2>&1) || exit_code=$?
    exit_code=${exit_code:-0}
    
    # Should detect HIGH risk for 137.137.137.137
    if echo "$output" | grep -qE "^HIGH\s+137\.137\.137\.137"; then
        pass "Detected attacker IP 137.137.137.137 as HIGH risk"
    else
        fail "Did not classify 137.137.137.137 as HIGH risk"
    fi
    
    # Should show real assert count (37384)
    if echo "$output" | grep -q "37384"; then
        pass "Shows real assert.user count (37384)"
    else
        fail "Missing real assert count"
    fi
    
    # Should show module status for all three
    if echo "$output" | grep -q "Module A.*log" && \
       echo "$output" | grep -q "Module B1.*Assert" && \
       echo "$output" | grep -q "Module B2.*FTDC"; then
        pass "Shows status for all three modules"
    else
        fail "Missing module status"
    fi
    
    # Should detect FTDC spikes if pymongo is available
    if echo "$output" | grep -q "spike.*detected\|FTDC samples"; then
        pass "FTDC decoder working (spikes detected)"
    else
        # This is acceptable if pymongo is not installed
        info "FTDC decoder not available (pymongo not installed)"
    fi
    
    # Should exit 1 (findings detected)
    if [[ $exit_code -eq 1 ]]; then
        pass "Exit code 1 (findings detected)"
    else
        fail "Expected exit code 1, got $exit_code"
    fi
}

#
# ============================================================================
# AUTO-DISCOVERY MODE TESTS
# ============================================================================
#

#
# Test: Auto-discovery with combined data
#
test_auto_discovery_combined() {
    info "Testing: Auto-discovery mode with logs + assert-counts"
    
    local data_dir="$SCRIPT_DIR/collected-data"
    
    if [[ ! -d "$data_dir" ]]; then
        fail "Test data not found: $data_dir (run generate-test-logs.sh first)"
        return
    fi
    
    local output
    local exit_code
    
    output=$(/bin/bash "$DETECTOR" --data-dir "$data_dir" -t 4320 2>&1) || exit_code=$?
    exit_code=${exit_code:-0}
    
    # Should show module status for A and B1
    if echo "$output" | grep -q "Module A"; then
        pass "Shows Module A status"
    else
        fail "Missing Module A status"
    fi
    
    if echo "$output" | grep -q "Module B1"; then
        pass "Shows Module B1 status"
    else
        fail "Missing Module B1 status"
    fi
    
    # Should show combined verdict
    if echo "$output" | grep -qi "Combined Verdict"; then
        pass "Shows combined verdict"
    else
        fail "Missing combined verdict"
    fi
    
    # Should exit 1 (has findings from both modules)
    if [[ $exit_code -eq 1 ]]; then
        pass "Exit code 1 (findings detected)"
    else
        fail "Expected exit code 1, got $exit_code"
    fi
}

#
# Test: Module B2 unavailable warning
#
test_b2_unavailable() {
    info "Testing: Module B2 shows as unavailable without FTDC"
    
    local data_dir="$SCRIPT_DIR/collected-data"
    
    if [[ ! -d "$data_dir" ]]; then
        fail "Test data not found: $data_dir"
        return
    fi
    
    local output
    
    output=$(/bin/bash "$DETECTOR" --data-dir "$data_dir" -t 4320 2>&1) || true
    
    # Should show B2 as unavailable (no FTDC files in test data)
    if echo "$output" | grep -q "Module B2.*FTDC.*unavailable\|−.*Module B2\|Module B2.*No FTDC"; then
        pass "Module B2 marked as unavailable"
    else
        fail "Module B2 status not shown correctly"
    fi
}

#
# Test: Caveats displayed
#
test_caveats_displayed() {
    info "Testing: Caveats are displayed"
    
    local data_dir="$SCRIPT_DIR/collected-data"
    
    if [[ ! -d "$data_dir" ]]; then
        fail "Test data not found"
        return
    fi
    
    local output
    
    output=$(/bin/bash "$DETECTOR" --data-dir "$data_dir" -t 4320 2>&1) || true
    
    # Should show caveats
    if echo "$output" | grep -q "Caveats"; then
        pass "Shows caveats section"
    else
        fail "Missing caveats section"
    fi
    
    if echo "$output" | grep -q "cumulative"; then
        pass "Mentions cumulative counter caveat"
    else
        fail "Missing cumulative counter caveat"
    fi
}

#
# ============================================================================
# MAIN
# ============================================================================
#
main() {
    echo
    echo -e "${BOLD}╔════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}║       MongoBleed Detector Test Suite                   ║${RESET}"
    echo -e "${BOLD}╚════════════════════════════════════════════════════════╝${RESET}"
    echo
    
    # Check detector exists
    if [[ ! -x "$DETECTOR" ]]; then
        echo -e "${RED}ERROR: Detector not found or not executable: $DETECTOR${RESET}"
        exit 2
    fi
    
    echo -e "${BOLD}Module A Tests (Log Correlation):${RESET}"
    test_example_log_exploitation
    echo
    test_generated_high_risk
    echo
    test_normal_traffic
    echo
    test_ipv6_handling
    echo
    test_malformed_tolerance
    echo
    test_help_and_version
    echo
    test_custom_thresholds
    echo
    
    echo -e "${BOLD}Module B1 Tests (Assert Counts):${RESET}"
    test_assert_counts_spike
    echo
    test_single_snapshot
    echo
    test_no_spikes
    echo
    
    echo -e "${BOLD}Real-World Data Tests:${RESET}"
    test_real_world_example
    echo
    
    echo -e "${BOLD}Auto-Discovery Mode Tests:${RESET}"
    test_auto_discovery_combined
    echo
    test_b2_unavailable
    echo
    test_caveats_displayed
    
    # Summary
    echo
    echo -e "${BOLD}════════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}Results:${RESET}"
    echo -e "  ${GREEN}Passed: $TESTS_PASSED${RESET}"
    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo -e "  ${RED}Failed: $TESTS_FAILED${RESET}"
    else
        echo -e "  Failed: $TESTS_FAILED"
    fi
    echo
    
    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo -e "${RED}Some tests failed!${RESET}"
        exit 1
    else
        echo -e "${GREEN}All tests passed!${RESET}"
        exit 0
    fi
}

main "$@"
