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
# Test: Example log exploitation detection
#
test_example_log_exploitation() {
    info "Testing: Example log exploitation detection"
    
    local example_log="$PROJECT_DIR/example-logs/mongod.log"
    
    if [[ ! -f "$example_log" ]]; then
        fail "Example log not found: $example_log"
        return
    fi
    
    local output
    local exit_code
    
    output=$(/bin/bash "$DETECTOR" --no-default-paths -p "$example_log" 2>&1) || exit_code=$?
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
# Main
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
    
    # Run tests
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

