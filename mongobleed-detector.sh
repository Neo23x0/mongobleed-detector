#!/usr/bin/env bash
#
# mongobleed-detector.sh
# Offline MongoDB Log Correlation Tool for CVE-2025-14847 (MongoBleed)
#
# Analyzes MongoDB JSON logs to identify likely exploitation patterns:
# - High connection counts from single source IPs
# - Absence of client metadata events
# - Short-term burst behavior
#
# Usage: ./mongobleed-detector.sh [OPTIONS] [PATHS...]
#
# Requirements: bash 4+, jq, awk, gzip (for compressed logs)
#

set -euo pipefail

readonly VERSION="1.0.0"
readonly SCRIPT_NAME="$(basename "$0")"

# Default configuration
DEFAULT_LOG_PATHS=("/var/log/mongodb/*.log" "/var/log/mongodb/*.log.*")
TIME_RANGE_MINUTES=4320  # 3 days (72 hours)
CONNECTION_THRESHOLD=100
BURST_RATE_THRESHOLD=400
METADATA_RATE_THRESHOLD=0.10

# Runtime state
ADDITIONAL_PATHS=()
SKIP_DEFAULT_PATHS=false

# Colors for terminal output (disabled if not a TTY)
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    GREEN='\033[0;32m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED=''
    YELLOW=''
    GREEN=''
    CYAN=''
    BOLD=''
    RESET=''
fi

usage() {
    cat <<EOF
${BOLD}${SCRIPT_NAME}${RESET} v${VERSION}
Offline MongoDB Log Correlation Tool for CVE-2025-14847 (MongoBleed)

${BOLD}USAGE${RESET}
    ${SCRIPT_NAME} [OPTIONS] [PATHS...]

${BOLD}DESCRIPTION${RESET}
    Analyzes MongoDB JSON logs to identify potential MongoBleed exploitation
    by correlating connection events with client metadata presence.

    Exploitation indicators:
    - High volume of connections from a single source IP
    - Absence of client metadata (legitimate clients always send metadata)
    - Short-duration burst behavior

${BOLD}OPTIONS${RESET}
    -p, --path <glob>       Additional log path/glob to scan (repeatable)
    -t, --time <minutes>    Lookback window in minutes (default: ${TIME_RANGE_MINUTES})
    -c, --conn-threshold    Connection count threshold (default: ${CONNECTION_THRESHOLD})
    -b, --burst-threshold   Burst rate threshold per minute (default: ${BURST_RATE_THRESHOLD})
    -m, --metadata-rate     Metadata rate threshold 0.0-1.0 (default: ${METADATA_RATE_THRESHOLD})
    --no-default-paths      Skip default log paths
    -h, --help              Show this help message
    -v, --version           Show version

${BOLD}DEFAULT LOG PATHS${RESET}
    /var/log/mongodb/*.log
    /var/log/mongodb/*.log.*

    Includes rotated and compressed (.gz) logs.

${BOLD}RISK LEVELS${RESET}
    HIGH   - Connections >= threshold, metadata rate < threshold, burst rate >= threshold
    MEDIUM - Connections >= threshold, metadata rate < threshold, burst rate < threshold  
    LOW    - Connections >= threshold, metadata rate >= threshold
    INFO   - Connections < threshold

${BOLD}EXAMPLES${RESET}
    # Scan default paths
    ${SCRIPT_NAME}

    # Scan specific directory
    ${SCRIPT_NAME} -p /path/to/logs/*.json

    # Custom thresholds with 24-hour lookback
    ${SCRIPT_NAME} -t 1440 -c 50 -b 300

    # Analyze a forensic copy
    ${SCRIPT_NAME} --no-default-paths -p /forensics/mongodb/*.log*

${BOLD}EXIT CODES${RESET}
    0 - No HIGH or MEDIUM findings
    1 - HIGH or MEDIUM findings detected
    2 - Error (missing dependencies, no logs found, etc.)

EOF
}

version() {
    echo "${SCRIPT_NAME} v${VERSION}"
}

error() {
    echo -e "${RED}ERROR:${RESET} $*" >&2
}

warn() {
    echo -e "${YELLOW}WARNING:${RESET} $*" >&2
}

info() {
    echo -e "${CYAN}INFO:${RESET} $*" >&2
}

check_dependencies() {
    local missing=()
    
    if ! command -v jq &>/dev/null; then
        missing+=("jq")
    fi
    
    if ! command -v awk &>/dev/null; then
        missing+=("awk")
    fi
    
    if ! command -v gzip &>/dev/null; then
        missing+=("gzip")
    fi
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Missing required dependencies: ${missing[*]}"
        echo "Install with: apt-get install ${missing[*]}" >&2
        echo "         or: yum install ${missing[*]}" >&2
        exit 2
    fi
    
    # Check jq version supports required features
    if ! echo '{}' | jq -e '.' &>/dev/null; then
        error "jq is installed but not functioning correctly"
        exit 2
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -p|--path)
                if [[ -z "${2:-}" ]]; then
                    error "Option $1 requires an argument"
                    exit 2
                fi
                ADDITIONAL_PATHS+=("$2")
                shift 2
                ;;
            -t|--time)
                if [[ -z "${2:-}" ]] || ! [[ "$2" =~ ^[0-9]+$ ]]; then
                    error "Option $1 requires a positive integer"
                    exit 2
                fi
                TIME_RANGE_MINUTES="$2"
                shift 2
                ;;
            -c|--conn-threshold)
                if [[ -z "${2:-}" ]] || ! [[ "$2" =~ ^[0-9]+$ ]]; then
                    error "Option $1 requires a positive integer"
                    exit 2
                fi
                CONNECTION_THRESHOLD="$2"
                shift 2
                ;;
            -b|--burst-threshold)
                if [[ -z "${2:-}" ]] || ! [[ "$2" =~ ^[0-9]+$ ]]; then
                    error "Option $1 requires a positive integer"
                    exit 2
                fi
                BURST_RATE_THRESHOLD="$2"
                shift 2
                ;;
            -m|--metadata-rate)
                if [[ -z "${2:-}" ]]; then
                    error "Option $1 requires a numeric argument"
                    exit 2
                fi
                # Validate float between 0 and 1
                if ! awk -v val="$2" 'BEGIN { if (val >= 0 && val <= 1) exit 0; else exit 1 }'; then
                    error "Metadata rate must be between 0.0 and 1.0"
                    exit 2
                fi
                METADATA_RATE_THRESHOLD="$2"
                shift 2
                ;;
            --no-default-paths)
                SKIP_DEFAULT_PATHS=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -v|--version)
                version
                exit 0
                ;;
            -*)
                error "Unknown option: $1"
                echo "Use --help for usage information" >&2
                exit 2
                ;;
            *)
                # Treat as additional path
                ADDITIONAL_PATHS+=("$1")
                shift
                ;;
        esac
    done
}

# Normalize IP address: strip port, handle IPv4 and IPv6
# Input formats:
#   IPv4: 1.2.3.4:port
#   IPv6: [2001:db8::1]:port
#   IPv6 unbracketed: 2001:db8::1:port (ambiguous, best effort)
normalize_ip() {
    local addr="$1"
    
    # Handle bracketed IPv6: [addr]:port
    if [[ "$addr" =~ ^\[([^\]]+)\] ]]; then
        echo "${BASH_REMATCH[1]}"
        return
    fi
    
    # Handle IPv4: addr:port (exactly one colon)
    if [[ "$addr" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):[0-9]+$ ]]; then
        echo "${BASH_REMATCH[1]}"
        return
    fi
    
    # Handle IPv4 without port
    if [[ "$addr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$addr"
        return
    fi
    
    # Handle unbracketed IPv6 with port: multiple colons, last segment is port
    # This is ambiguous but we try to detect it by checking if last segment is numeric
    if [[ "$addr" =~ : ]]; then
        # Check if it looks like IPv6:port (last segment after last colon is a small number)
        local last_segment="${addr##*:}"
        if [[ "$last_segment" =~ ^[0-9]+$ ]] && [[ "$last_segment" -lt 65536 ]]; then
            # Strip the port
            echo "${addr%:*}"
            return
        fi
        # Pure IPv6 without port
        echo "$addr"
        return
    fi
    
    # Unknown format, return as-is
    echo "$addr"
}

# Read file (handles .gz compression)
read_log_file() {
    local file="$1"
    
    if [[ "$file" == *.gz ]]; then
        gzip -dc "$file" 2>/dev/null || true
    else
        cat "$file" 2>/dev/null || true
    fi
}

# Collect all log files to process
collect_log_files() {
    local files=()
    local patterns=()
    
    # Add default paths unless disabled
    if [[ "$SKIP_DEFAULT_PATHS" != true ]]; then
        patterns+=("${DEFAULT_LOG_PATHS[@]}")
    fi
    
    # Add additional paths
    patterns+=("${ADDITIONAL_PATHS[@]}")
    
    if [[ ${#patterns[@]} -eq 0 ]]; then
        error "No log paths specified. Use -p to specify paths or allow default paths."
        exit 2
    fi
    
    # Expand globs and collect files
    for pattern in "${patterns[@]}"; do
        # Use nullglob behavior via compgen
        while IFS= read -r -d '' file; do
            if [[ -f "$file" && -r "$file" ]]; then
                files+=("$file")
            fi
        done < <(compgen -G "$pattern" | tr '\n' '\0' 2>/dev/null || true)
    done
    
    # Remove duplicates and sort
    if [[ ${#files[@]} -gt 0 ]]; then
        printf '%s\n' "${files[@]}" | sort -u
    fi
}

# Main analysis function using streaming processing
analyze_logs() {
    local cutoff_epoch="$1"
    shift
    local log_files=("$@")
    
    # jq filter to extract relevant events
    # Outputs: TYPE|TIMESTAMP|SOURCE_IP
    # TYPE: C=connection, M=metadata, D=disconnect
    # Uses -R to read raw lines and fromjson? to tolerate malformed lines
    local jq_filter='
        fromjson? |
        select(.id == 22943 or .id == 51800 or .id == 22944) |
        (
            if .id == 22943 then "C"
            elif .id == 51800 then "M"
            else "D"
            end
        ) as $type |
        (.t."$date" // .t) as $ts |
        (
            if .id == 22943 then
                (.attr.session_remote // .attr.remote // "")
            else
                (.attr.remote // "")
            end
        ) as $remote |
        select($remote != "") |
        "\($type)|\($ts)|\($remote)"
    '
    
    # Process all logs through jq, streaming one line at a time
    # -R reads raw lines, fromjson? in filter handles malformed lines gracefully
    # Then use awk for aggregation (POSIX-compliant)
    (
        for file in "${log_files[@]}"; do
            read_log_file "$file"
        done
    ) | jq -R -r "$jq_filter" 2>/dev/null | awk -F'|' -v cutoff="$cutoff_epoch" -v conn_thresh="$CONNECTION_THRESHOLD" \
        -v burst_thresh="$BURST_RATE_THRESHOLD" -v meta_thresh="$METADATA_RATE_THRESHOLD" '
    
    function iso_to_epoch(iso,    y, mo, d, H, M, S, epoch, days, tz_pos, tz_sign, tz_h, tz_m, tz_offset, a, jd) {
        # Parse ISO 8601: 2020-05-20T19:18:40.604+00:00 or 2020-05-20T19:18:40.604Z
        # Format is fixed position: YYYY-MM-DDTHH:MM:SS
        if (length(iso) < 19) return 0
        if (substr(iso, 5, 1) != "-" || substr(iso, 8, 1) != "-" || substr(iso, 11, 1) != "T") return 0
        
        y = int(substr(iso, 1, 4))
        mo = int(substr(iso, 6, 2))
        d = int(substr(iso, 9, 2))
        H = int(substr(iso, 12, 2))
        M = int(substr(iso, 15, 2))
        S = int(substr(iso, 18, 2))
        
        # Calculate days since Unix epoch using Julian Day Number algorithm
        # JDN for 1970-01-01 is 2440588
        a = int((14 - mo) / 12)
        y = y + 4800 - a
        mo = mo + 12 * a - 3
        jd = d + int((153 * mo + 2) / 5) + 365 * y + int(y / 4) - int(y / 100) + int(y / 400) - 32045
        days = jd - 2440588
        
        # Calculate epoch
        epoch = days * 86400 + H * 3600 + M * 60 + S
        
        # Handle timezone offset (+HH:MM, -HH:MM, or Z)
        # Look for + or - after position 19
        tz_pos = 0
        if (index(substr(iso, 20), "+") > 0) {
            tz_pos = 19 + index(substr(iso, 20), "+")
            tz_sign = -1
        } else if (index(substr(iso, 20), "-") > 0) {
            tz_pos = 19 + index(substr(iso, 20), "-")
            tz_sign = 1
        }
        
        if (tz_pos > 0) {
            tz_h = int(substr(iso, tz_pos + 1, 2))
            # Handle both +HH:MM and +HHMM formats
            if (substr(iso, tz_pos + 3, 1) == ":") {
                tz_m = int(substr(iso, tz_pos + 4, 2))
            } else {
                tz_m = int(substr(iso, tz_pos + 3, 2))
            }
            tz_offset = tz_sign * (tz_h * 3600 + tz_m * 60)
            epoch += tz_offset
        }
        # Z means UTC, no adjustment needed
        
        return epoch
    }
    
    function normalize_ip(addr,    ip, pos, bracket_end, colon_pos, n, parts, i, last, result) {
        # Bracketed IPv6: [addr]:port
        if (substr(addr, 1, 1) == "[") {
            bracket_end = index(addr, "]")
            if (bracket_end > 1) {
                return substr(addr, 2, bracket_end - 2)
            }
        }
        
        # Count colons to distinguish IPv4 from IPv6
        n = gsub(/:/, ":", addr)
        
        # IPv4 with port: exactly one colon
        if (n == 1) {
            colon_pos = index(addr, ":")
            ip = substr(addr, 1, colon_pos - 1)
            # Verify it looks like IPv4
            if (match(ip, /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/)) {
                return ip
            }
        }
        
        # IPv4 without port
        if (n == 0 && match(addr, /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/)) {
            return addr
        }
        
        # IPv6 handling - try to strip port if present
        # IPv6 addresses have multiple colons; if last segment is a port number, strip it
        if (n > 1) {
            split(addr, parts, ":")
            # Find actual number of parts
            for (i = 1; i in parts; i++) {}
            i--
            if (i > 1) {
                last = parts[i]
                if (match(last, /^[0-9]+$/) && int(last) < 65536 && int(last) > 0) {
                    # Likely a port, remove it
                    result = ""
                    for (j = 1; j < i; j++) {
                        if (j > 1) result = result ":"
                        result = result parts[j]
                    }
                    return result
                }
            }
            return addr
        }
        
        return addr
    }
    
    function format_epoch(epoch,    days, secs, y, mo, d, H, M, S, leap, dom) {
        # Convert epoch to UTC ISO timestamp (simplified)
        # This is a basic implementation for output formatting
        secs = epoch
        days = int(secs / 86400)
        secs = secs % 86400
        H = int(secs / 3600)
        secs = secs % 3600
        M = int(secs / 60)
        S = secs % 60
        
        # Calculate year/month/day from days since epoch
        y = 1970
        while (1) {
            leap = (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)) ? 1 : 0
            if (days < 365 + leap) break
            days -= 365 + leap
            y++
        }
        
        # Month lengths
        split("31,28,31,30,31,30,31,31,30,31,30,31", dom, ",")
        if (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)) dom[2] = 29
        
        mo = 1
        while (mo <= 12 && days >= dom[mo]) {
            days -= dom[mo]
            mo++
        }
        d = days + 1
        
        return sprintf("%04d-%02d-%02dT%02d:%02d:%02dZ", y, mo, d, H, M, S)
    }
    
    {
        type = $1
        ts_str = $2
        remote = $3
        
        # Parse timestamp
        epoch = iso_to_epoch(ts_str)
        if (epoch < cutoff) next
        
        # Normalize IP
        ip = normalize_ip(remote)
        if (ip == "") next
        
        # Track per IP
        if (type == "C") {
            conn_count[ip]++
            if (!(ip in first_seen) || epoch < first_seen[ip]) first_seen[ip] = epoch
            if (!(ip in last_seen) || epoch > last_seen[ip]) last_seen[ip] = epoch
        } else if (type == "M") {
            meta_count[ip]++
            if (!(ip in first_seen) || epoch < first_seen[ip]) first_seen[ip] = epoch
            if (!(ip in last_seen) || epoch > last_seen[ip]) last_seen[ip] = epoch
        } else if (type == "D") {
            disc_count[ip]++
        }
    }
    
    END {
        # Calculate metrics and classify
        for (ip in conn_count) {
            cc = conn_count[ip]
            mc = (ip in meta_count) ? meta_count[ip] : 0
            dc = (ip in disc_count) ? disc_count[ip] : 0
            
            # Metadata rate
            meta_rate = (cc > 0) ? mc / cc : 0
            
            # Burst rate (connections per minute)
            duration = last_seen[ip] - first_seen[ip]
            if (duration < 1) duration = 1
            burst_rate = cc / (duration / 60)
            
            # Risk classification
            if (cc >= conn_thresh) {
                if (meta_rate < meta_thresh) {
                    if (burst_rate >= burst_thresh) {
                        risk = "HIGH"
                        risk_order = 1
                    } else {
                        risk = "MEDIUM"
                        risk_order = 2
                    }
                } else {
                    risk = "LOW"
                    risk_order = 3
                }
            } else {
                risk = "INFO"
                risk_order = 4
            }
            
            # Format timestamps
            first_ts = format_epoch(first_seen[ip])
            last_ts = format_epoch(last_seen[ip])
            
            printf "%d|%s|%s|%d|%d|%d|%.4f|%.2f|%s|%s\n", \
                risk_order, risk, ip, cc, mc, dc, meta_rate, burst_rate, first_ts, last_ts
        }
    }
    ' | sort -t'|' -k1,1n -k4,4nr | cut -d'|' -f2-
}

# Format and display results
display_results() {
    local results="$1"
    
    if [[ -z "$results" ]]; then
        echo
        info "No connection events found in the specified time window."
        echo
        return 0
    fi
    
    # Count findings by risk level
    local high_count=0
    local medium_count=0
    local low_count=0
    local info_count=0
    
    while IFS='|' read -r risk ip cc mc dc mr br first last; do
        case "$risk" in
            HIGH) ((high_count++)) || true ;;
            MEDIUM) ((medium_count++)) || true ;;
            LOW) ((low_count++)) || true ;;
            INFO) ((info_count++)) || true ;;
        esac
    done <<< "$results"
    
    echo
    echo -e "${BOLD}╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}║                              MongoBleed (CVE-2025-14847) Detection Results                                       ║${RESET}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝${RESET}"
    echo
    echo -e "${BOLD}Analysis Parameters:${RESET}"
    echo "  Time Window:        ${TIME_RANGE_MINUTES} minutes"
    echo "  Connection Thresh:  ${CONNECTION_THRESHOLD}"
    echo "  Burst Rate Thresh:  ${BURST_RATE_THRESHOLD}/min"
    echo "  Metadata Rate:      ${METADATA_RATE_THRESHOLD}"
    echo
    
    # Print table header
    printf "${BOLD}%-8s %-40s %10s %10s %10s %12s %14s %-22s %-22s${RESET}\n" \
        "Risk" "SourceIP" "ConnCount" "MetaCount" "DiscCount" "MetaRate%" "BurstRate/m" "FirstSeen (UTC)" "LastSeen (UTC)"
    printf "%-8s %-40s %10s %10s %10s %12s %14s %-22s %-22s\n" \
        "--------" "----------------------------------------" "----------" "----------" "----------" "------------" "--------------" "----------------------" "----------------------"
    
    # Print results
    while IFS='|' read -r risk ip cc mc dc mr br first last; do
        local color=""
        case "$risk" in
            HIGH) color="$RED" ;;
            MEDIUM) color="$YELLOW" ;;
            LOW) color="$GREEN" ;;
            *) color="" ;;
        esac
        
        # Format metadata rate as percentage
        local mr_pct
        mr_pct=$(awk -v mr="$mr" 'BEGIN { printf "%.2f", mr * 100 }')
        
        printf "${color}%-8s${RESET} %-40s %10d %10d %10d %11s%% %14.2f %-22s %-22s\n" \
            "$risk" "$ip" "$cc" "$mc" "$dc" "$mr_pct" "$br" "$first" "$last"
    done <<< "$results"
    
    echo
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}Summary:${RESET}"
    
    if [[ $high_count -gt 0 ]]; then
        echo -e "  ${RED}HIGH:${RESET}   $high_count source(s) - Likely exploitation detected"
    fi
    if [[ $medium_count -gt 0 ]]; then
        echo -e "  ${YELLOW}MEDIUM:${RESET} $medium_count source(s) - Suspicious activity, investigation recommended"
    fi
    if [[ $low_count -gt 0 ]]; then
        echo -e "  ${GREEN}LOW:${RESET}    $low_count source(s) - High volume but metadata present"
    fi
    if [[ $info_count -gt 0 ]]; then
        echo -e "  INFO:   $info_count source(s) - Normal activity"
    fi
    
    if [[ $high_count -gt 0 || $medium_count -gt 0 ]]; then
        echo
        echo -e "${BOLD}${RED}⚠ IMPORTANT:${RESET} If exploitation is confirmed, patching alone is insufficient."
        echo "  - Rotate all credentials that may have been exposed"
        echo "  - Review accessed data for sensitive information disclosure"
        echo "  - Check for lateral movement from affected systems"
        echo "  - Preserve logs for forensic analysis"
        return 1
    fi
    
    echo
    echo -e "${GREEN}No HIGH or MEDIUM risk findings detected.${RESET}"
    return 0
}

main() {
    check_dependencies
    parse_args "$@"
    
    # Calculate cutoff timestamp
    local now_epoch
    now_epoch=$(date +%s)
    local cutoff_epoch=$((now_epoch - TIME_RANGE_MINUTES * 60))
    
    # Collect log files
    local log_files=()
    while IFS= read -r file; do
        [[ -n "$file" ]] && log_files+=("$file")
    done < <(collect_log_files)
    
    if [[ ${#log_files[@]} -eq 0 ]]; then
        error "No readable log files found matching specified paths."
        echo "Default paths checked: ${DEFAULT_LOG_PATHS[*]}" >&2
        echo "Additional paths: ${ADDITIONAL_PATHS[*]:-none}" >&2
        exit 2
    fi
    
    info "Analyzing ${#log_files[@]} log file(s)..."
    # Format cutoff date (compatible with both GNU and BSD date)
    local cutoff_date
    cutoff_date=$(date -u -d "@$cutoff_epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null) || \
    cutoff_date=$(date -u -r "$cutoff_epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null) || \
    cutoff_date="epoch $cutoff_epoch"
    info "Time window: $cutoff_date to now"
    
    # Run analysis
    local results
    results=$(analyze_logs "$cutoff_epoch" "${log_files[@]}")
    
    # Display results
    if display_results "$results"; then
        exit 0
    else
        exit 1
    fi
}

main "$@"

