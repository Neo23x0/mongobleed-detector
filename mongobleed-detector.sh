#!/usr/bin/env bash
#
# mongobleed-detector.sh
# Offline MongoDB Log Correlation Tool for CVE-2025-14847 (MongoBleed)
#
# Analyzes MongoDB data to identify likely exploitation patterns:
# - Module A: Log correlation (connection events, metadata absence)
# - Module B1: Assert counts analysis (serverStatus.asserts snapshots)
# - Module B2: FTDC spike detection (diagnostic.data time series)
#
# Usage: ./mongobleed-detector.sh [OPTIONS] [PATHS...]
#
# Requirements: bash 4+, jq, awk, gzip (for compressed logs)
#               python3 + pymongo (optional, for FTDC decoding)
#

set -euo pipefail

readonly VERSION="2.0.0"
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default configuration
DEFAULT_LOG_PATHS=("/var/log/mongodb/*.log" "/var/log/mongodb/*.log.*")
TIME_RANGE_MINUTES=4320  # 3 days (72 hours)
CONNECTION_THRESHOLD=100
BURST_RATE_THRESHOLD=400
METADATA_RATE_THRESHOLD=0.10
SPIKE_THRESHOLD=100  # Delta threshold for assert spikes
USER_RATIO_THRESHOLD=250  # Ratio threshold for single-snapshot heuristic

# Runtime state
ADDITIONAL_PATHS=()
SKIP_DEFAULT_PATHS=false
FORENSIC_DIR=""
DATA_DIR=""  # collected-data directory for auto-discovery

# Module availability
MODULE_A_AVAILABLE=false
MODULE_B1_AVAILABLE=false
MODULE_B2_AVAILABLE=false

# Module results (for correlation)
MODULE_A_RESULTS=""
MODULE_B1_RESULTS=""
MODULE_B2_SPIKES=""
FTDC_TIME_RANGE=""

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
Offline MongoDB Analysis Tool for CVE-2025-14847 (MongoBleed)

${BOLD}USAGE${RESET}
    ${SCRIPT_NAME} [OPTIONS] [PATHS...]

${BOLD}DESCRIPTION${RESET}
    Analyzes MongoDB data to identify potential MongoBleed exploitation using
    multiple detection modules:

    Module A: Log Correlation
      - Connection events with metadata absence detection
      - Burst rate analysis

    Module B1: Assert Counts
      - serverStatus().asserts snapshot analysis
      - Delta computation between snapshots

    Module B2: FTDC Spike Detection
      - Full-Time Diagnostic Data Capture analysis
      - Time-localized spike detection

${BOLD}OPTIONS${RESET}
    -d, --data-dir <path>   Directory with collected data (auto-discovery mode)
                            Expected structure:
                              <path>/logs/           - MongoDB JSON logs
                              <path>/assert-counts/  - serverStatus asserts JSON
                              <path>/ftdc-files/     - FTDC metrics.* files
    -p, --path <glob>       Additional log path/glob to scan (repeatable)
    -t, --time <minutes>    Lookback window in minutes (default: ${TIME_RANGE_MINUTES})
    -c, --conn-threshold    Connection count threshold (default: ${CONNECTION_THRESHOLD})
    -b, --burst-threshold   Burst rate threshold per minute (default: ${BURST_RATE_THRESHOLD})
    -m, --metadata-rate     Metadata rate threshold 0.0-1.0 (default: ${METADATA_RATE_THRESHOLD})
    --spike-threshold       Assert spike threshold (default: ${SPIKE_THRESHOLD})
    --user-ratio-threshold  User/other assert ratio for single snapshot (default: ${USER_RATIO_THRESHOLD})
    --no-default-paths      Skip default log paths
    --forensic-dir <path>   Analyze subdirectories as separate hosts
    -h, --help              Show this help message
    -v, --version           Show version

${BOLD}AUTO-DISCOVERY MODE${RESET}
    When using --data-dir, the tool automatically detects available data:
      - logs/*.log, logs/*.log.gz      -> Module A (Log Correlation)
      - assert-counts/*.json           -> Module B1 (Assert Counts)
      - ftdc-files/metrics.*           -> Module B2 (FTDC Spikes)

${BOLD}CONFIDENCE LEVELS${RESET}
    HIGH   - FTDC spikes detected AND suspicious logs in same time window
    MEDIUM - FTDC spikes OR suspicious logs (but not correlated)
    LOW    - Only cumulative assert counts without spikes
    INFO   - No significant findings

${BOLD}EXAMPLES${RESET}
    # Auto-discovery mode with collected data
    ${SCRIPT_NAME} --data-dir ./collected-data/

    # Scan default log paths
    ${SCRIPT_NAME}

    # Scan specific directory
    ${SCRIPT_NAME} -p /path/to/logs/*.json

    # Custom thresholds with 24-hour lookback
    ${SCRIPT_NAME} -t 1440 -c 50 -b 300

${BOLD}EXIT CODES${RESET}
    0 - No HIGH or MEDIUM findings
    1 - HIGH or MEDIUM findings detected
    2 - Error (missing dependencies, no data found, etc.)

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
            -d|--data-dir)
                if [[ -z "${2:-}" ]]; then
                    error "Option $1 requires a directory path"
                    exit 2
                fi
                if [[ ! -d "$2" ]]; then
                    error "Data directory not found: $2"
                    exit 2
                fi
                DATA_DIR="$2"
                SKIP_DEFAULT_PATHS=true
                shift 2
                ;;
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
            --spike-threshold)
                if [[ -z "${2:-}" ]] || ! [[ "$2" =~ ^[0-9]+$ ]]; then
                    error "Option $1 requires a positive integer"
                    exit 2
                fi
                SPIKE_THRESHOLD="$2"
                shift 2
                ;;
            --user-ratio-threshold)
                if [[ -z "${2:-}" ]] || ! [[ "$2" =~ ^[0-9]+$ ]]; then
                    error "Option $1 requires a positive integer"
                    exit 2
                fi
                USER_RATIO_THRESHOLD="$2"
                shift 2
                ;;
            --no-default-paths)
                SKIP_DEFAULT_PATHS=true
                shift
                ;;
            --forensic-dir)
                if [[ -z "${2:-}" ]]; then
                    error "Option $1 requires a directory path"
                    exit 2
                fi
                if [[ ! -d "$2" ]]; then
                    error "Forensic directory not found: $2"
                    exit 2
                fi
                FORENSIC_DIR="$2"
                SKIP_DEFAULT_PATHS=true
                shift 2
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
    
    # Handle unbracketed IPv6 with port
    if [[ "$addr" =~ : ]]; then
        local last_segment="${addr##*:}"
        if [[ "$last_segment" =~ ^[0-9]+$ ]] && [[ "$last_segment" -lt 65536 ]]; then
            echo "${addr%:*}"
            return
        fi
        echo "$addr"
        return
    fi
    
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

# Discover available data sources in data directory
discover_data_sources() {
    local data_dir="$1"
    
    # Check for logs
    local log_dir="$data_dir/logs"
    if [[ -d "$log_dir" ]]; then
        local log_count
        log_count=$(find "$log_dir" -maxdepth 1 -type f \( -name "*.log" -o -name "*.log.*" -o -name "*.log*.gz" \) 2>/dev/null | wc -l)
        if [[ $log_count -gt 0 ]]; then
            MODULE_A_AVAILABLE=true
            ADDITIONAL_PATHS+=("$log_dir"/*.log "$log_dir"/*.log.* "$log_dir"/*.log*.gz)
        fi
    fi
    
    # Check for assert-counts
    local assert_dir="$data_dir/assert-counts"
    if [[ -d "$assert_dir" ]]; then
        local assert_count
        assert_count=$(find "$assert_dir" -maxdepth 1 -type f -name "*.json" 2>/dev/null | wc -l)
        if [[ $assert_count -gt 0 ]]; then
            MODULE_B1_AVAILABLE=true
        fi
    fi
    
    # Check for ftdc-files
    local ftdc_dir="$data_dir/ftdc-files"
    if [[ -d "$ftdc_dir" ]]; then
        local ftdc_count
        ftdc_count=$(find "$ftdc_dir" -maxdepth 1 -type f -name "metrics.*" 2>/dev/null | wc -l)
        if [[ $ftdc_count -gt 0 ]]; then
            # Check if we can decode FTDC
            if [[ -f "$SCRIPT_DIR/ftdc-decode.py" ]] && command -v python3 &>/dev/null; then
                MODULE_B2_AVAILABLE=true
            else
                warn "FTDC files found but ftdc-decode.py or python3 not available"
            fi
        fi
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
        return
    fi
    
    # Expand globs and collect files
    for pattern in "${patterns[@]}"; do
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

# Module A: Main log analysis function
analyze_logs() {
    local cutoff_epoch="$1"
    shift
    local log_files=("$@")
    
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
    
    (
        for file in "${log_files[@]}"; do
            read_log_file "$file"
        done
    ) | jq -R -r "$jq_filter" 2>/dev/null | awk -F'|' -v cutoff="$cutoff_epoch" -v conn_thresh="$CONNECTION_THRESHOLD" \
        -v burst_thresh="$BURST_RATE_THRESHOLD" -v meta_thresh="$METADATA_RATE_THRESHOLD" '
    
    function iso_to_epoch(iso,    y, mo, d, H, M, S, epoch, days, tz_pos, tz_sign, tz_h, tz_m, tz_offset, a, jd) {
        if (length(iso) < 19) return 0
        if (substr(iso, 5, 1) != "-" || substr(iso, 8, 1) != "-" || substr(iso, 11, 1) != "T") return 0
        
        y = int(substr(iso, 1, 4))
        mo = int(substr(iso, 6, 2))
        d = int(substr(iso, 9, 2))
        H = int(substr(iso, 12, 2))
        M = int(substr(iso, 15, 2))
        S = int(substr(iso, 18, 2))
        
        a = int((14 - mo) / 12)
        y = y + 4800 - a
        mo = mo + 12 * a - 3
        jd = d + int((153 * mo + 2) / 5) + 365 * y + int(y / 4) - int(y / 100) + int(y / 400) - 32045
        days = jd - 2440588
        
        epoch = days * 86400 + H * 3600 + M * 60 + S
        
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
            if (substr(iso, tz_pos + 3, 1) == ":") {
                tz_m = int(substr(iso, tz_pos + 4, 2))
            } else {
                tz_m = int(substr(iso, tz_pos + 3, 2))
            }
            tz_offset = tz_sign * (tz_h * 3600 + tz_m * 60)
            epoch += tz_offset
        }
        
        return epoch
    }
    
    function normalize_ip(addr,    ip, pos, bracket_end, colon_pos, n, parts, i, last, result) {
        if (substr(addr, 1, 1) == "[") {
            bracket_end = index(addr, "]")
            if (bracket_end > 1) {
                return substr(addr, 2, bracket_end - 2)
            }
        }
        
        n = gsub(/:/, ":", addr)
        
        if (n == 1) {
            colon_pos = index(addr, ":")
            ip = substr(addr, 1, colon_pos - 1)
            if (match(ip, /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/)) {
                return ip
            }
        }
        
        if (n == 0 && match(addr, /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/)) {
            return addr
        }
        
        if (n > 1) {
            split(addr, parts, ":")
            for (i = 1; i in parts; i++) {}
            i--
            if (i > 1) {
                last = parts[i]
                if (match(last, /^[0-9]+$/) && int(last) < 65536 && int(last) > 0) {
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
        secs = epoch
        days = int(secs / 86400)
        secs = secs % 86400
        H = int(secs / 3600)
        secs = secs % 3600
        M = int(secs / 60)
        S = secs % 60
        
        y = 1970
        while (1) {
            leap = (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)) ? 1 : 0
            if (days < 365 + leap) break
            days -= 365 + leap
            y++
        }
        
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
        
        epoch = iso_to_epoch(ts_str)
        if (epoch < cutoff) next
        
        ip = normalize_ip(remote)
        if (ip == "") next
        
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
        for (ip in conn_count) {
            cc = conn_count[ip]
            mc = (ip in meta_count) ? meta_count[ip] : 0
            dc = (ip in disc_count) ? disc_count[ip] : 0
            
            meta_rate = (cc > 0) ? mc / cc : 0
            
            duration = last_seen[ip] - first_seen[ip]
            if (duration < 1) duration = 1
            burst_rate = cc / (duration / 60)
            
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
            
            first_ts = format_epoch(first_seen[ip])
            last_ts = format_epoch(last_seen[ip])
            
            printf "%d|%s|%s|%d|%d|%d|%.4f|%.2f|%s|%s\n", \
                risk_order, risk, ip, cc, mc, dc, meta_rate, burst_rate, first_ts, last_ts
        }
    }
    ' | sort -t'|' -k1,1n -k4,4nr | cut -d'|' -f2-
}

# Module B1: Analyze assert-counts JSON files
analyze_assert_counts() {
    local assert_dir="$1"
    local threshold="$2"
    local ratio_threshold="$3"
    
    # Collect and sort JSON files by timestamp
    local json_files=()
    while IFS= read -r -d '' file; do
        if [[ -f "$file" && -r "$file" ]]; then
            json_files+=("$file")
        fi
    done < <(find "$assert_dir" -maxdepth 1 -type f -name "*.json" -print0 2>/dev/null)
    
    if [[ ${#json_files[@]} -eq 0 ]]; then
        echo "NO_DATA"
        return
    fi
    
    # Parse all JSON files and extract asserts data (including all types for ratio analysis)
    local all_data=""
    for file in "${json_files[@]}"; do
        local data
        data=$(jq -r '
            if .timestamp and .asserts then
                "\(.timestamp)|\(.hostname // "unknown")|\(.asserts.user // 0)|\(.asserts.rollovers // 0)|\(.uptime // 0)|\(.asserts.regular // 0)|\(.asserts.warning // 0)|\(.asserts.msg // 0)|\(.asserts.tripwire // 0)"
            else
                empty
            end
        ' "$file" 2>/dev/null) || continue
        [[ -n "$data" ]] && all_data+="$data"$'\n'
    done
    
    if [[ -z "$all_data" ]]; then
        echo "NO_DATA"
        return
    fi
    
    # Sort by timestamp and compute deltas (filter empty lines first)
    echo "$all_data" | grep -v '^$' | sort -t'|' -k1,1 | awk -F'|' -v threshold="$threshold" -v ratio_thresh="$ratio_threshold" '
    NR == 1 {
        prev_ts = $1
        prev_host = $2
        prev_user = $3
        prev_rollovers = $4
        prev_uptime = $5
        prev_regular = $6
        prev_warning = $7
        prev_msg = $8
        prev_tripwire = $9
        first_ts = $1
        first_user = $3
        next
    }
    {
        ts = $1
        host = $2
        user = $3
        rollovers = $4
        uptime = $5
        
        delta = user - prev_user
        
        if (delta >= threshold) {
            spikes++
            spike_data = spike_data sprintf("SPIKE|%s|%s|%d|%d|%d\n", prev_ts, ts, delta, prev_user, user)
        }
        
        last_ts = ts
        last_user = user
        total_delta = user - first_user
        
        prev_ts = ts
        prev_host = host
        prev_user = user
        prev_rollovers = rollovers
        prev_uptime = uptime
    }
    END {
        if (NR == 1) {
            # Single snapshot - apply ratio-based heuristic
            user = prev_user
            regular = prev_regular
            warning = prev_warning
            msg = prev_msg
            tripwire = prev_tripwire
            
            # Find max of other assert types
            max_other = regular
            if (warning > max_other) max_other = warning
            if (msg > max_other) max_other = msg
            if (tripwire > max_other) max_other = tripwire
            
            # Determine if suspicious based on ratio
            suspicious = 0
            ratio = 0
            if (max_other > 0) {
                ratio = user / max_other
                if (ratio >= ratio_thresh) {
                    suspicious = 1
                }
            } else if (user > 0) {
                # All others are zero but user has value - also suspicious
                suspicious = 1
                ratio = -1  # Special marker for "infinite" ratio
            }
            
            if (suspicious) {
                printf "SINGLE_SUSPICIOUS|%s|%s|%d|%d|%d|%d|%d|%d|%d|%.0f\n", prev_ts, prev_host, user, prev_rollovers, prev_uptime, regular, warning, msg, tripwire, ratio
            } else {
                printf "SINGLE|%s|%s|%d|%d|%d|%d|%d|%d|%d\n", prev_ts, prev_host, user, prev_rollovers, prev_uptime, regular, warning, msg, tripwire
            }
        } else {
            printf "SUMMARY|%d|%s|%s|%d|%d\n", NR, first_ts, last_ts, first_user, last_user
            if (spikes > 0) {
                printf "%s", spike_data
            }
        }
    }
    '
}

# Module B2: Analyze FTDC files using ftdc-decode.py
analyze_ftdc_files() {
    local ftdc_dir="$1"
    local threshold="$2"
    
    local decoder="$SCRIPT_DIR/ftdc-decode.py"
    
    if [[ ! -f "$decoder" ]]; then
        echo "NO_DECODER"
        return
    fi
    
    # Try venv Python first (for pymongo), then system Python
    local python_cmd=""
    if [[ -f "$SCRIPT_DIR/.venv/bin/python3" ]]; then
        python_cmd="$SCRIPT_DIR/.venv/bin/python3"
    elif command -v python3 &>/dev/null; then
        python_cmd="python3"
    else
        echo "NO_PYTHON"
        return
    fi
    
    # Run the decoder with spike detection
    local result
    result=$("$python_cmd" "$decoder" --dir "$ftdc_dir" --detect-spikes --threshold "$threshold" --quiet 2>/dev/null) || {
        echo "DECODE_ERROR"
        return
    }
    
    if [[ -z "$result" ]] || [[ "$result" == "[]" ]]; then
        echo "NO_DATA"
        return
    fi
    
    echo "$result"
}

# Display module status
display_module_status() {
    echo
    echo -e "${BOLD}Module Status:${RESET}"
    
    if [[ "$MODULE_A_AVAILABLE" == true ]]; then
        local log_count
        log_count=$(collect_log_files | wc -l)
        echo -e "  ${GREEN}[✓]${RESET} Module A (Log Correlation): $log_count log file(s) found"
    else
        echo -e "  ${YELLOW}[−]${RESET} Module A (Log Correlation): No log files found"
    fi
    
    if [[ "$MODULE_B1_AVAILABLE" == true ]]; then
        local assert_count
        assert_count=$(find "$DATA_DIR/assert-counts" -maxdepth 1 -type f -name "*.json" 2>/dev/null | wc -l)
        echo -e "  ${GREEN}[✓]${RESET} Module B1 (Assert Counts): $assert_count snapshot(s) found"
    else
        echo -e "  ${YELLOW}[−]${RESET} Module B1 (Assert Counts): No assert-counts found"
    fi
    
    if [[ "$MODULE_B2_AVAILABLE" == true ]]; then
        local ftdc_count
        ftdc_count=$(find "$DATA_DIR/ftdc-files" -maxdepth 1 -type f -name "metrics.*" 2>/dev/null | wc -l)
        echo -e "  ${GREEN}[✓]${RESET} Module B2 (FTDC Spikes): $ftdc_count metrics file(s) found"
    else
        echo -e "  ${YELLOW}[−]${RESET} Module B2 (FTDC Spikes): No FTDC files or decoder unavailable"
    fi
    
    echo
}

# Display combined results with correlation
display_combined_results() {
    local log_results="$1"
    local b1_results="$2"
    local b2_results="$3"
    
    # Parse results
    local log_high=0 log_medium=0 log_suspicious_ips=""
    local b1_spikes=0 b1_summary="" b1_suspicious=false
    local b2_spikes=0 b2_spike_windows=""
    
    # Count log findings
    if [[ -n "$log_results" ]]; then
        while IFS='|' read -r risk ip cc mc dc mr br first last; do
            case "$risk" in
                HIGH) ((log_high++)) || true; log_suspicious_ips+="$ip " ;;
                MEDIUM) ((log_medium++)) || true; log_suspicious_ips+="$ip " ;;
            esac
        done <<< "$log_results"
    fi
    
    # Parse B1 results
    if [[ -n "$b1_results" ]] && [[ "$b1_results" != "NO_DATA" ]]; then
        while IFS='|' read -r type rest; do
            case "$type" in
                SPIKE) ((b1_spikes++)) || true ;;
                SUMMARY) b1_summary="$rest" ;;
                SINGLE_SUSPICIOUS) b1_suspicious=true ;;
            esac
        done <<< "$b1_results"
    fi
    
    # Parse B2 results
    if [[ -n "$b2_results" ]] && [[ "$b2_results" != "NO_"* ]] && [[ "$b2_results" != "DECODE_ERROR" ]]; then
        b2_spikes=$(echo "$b2_results" | jq -r '.spike_count // 0' 2>/dev/null) || b2_spikes=0
        if [[ $b2_spikes -gt 0 ]]; then
            b2_spike_windows=$(echo "$b2_results" | jq -r '.spikes[] | "\(.start_ts) - \(.end_ts) (+\(.delta_user) user asserts)"' 2>/dev/null) || true
        fi
    fi
    
    # Determine combined confidence
    local confidence="INFO"
    local has_log_findings=false
    local has_ftdc_spikes=false
    local has_b1_suspicious=false
    
    [[ $log_high -gt 0 || $log_medium -gt 0 ]] && has_log_findings=true
    [[ $b2_spikes -gt 0 ]] && has_ftdc_spikes=true
    [[ "$b1_suspicious" == true ]] && has_b1_suspicious=true
    
    if [[ "$has_log_findings" == true && "$has_ftdc_spikes" == true ]]; then
        confidence="HIGH"
    elif [[ "$has_log_findings" == true || "$has_ftdc_spikes" == true ]]; then
        confidence="MEDIUM"
    elif [[ "$has_b1_suspicious" == true ]]; then
        # Single snapshot with suspicious ratio pattern
        confidence="MEDIUM"
    elif [[ $b1_spikes -gt 0 ]]; then
        confidence="LOW"
    fi
    
    # Display header
    echo
    echo -e "${BOLD}╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}║                              MongoBleed (CVE-2025-14847) Detection Results                                       ║${RESET}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝${RESET}"
    
    # Display module status if in data-dir mode
    if [[ -n "$DATA_DIR" ]]; then
        display_module_status
    fi
    
    echo -e "${BOLD}Analysis Parameters:${RESET}"
    echo "  Time Window:        ${TIME_RANGE_MINUTES} minutes"
    echo "  Connection Thresh:  ${CONNECTION_THRESHOLD}"
    echo "  Burst Rate Thresh:  ${BURST_RATE_THRESHOLD}/min"
    echo "  Metadata Rate:      ${METADATA_RATE_THRESHOLD}"
    echo "  Spike Threshold:    ${SPIKE_THRESHOLD}"
    echo "  User Ratio Thresh:  ${USER_RATIO_THRESHOLD}x"
    echo
    
    # Display Module A results (log correlation)
    if [[ -n "$log_results" ]]; then
        echo -e "${BOLD}Module A - Log Correlation Findings:${RESET}"
        echo
        printf "${BOLD}%-8s %-40s %10s %10s %10s %12s %14s %-22s %-22s${RESET}\n" \
            "Risk" "SourceIP" "ConnCount" "MetaCount" "DiscCount" "MetaRate%" "BurstRate/m" "FirstSeen (UTC)" "LastSeen (UTC)"
        printf "%-8s %-40s %10s %10s %10s %12s %14s %-22s %-22s\n" \
            "--------" "----------------------------------------" "----------" "----------" "----------" "------------" "--------------" "----------------------" "----------------------"
        
        while IFS='|' read -r risk ip cc mc dc mr br first last; do
            local color=""
            case "$risk" in
                HIGH) color="$RED" ;;
                MEDIUM) color="$YELLOW" ;;
                LOW) color="$GREEN" ;;
                *) color="" ;;
            esac
            
            local mr_pct
            mr_pct=$(awk -v mr="$mr" 'BEGIN { printf "%.2f", mr * 100 }')
            
            printf "${color}%-8s${RESET} %-40s %10d %10d %10d %11s%% %14.2f %-22s %-22s\n" \
                "$risk" "$ip" "$cc" "$mc" "$dc" "$mr_pct" "$br" "$first" "$last"
        done <<< "$log_results"
        echo
    else
        echo -e "${BOLD}Module A - Log Correlation:${RESET} No connection events found"
        echo
    fi
    
    # Display Module B1 results (assert counts)
    if [[ -n "$b1_results" ]] && [[ "$b1_results" != "NO_DATA" ]]; then
        echo -e "${BOLD}Module B1 - Assert Counts Analysis:${RESET}"
        
        while IFS='|' read -r type rest; do
            case "$type" in
                SINGLE)
                    IFS='|' read -r ts host user rollovers uptime regular warning msg tripwire <<< "$rest"
                    echo "  Single snapshot (no baseline for comparison)"
                    echo "    Timestamp:   $ts"
                    echo "    Hostname:    $host"
                    echo "    asserts.user:     $user"
                    echo "    asserts.regular:  $regular"
                    echo "    asserts.warning:  $warning"
                    echo "    asserts.msg:      $msg"
                    echo "    asserts.tripwire: $tripwire"
                    echo "    rollovers:        $rollovers"
                    echo "    uptime:           ${uptime}s"
                    ;;
                SINGLE_SUSPICIOUS)
                    IFS='|' read -r ts host user rollovers uptime regular warning msg tripwire ratio <<< "$rest"
                    echo -e "  ${RED}⚠ SUSPICIOUS PATTERN DETECTED${RESET}"
                    echo "    Timestamp:   $ts"
                    echo "    Hostname:    $host"
                    echo "    asserts.user:     $user"
                    echo "    asserts.regular:  $regular"
                    echo "    asserts.warning:  $warning"
                    echo "    asserts.msg:      $msg"
                    echo "    asserts.tripwire: $tripwire"
                    if [[ "$ratio" == "-1" ]]; then
                        echo -e "    ${RED}Ratio: user asserts present with ALL other types at zero${RESET}"
                    else
                        echo -e "    ${RED}Ratio: user is ${ratio}x higher than max other type (threshold: ${USER_RATIO_THRESHOLD}x)${RESET}"
                    fi
                    echo "    This pattern is consistent with MongoBleed exploitation"
                    ;;
                SUMMARY)
                    IFS='|' read -r count first_ts last_ts first_user last_user <<< "$rest"
                    echo "  Analyzed $count snapshots from $first_ts to $last_ts"
                    echo "    asserts.user: $first_user -> $last_user (delta: $((last_user - first_user)))"
                    ;;
                SPIKE)
                    IFS='|' read -r start_ts end_ts delta prev_user curr_user <<< "$rest"
                    echo -e "  ${RED}SPIKE DETECTED:${RESET} $start_ts to $end_ts"
                    echo "    Delta: +$delta user asserts ($prev_user -> $curr_user)"
                    ;;
            esac
        done <<< "$b1_results"
        echo
    fi
    
    # Display Module B2 results (FTDC spikes)
    if [[ -n "$b2_results" ]] && [[ "$b2_results" != "NO_"* ]] && [[ "$b2_results" != "DECODE_ERROR" ]]; then
        echo -e "${BOLD}Module B2 - FTDC Spike Detection:${RESET}"
        
        local total_samples time_start time_end
        total_samples=$(echo "$b2_results" | jq -r '.total_samples // 0' 2>/dev/null)
        time_start=$(echo "$b2_results" | jq -r '.time_range.start // "unknown"' 2>/dev/null)
        time_end=$(echo "$b2_results" | jq -r '.time_range.end // "unknown"' 2>/dev/null)
        
        echo "  Analyzed $total_samples FTDC samples"
        echo "  Time range: $time_start to $time_end"
        
        if [[ $b2_spikes -gt 0 ]]; then
            echo -e "  ${RED}$b2_spikes spike(s) detected:${RESET}"
            echo "$b2_results" | jq -r '.spikes[] | "    \(.start_ts) - \(.end_ts): +\(.delta_user) user asserts"' 2>/dev/null
        else
            echo "  No spikes detected (threshold: $SPIKE_THRESHOLD)"
        fi
        echo
    elif [[ "$b2_results" == "DECODE_ERROR" ]]; then
        echo -e "${BOLD}Module B2 - FTDC Spike Detection:${RESET}"
        echo -e "  ${YELLOW}Warning: FTDC decoding failed. Install pymongo: pip install pymongo${RESET}"
        echo
    fi
    
    # Combined verdict
    echo -e "${BOLD}═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}Combined Verdict:${RESET}"
    
    case "$confidence" in
        HIGH)
            echo -e "  ${RED}${BOLD}HIGH CONFIDENCE${RESET} - Exploitation likely"
            echo "    - FTDC spikes detected AND suspicious connection patterns found"
            if [[ -n "$b2_spike_windows" ]]; then
                echo "    - Spike windows:"
                echo "$b2_spike_windows" | sed 's/^/      /'
            fi
            if [[ -n "$log_suspicious_ips" ]]; then
                echo "    - Suspicious IPs: $log_suspicious_ips"
            fi
            ;;
        MEDIUM)
            echo -e "  ${YELLOW}${BOLD}MEDIUM CONFIDENCE${RESET} - Investigation recommended"
            if [[ "$has_ftdc_spikes" == true ]]; then
                echo "    - FTDC spikes detected but log correlation unavailable/inconclusive"
            elif [[ "$has_log_findings" == true ]]; then
                echo "    - Suspicious connection patterns but FTDC data unavailable for correlation"
            elif [[ "$has_b1_suspicious" == true ]]; then
                echo "    - Suspicious assert ratio: user asserts disproportionately high vs other types"
                echo "    - Pattern is consistent with MongoBleed exploitation"
            fi
            ;;
        LOW)
            echo -e "  ${GREEN}LOW CONFIDENCE${RESET} - Anomalies detected, no strong indicators"
            echo "    - Assert count spikes found but no corroborating evidence"
            ;;
        *)
            echo -e "  ${GREEN}INFO${RESET} - No significant indicators of exploitation"
            ;;
    esac
    
    # Important caveats and recommendations
    if [[ "$confidence" == "HIGH" || "$confidence" == "MEDIUM" ]]; then
        echo
        echo -e "${BOLD}${RED}⚠ IMPORTANT:${RESET} If exploitation is confirmed, patching alone is insufficient."
        echo "  - Rotate all credentials that may have been exposed"
        echo "  - Review accessed data for sensitive information disclosure"
        echo "  - Check for lateral movement from affected systems"
        echo "  - Preserve logs for forensic analysis"
    fi
    
    # Caveats
    echo
    echo -e "${BOLD}Caveats:${RESET}"
    echo "  - Connection metadata absence is PoC-specific and can be evaded"
    echo "  - Assertion counters are cumulative - false positives possible without baseline"
    echo "  - FTDC provides timing but not perfect attribution"
    echo "  - Patch + rotate secrets remains mandatory regardless of detection results"
    echo
    
    # Return exit code based on confidence
    case "$confidence" in
        HIGH|MEDIUM) return 1 ;;
        *) return 0 ;;
    esac
}

# Format and display results (legacy mode - logs only)
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
    
    printf "${BOLD}%-8s %-40s %10s %10s %10s %12s %14s %-22s %-22s${RESET}\n" \
        "Risk" "SourceIP" "ConnCount" "MetaCount" "DiscCount" "MetaRate%" "BurstRate/m" "FirstSeen (UTC)" "LastSeen (UTC)"
    printf "%-8s %-40s %10s %10s %10s %12s %14s %-22s %-22s\n" \
        "--------" "----------------------------------------" "----------" "----------" "----------" "------------" "--------------" "----------------------" "----------------------"
    
    while IFS='|' read -r risk ip cc mc dc mr br first last; do
        local color=""
        case "$risk" in
            HIGH) color="$RED" ;;
            MEDIUM) color="$YELLOW" ;;
            LOW) color="$GREEN" ;;
            *) color="" ;;
        esac
        
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

# Analyze forensic directory with hostname subfolders
analyze_forensic_dir() {
    local forensic_dir="$1"
    local cutoff_epoch="$2"
    local all_results=""
    local host_count=0
    
    for host_dir in "$forensic_dir"/*/; do
        [[ -d "$host_dir" ]] || continue
        
        local hostname
        hostname=$(basename "$host_dir")
        
        local log_files=()
        while IFS= read -r -d '' file; do
            if [[ -f "$file" && -r "$file" ]]; then
                log_files+=("$file")
            fi
        done < <(find "$host_dir" -maxdepth 1 -type f \( -name "*.log" -o -name "*.log.*" -o -name "*.log*.gz" \) -print0 2>/dev/null)
        
        if [[ ${#log_files[@]} -eq 0 ]]; then
            warn "No log files found in $host_dir"
            continue
        fi
        
        ((host_count++)) || true
        info "Analyzing $hostname (${#log_files[@]} file(s))..."
        
        local host_results
        host_results=$(analyze_logs "$cutoff_epoch" "${log_files[@]}")
        
        if [[ -n "$host_results" ]]; then
            while IFS= read -r line; do
                all_results+="${hostname}|${line}"$'\n'
            done <<< "$host_results"
        fi
    done
    
    if [[ $host_count -eq 0 ]]; then
        error "No host subdirectories found in $forensic_dir"
        exit 2
    fi
    
    info "Analyzed $host_count host(s)"
    
    if [[ -n "$all_results" ]]; then
        echo "$all_results" | awk -F'|' '{
            risk = $2
            if (risk == "HIGH") order = 1
            else if (risk == "MEDIUM") order = 2
            else if (risk == "LOW") order = 3
            else order = 4
            print order "|" $0
        }' | sort -t'|' -k1,1n -k2,2 -k5,5nr | cut -d'|' -f2-
    fi
}

# Display results with hostname column (forensic mode)
display_forensic_results() {
    local results="$1"
    
    if [[ -z "$results" ]]; then
        echo
        info "No connection events found in the specified time window."
        echo
        return 0
    fi
    
    local high_count=0
    local medium_count=0
    local low_count=0
    local info_count=0
    
    while IFS='|' read -r hostname risk ip cc mc dc mr br first last; do
        case "$risk" in
            HIGH) ((high_count++)) || true ;;
            MEDIUM) ((medium_count++)) || true ;;
            LOW) ((low_count++)) || true ;;
            INFO) ((info_count++)) || true ;;
        esac
    done <<< "$results"
    
    echo
    echo -e "${BOLD}╔════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}║                              MongoBleed (CVE-2025-14847) Forensic Analysis Results                                                 ║${RESET}"
    echo -e "${BOLD}╚════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝${RESET}"
    echo
    echo -e "${BOLD}Analysis Parameters:${RESET}"
    echo "  Time Window:        ${TIME_RANGE_MINUTES} minutes"
    echo "  Connection Thresh:  ${CONNECTION_THRESHOLD}"
    echo "  Burst Rate Thresh:  ${BURST_RATE_THRESHOLD}/min"
    echo "  Metadata Rate:      ${METADATA_RATE_THRESHOLD}"
    echo
    
    printf "${BOLD}%-20s %-8s %-30s %10s %10s %10s %12s %14s %-20s %-20s${RESET}\n" \
        "Hostname" "Risk" "SourceIP" "ConnCount" "MetaCount" "DiscCount" "MetaRate%" "BurstRate/m" "FirstSeen" "LastSeen"
    printf "%-20s %-8s %-30s %10s %10s %10s %12s %14s %-20s %-20s\n" \
        "--------------------" "--------" "------------------------------" "----------" "----------" "----------" "------------" "--------------" "--------------------" "--------------------"
    
    while IFS='|' read -r hostname risk ip cc mc dc mr br first last; do
        [[ -z "$hostname" || -z "$risk" ]] && continue
        
        local color=""
        case "$risk" in
            HIGH) color="$RED" ;;
            MEDIUM) color="$YELLOW" ;;
            LOW) color="$GREEN" ;;
            *) color="" ;;
        esac
        
        local mr_pct
        mr_pct=$(awk -v mr="$mr" 'BEGIN { printf "%.2f", mr * 100 }')
        
        local disp_hostname="${hostname:0:20}"
        local disp_ip="${ip:0:30}"
        
        printf "%-20s ${color}%-8s${RESET} %-30s %10d %10d %10d %11s%% %14.2f %-20s %-20s\n" \
            "$disp_hostname" "$risk" "$disp_ip" "$cc" "$mc" "$dc" "$mr_pct" "$br" "$first" "$last"
    done <<< "$results"
    
    echo
    echo -e "${BOLD}════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}Summary:${RESET}"
    
    if [[ $high_count -gt 0 ]]; then
        echo -e "  ${RED}HIGH:${RESET}   $high_count finding(s) - Likely exploitation detected"
    fi
    if [[ $medium_count -gt 0 ]]; then
        echo -e "  ${YELLOW}MEDIUM:${RESET} $medium_count finding(s) - Suspicious activity, investigation recommended"
    fi
    if [[ $low_count -gt 0 ]]; then
        echo -e "  ${GREEN}LOW:${RESET}    $low_count finding(s) - High volume but metadata present"
    fi
    if [[ $info_count -gt 0 ]]; then
        echo -e "  INFO:   $info_count finding(s) - Normal activity"
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
    
    local cutoff_date
    cutoff_date=$(date -u -d "@$cutoff_epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null) || \
    cutoff_date=$(date -u -r "$cutoff_epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null) || \
    cutoff_date="epoch $cutoff_epoch"
    
    # Auto-discovery mode with data directory
    if [[ -n "$DATA_DIR" ]]; then
        info "Auto-discovery mode: analyzing $DATA_DIR"
        info "Time window: $cutoff_date to now"
        
        discover_data_sources "$DATA_DIR"
        
        local log_results=""
        local b1_results=""
        local b2_results=""
        
        # Run Module A (Log Correlation)
        if [[ "$MODULE_A_AVAILABLE" == true ]]; then
            local log_files=()
            while IFS= read -r file; do
                [[ -n "$file" ]] && log_files+=("$file")
            done < <(collect_log_files)
            
            if [[ ${#log_files[@]} -gt 0 ]]; then
                info "Module A: Analyzing ${#log_files[@]} log file(s)..."
                log_results=$(analyze_logs "$cutoff_epoch" "${log_files[@]}")
            fi
        fi
        
        # Run Module B1 (Assert Counts)
        if [[ "$MODULE_B1_AVAILABLE" == true ]]; then
            info "Module B1: Analyzing assert-counts..."
            b1_results=$(analyze_assert_counts "$DATA_DIR/assert-counts" "$SPIKE_THRESHOLD" "$USER_RATIO_THRESHOLD")
        fi
        
        # Run Module B2 (FTDC Spikes)
        if [[ "$MODULE_B2_AVAILABLE" == true ]]; then
            info "Module B2: Analyzing FTDC files..."
            b2_results=$(analyze_ftdc_files "$DATA_DIR/ftdc-files" "$SPIKE_THRESHOLD")
        fi
        
        # Display combined results
        if display_combined_results "$log_results" "$b1_results" "$b2_results"; then
            exit 0
        else
            exit 1
        fi
    fi
    
    # Handle forensic mode
    if [[ -n "$FORENSIC_DIR" ]]; then
        info "Forensic mode: analyzing subdirectories in $FORENSIC_DIR"
        info "Time window: $cutoff_date to now"
        
        local results
        results=$(analyze_forensic_dir "$FORENSIC_DIR" "$cutoff_epoch")
        
        if display_forensic_results "$results"; then
            exit 0
        else
            exit 1
        fi
    fi
    
    # Standard mode: collect log files
    local log_files=()
    while IFS= read -r file; do
        [[ -n "$file" ]] && log_files+=("$file")
    done < <(collect_log_files)
    
    if [[ ${#log_files[@]} -eq 0 ]]; then
        error "No readable log files found matching specified paths."
        echo "Default paths checked: ${DEFAULT_LOG_PATHS[*]}" >&2
        echo "Additional paths: ${ADDITIONAL_PATHS[*]:-none}" >&2
        echo "" >&2
        echo "Tip: Use --data-dir to specify a directory with collected data:" >&2
        echo "  $SCRIPT_NAME --data-dir ./collected-data/" >&2
        exit 2
    fi
    
    info "Analyzing ${#log_files[@]} log file(s)..."
    info "Time window: $cutoff_date to now"
    
    local results
    results=$(analyze_logs "$cutoff_epoch" "${log_files[@]}")
    
    if display_results "$results"; then
        exit 0
    else
        exit 1
    fi
}

main "$@"
