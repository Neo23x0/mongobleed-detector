# MongoBleed Detector

**Offline MongoDB Log Correlation Tool for CVE-2025-14847 (MongoBleed)**

A standalone Linux command-line script that analyzes MongoDB JSON logs locally and identifies likely exploitation of CVE-2025-14847.

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Example](#example)
- [Multi-Host Analysis](#multi-host-analysis)
- [Risk Classification](#risk-classification)
- [Testing](#testing)
- [Disclaimer](#disclaimer)
- [References & Credits](#references--credits)
- [License](#license)

## Overview

MongoBleed (CVE-2025-14847) is a memory disclosure vulnerability in MongoDB's zlib decompression that allows attackers to extract sensitive data—credentials, session tokens, PII—directly from server memory without authentication.

This tool helps incident responders detect exploitation attempts by analyzing MongoDB logs for the characteristic attack pattern:

- **High connection volume** from a single source IP
- **Absence of client metadata** (legitimate clients always send metadata)
- **Short-duration burst behavior** (100,000+ connections per minute)

### Features

- **Offline & Agentless** - No network connectivity, no agents, no SIEM required
- **Streaming Processing** - Handles large log files without loading into memory
- **Compressed Log Support** - Transparently processes `.gz` rotated logs
- **IPv4 & IPv6** - Full support for both address formats
- **Configurable Thresholds** - Customize detection sensitivity
- **Risk Classification** - HIGH, MEDIUM, LOW, INFO severity levels
- **Forensic Folder Mode** - Analyze collected evidence from multiple hosts
- **Remote Execution** - Python wrapper for SSH-based scanning of multiple hosts

## How It Works

The tool correlates three MongoDB log event types:

| Event ID | Type | Description |
|----------|------|-------------|
| 22943 | Connection Accepted | Logged when a client connects |
| 51800 | Client Metadata | Logged when a client sends driver/application info |
| 22944 | Connection Closed | Logged when a client disconnects |

**Key insight**: Every legitimate MongoDB driver sends client metadata immediately after connecting. The MongoBleed exploit connects, extracts memory, and disconnects—but never sends metadata.

A source IP with hundreds of connections but zero metadata events is almost certainly exploitation, not legitimate traffic.

## Requirements

### Shell Script (mongobleed-detector.sh)

- Linux or macOS (bash 4+)
- `jq` - JSON processor
- `awk` (gawk recommended)
- `gzip` - For compressed log support

### Python Remote Scanner (mongobleed-remote.py)

- Python 3.8+
- Native SSH client (`ssh`, `scp` commands)
- No additional Python packages required

### Install Dependencies

```bash
# Shell script dependencies
# Debian/Ubuntu
apt-get install jq gawk gzip

# RHEL/CentOS/Fedora
dnf install jq gawk gzip

# macOS
brew install jq gawk

# Python remote scanner has no additional dependencies
# Uses native ssh/scp commands
```

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/mongobleed-detector.git
cd mongobleed-detector

# Make executable
chmod +x mongobleed-detector.sh
```

## Usage

```bash
# Scan default paths (/var/log/mongodb/*.log*)
./mongobleed-detector.sh

# Scan specific log files
./mongobleed-detector.sh -p /path/to/logs/*.json

# Custom time window (7 days)
./mongobleed-detector.sh -t 10080

# Custom thresholds
./mongobleed-detector.sh -c 50 -b 300 -m 0.15

# Analyze forensic copy (skip default paths)
./mongobleed-detector.sh --no-default-paths -p /forensics/mongodb/*.log*

# Analyze collected evidence from multiple hosts (forensic mode)
./mongobleed-detector.sh --forensic-dir /evidence/

# Show help
./mongobleed-detector.sh --help
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-p, --path <glob>` | Additional log path/glob (repeatable) | - |
| `-t, --time <minutes>` | Lookback window in minutes | 4320 (3 days) |
| `-c, --conn-threshold` | Connection count threshold | 100 |
| `-b, --burst-threshold` | Burst rate threshold per minute | 400 |
| `-m, --metadata-rate` | Metadata rate threshold (0.0-1.0) | 0.10 |
| `--no-default-paths` | Skip default log paths | false |
| `--forensic-dir <path>` | Analyze subdirectories as separate hosts | - |
| `-h, --help` | Show help message | - |
| `-v, --version` | Show version | - |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No HIGH or MEDIUM findings |
| 1 | HIGH or MEDIUM findings detected |
| 2 | Error (missing dependencies, no logs, etc.) |

## Example

Running the detector against a log containing exploitation attempts:

```bash
$ ./mongobleed-detector.sh --no-default-paths -p example-logs/mongod.log
```

**Output:**

```
INFO: Analyzing 1 log file(s)...
INFO: Time window: 2025-12-24T13:22:17Z to now

╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                              MongoBleed (CVE-2025-14847) Detection Results                                       ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝

Analysis Parameters:
  Time Window:        4320 minutes
  Connection Thresh:  100
  Burst Rate Thresh:  400/min
  Metadata Rate:      0.10

Risk     SourceIP                                  ConnCount  MetaCount  DiscCount    MetaRate%    BurstRate/m FirstSeen (UTC)        LastSeen (UTC)        
-------- ---------------------------------------- ---------- ---------- ---------- ------------ -------------- ---------------------- ----------------------
HIGH     137.137.137.137                                8172          0       8172        0.00%         490.32 2025-12-27T12:55:52Z   2025-12-27T13:12:32Z  

═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Summary:
  HIGH:   1 source(s) - Likely exploitation detected

⚠ IMPORTANT: If exploitation is confirmed, patching alone is insufficient.
  - Rotate all credentials that may have been exposed
  - Review accessed data for sensitive information disclosure
  - Check for lateral movement from affected systems
  - Preserve logs for forensic analysis
```

The detector identified **8,172 connections** from `137.137.137.137` with **0% metadata rate** and a burst rate of **490 connections/minute**—a clear exploitation signature.

## Multi-Host Analysis

The tool provides two methods for analyzing logs from multiple MongoDB hosts:

### Forensic Folder Mode

When you have collected log files from multiple hosts into a local directory structure, use `--forensic-dir`:

```
/evidence/
├── mongodb-prod-01/
│   ├── mongod.log
│   └── mongod.log.1.gz
├── mongodb-prod-02/
│   └── mongod.log
└── mongodb-staging/
    └── mongod.log
```

```bash
./mongobleed-detector.sh --forensic-dir /evidence/
```

The output includes a `Hostname` column derived from the subdirectory names:

```
Hostname             Risk     SourceIP         ConnCount  MetaCount  ...
-------------------- -------- ---------------- ---------- ----------
mongodb-prod-01      HIGH     137.137.137.137       8172          0  ...
mongodb-prod-02      INFO     10.0.0.1                 5          5  ...
mongodb-staging      MEDIUM   192.168.1.50           200          2  ...
```

### Remote Execution via SSH

For live analysis across multiple hosts, use the Python wrapper:

```bash
# Scan hosts from a file
./mongobleed-remote.py --hosts-file hosts.txt --user admin

# Scan specific hosts
./mongobleed-remote.py --host mongo1.example.com --host mongo2.example.com --user admin

# Use specific SSH key with parallel execution
./mongobleed-remote.py --hosts-file hosts.txt --user admin --key ~/.ssh/mongodb_key --parallel 10

# Pass additional SSH options (e.g., jump host)
./mongobleed-remote.py --hosts-file hosts.txt --user admin -o "ProxyJump=bastion.example.com"
```

The Python wrapper:
- Uses native `ssh` and `scp` commands (no Python dependencies)
- Respects `~/.ssh/config` (host aliases, ProxyJump, etc.)
- Works with ssh-agent automatically
- Copies and executes the detector script remotely
- Aggregates results into a combined table with hostname column
- Supports parallel execution for faster scanning

**hosts.txt format:**
```
mongodb-prod-01.example.com
mongodb-prod-02.example.com
mongodb-staging.example.com
# Comments are ignored
```

## Risk Classification

| Risk | Criteria | Interpretation |
|------|----------|----------------|
| **HIGH** | Connections ≥ threshold, metadata rate < 10%, burst rate ≥ 400/min | Likely active exploitation |
| **MEDIUM** | Connections ≥ threshold, metadata rate < 10%, burst rate < 400/min | Suspicious, investigate further |
| **LOW** | Connections ≥ threshold, metadata rate ≥ 10% | High volume but likely legitimate |
| **INFO** | Connections < threshold | Normal activity |

### Interpreting Results

- **HIGH** - Strong indicator of MongoBleed exploitation. Immediate investigation required.
- **MEDIUM** - Suspicious pattern with missing metadata. Could be misconfigured client or slower exploitation attempt.
- **LOW** - High connection volume but client metadata is present. Likely legitimate but unusual traffic.
- **INFO** - Normal activity below detection thresholds.

## Testing

The repository includes a test suite to validate the detector.

### Generate Test Logs

```bash
./test/generate-test-logs.sh
```

This creates synthetic logs with various patterns:
- `exploit_high.log` - HIGH risk exploitation pattern
- `suspicious_medium.log` - MEDIUM risk pattern
- `highvolume_low.log` - LOW risk (high volume, metadata present)
- `normal_info.log` - INFO risk (normal traffic)
- `ipv6_test.log` - IPv6 address handling
- `malformed_mixed.log` - Malformed line tolerance
- `compressed.log.gz` - Compressed log support

### Run Tests

```bash
./test/test-detector.sh
```

**Expected output:**

```
╔════════════════════════════════════════════════════════╗
║       MongoBleed Detector Test Suite                   ║
╚════════════════════════════════════════════════════════╝

→ Testing: Example log exploitation detection
✓ PASS: Exit code is 1 (findings detected)
✓ PASS: Detected source IP 137.137.137.137
✓ PASS: Classified as HIGH or MEDIUM risk
✓ PASS: Detected 0% metadata rate
✓ PASS: Shows post-exploitation warning

→ Testing: Generated HIGH risk pattern
✓ PASS: Classified 10.0.0.99 as HIGH risk

... (16 tests total)

Results:
  Passed: 16
  Failed: 0

All tests passed!
```

## Disclaimer

> **⚠️ LIMITED TESTING NOTICE**
>
> This tool has been validated against:
> - A nearly empty MongoDB log (startup events only)
> - A log containing confirmed MongoBleed exploitation artifacts
> - Synthetic test data with various attack patterns
>
> **It has NOT been extensively tested against high-volume production MongoDB logs.**
>
> We encourage users to:
> 1. Test this tool against your production logs before relying on it for incident response
> 2. Report false positives or false negatives via GitHub issues
> 3. Share anonymized statistics about legitimate traffic patterns to help improve thresholds
>
> The default thresholds are based on the documented exploit behavior (100,000+ connections/minute with 0% metadata), but your environment may differ.

### Known Limitations

- **JSON logging required** - MongoDB 4.4+ defaults to JSON logs. Legacy text logs are not supported.
- **Log retention matters** - Can only analyze logs that exist. Aggressive rotation or attacker log clearing will destroy evidence.
- **Evasion possible** - A motivated attacker could modify the exploit to send fake metadata, though this would reduce exploitation speed.

## References & Credits

### Detection Research

The detection logic in this tool is based on the excellent research by **Eric Capuano**, who analyzed the MongoBleed exploitation artifacts and identified the key behavioral signature: rapid connections without client metadata.

📖 **[Hunting MongoBleed (CVE-2025-14847)](https://blog.ecapuano.com/p/hunting-mongobleed-cve-2025-14847)** - Eric's detailed writeup on the vulnerability, attack pattern, and detection methodology.

> "Every legitimate MongoDB driver—whether it's PyMongo, the Node.js driver, mongosh, or any other—sends a 'client metadata' message immediately after connecting. The MongoBleed exploit? It connects, does its thing, and disconnects. No metadata. Ever."
>
> — Eric Capuano

### Additional Resources

- [CVE-2025-14847 (MITRE)](https://cve.mitre.org/)
- [Kevin Beaumont's MongoBleed Writeup](https://doublepulsar.com/)
- [mongobleed POC by Joe Desimone](https://github.com/)
- [Ox Security Technical Analysis](https://ox.security/)

### Affected Versions

| Version | Vulnerable | Fixed In |
|---------|------------|----------|
| 8.2.x | 8.2.0 - 8.2.2 | 8.2.3 |
| 8.0.x | 8.0.0 - 8.0.16 | 8.0.17 |
| 7.0.x | 7.0.0 - 7.0.27 | 7.0.28 |
| 6.0.x | 6.0.0 - 6.0.26 | 6.0.27 |
| 5.0.x | 5.0.0 - 5.0.31 | 5.0.32 |
| 4.4.x | 4.4.0 - 4.4.29 | 4.4.30 |
| 4.2.x | 4.2.0+ | No fix |
| 4.0.x | 4.0.0+ | No fix |
| 3.6.x | 3.6.0+ | No fix |

## Post-Detection Actions

If HIGH or MEDIUM findings are confirmed:

1. **Preserve Evidence** - Copy logs before they rotate
2. **Credential Rotation** - Rotate all MongoDB credentials and any secrets that may have been in memory
3. **Data Review** - Assess what sensitive data may have been exposed
4. **Lateral Movement** - Check for attacker movement to other systems
5. **Patch Immediately** - Apply MongoDB security updates
6. **Report** - Follow your incident response procedures

## License

See [LICENSE](LICENSE) file.

## Contributing

Contributions welcome! Please submit issues and pull requests.

If you test this tool against production logs, we'd especially appreciate feedback on:
- False positive rates
- Legitimate traffic patterns (connections/min, metadata rates)
- Any edge cases or parsing failures
