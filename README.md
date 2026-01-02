# MongoBleed Detector

**Offline MongoDB Analysis Tool for CVE-2025-14847 (MongoBleed)**

A standalone Linux command-line tool that analyzes MongoDB data to identify likely exploitation of CVE-2025-14847 using multiple detection modules.

## Table of Contents

- [Overview](#overview)
- [Detection Modules](#detection-modules)
- [Requirements](#requirements)
- [Installation](#installation)
- [Two Modes of Operation](#two-modes-of-operation)
- [Mode 1: Local Analysis](#mode-1-local-analysis)
- [Mode 2: Remote Collection](#mode-2-remote-collection)
- [Command-Line Options](#command-line-options)
- [Confidence Levels](#confidence-levels)
- [Example Output](#example-output)
- [Testing](#testing)
- [Caveats & Limitations](#caveats--limitations)
- [References & Credits](#references--credits)
- [License](#license)

## Overview

MongoBleed (CVE-2025-14847) is a memory disclosure vulnerability in MongoDB's zlib decompression that allows attackers to extract sensitive data—credentials, session tokens, PII—directly from server memory without authentication.

This tool helps incident responders detect exploitation attempts using multiple evidence sources:

- **Module A**: Log correlation (connection events, metadata absence)
- **Module B1**: Assert counts analysis (serverStatus.asserts snapshots)
- **Module B2**: FTDC spike detection (diagnostic.data time series)

### Key Features

- **Multi-Module Detection** - Correlates multiple data sources for higher confidence
- **Offline & Agentless** - No network connectivity required during analysis
- **Auto-Discovery** - Automatically detects available data sources
- **Remote Collection** - Collects data from multiple hosts via SSH
- **Combined Scoring** - HIGH/MEDIUM/LOW confidence verdicts
- **Streaming Processing** - Handles large log files efficiently

## Detection Modules

### Module A: Log Correlation

Analyzes MongoDB JSON logs to detect exploitation patterns:

| Event ID | Type | Description |
|----------|------|-------------|
| 22943 | Connection Accepted | Logged when a client connects |
| 51800 | Client Metadata | Logged when a client sends driver/application info |
| 22944 | Connection Closed | Logged when a client disconnects |

**Key insight**: Legitimate MongoDB drivers always send client metadata. The MongoBleed exploit connects, extracts memory, and disconnects—but never sends metadata.

### Module B1: Assert Counts

Analyzes snapshots of `db.serverStatus().asserts` to detect unusual spikes in `asserts.user` counters. While cumulative counters can produce false positives, comparing multiple snapshots allows detection of exploitation bursts.

### Module B2: FTDC Spike Detection

Analyzes MongoDB's Full-Time Diagnostic Data Capture (FTDC) files to detect time-localized spikes in assertion counters. FTDC samples serverStatus periodically, enabling precise timing of potential attacks.

## Requirements

### Shell Script (mongobleed-detector.sh)

- Linux or macOS (bash 4+)
- `jq` - JSON processor
- `awk` (gawk recommended)
- `gzip` - For compressed log support

### Python Components (optional, for FTDC decoding)

- Python 3.8+
- `pymongo` - For FTDC file decoding

### Remote Scanner (mongobleed-remote.py)

- Python 3.8+
- Native SSH client (`ssh`, `scp` commands)
- No additional Python packages required for basic operation

### Install Dependencies

```bash
# Shell script dependencies
# Debian/Ubuntu
apt-get install jq gawk gzip

# RHEL/CentOS/Fedora
dnf install jq gawk gzip

# macOS
brew install jq gawk

# Python dependencies (for FTDC decoding)
pip install -r requirements.txt
```

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/mongobleed-detector.git
cd mongobleed-detector

# Make scripts executable
chmod +x mongobleed-detector.sh
chmod +x mongobleed-remote.py
chmod +x ftdc-decode.py

# Install Python dependencies (optional, for FTDC support)
pip install -r requirements.txt
```

## Two Modes of Operation

### Mode 1: Local Analysis

Analyze data that has been manually collected from MongoDB hosts.

### Mode 2: Remote Collection

Automatically collect data from multiple hosts via SSH, then analyze locally.

## Mode 1: Local Analysis

### Step 1: Collect Data

Collect data from your MongoDB hosts and organize it into this structure:

```
./collected-data/
├── logs/                    # MongoDB JSON logs
│   ├── mongod.log
│   ├── mongod.log.1
│   └── mongod.log.2.gz
├── assert-counts/           # serverStatus().asserts snapshots
│   ├── asserts-2025-01-01.json
│   └── asserts-2025-01-02.json
└── ftdc-files/              # FTDC diagnostic.data contents
    ├── metrics.2025-01-02T10-00-00Z-00000
    └── metrics.interim
```

#### Collecting Logs

```bash
# Copy from remote host
scp user@mongohost:/var/log/mongodb/mongod.log* ./collected-data/logs/
```

#### Collecting Assert Counts

Run this command on the MongoDB host (requires mongosh access):

```bash
mongosh --quiet --eval 'JSON.stringify({
  timestamp: new Date().toISOString(),
  hostname: db.hostInfo().system.hostname,
  asserts: db.serverStatus().asserts,
  uptime: db.serverStatus().uptime
})' > asserts-$(date +%Y%m%d-%H%M%S).json
```

Copy the resulting JSON file to `./collected-data/assert-counts/`.

**Tip**: Run this command multiple times (e.g., hourly) to establish a baseline and detect spikes.

#### Collecting FTDC Files

FTDC files are located at:
- **mongod**: `<storage.dbPath>/diagnostic.data/` (commonly `/var/lib/mongodb/diagnostic.data/`)
- **mongos**: Derived from `systemLog.path` (e.g., `/var/log/mongodb/mongos.diagnostic.data/`)

```bash
# Copy FTDC files (may require sudo)
sudo cp /var/lib/mongodb/diagnostic.data/metrics.* ./collected-data/ftdc-files/
```

### Step 2: Run Analysis

```bash
# Auto-discovery mode - analyzes all available data
./mongobleed-detector.sh --data-dir ./collected-data/

# With custom thresholds
./mongobleed-detector.sh --data-dir ./collected-data/ \
    -t 1440 \              # 24-hour lookback
    -c 50 \                # Lower connection threshold
    --spike-threshold 50   # Lower spike threshold
```

### Legacy Mode (Logs Only)

For backward compatibility, you can still analyze logs directly:

```bash
# Scan default paths
./mongobleed-detector.sh

# Scan specific log files
./mongobleed-detector.sh -p /path/to/logs/*.json

# Forensic mode (analyze multiple hosts)
./mongobleed-detector.sh --forensic-dir /evidence/
```

## Mode 2: Remote Collection

Automatically collect data from multiple hosts and analyze:

```bash
# Create hosts file
cat > hosts.txt << EOF
mongo-prod-01.example.com
mongo-prod-02.example.com
mongo-staging.example.com
EOF

# Collect and analyze
./mongobleed-remote.py --hosts-file hosts.txt --user admin --output-dir ./collected-data/
```

### Remote Scanner Options

```bash
# Use specific SSH key
./mongobleed-remote.py --hosts-file hosts.txt --user admin --key ~/.ssh/mongodb_key

# Parallel execution
./mongobleed-remote.py --hosts-file hosts.txt --user admin --parallel 10

# Skip FTDC collection (faster)
./mongobleed-remote.py --hosts-file hosts.txt --user admin --skip-ftdc

# Collect only, analyze later
./mongobleed-remote.py --hosts-file hosts.txt --user admin --collect-only

# Pass SSH options (e.g., jump host)
./mongobleed-remote.py --hosts-file hosts.txt --user admin \
    -o "ProxyJump=bastion.example.com"
```

### What Gets Collected

| Data Type | Source | Destination |
|-----------|--------|-------------|
| Logs | `/var/log/mongodb/mongod.log*` | `<output-dir>/<hostname>/logs/` |
| Assert Counts | `mongosh` command | `<output-dir>/<hostname>/assert-counts/` |
| FTDC Files | `/var/lib/mongodb/diagnostic.data/metrics.*` | `<output-dir>/<hostname>/ftdc-files/` |

## Command-Line Options

### mongobleed-detector.sh

| Option | Description | Default |
|--------|-------------|---------|
| `-d, --data-dir <path>` | Directory with collected data (auto-discovery mode) | - |
| `-p, --path <glob>` | Additional log path/glob (repeatable) | - |
| `-t, --time <minutes>` | Lookback window in minutes | 4320 (3 days) |
| `-c, --conn-threshold` | Connection count threshold | 100 |
| `-b, --burst-threshold` | Burst rate threshold per minute | 400 |
| `-m, --metadata-rate` | Metadata rate threshold (0.0-1.0) | 0.10 |
| `--spike-threshold` | Assert spike threshold | 100 |
| `--no-default-paths` | Skip default log paths | false |
| `--forensic-dir <path>` | Analyze subdirectories as separate hosts | - |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No HIGH or MEDIUM findings |
| 1 | HIGH or MEDIUM findings detected |
| 2 | Error (missing dependencies, no data, etc.) |

## Confidence Levels

The tool provides a combined confidence verdict based on all available evidence:

| Confidence | Criteria | Interpretation |
|------------|----------|----------------|
| **HIGH** | FTDC peaks detected AND suspicious logs in same time window | Strong indicator of exploitation |
| **MEDIUM** | FTDC peaks OR suspicious logs (not correlated) | Investigation recommended |
| **LOW** | Only cumulative assert counts without spikes | Anomaly detected, weak evidence |
| **INFO** | No significant findings | Normal activity |

### Module-Specific Risk Levels

For log correlation (Module A), individual IPs are classified:

| Risk | Criteria |
|------|----------|
| **HIGH** | Connections ≥ threshold, metadata rate < 10%, burst rate ≥ 400/min |
| **MEDIUM** | Connections ≥ threshold, metadata rate < 10%, burst rate < 400/min |
| **LOW** | Connections ≥ threshold, metadata rate ≥ 10% |
| **INFO** | Connections < threshold |

## Example Output

```
INFO: Auto-discovery mode: analyzing ./collected-data/
INFO: Module A: Analyzing 3 log file(s)...
INFO: Module B1: Analyzing assert-counts...

╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                              MongoBleed (CVE-2025-14847) Detection Results                                       ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝

Module Status:
  [✓] Module A (Log Correlation): 3 log file(s) found
  [✓] Module B1 (Assert Counts): 4 snapshot(s) found
  [−] Module B2 (FTDC Spikes): No FTDC files or decoder unavailable

Analysis Parameters:
  Time Window:        4320 minutes
  Connection Thresh:  100
  Burst Rate Thresh:  400/min
  Metadata Rate:      0.10
  Spike Threshold:    100

Module A - Log Correlation Findings:

Risk     SourceIP                                  ConnCount  MetaCount  DiscCount    MetaRate%    BurstRate/m FirstSeen (UTC)        LastSeen (UTC)        
-------- ---------------------------------------- ---------- ---------- ---------- ------------ -------------- ---------------------- ----------------------
HIGH     137.137.137.137                                8172          0       8172        0.00%         490.32 2025-12-27T12:55:52Z   2025-12-27T13:12:32Z  

Module B1 - Assert Counts Analysis:
  Analyzed 4 snapshots from 2025-01-01T10:00:00Z to 2025-01-01T11:30:00Z
    asserts.user: 100 -> 860 (delta: 760)
  SPIKE DETECTED: 2025-01-01T10:30:00Z to 2025-01-01T11:00:00Z
    Delta: +740 user asserts (110 -> 850)

═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
Combined Verdict:
  MEDIUM CONFIDENCE - Investigation recommended
    - Suspicious connection patterns but FTDC data unavailable for correlation

⚠ IMPORTANT: If exploitation is confirmed, patching alone is insufficient.
  - Rotate all credentials that may have been exposed
  - Review accessed data for sensitive information disclosure
  - Check for lateral movement from affected systems
  - Preserve logs for forensic analysis

Caveats:
  - Connection metadata absence is PoC-specific and can be evaded
  - Assertion counters are cumulative - false positives possible without baseline
  - FTDC provides timing but not perfect attribution
  - Patch + rotate secrets remains mandatory regardless of detection results
```

## Testing

The repository includes a test suite to validate the detector.

### Real-World Example Data

The `example-data/` directory contains real data from a MongoDB 8.0.16 instance that was attacked using the MongoBleed PoC:

```
example-data/
├── logs/                    # Real MongoDB logs with attack patterns
│   ├── mongod.log
│   └── mongod.log.1.gz
├── assert-counts/           # Post-attack serverStatus().asserts snapshot
│   └── asserts-post-attack.json
└── ftdc-files/              # Real FTDC diagnostic data files
    └── metrics.*
```

This data shows:
- **16,344 connections** from attacker IP 137.137.137.137 with 0% metadata
- **37,384 user asserts** accumulated during the attack
- **FTDC files** spanning the attack window

### Generate Synthetic Test Data

```bash
./test/generate-test-logs.sh
```

This creates additional synthetic test data with various patterns:
- Log files with HIGH/MEDIUM/LOW/INFO risk patterns
- Assert-counts JSON snapshots (with and without spikes)
- Edge cases (IPv6, malformed input, etc.)

### Run Tests

```bash
./test/test-detector.sh
```

**Expected output:**

```
╔════════════════════════════════════════════════════════╗
║       MongoBleed Detector Test Suite                   ║
╚════════════════════════════════════════════════════════╝

Module A Tests (Log Correlation):
✓ PASS: Exit code is 1 (findings detected)
✓ PASS: Detected source IP 137.137.137.137
...

Module B1 Tests (Assert Counts):
✓ PASS: Shows Module B1 status
✓ PASS: Detected assert spike
...

Auto-Discovery Mode Tests:
✓ PASS: Shows Module A status
✓ PASS: Shows combined verdict
...

Results:
  Passed: 24
  Failed: 0

All tests passed!
```

## Caveats & Limitations

> **⚠️ Important Limitations**

### Detection Limitations

1. **PoC-Specific Detection**: The metadata absence detection is based on the known MongoBleed PoC behavior. A sophisticated attacker could modify the exploit to send fake metadata, though this would reduce exploitation speed.

2. **Cumulative Counters**: `asserts.user` is cumulative since mongod restart. Without baseline snapshots, high values may be normal for long-running instances. Multiple snapshots over time significantly improve accuracy.

3. **FTDC Timing**: FTDC provides timing information but not perfect attribution. Use in conjunction with log correlation for best results.

4. **Log Retention**: Can only analyze logs that exist. Aggressive rotation or attacker log clearing will destroy evidence.

### Technical Requirements

1. **JSON Logging Required**: MongoDB 4.4+ defaults to JSON logs. Legacy text logs are not supported.

2. **FTDC Decoder**: FTDC decoding requires Python 3 with pymongo. Without it, Module B2 is unavailable.

3. **mongosh Access**: Collecting assert counts requires mongosh with appropriate permissions.

### Post-Detection Actions

If HIGH or MEDIUM findings are confirmed:

1. **Preserve Evidence** - Copy logs before they rotate
2. **Credential Rotation** - Rotate all MongoDB credentials and any secrets that may have been in memory
3. **Data Review** - Assess what sensitive data may have been exposed
4. **Lateral Movement** - Check for attacker movement to other systems
5. **Patch Immediately** - Apply MongoDB security updates
6. **Report** - Follow your incident response procedures

## References & Credits

### Detection Research

The detection logic in this tool is based on research by **Eric Capuano** and **Tamir Zimerman**:

- [Hunting MongoBleed (CVE-2025-14847)](https://blog.ecapuano.com/p/hunting-mongobleed-cve-2025-14847) - Eric Capuano's writeup on the vulnerability and detection methodology
- [A Different MongoBleed Perspective](https://medium.com/@ant1d0t3/a-different-mongobleed-perspective-5f08b4bf887a) - Tamir Zimerman's analysis of assertion-based detection

### MongoDB Documentation

- [serverStatus Command](https://www.mongodb.com/docs/v7.0/reference/command/serverstatus/) - asserts field documentation
- [Full Time Diagnostic Data Capture](https://www.mongodb.com/docs/manual/administration/full-time-diagnostic-data-capture/) - FTDC storage locations
- [What is MongoDB FTDC](https://www.alexbevi.com/blog/2020/01/26/what-is-mongodb-ftdc-aka-diagnostic-dot-data/) - FTDC format background

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

## License

See [LICENSE](LICENSE) file.

## Contributing

Contributions welcome! Please submit issues and pull requests.

If you test this tool against production data, we'd especially appreciate feedback on:
- False positive rates
- Legitimate traffic patterns
- Edge cases or parsing failures
- FTDC decoding issues
