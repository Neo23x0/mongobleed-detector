#!/usr/bin/env python3
"""
mongobleed-remote.py
Remote MongoDB Data Collection and Analysis for CVE-2025-14847 (MongoBleed)

Collects data from multiple remote hosts via SSH:
- MongoDB logs
- serverStatus().asserts snapshots (via mongosh)
- FTDC diagnostic.data files

Then runs mongobleed-detector.sh locally on the collected data.

Uses native SSH - no additional Python dependencies required.
Respects ~/.ssh/config, ssh-agent, and ProxyJump configurations.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


VERSION = "2.0.0"
SCRIPT_DIR = Path(__file__).parent
DETECTOR_SCRIPT = SCRIPT_DIR / "mongobleed-detector.sh"

# Default remote paths
DEFAULT_LOG_PATHS = [
    "/var/log/mongodb/mongod.log",
    "/var/log/mongodb/mongod.log.1",
    "/var/log/mongodb/mongod.log.2.gz",
]
DEFAULT_FTDC_PATHS = [
    "/var/lib/mongodb/diagnostic.data",
    "/data/db/diagnostic.data",
]

# Risk level sort order
RISK_ORDER = {"HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class CollectionResult:
    """Results from collecting data from a single host."""
    hostname: str
    success: bool
    error: Optional[str] = None
    logs_collected: int = 0
    asserts_collected: bool = False
    ftdc_collected: int = 0


@dataclass
class HostResult:
    """Results from analyzing a single host."""
    hostname: str
    success: bool
    error: Optional[str] = None
    findings: list = field(default_factory=list)
    high_count: int = 0
    medium_count: int = 0


@dataclass
class Finding:
    """A single detection finding."""
    hostname: str
    risk: str
    source_ip: str
    conn_count: int
    meta_count: int
    disc_count: int
    meta_rate: str
    burst_rate: str
    first_seen: str
    last_seen: str


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Remote MongoDB Data Collection and Analysis for CVE-2025-14847 (MongoBleed)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Uses native SSH - respects ~/.ssh/config, ssh-agent, and ProxyJump.
No additional Python dependencies required.

This tool operates in two phases:
  1. Collection: Gathers logs, assert-counts, and FTDC files from remote hosts
  2. Analysis: Runs mongobleed-detector.sh locally on collected data

Examples:
    # Collect and analyze data from hosts
    %(prog)s --hosts-file hosts.txt --user admin --output-dir ./collected-data

    # Collect from specific hosts with custom log paths
    %(prog)s --host mongo1 --host mongo2 --user admin --log-path /custom/path/*.log

    # Skip FTDC collection (faster, but less accurate)
    %(prog)s --hosts-file hosts.txt --user admin --skip-ftdc

    # Collect only, don't analyze
    %(prog)s --hosts-file hosts.txt --user admin --collect-only
        """
    )
    
    # Host specification
    host_group = parser.add_argument_group("Host Selection")
    host_group.add_argument(
        "--host", "-H",
        action="append",
        dest="hosts",
        metavar="HOSTNAME",
        help="Remote host to scan (repeatable)"
    )
    host_group.add_argument(
        "--hosts-file", "-f",
        type=Path,
        metavar="FILE",
        help="File containing hostnames (one per line)"
    )
    
    # SSH options
    ssh_group = parser.add_argument_group("SSH Options")
    ssh_group.add_argument(
        "--user", "-u",
        default=os.environ.get("USER", "root"),
        help="SSH username (default: current user)"
    )
    ssh_group.add_argument(
        "--key", "-k",
        type=Path,
        metavar="FILE",
        help="SSH private key file (default: use ssh-agent or default keys)"
    )
    ssh_group.add_argument(
        "--port", "-P",
        type=int,
        default=22,
        help="SSH port (default: 22)"
    )
    ssh_group.add_argument(
        "--ssh-options", "-o",
        action="append",
        dest="ssh_opts",
        metavar="OPTION",
        help="Additional SSH options (repeatable, e.g., -o 'ProxyJump=bastion')"
    )
    
    # Collection options
    collect_group = parser.add_argument_group("Collection Options")
    collect_group.add_argument(
        "--output-dir", "-O",
        type=Path,
        default=Path("./collected-data"),
        help="Directory to store collected data (default: ./collected-data)"
    )
    collect_group.add_argument(
        "--log-path",
        action="append",
        dest="log_paths",
        metavar="PATH",
        help="Remote log path to collect (repeatable)"
    )
    collect_group.add_argument(
        "--ftdc-path",
        action="append",
        dest="ftdc_paths",
        metavar="PATH",
        help="Remote FTDC directory path (repeatable)"
    )
    collect_group.add_argument(
        "--skip-logs",
        action="store_true",
        help="Skip log collection"
    )
    collect_group.add_argument(
        "--skip-asserts",
        action="store_true",
        help="Skip serverStatus().asserts collection"
    )
    collect_group.add_argument(
        "--skip-ftdc",
        action="store_true",
        help="Skip FTDC file collection"
    )
    collect_group.add_argument(
        "--collect-only",
        action="store_true",
        help="Only collect data, don't run analysis"
    )
    
    # Execution options
    exec_group = parser.add_argument_group("Execution Options")
    exec_group.add_argument(
        "--parallel", "-j",
        type=int,
        default=5,
        metavar="N",
        help="Number of parallel connections (default: 5)"
    )
    exec_group.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="SSH command timeout in seconds (default: 300)"
    )
    
    # Detector options (passed through to shell script)
    detector_group = parser.add_argument_group("Detector Options")
    detector_group.add_argument(
        "--time", "-t",
        type=int,
        default=4320,
        metavar="MINUTES",
        help="Lookback window in minutes (default: 4320 = 3 days)"
    )
    detector_group.add_argument(
        "--conn-threshold", "-c",
        type=int,
        default=100,
        help="Connection count threshold (default: 100)"
    )
    detector_group.add_argument(
        "--burst-threshold", "-b",
        type=int,
        default=400,
        help="Burst rate threshold per minute (default: 400)"
    )
    detector_group.add_argument(
        "--metadata-rate", "-m",
        type=float,
        default=0.10,
        help="Metadata rate threshold (default: 0.10)"
    )
    detector_group.add_argument(
        "--spike-threshold",
        type=int,
        default=100,
        help="Assert spike threshold (default: 100)"
    )
    
    # Output options
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress messages"
    )
    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"%(prog)s {VERSION}"
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.hosts and not args.hosts_file:
        parser.error("At least one of --host or --hosts-file is required")
    
    if not DETECTOR_SCRIPT.exists():
        parser.error(f"Detector script not found: {DETECTOR_SCRIPT}")
    
    # Check that ssh and scp are available
    if not shutil.which("ssh"):
        parser.error("ssh command not found in PATH")
    if not shutil.which("scp"):
        parser.error("scp command not found in PATH")
    
    # Set default paths if not specified
    if not args.log_paths:
        args.log_paths = DEFAULT_LOG_PATHS
    if not args.ftdc_paths:
        args.ftdc_paths = DEFAULT_FTDC_PATHS
    
    return args


def load_hosts(args) -> list[str]:
    """Load host list from arguments and/or file."""
    hosts = []
    
    if args.hosts:
        hosts.extend(args.hosts)
    
    if args.hosts_file:
        if not args.hosts_file.exists():
            print(f"ERROR: Hosts file not found: {args.hosts_file}", file=sys.stderr)
            sys.exit(2)
        
        with open(args.hosts_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    hosts.append(line)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_hosts = []
    for host in hosts:
        if host not in seen:
            seen.add(host)
            unique_hosts.append(host)
    
    return unique_hosts


def build_ssh_command(args, hostname: str) -> list[str]:
    """Build the base SSH command with options."""
    cmd = ["ssh"]
    
    cmd.extend(["-o", "BatchMode=yes"])
    cmd.extend(["-o", "StrictHostKeyChecking=accept-new"])
    cmd.extend(["-o", f"ConnectTimeout={min(30, args.timeout)}"])
    
    if args.port != 22:
        cmd.extend(["-p", str(args.port)])
    
    if args.key:
        cmd.extend(["-i", str(args.key)])
    
    if args.ssh_opts:
        for opt in args.ssh_opts:
            cmd.extend(["-o", opt])
    
    cmd.append(f"{args.user}@{hostname}")
    
    return cmd


def build_scp_command(args, hostname: str, src: str, dst: str, recursive: bool = False) -> list[str]:
    """Build SCP command to copy from remote to local."""
    cmd = ["scp"]
    
    cmd.extend(["-o", "BatchMode=yes"])
    cmd.extend(["-o", "StrictHostKeyChecking=accept-new"])
    cmd.extend(["-o", f"ConnectTimeout={min(30, args.timeout)}"])
    
    if recursive:
        cmd.append("-r")
    
    if args.port != 22:
        cmd.extend(["-P", str(args.port)])
    
    if args.key:
        cmd.extend(["-i", str(args.key)])
    
    if args.ssh_opts:
        for opt in args.ssh_opts:
            cmd.extend(["-o", opt])
    
    cmd.append(f"{args.user}@{hostname}:{src}")
    cmd.append(dst)
    
    return cmd


def collect_logs(hostname: str, args, host_dir: Path) -> int:
    """Collect log files from remote host. Returns number of files collected."""
    logs_dir = host_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    
    collected = 0
    for log_path in args.log_paths:
        # Check if file exists on remote
        ssh_cmd = build_ssh_command(args, hostname)
        ssh_cmd.append(f"test -f {log_path} && echo exists")
        
        result = subprocess.run(
            ssh_cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if "exists" in result.stdout:
            # Copy the file
            local_name = Path(log_path).name
            scp_cmd = build_scp_command(
                args, hostname,
                log_path,
                str(logs_dir / local_name)
            )
            
            scp_result = subprocess.run(
                scp_cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if scp_result.returncode == 0:
                collected += 1
    
    return collected


def collect_assert_counts(hostname: str, args, host_dir: Path) -> bool:
    """Collect serverStatus().asserts from remote host. Returns success status."""
    asserts_dir = host_dir / "assert-counts"
    asserts_dir.mkdir(parents=True, exist_ok=True)
    
    # Build mongosh command to get asserts
    mongosh_cmd = """
    mongosh --quiet --eval 'JSON.stringify({
        timestamp: new Date().toISOString(),
        hostname: db.hostInfo().system.hostname || "unknown",
        asserts: db.serverStatus().asserts,
        uptime: db.serverStatus().uptime
    })'
    """
    
    ssh_cmd = build_ssh_command(args, hostname)
    ssh_cmd.append(mongosh_cmd.strip())
    
    try:
        result = subprocess.run(
            ssh_cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0 and result.stdout.strip():
            # Validate JSON
            try:
                data = json.loads(result.stdout.strip())
                if "asserts" in data:
                    # Save to file
                    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                    output_file = asserts_dir / f"asserts-{timestamp}.json"
                    with open(output_file, 'w') as f:
                        json.dump(data, f, indent=2)
                    return True
            except json.JSONDecodeError:
                pass
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    
    return False


def collect_ftdc_files(hostname: str, args, host_dir: Path) -> int:
    """Collect FTDC files from remote host. Returns number of files collected."""
    ftdc_dir = host_dir / "ftdc-files"
    ftdc_dir.mkdir(parents=True, exist_ok=True)
    
    collected = 0
    for ftdc_path in args.ftdc_paths:
        # Check if directory exists and has metrics files
        ssh_cmd = build_ssh_command(args, hostname)
        ssh_cmd.append(f"test -d {ftdc_path} && ls {ftdc_path}/metrics.* 2>/dev/null | head -5")
        
        result = subprocess.run(
            ssh_cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0 and result.stdout.strip():
            # Copy metrics files (limited to most recent)
            for remote_file in result.stdout.strip().split('\n'):
                if remote_file:
                    local_name = Path(remote_file).name
                    scp_cmd = build_scp_command(
                        args, hostname,
                        remote_file,
                        str(ftdc_dir / local_name)
                    )
                    
                    scp_result = subprocess.run(
                        scp_cmd,
                        capture_output=True,
                        text=True,
                        timeout=120
                    )
                    
                    if scp_result.returncode == 0:
                        collected += 1
            
            # If we found files in this path, don't check other paths
            if collected > 0:
                break
    
    return collected


def collect_from_host(hostname: str, args, output_dir: Path) -> CollectionResult:
    """Collect all data from a single host."""
    result = CollectionResult(hostname=hostname, success=False)
    
    # Create host-specific directory
    host_dir = output_dir / hostname
    host_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        # Collect logs
        if not args.skip_logs:
            result.logs_collected = collect_logs(hostname, args, host_dir)
        
        # Collect assert counts
        if not args.skip_asserts:
            result.asserts_collected = collect_assert_counts(hostname, args, host_dir)
        
        # Collect FTDC files
        if not args.skip_ftdc:
            result.ftdc_collected = collect_ftdc_files(hostname, args, host_dir)
        
        # Mark as success if we collected anything
        if result.logs_collected > 0 or result.asserts_collected or result.ftdc_collected > 0:
            result.success = True
        else:
            result.error = "No data collected"
        
    except subprocess.TimeoutExpired:
        result.error = "Connection timeout"
    except Exception as e:
        result.error = str(e)[:80]
    
    return result


def reorganize_for_analysis(output_dir: Path) -> Path:
    """Reorganize collected data into the standard structure for analysis."""
    # Create combined directories
    combined_dir = output_dir / "_combined"
    logs_dir = combined_dir / "logs"
    asserts_dir = combined_dir / "assert-counts"
    ftdc_dir = combined_dir / "ftdc-files"
    
    logs_dir.mkdir(parents=True, exist_ok=True)
    asserts_dir.mkdir(parents=True, exist_ok=True)
    ftdc_dir.mkdir(parents=True, exist_ok=True)
    
    # Copy files from each host directory
    for host_dir in output_dir.iterdir():
        if not host_dir.is_dir() or host_dir.name.startswith("_"):
            continue
        
        hostname = host_dir.name
        
        # Copy logs with hostname prefix
        host_logs = host_dir / "logs"
        if host_logs.exists():
            for log_file in host_logs.iterdir():
                if log_file.is_file():
                    dest = logs_dir / f"{hostname}_{log_file.name}"
                    shutil.copy2(log_file, dest)
        
        # Copy assert-counts with hostname prefix
        host_asserts = host_dir / "assert-counts"
        if host_asserts.exists():
            for assert_file in host_asserts.iterdir():
                if assert_file.is_file():
                    dest = asserts_dir / f"{hostname}_{assert_file.name}"
                    shutil.copy2(assert_file, dest)
        
        # Copy FTDC files with hostname prefix
        host_ftdc = host_dir / "ftdc-files"
        if host_ftdc.exists():
            for ftdc_file in host_ftdc.iterdir():
                if ftdc_file.is_file():
                    dest = ftdc_dir / f"{hostname}_{ftdc_file.name}"
                    shutil.copy2(ftdc_file, dest)
    
    return combined_dir


def run_analysis(data_dir: Path, args) -> int:
    """Run mongobleed-detector.sh on collected data. Returns exit code."""
    cmd = [
        str(DETECTOR_SCRIPT),
        "--data-dir", str(data_dir),
        "-t", str(args.time),
        "-c", str(args.conn_threshold),
        "-b", str(args.burst_threshold),
        "-m", str(args.metadata_rate),
        "--spike-threshold", str(args.spike_threshold),
    ]
    
    result = subprocess.run(cmd)
    return result.returncode


def print_collection_summary(results: list[CollectionResult], args):
    """Print summary of collection results."""
    print()
    print("╔" + "═" * 80 + "╗")
    print("║" + "MongoBleed Data Collection Summary".center(80) + "║")
    print("╚" + "═" * 80 + "╝")
    print()
    
    successful = [r for r in results if r.success]
    failed = [r for r in results if not r.success]
    
    print(f"Hosts: {len(successful)}/{len(results)} successful")
    print()
    
    if successful:
        print("Collected Data:")
        print(f"{'Hostname':<30} {'Logs':<10} {'Asserts':<10} {'FTDC':<10}")
        print("-" * 60)
        for r in successful:
            asserts_str = "✓" if r.asserts_collected else "−"
            print(f"{r.hostname:<30} {r.logs_collected:<10} {asserts_str:<10} {r.ftdc_collected:<10}")
        print()
    
    if failed:
        print("Failed Hosts:")
        for r in failed:
            print(f"  ✗ {r.hostname}: {r.error}")
        print()
    
    print(f"Data saved to: {args.output_dir}")
    print()


def main():
    args = parse_args()
    
    # Load hosts
    hosts = load_hosts(args)
    if not hosts:
        print("ERROR: No hosts specified", file=sys.stderr)
        sys.exit(2)
    
    # Create output directory
    args.output_dir.mkdir(parents=True, exist_ok=True)
    
    if not args.quiet:
        print(f"MongoBleed Remote Collector v{VERSION}")
        print(f"Collecting from {len(hosts)} host(s) with {args.parallel} parallel connections...")
        print()
    
    # Phase 1: Collection
    collection_results = []
    with ThreadPoolExecutor(max_workers=args.parallel) as executor:
        futures = {
            executor.submit(collect_from_host, host, args, args.output_dir): host
            for host in hosts
        }
        
        for future in as_completed(futures):
            host = futures[future]
            try:
                result = future.result()
                collection_results.append(result)
                
                if not args.quiet:
                    if result.success:
                        parts = []
                        if result.logs_collected:
                            parts.append(f"{result.logs_collected} logs")
                        if result.asserts_collected:
                            parts.append("asserts")
                        if result.ftdc_collected:
                            parts.append(f"{result.ftdc_collected} ftdc")
                        status = f"\033[0;32m✓ {', '.join(parts)}\033[0m"
                    else:
                        status = f"\033[0;31m✗ {result.error}\033[0m"
                    print(f"  [{status}] {host}")
                    
            except Exception as e:
                collection_results.append(
                    CollectionResult(hostname=host, success=False, error=str(e))
                )
                if not args.quiet:
                    print(f"  [\033[0;31m✗ Error\033[0m] {host}: {e}")
    
    # Print collection summary
    print_collection_summary(collection_results, args)
    
    # Check if we have any data
    successful = [r for r in collection_results if r.success]
    if not successful:
        print("ERROR: No data collected from any host", file=sys.stderr)
        sys.exit(2)
    
    if args.collect_only:
        print("Collection complete. Run analysis manually with:")
        print(f"  ./mongobleed-detector.sh --data-dir {args.output_dir}/_combined/")
        sys.exit(0)
    
    # Phase 2: Reorganize and analyze
    print("Reorganizing data for analysis...")
    combined_dir = reorganize_for_analysis(args.output_dir)
    
    print("Running analysis...")
    print()
    
    exit_code = run_analysis(combined_dir, args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
