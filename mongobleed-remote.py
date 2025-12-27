#!/usr/bin/env python3
"""
mongobleed-remote.py
Remote MongoDB Log Analysis Tool for CVE-2025-14847 (MongoBleed)

Executes mongobleed-detector.sh on multiple remote hosts via SSH
and aggregates results into a combined report.

Uses native SSH - no additional Python dependencies required.
Respects ~/.ssh/config, ssh-agent, and ProxyJump configurations.
"""

import argparse
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


VERSION = "1.0.0"
SCRIPT_DIR = Path(__file__).parent
DETECTOR_SCRIPT = SCRIPT_DIR / "mongobleed-detector.sh"

# Risk level sort order
RISK_ORDER = {"HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


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
        description="Remote MongoDB Log Analysis for CVE-2025-14847 (MongoBleed)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Uses native SSH - respects ~/.ssh/config, ssh-agent, and ProxyJump.
No additional Python dependencies required.

Examples:
    # Scan hosts from a file
    %(prog)s --hosts-file hosts.txt --user admin

    # Scan specific hosts
    %(prog)s --host mongo1.example.com --host mongo2.example.com --user admin

    # Use specific SSH key
    %(prog)s --hosts-file hosts.txt --user admin --key ~/.ssh/mongodb_key

    # Parallel execution with custom detector options
    %(prog)s --hosts-file hosts.txt --user admin --parallel 10 --time 1440
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
        "--path", "-p",
        action="append",
        dest="log_paths",
        metavar="GLOB",
        help="Additional log path on remote hosts (repeatable)"
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
    
    return args


def load_hosts(args) -> list[str]:
    """Load host list from arguments and/or file."""
    hosts = []
    
    # Add hosts from command line
    if args.hosts:
        hosts.extend(args.hosts)
    
    # Add hosts from file
    if args.hosts_file:
        if not args.hosts_file.exists():
            print(f"ERROR: Hosts file not found: {args.hosts_file}", file=sys.stderr)
            sys.exit(2)
        
        with open(args.hosts_file) as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
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
    
    # Add SSH options
    cmd.extend(["-o", "BatchMode=yes"])  # No password prompts
    cmd.extend(["-o", "StrictHostKeyChecking=accept-new"])  # Accept new host keys
    cmd.extend(["-o", f"ConnectTimeout={min(30, args.timeout)}"])
    
    # Port
    if args.port != 22:
        cmd.extend(["-p", str(args.port)])
    
    # SSH key
    if args.key:
        cmd.extend(["-i", str(args.key)])
    
    # Additional SSH options
    if args.ssh_opts:
        for opt in args.ssh_opts:
            cmd.extend(["-o", opt])
    
    # User@host
    cmd.append(f"{args.user}@{hostname}")
    
    return cmd


def build_scp_command(args, hostname: str, src: str, dst: str) -> list[str]:
    """Build SCP command with options."""
    cmd = ["scp"]
    
    # Add options
    cmd.extend(["-o", "BatchMode=yes"])
    cmd.extend(["-o", "StrictHostKeyChecking=accept-new"])
    cmd.extend(["-o", f"ConnectTimeout={min(30, args.timeout)}"])
    
    # Port
    if args.port != 22:
        cmd.extend(["-P", str(args.port)])
    
    # SSH key
    if args.key:
        cmd.extend(["-i", str(args.key)])
    
    # Additional SSH options
    if args.ssh_opts:
        for opt in args.ssh_opts:
            cmd.extend(["-o", opt])
    
    # Source and destination
    cmd.append(src)
    cmd.append(f"{args.user}@{hostname}:{dst}")
    
    return cmd


def build_detector_command(args) -> str:
    """Build the detector command with options."""
    cmd_parts = ["/tmp/mongobleed-detector.sh"]
    
    cmd_parts.extend(["-t", str(args.time)])
    cmd_parts.extend(["-c", str(args.conn_threshold)])
    cmd_parts.extend(["-b", str(args.burst_threshold)])
    cmd_parts.extend(["-m", str(args.metadata_rate)])
    
    if args.log_paths:
        for path in args.log_paths:
            cmd_parts.extend(["-p", f"'{path}'"])
    
    return " ".join(cmd_parts)


def analyze_host(hostname: str, args) -> HostResult:
    """Analyze a single remote host via SSH."""
    result = HostResult(hostname=hostname, success=False)
    
    try:
        # Step 1: Copy script to remote host
        scp_cmd = build_scp_command(
            args, hostname,
            str(DETECTOR_SCRIPT),
            "/tmp/mongobleed-detector.sh"
        )
        
        scp_result = subprocess.run(
            scp_cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if scp_result.returncode != 0:
            error_msg = scp_result.stderr.strip() or "SCP failed"
            # Clean up common SSH error messages
            if "Permission denied" in error_msg:
                result.error = "SSH authentication failed"
            elif "Connection refused" in error_msg:
                result.error = "Connection refused"
            elif "No route to host" in error_msg or "Host is unreachable" in error_msg:
                result.error = "Host unreachable"
            elif "Connection timed out" in error_msg:
                result.error = "Connection timeout"
            else:
                result.error = error_msg[:80]
            return result
        
        # Step 2: Make script executable and run it
        ssh_cmd = build_ssh_command(args, hostname)
        detector_cmd = build_detector_command(args)
        ssh_cmd.append(f"chmod +x /tmp/mongobleed-detector.sh && {detector_cmd}")
        
        ssh_result = subprocess.run(
            ssh_cmd,
            capture_output=True,
            text=True,
            timeout=args.timeout
        )
        
        # Step 3: Clean up remote script
        cleanup_cmd = build_ssh_command(args, hostname)
        cleanup_cmd.append("rm -f /tmp/mongobleed-detector.sh")
        subprocess.run(cleanup_cmd, capture_output=True, timeout=30)
        
        # Parse results
        if ssh_result.returncode == 2:
            result.error = ssh_result.stderr.strip()[:80] or "Detector script error"
            return result
        
        result.success = True
        result.findings = parse_detector_output(hostname, ssh_result.stdout)
        
        for finding in result.findings:
            if finding.risk == "HIGH":
                result.high_count += 1
            elif finding.risk == "MEDIUM":
                result.medium_count += 1
        
    except subprocess.TimeoutExpired:
        result.error = "Command timeout"
    except FileNotFoundError as e:
        result.error = f"Command not found: {e.filename}"
    except Exception as e:
        result.error = f"Error: {str(e)[:60]}"
    
    return result


def parse_detector_output(hostname: str, output: str) -> list[Finding]:
    """Parse detector output and extract findings."""
    findings = []
    
    in_table = False
    for line in output.split("\n"):
        line = line.strip()
        
        # Detect start of data rows (after header separator)
        if line.startswith("--------"):
            in_table = True
            continue
        
        if not in_table:
            continue
        
        # Stop at summary section
        if line.startswith("═") or not line:
            break
        
        # Parse data row
        parts = line.split()
        if len(parts) >= 9:
            try:
                risk = parts[0]
                if risk not in RISK_ORDER:
                    continue
                
                finding = Finding(
                    hostname=hostname,
                    risk=risk,
                    source_ip=parts[1],
                    conn_count=int(parts[2]),
                    meta_count=int(parts[3]),
                    disc_count=int(parts[4]),
                    meta_rate=parts[5],
                    burst_rate=parts[6],
                    first_seen=parts[7],
                    last_seen=parts[8] if len(parts) > 8 else ""
                )
                findings.append(finding)
            except (ValueError, IndexError):
                continue
    
    return findings


def print_combined_results(results: list[HostResult], args):
    """Print combined results table."""
    # Collect all findings
    all_findings = []
    for result in results:
        all_findings.extend(result.findings)
    
    # Sort by risk level, then hostname, then connection count
    all_findings.sort(key=lambda f: (
        RISK_ORDER.get(f.risk, 99),
        f.hostname,
        -f.conn_count
    ))
    
    # Count totals
    total_high = sum(r.high_count for r in results)
    total_medium = sum(r.medium_count for r in results)
    successful_hosts = sum(1 for r in results if r.success)
    failed_hosts = [r for r in results if not r.success]
    
    # Print header
    print()
    print("╔" + "═" * 130 + "╗")
    print("║" + "MongoBleed (CVE-2025-14847) Remote Analysis Results".center(130) + "║")
    print("╚" + "═" * 130 + "╝")
    print()
    print(f"Hosts Analyzed: {successful_hosts}/{len(results)}")
    print()
    
    # Print failures if any
    if failed_hosts:
        print("Failed Hosts:")
        for r in failed_hosts:
            print(f"  ✗ {r.hostname}: {r.error}")
        print()
    
    if not all_findings:
        if successful_hosts > 0:
            print("No findings detected across all hosts.")
        print()
        return
    
    # Print table header
    header = f"{'Hostname':<20} {'Risk':<8} {'SourceIP':<40} {'ConnCount':>10} {'MetaCount':>10} {'DiscCount':>10} {'MetaRate%':>12} {'BurstRate/m':>14}"
    separator = f"{'-'*20} {'-'*8} {'-'*40} {'-'*10} {'-'*10} {'-'*10} {'-'*12} {'-'*14}"
    
    print(header)
    print(separator)
    
    # Print findings
    for f in all_findings:
        # Color codes
        if f.risk == "HIGH":
            color = "\033[0;31m"  # Red
        elif f.risk == "MEDIUM":
            color = "\033[0;33m"  # Yellow
        elif f.risk == "LOW":
            color = "\033[0;32m"  # Green
        else:
            color = ""
        reset = "\033[0m" if color else ""
        
        print(f"{f.hostname:<20} {color}{f.risk:<8}{reset} {f.source_ip:<40} {f.conn_count:>10} {f.meta_count:>10} {f.disc_count:>10} {f.meta_rate:>12} {f.burst_rate:>14}")
    
    # Print summary
    print()
    print("═" * 132)
    print("Summary:")
    if total_high > 0:
        print(f"  \033[0;31mHIGH:\033[0m   {total_high} finding(s) - Likely exploitation detected")
    if total_medium > 0:
        print(f"  \033[0;33mMEDIUM:\033[0m {total_medium} finding(s) - Suspicious activity, investigation recommended")
    
    if total_high > 0 or total_medium > 0:
        print()
        print("\033[1m\033[0;31m⚠ IMPORTANT:\033[0m If exploitation is confirmed, patching alone is insufficient.")
        print("  - Rotate all credentials that may have been exposed")
        print("  - Review accessed data for sensitive information disclosure")
        print("  - Check for lateral movement from affected systems")
        print("  - Preserve logs for forensic analysis")
    else:
        print("  No HIGH or MEDIUM risk findings detected.")
    
    print()


def main():
    args = parse_args()
    
    # Load hosts
    hosts = load_hosts(args)
    if not hosts:
        print("ERROR: No hosts specified", file=sys.stderr)
        sys.exit(2)
    
    if not args.quiet:
        print(f"MongoBleed Remote Scanner v{VERSION}")
        print(f"Scanning {len(hosts)} host(s) with {args.parallel} parallel connections...")
        print()
    
    # Execute on all hosts in parallel
    results = []
    with ThreadPoolExecutor(max_workers=args.parallel) as executor:
        futures = {
            executor.submit(analyze_host, host, args): host
            for host in hosts
        }
        
        for future in as_completed(futures):
            host = futures[future]
            try:
                result = future.result()
                results.append(result)
                
                if not args.quiet:
                    if result.success:
                        if result.high_count:
                            status = f"\033[0;31m✓ {result.high_count} HIGH\033[0m"
                        elif result.medium_count:
                            status = f"\033[0;33m✓ {result.medium_count} MEDIUM\033[0m"
                        else:
                            status = "\033[0;32m✓ OK\033[0m"
                    else:
                        status = f"\033[0;31m✗ {result.error}\033[0m"
                    print(f"  [{status}] {host}")
                    
            except Exception as e:
                results.append(HostResult(hostname=host, success=False, error=str(e)))
                if not args.quiet:
                    print(f"  [\033[0;31m✗ Error\033[0m] {host}: {e}")
    
    # Print combined results
    print_combined_results(results, args)
    
    # Exit code based on findings
    total_high = sum(r.high_count for r in results)
    total_medium = sum(r.medium_count for r in results)
    
    if total_high > 0 or total_medium > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
