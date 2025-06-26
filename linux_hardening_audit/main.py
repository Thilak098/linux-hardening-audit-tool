#!/usr/bin/env python3
"""
Linux Hardening Audit Tool (LHAT)
================================

A comprehensive security auditing tool for Linux systems that:
- Checks compliance with CIS, STIG, and custom benchmarks
- Identifies security misconfigurations
- Generates detailed remediation reports

Features:
- Modular check system for easy expansion
- Multiple output formats (JSON, HTML, colored CLI)
- Custom benchmark support
- Quick scan mode for critical vulnerabilities

Usage:
  lh-audit [--format FORMAT] [--output FILE] [--benchmark BENCHMARK] [--quick]
"""

import argparse
import json
from pathlib import Path
from typing import Dict, List

# Security check imports
from linux_hardening_audit.checks.authentication import (
    check_password_max_days,
    check_password_min_len
)
from linux_hardening_audit.checks.filesystem import check_shadow_permissions
from linux_hardening_audit.checks.ssh import check_ssh_root_login
from linux_hardening_audit.checks.services import check_unwanted_services
from linux_hardening_audit.checks.network import (
    check_open_ports,
    check_ip_forwarding,
    check_icmp_redirects
)
from linux_hardening_audit.checks.firewall import (
    check_ufw_status,
    check_firewall_default_deny,
    check_firewall_rules
)
from linux_hardening_audit.checks.packages import (
    check_vulnerable_packages,
    check_unwanted_packages
)

# Report generators
from linux_hardening_audit.outputs.json import generate_report
from linux_hardening_audit.outputs.html import generate_html_report


def print_colorized(report_json: str) -> None:
    """Print color-coded audit results to terminal.
    
    Args:
        report_json: JSON string containing audit findings
    """
    try:
        report = json.loads(report_json)
        for finding in report["findings"]:
            fmt = finding.get("terminal_format", {})
            print(f"{fmt.get('severity_color', '')}"
                  f"[{finding['severity']}] {finding['id']}: "
                  f"{finding['status']}{fmt.get('reset_color', '')}")
    except Exception as e:
        print(f"Error colorizing output: {e}")
        print(report_json)


def load_benchmark(benchmark_name: str) -> List[Dict]:
    """Load security benchmark checks from JSON file.
    
    Args:
        benchmark_name: Name of benchmark file (without extension)
    
    Returns:
        List of benchmark checks or empty list on error
    """
    benchmark_path = Path("benchmarks") / f"{benchmark_name}.json"
    try:
        with open(benchmark_path) as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading benchmark: {e}")
        return []
def run_default_checks() -> List[Dict]:
    """Run all standard security checks"""
    return [
        # Authentication
        check_password_max_days(),
        check_password_min_len(),
        
        # Filesystem
        check_shadow_permissions(),
        
        # SSH
        check_ssh_root_login(),
        
        # Services
        check_unwanted_services(),
        
        # Network
        check_open_ports(),
        check_ip_forwarding(),
        check_icmp_redirects(),
        
        # Firewall
        check_ufw_status(),
        check_firewall_default_deny(),
        check_firewall_rules(),
        
        # Packages
        check_vulnerable_packages(),
        check_unwanted_packages()
    ]

def run_benchmark_checks(benchmark_name: str) -> List[Dict]:
    """Run checks from specified benchmark"""
    benchmark_checks = load_benchmark(benchmark_name)
    results = []
    
    for check in benchmark_checks:
        # Map benchmark checks to our check functions
        if check["id"] == "password_max_days":
            results.append(check_password_max_days())
        elif check["id"] == "ssh_root_login":
            results.append(check_ssh_root_login())
        elif check["id"] == "open_ports":
            results.append(check_open_ports())
        elif check["id"] == "ufw_status":
            results.append(check_ufw_status())
        # Add more mappings as needed
        else:
            results.append({
                "check": check["id"],
                "status": "SKIPPED",
                "message": "Check not implemented",
                "severity": check.get("severity", "LOW")
            })
    
    return results

def parse_args():
    """Handle command-line arguments"""
    parser = argparse.ArgumentParser(
        description="Linux Hardening Audit Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--format",
        choices=["json", "html", "color"],
        default="color",
        help="Output format"
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Save report to file (default: stdout)"
    )
    parser.add_argument(
        "--benchmark",
        choices=["cis_level1", "cis_level2", "stig"],
        help="Run specific compliance benchmark"
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run only critical checks (no package scans)"
    )
    return parser.parse_args()

def main():
    args = parse_args()
    
    # Run appropriate checks
    if args.benchmark:
        results = run_benchmark_checks(args.benchmark)
    else:
        results = run_default_checks()
        if args.quick:
            results = [r for r in results if r.get("severity") in ("CRITICAL", "HIGH")]
    
    # Generate report
    if args.format == "html":
        report = generate_html_report(results)
    else:
        report = generate_report(results)
        if args.format == "color":
            print_colorized(report)
            return
    
    # Output handling
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"Report saved to {args.output}")
    else:
        print(report)

if __name__ == "__main__":
    main()
