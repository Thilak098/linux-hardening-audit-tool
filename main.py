#!/usr/bin/env python3
from checks.authentication import check_password_max_days, check_password_min_len
from checks.filesystem import check_shadow_permissions
from checks.ssh import check_ssh_root_login
from checks.services import check_unwanted_services
from outputs.json import generate_report
from outputs.html import generate_html_report
import json
import argparse
from typing import List, Dict
from pathlib import Path

def print_colorized(report_json: str):
    """Prints colorized output in terminals"""
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
    """Load benchmark checks from JSON file"""
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
        check_password_max_days(),
        check_password_min_len(),
        check_shadow_permissions(),
        check_ssh_root_login(),
        check_unwanted_services()
    ]

def run_benchmark_checks(benchmark_name: str) -> List[Dict]:
    """Run checks from specified benchmark"""
    benchmark_checks = load_benchmark(benchmark_name)
    results = []
    
    for check in benchmark_checks:
        # Map benchmark checks to our check functions
        if check["check"] == "password_max_days":
            results.append(check_password_max_days())
        elif check["check"] == "ssh_root_login":
            results.append(check_ssh_root_login())
        # Add more mappings as needed
        else:
            results.append({
                "check": check["check"],
                "status": "SKIPPED",
                "message": "Check not implemented"
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
    return parser.parse_args()

def main():
    args = parse_args()
    
    # Run appropriate checks
    if args.benchmark:
        results = run_benchmark_checks(args.benchmark)
    else:
        results = run_default_checks()
    
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

