import json
import time
from typing import List, Dict
from datetime import datetime

def generate_report(results: List[Dict]) -> str:
    """
    Generates a professional JSON security audit report with:
    - Execution timing metrics
    - Comprehensive timestamping
    - Detailed summary statistics
    """
    # Calculate total execution time
    total_duration = sum(r.get("duration", 0) for r in results) if results else 0

    report = {
        "meta": {
            "tool": "Linux Hardening Auditor",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "statistics": {
                "total_checks": len(results),
                "passed": sum(1 for r in results if r.get("status") == "PASS"),
                "failed": sum(1 for r in results if r.get("status") == "FAIL"),
                "errors": sum(1 for r in results if r.get("status") == "ERROR"),
                "total_duration_seconds": round(total_duration, 3),
                "average_duration_seconds": round(total_duration / max(1, len(results)), 3)
            }
        },
        "findings": [
            {
                "id": r["check"],
                "status": r["status"],
                "severity": r.get("severity", "medium").upper(),
                "duration_seconds": round(r.get("duration", 0), 3),
                "timestamp": r.get("timestamp", datetime.utcnow().isoformat() + "Z"),
                "details": {
                    "current_value": r.get("value"),
                    "expected_value": r.get("expected"),
                    "resource": r.get("resource", "/etc/login.defs")
                },
                "remediation": r.get("remediation", "")
            } for r in results
        ]
    }

    return json.dumps(report, indent=2)

# Test function
def _test():
    test_data = [{
        "check": "password_policy",
        "status": "FAIL",
        "duration": 0.45,
        "value": 120,
        "expected": 90,
        "remediation": "Set PASS_MAX_DAYS to 90 in /etc/login.defs"
    }]
    print(generate_report(test_data))

if __name__ == "__main__":
    _test()
