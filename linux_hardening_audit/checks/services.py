import subprocess

def check_unwanted_services():
    """Check for risky running services"""
    try:
        services = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--state=running"],
            capture_output=True, text=True
        )
        risky = ["telnet", "rsh", "rexec"]
        found = [s for s in risky if s in services.stdout]
        return {
            "check": "unwanted_services",
            "status": "FAIL" if found else "PASS",
            "value": ", ".join(found) if found else "None",
            "expected": "None",
            "severity": "HIGH",
            "remediation": "Disable services: " + ", ".join(found) if found else ""
        }
    except Exception as e:
        return {"check": "unwanted_services", "status": "ERROR", "error": str(e)}
