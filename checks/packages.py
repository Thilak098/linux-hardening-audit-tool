import subprocess
from typing import Dict

def check_vulnerable_packages() -> Dict:
    """Check for outdated or vulnerable packages"""
    try:
        # Check for outdated packages
        outdated = subprocess.run(
            ['apt-get', '-qq', 'update'],
            stderr=subprocess.PIPE
        )
        
        outdated_pkgs = subprocess.run(
            ['apt-get', '-qq', 'upgrade', '--dry-run'],
            stdout=subprocess.PIPE, text=True
        ).stdout.count("upgraded")
        
        return {
            "check": "vulnerable_packages",
            "status": "PASS" if outdated_pkgs == 0 else "FAIL",
            "value": f"{outdated_pkgs} upgradable",
            "expected": "0 upgradable",
            "severity": "HIGH",
            "remediation": "Run: sudo apt-get upgrade"
        }
    except Exception as e:
        return {
            "check": "vulnerable_packages",
            "status": "ERROR",
            "error": str(e)
        }

def check_unwanted_packages() -> Dict:
    """Check for known risky packages"""
    try:
        unwanted = ["telnet", "rsh-server", "nis"]
        installed = subprocess.run(
            ['dpkg', '-l'] + unwanted,
            stdout=subprocess.PIPE, text=True
        ).stdout.count("ii ")
        
        return {
            "check": "unwanted_packages",
            "status": "PASS" if installed == 0 else "FAIL",
            "value": f"{installed} found",
            "expected": "0 found",
            "severity": "MEDIUM",
            "remediation": f"Run: sudo apt remove {' '.join(unwanted)}"
        }
    except Exception as e:
        return {
            "check": "unwanted_packages",
            "status": "ERROR",
            "error": str(e)
        }
