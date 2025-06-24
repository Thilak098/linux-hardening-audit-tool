import subprocess
from typing import Dict
from datetime import datetime

def check_ufw_status() -> Dict:
    """Check if UFW firewall is active"""
    try:
        status = subprocess.run(
            ['ufw', 'status'],
            capture_output=True,
            text=True
        ).stdout
        
        is_active = "Status: active" in status
        return {
            "check": "ufw_status",
            "status": "PASS" if is_active else "FAIL",
            "value": "active" if is_active else "inactive",
            "expected": "active",
            "severity": "CRITICAL",
            "remediation": "Enable with: sudo ufw enable",
            "timestamp": datetime.now().isoformat()
        }
    except FileNotFoundError:
        return {
            "check": "ufw_status",
            "status": "SKIPPED",
            "value": "ufw not installed",
            "remediation": "Install with: sudo apt install ufw",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "check": "ufw_status",
            "status": "ERROR",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

def check_default_deny() -> Dict:
    """Check default firewall deny policies"""
    try:
        status = subprocess.run(
            ['ufw', 'status', 'verbose'],
            capture_output=True,
            text=True
        ).stdout
        
        deny_in = "Default: deny (incoming)" in status
        deny_out = "Default: deny (outgoing)" in status
        return {
            "check": "firewall_default_deny",
            "status": "PASS" if deny_in and deny_out else "FAIL",
            "value": f"in:{deny_in}, out:{deny_out}",
            "expected": "in:True, out:True",
            "severity": "HIGH",
            "remediation": "Set with: sudo ufw default deny",
            "timestamp": datetime.now().isoformat()
        }
    except FileNotFoundError:
        return {
            "check": "firewall_default_deny",
            "status": "SKIPPED",
            "value": "ufw not installed",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "check": "firewall_default_deny",
            "status": "ERROR",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

def check_firewall_rules() -> Dict:
    """Check for overly permissive firewall rules"""
    try:
        # First check if ufw exists
        subprocess.run(['which', 'ufw'], check=True, stdout=subprocess.PIPE)
        
        rules = subprocess.run(
            ['ufw', 'status', 'numbered'],
            capture_output=True,
            text=True
        ).stdout
        
        risky_rules = sum(
            1 for line in rules.split('\n')
            if "ALLOW" in line and ("anywhere" in line or "0.0.0.0/0" in line)
        )
        
        return {
            "check": "firewall_rules",
            "status": "PASS" if risky_rules == 0 else "WARN",
            "value": f"{risky_rules} overly permissive rules",
            "expected": "0 overly permissive rules",
            "severity": "MEDIUM",
            "remediation": "Review with: sudo ufw status numbered",
            "timestamp": datetime.now().isoformat()
        }
    except subprocess.CalledProcessError:
        return {
            "check": "firewall_rules",
            "status": "SKIPPED",
            "value": "ufw not available",
            "expected": "UFW firewall required",
            "severity": "LOW",
            "remediation": "Install with: sudo apt install ufw",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "check": "firewall_rules",
            "status": "ERROR",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }
