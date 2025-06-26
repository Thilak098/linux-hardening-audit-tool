import subprocess
from datetime import datetime
from typing import Dict, Union, List

def check_ufw_status() -> Dict[str, Union[str, bool, dict]]:
    """Check if UFW firewall is active with enhanced detection"""
    try:
        result = subprocess.run(
            ['ufw', 'status'],
            capture_output=True,
            text=True,
            check=True
        )
        status = result.stdout.lower()
        
        is_active = "active" in status
        is_enabled = "enabled" in status
        
        return {
            "check": "ufw_status",
            "status": "PASS" if is_active else "FAIL",
            "value": {
                "active": is_active,
                "enabled": is_enabled,
                "version": get_ufw_version()
            },
            "expected": {
                "active": True,
                "enabled": True
            },
            "severity": "CRITICAL",
            "remediation": "sudo ufw enable && sudo ufw reload" if not is_active else None,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
    except subprocess.CalledProcessError as e:
        return handle_ufw_error("ufw_status", e)
    except Exception as e:
        return handle_generic_error("ufw_status", e)

def check_firewall_default_deny() -> Dict[str, Union[str, dict]]:  # Renamed from check_default_deny
    """Verify default deny policies with detailed output"""
    try:
        result = subprocess.run(
            ['ufw', 'status', 'verbose'],
            capture_output=True,
            text=True,
            check=True
        )
        status = result.stdout
        
        policies = {
            "incoming": "deny (incoming)" in status,
            "outgoing": "deny (outgoing)" in status,
            "routed": "deny (routed)" in status if "routed" in status else None
        }
        
        all_deny = all(v for v in policies.values() if v is not None)
        
        return {
            "check": "firewall_default_deny",
            "status": "PASS" if all_deny else "FAIL",
            "value": policies,
            "expected": {
                "incoming": True,
                "outgoing": True,
                "routed": True
            },
            "severity": "HIGH",
            "remediation": "sudo ufw default deny incoming && sudo ufw default deny outgoing",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
    except subprocess.CalledProcessError as e:
        return handle_ufw_error("firewall_default_deny", e)
    except Exception as e:
        return handle_generic_error("firewall_default_deny", e)

def check_firewall_rules() -> Dict[str, Union[str, List[dict]]]:
    """Analyze firewall rules with risk assessment"""
    try:
        result = subprocess.run(
            ['ufw', 'status', 'numbered'],
            capture_output=True,
            text=True,
            check=True
        )
        rules = []
        risky_rules = []
        
        for line in result.stdout.split('\n'):
            if any(x in line for x in ['ALLOW', 'DENY', 'LIMIT']):
                rule = {
                    "raw": line.strip(),
                    "risk": "high" if "ANYWHERE" in line else "medium"
                }
                rules.append(rule)
                if rule["risk"] == "high":
                    risky_rules.append(rule)
        
        return {
            "check": "firewall_rules",
            "status": "PASS" if not risky_rules else "WARN",
            "value": {
                "total_rules": len(rules),
                "risky_rules": risky_rules,
                "all_rules": rules if len(rules) < 10 else "Too many to display"
            },
            "expected": {
                "risky_rules": 0,
                "total_rules": ">0"
            },
            "severity": "MEDIUM" if risky_rules else "LOW",
            "remediation": "Review rules with: sudo ufw status numbered",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
    except subprocess.CalledProcessError as e:
        return handle_ufw_error("firewall_rules", e)
    except Exception as e:
        return handle_generic_error("firewall_rules", e)

# Helper functions (keep these at the bottom)
def get_ufw_version() -> str:
    try:
        return subprocess.run(
            ['ufw', '--version'],
            capture_output=True,
            text=True
        ).stdout.split('\n')[0]
    except:
        return "unknown"

def handle_ufw_error(check_name: str, error: Exception) -> Dict[str, str]:
    return {
        "check": check_name,
        "status": "SKIPPED",
        "value": "UFW not available",
        "remediation": "Install with: sudo apt install ufw",
        "severity": "MEDIUM",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "error": str(error)
    }

def handle_generic_error(check_name: str, error: Exception) -> Dict[str, str]:
    return {
        "check": check_name,
        "status": "ERROR",
        "severity": "HIGH",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "error": str(error)
    }
