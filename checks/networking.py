import subprocess
from typing import Dict
from datetime import datetime

def check_open_ports() -> Dict:
    """Check for unnecessary open network ports"""
    try:
        # Get listening ports using ss (socket statistics)
        result = subprocess.run(
            ['ss', '-tuln'],
            capture_output=True,
            text=True
        )
        listening_ports = [
            line.split()[4] 
            for line in result.stdout.splitlines()[1:] 
            if "LISTEN" in line
        ]
        
        return {
            "check": "open_ports",
            "status": "WARN" if len(listening_ports) > 5 else "PASS",
            "value": f"{len(listening_ports)} ports",
            "expected": "≤5 listening ports",
            "severity": "MEDIUM",
            "remediation": "Review with: sudo ss -tulnp",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "check": "open_ports",
            "status": "ERROR",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

def check_ip_forwarding() -> Dict:
    """Verify IP forwarding is disabled"""
    try:
        result = subprocess.run(
            ['sysctl', '-n', 'net.ipv4.ip_forward'],
            capture_output=True,
            text=True
        )
        enabled = result.stdout.strip()
        
        return {
            "check": "ip_forwarding",
            "status": "PASS" if enabled == "0" else "FAIL",
            "value": enabled,
            "expected": "0",
            "severity": "HIGH",
            "remediation": "Set net.ipv4.ip_forward=0 in /etc/sysctl.conf",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "check": "ip_forwarding",
            "status": "ERROR",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

def check_icmp_redirects() -> Dict:
    """Check if ICMP redirects are disabled"""
    try:
        result = subprocess.run(
            ['sysctl', '-n', 'net.ipv4.conf.all.accept_redirects'],
            capture_output=True,
            text=True
        )
        enabled = result.stdout.strip()
        
        return {
            "check": "icmp_redirects",
            "status": "PASS" if enabled == "0" else "FAIL",
            "value": enabled,
            "expected": "0",
            "severity": "MEDIUM",
            "remediation": "Set net.ipv4.conf.all.accept_redirects=0 in /etc/sysctl.conf",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {
            "check": "icmp_redirects",
            "status": "ERROR",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }
