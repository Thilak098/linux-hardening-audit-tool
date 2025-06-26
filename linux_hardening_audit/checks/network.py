import subprocess
from datetime import datetime
from typing import Dict, Union, List

def check_open_ports() -> Dict[str, Union[str, int, list]]:
    """Check for unnecessary open ports"""
    try:
        result = subprocess.run(
            ["ss", "-tuln"],
            capture_output=True, text=True, check=True
        )
        open_ports = []
        risky_ports = [21, 23, 111, 515, 2049]  # FTP, Telnet, RPC, etc.
        
        for line in result.stdout.splitlines()[1:]:  # Skip header
            port = int(line.split()[3].split(':')[-1])
            if port in risky_ports:
                open_ports.append(port)
                
        return {
            "check": "open_ports",
            "status": "FAIL" if open_ports else "PASS",
            "value": open_ports or "No risky ports",
            "expected": "No risky ports open",
            "remediation": f"Close ports: {open_ports}" if open_ports else "None needed",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "severity": "HIGH"
        }
    except Exception as e:
        return error_response("open_ports", e)

def check_ip_forwarding() -> Dict[str, Union[str, int]]:
    """Verify IP forwarding is disabled"""
    try:
        result = subprocess.run(
            ["sysctl", "-n", "net.ipv4.ip_forward"],
            capture_output=True, text=True, check=True
        )
        enabled = int(result.stdout.strip())
        return {
            "check": "ip_forwarding",
            "status": "FAIL" if enabled else "PASS",
            "value": enabled,
            "expected": 0,
            "remediation": "Set 'net.ipv4.ip_forward=0' in /etc/sysctl.conf" if enabled else "None needed",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "severity": "MEDIUM"
        }
    except Exception as e:
        return error_response("ip_forwarding", e)

def check_icmp_redirects() -> Dict[str, Union[str, int]]:
    """Check if ICMP redirects are disabled (should be 0)"""
    try:
        result = subprocess.run(
            ["sysctl", "-n", "net.ipv4.conf.all.accept_redirects"],
            capture_output=True, text=True, check=True
        )
        enabled = int(result.stdout.strip())
        return {
            "check": "icmp_redirects",
            "status": "FAIL" if enabled else "PASS",
            "value": enabled,
            "expected": 0,
            "remediation": "Set 'net.ipv4.conf.all.accept_redirects=0' in /etc/sysctl.conf" if enabled else "None needed",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "severity": "MEDIUM"
        }
    except Exception as e:
        return error_response("icmp_redirects", e)

def check_kernel_params() -> Dict[str, Union[str, List[Dict]]]:
    """Audit critical kernel parameters"""
    params = {
        "net.ipv4.conf.all.accept_source_route": 0,
        "net.ipv4.conf.all.send_redirects": 0,
        "net.ipv4.conf.all.rp_filter": 1,
        "kernel.randomize_va_space": 2,
        "net.ipv6.conf.all.disable_ipv6": 1
    }
    
    results = []
    try:
        for param, expected in params.items():
            result = subprocess.run(
                ["sysctl", "-n", param],
                capture_output=True, text=True
            )
            current = result.stdout.strip()
            results.append({
                "parameter": param,
                "current": current,
                "expected": str(expected),
                "compliant": current == str(expected)
            })

        non_compliant = [r for r in results if not r["compliant"]]
        return {
            "check": "kernel_params",
            "status": "FAIL" if non_compliant else "PASS",
            "value": results,
            "expected": "All parameters compliant",
            "remediation": "\n".join(
                f"Set {p['parameter']}={p['expected']} in /etc/sysctl.conf"
                for p in non_compliant
            ) if non_compliant else "None needed",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "severity": "HIGH" if non_compliant else "LOW"
        }
    except Exception as e:
        return error_response("kernel_params", e)

def error_response(check_name: str, error: Exception) -> Dict[str, str]:
    """Standard error response"""
    return {
        "check": check_name,
        "status": "ERROR",
        "error": str(error),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "severity": "MEDIUM"
    }
