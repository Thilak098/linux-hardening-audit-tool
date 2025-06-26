import subprocess
from datetime import datetime
from typing import Dict, Union, List

def check_vulnerable_packages() -> Dict[str, Union[str, int, List[str]]]:
    """Check for outdated or vulnerable packages with detailed reporting"""
    timestamp = datetime.utcnow().isoformat() + "Z"
    try:
        # Update package lists silently (no stderr output)
        subprocess.run(
            ['apt-get', '-qq', 'update'],
            stderr=subprocess.DEVNULL,
            check=True
        )
        
        # Get upgradable packages (silent mode)
        upgrade_result = subprocess.run(
            ['apt', 'list', '--upgradable'],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=True
        )
        
        upgradable_pkgs = [
            line.split('/')[0] 
            for line in upgrade_result.stdout.splitlines()[1:]  # Skip header
            if line.strip()
        ]
        
        # Check security updates specifically
        security_result = subprocess.run(
            ['grep', '-r', 'security', '/var/lib/apt/lists/'],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        security_updates = bool(security_result.stdout.strip())
        
        return {
            "check": "vulnerable_packages",
            "status": "PASS" if not upgradable_pkgs else ("FAIL" if security_updates else "WARN"),
            "value": {
                "total_upgradable": len(upgradable_pkgs),
                "security_updates": security_updates,
                "packages": upgradable_pkgs[:10]  # Limit output
            },
            "expected": "0 security updates",
            "remediation": "Run: sudo apt-get upgrade && sudo apt-get autoremove",
            "timestamp": timestamp,
            "severity": "CRITICAL" if security_updates else "MEDIUM"
        }
    except Exception as e:
        return error_response("vulnerable_packages", e, timestamp)

def check_unwanted_packages() -> Dict[str, Union[str, int, List[str]]]:
    """Check for known risky packages without command line noise"""
    timestamp = datetime.utcnow().isoformat() + "Z"
    unwanted = [
        "telnet", "rsh-server", "nis", "ypbind", "rsh-client",
        "talk", "talkd", "xinetd", "ldap-utils", "tftp",
        "snmp", "dovecot", "sendmail", "bind9", "vsftpd"
    ]
    
    try:
        # Single dpkg call for all packages
        result = subprocess.run(
            ['dpkg', '--get-selections'],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=True
        )
        
        installed = [
            pkg for pkg in unwanted 
            if f"{pkg}\tinstall" in result.stdout
        ]
        
        return {
            "check": "unwanted_packages",
            "status": "PASS" if not installed else "FAIL",
            "value": {
                "count": len(installed),
                "packages": installed
            },
            "expected": "0 unwanted packages",
            "remediation": f"Run: sudo apt purge {' '.join(installed)}" if installed else "None needed",
            "timestamp": timestamp,
            "severity": "HIGH" if installed else "LOW"
        }
    except Exception as e:
        return error_response("unwanted_packages", e, timestamp)

def check_non_essential_services() -> Dict[str, Union[str, int, List[str]]]:
    """Check for running non-essential services silently"""
    timestamp = datetime.utcnow().isoformat() + "Z"
    risky_services = [
        "telnet", "rsh", "rexec", "rlogin", "tftp",
        "xinetd", "vsftpd", "snmpd", "smtpd", "dovecot"
    ]
    
    try:
        # Get services in one call
        result = subprocess.run(
            ['systemctl', 'list-units', '--type=service', '--state=running', '--no-legend'],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=True
        )
        
        detected = [
            line.split()[0] 
            for line in result.stdout.splitlines()
            if any(svc in line.lower() for svc in risky_services)
        ]
        
        return {
            "check": "non_essential_services",
            "status": "PASS" if not detected else "FAIL",
            "value": detected,
            "expected": "No risky services running",
            "remediation": f"Run: sudo systemctl disable --now {' '.join(detected)}" if detected else "None needed",
            "timestamp": timestamp,
            "severity": "HIGH" if detected else "LOW"
        }
    except Exception as e:
        return error_response("non_essential_services", e, timestamp)

def error_response(check_name: str, error: Exception, timestamp: str) -> Dict[str, str]:
    """Standardized error response"""
    return {
        "check": check_name,
        "status": "ERROR",
        "error": str(error),
        "timestamp": timestamp,
        "severity": "MEDIUM"
    }
