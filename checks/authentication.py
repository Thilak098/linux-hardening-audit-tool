import subprocess
from typing import Dict, Union

def check_password_max_days() -> Dict[str, Union[str, int]]:
    """
    Check if password expiration is set to <= 90 days in /etc/login.defs
    Returns:
        {
            "check": "password_max_days",
            "status": "PASS"|"FAIL"|"ERROR",
            "value": int (actual days),
            "expected": 90,
            "recommendation": "Set PASS_MAX_DAYS to 90 or less"
        }
    """
    try:
        # Run grep command to find PASS_MAX_DAYS
        result = subprocess.run(
            ["grep", "^PASS_MAX_DAYS", "/etc/login.defs"],
            capture_output=True,
            text=True,
            check=True
        )
        
        # Extract the numeric value
        days = int(result.stdout.strip().split()[1])
        
        return {
            "check": "password_max_days",
            "status": "PASS" if days <= 90 else "FAIL",
            "value": days,
            "expected": 90,
            "recommendation": "Set PASS_MAX_DAYS to 90 or less in /etc/login.defs"
        }
        
    except subprocess.CalledProcessError:
        return {
            "check": "password_max_days",
            "status": "FAIL",
            "error": "PASS_MAX_DAYS not found in /etc/login.defs",
            "recommendation": "Add PASS_MAX_DAYS 90 to /etc/login.defs"
        }
    except Exception as e:
        return {
            "check": "password_max_days",
            "status": "ERROR",
            "error": str(e)
        }


# Additional check example
def check_password_min_len() -> Dict[str, Union[str, int]]:
    """Check minimum password length requirement"""
    try:
        result = subprocess.run(
            ["grep", "^PASS_MIN_LEN", "/etc/login.defs"],
            capture_output=True, text=True, check=True
        )
        min_len = int(result.stdout.strip().split()[1])
        return {
            "check": "password_min_len",
            "status": "PASS" if min_len >= 12 else "FAIL",
            "value": min_len,
            "expected": 12
        }
    except Exception as e:
        return {
            "check": "password_min_len",
            "status": "ERROR",
            "error": str(e)
        }
