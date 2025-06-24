import os
import stat

def check_shadow_permissions():
    try:
        mode = os.stat("/etc/shadow").st_mode
        return {
            "check": "shadow_perms",
            "status": "PASS" if (mode & 0o777) == 0o640 else "FAIL",
            "value": oct(mode & 0o777),
            "expected": "0o640",
            "remediation": "Run: sudo chmod 640 /etc/shadow"
        }
    except Exception as e:
        return {"check": "shadow_perms", "status": "ERROR", "error": str(e)}
