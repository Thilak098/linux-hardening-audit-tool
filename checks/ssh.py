import subprocess

def check_ssh_root_login():
    try:
        result = subprocess.run(
            ["grep", "^PermitRootLogin", "/etc/ssh/sshd_config"],
            capture_output=True, text=True
        )
        value = result.stdout.strip().split()[1] if result.stdout else ""
        return {
            "check": "ssh_root_login",
            "status": "PASS" if value.lower() == "no" else "FAIL",
            "value": value,
            "expected": "no",
            "remediation": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config"
        }
    except Exception as e:
        return {"check": "ssh_root_login", "status": "ERROR", "error": str(e)}
