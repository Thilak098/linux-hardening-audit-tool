def check_selinux_enforcing():
    try:
        with open("/etc/selinux/config") as f:
            return "SELINUX=enforcing" in f.read()
    except:
        return False
