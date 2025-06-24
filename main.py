from checks.ssh import check_ssh_protocol

if __name__ == "__main__":
    results = [check_ssh_protocol()]
    print(results)

