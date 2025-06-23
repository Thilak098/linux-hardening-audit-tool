from checks.authentication import check_password_max_days, check_password_min_len

if __name__ == "__main__":
    results = [
        check_password_max_days(),
        check_password_min_len()
    ]
    print(results)
