from waf import RateLimiter, detect_sql_injection, detect_suspicious_input, detect_xss


def assert_true(name: str, value: bool) -> None:
    if not value:
        raise AssertionError(f"{name} failed: expected True")
    print(f"[PASS] {name}")


def assert_false(name: str, value: bool) -> None:
    if value:
        raise AssertionError(f"{name} failed: expected False")
    print(f"[PASS] {name}")


def run_waf_unit_tests() -> None:
    print("Unit STEP 1 - SQL detection")
    is_sql, _ = detect_sql_injection("' OR 1=1 --")
    assert_true("Detect SQL attack", is_sql)
    is_sql_normal, _ = detect_sql_injection("alice")
    assert_false("Allow normal SQL-safe input", is_sql_normal)

    print("Unit STEP 2 - XSS detection")
    is_xss, _ = detect_xss("<script>alert(1)</script>")
    assert_true("Detect XSS attack", is_xss)
    is_xss_normal, _ = detect_xss("hello_user")
    assert_false("Allow normal XSS-safe input", is_xss_normal)

    print("Unit STEP 3 - Suspicious detection")
    suspicious_long, _ = detect_suspicious_input("a" * 81)
    assert_true("Flag very long input", suspicious_long)
    suspicious_normal, _ = detect_suspicious_input("normaluser")
    assert_false("Do not flag normal input", suspicious_normal)

    print("Unit STEP 4 - Rate limiter")
    limiter = RateLimiter(max_requests=5, window_seconds=10)
    ip = "192.168.1.10"
    results = [limiter.allow_request(ip)[0] for _ in range(6)]
    expected = [True, True, True, True, True, False]
    if results != expected:
        raise AssertionError(f"RateLimiter failed: expected {expected}, got {results}")
    print("[PASS] RateLimiter sequence check")

    print("All WAF unit tests passed.")


if __name__ == "__main__":
    run_waf_unit_tests()
