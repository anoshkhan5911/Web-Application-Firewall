from app import app


def _assert_status(name: str, actual: int, expected: int) -> None:
    if actual != expected:
        raise AssertionError(f"{name} failed: expected {expected}, got {actual}")
    print(f"[PASS] {name}: {actual}")


def run_tests() -> None:
    client = app.test_client()

    print("STEP 1/5 - Basic route checks")
    home = client.get("/", environ_base={"REMOTE_ADDR": "10.0.0.1"})
    _assert_status("Home route", home.status_code, 200)

    get_login = client.get(
        "/login?username=alice",
        follow_redirects=True,
        environ_base={"REMOTE_ADDR": "10.0.0.2"},
    )
    _assert_status("Login GET with username", get_login.status_code, 200)

    post_login = client.post(
        "/login",
        data={"username": "bob"},
        follow_redirects=True,
        environ_base={"REMOTE_ADDR": "10.0.0.3"},
    )
    _assert_status("Login POST with username", post_login.status_code, 200)

    print("STEP 2/5 - SQL and XSS blocking checks")
    sql_attack = client.get(
        "/login?username=' OR 1=1 --",
        environ_base={"REMOTE_ADDR": "10.0.0.4"},
    )
    _assert_status("SQL injection block", sql_attack.status_code, 403)

    xss_attack = client.get(
        "/login?username=<script>alert(1)</script>",
        environ_base={"REMOTE_ADDR": "10.0.0.5"},
    )
    _assert_status("XSS block", xss_attack.status_code, 403)

    print("STEP 3/5 - Suspicious input should be allowed (but logged)")
    suspicious = client.get(
        "/login?username=normal_user_with_very_very_very_very_very_very_very_long_value",
        follow_redirects=True,
        environ_base={"REMOTE_ADDR": "10.0.0.6"},
    )
    _assert_status("Suspicious but allowed request", suspicious.status_code, 200)

    print("STEP 4/5 - Rate limit check")
    limiter_results = []
    for _ in range(6):
        result = client.get(
            "/login?username=charlie",
            follow_redirects=True,
            environ_base={"REMOTE_ADDR": "10.0.0.99"},
        )
        limiter_results.append(result.status_code)
    expected_sequence = [200, 200, 200, 200, 200, 429]
    if limiter_results != expected_sequence:
        raise AssertionError(
            f"Rate limit failed: expected {expected_sequence}, got {limiter_results}"
        )
    print(f"[PASS] Rate limit sequence: {limiter_results}")

    print("STEP 5/5 - Dashboard check")
    dashboard = client.get("/dashboard", environ_base={"REMOTE_ADDR": "10.0.0.100"})
    _assert_status("Dashboard route", dashboard.status_code, 200)
    dashboard_search = client.get(
        "/dashboard?q=sql&page=1",
        environ_base={"REMOTE_ADDR": "10.0.0.100"},
    )
    _assert_status("Dashboard search route", dashboard_search.status_code, 200)
    dashboard_csv = client.get(
        "/dashboard/export.csv",
        environ_base={"REMOTE_ADDR": "10.0.0.100"},
    )
    _assert_status("Dashboard CSV export", dashboard_csv.status_code, 200)
    if "text/csv" not in dashboard_csv.content_type:
        raise AssertionError(
            f"Dashboard CSV content type failed: got {dashboard_csv.content_type}"
        )
    print(f"[PASS] Dashboard CSV content type: {dashboard_csv.content_type}")

    clear_fail = client.post(
        "/dashboard/clear",
        data={"confirm": "NO"},
        follow_redirects=False,
        environ_base={"REMOTE_ADDR": "10.0.0.100"},
    )
    _assert_status("Dashboard clear reject without YES", clear_fail.status_code, 302)

    clear_success = client.post(
        "/dashboard/clear",
        data={"confirm": "YES"},
        follow_redirects=False,
        environ_base={"REMOTE_ADDR": "10.0.0.100"},
    )
    _assert_status("Dashboard clear with YES", clear_success.status_code, 302)

    print("All step-by-step tests passed.")


if __name__ == "__main__":
    run_tests()
