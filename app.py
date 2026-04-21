from __future__ import annotations

from flask import Flask, render_template, request

from config import Config
from logger import log_request
from routes import main_bp
from waf import (
    RateLimiter,
    detect_sql_injection,
    detect_suspicious_input,
    detect_xss,
)

app = Flask(__name__)
app.config.from_object(Config)
app.register_blueprint(main_bp)
rate_limiter = RateLimiter(
    max_requests=app.config["RATE_LIMIT_MAX_REQUESTS"],
    window_seconds=app.config["RATE_LIMIT_WINDOW_SECONDS"],
)


def get_username() -> str:
    # Step 2: Flask reads URL input from request.args and form input from request.form.
    return request.args.get("username") or request.form.get("username") or ""


def blocked_response(
    client_ip: str,
    username: str,
    attack_type: str,
    reason: str,
    status_code: int,
):
    return (
        render_template(
            "blocked.html",
            username=username or "(empty)",
            ip=client_ip,
            attack_type=attack_type,
            reason=reason,
            status_code=status_code,
        ),
        status_code,
    )


@app.before_request
def global_waf_filter():
    # Skip filtering for dashboard so monitoring page always stays available.
    if request.path.startswith("/dashboard"):
        return None
    if request.path.startswith("/static"):
        return None
    if request.path == "/login/get-step":
        return None
    if request.path == "/login" and request.args.get("submitted") == "1":
        return None
    if (
        request.path == "/login"
        and request.method == "POST"
        and request.form.get("mode") == "two_step"
    ):
        # In two-step mode we intentionally defer SQL/XSS decision
        # to the dedicated GET verification stage.
        return None

    # Step 9: Rate limiting for every request globally.
    client_ip = request.remote_addr or "unknown"
    allowed_rate, rate_reason = rate_limiter.allow_request(client_ip)
    if not allowed_rate:
        log_request(
            ip=client_ip,
            path=request.path,
            status="BLOCKED",
            attack_type="RATE_LIMIT",
            details=rate_reason,
        )
        return blocked_response(
            client_ip=client_ip,
            username=get_username(),
            attack_type="RATE_LIMIT",
            reason=rate_reason,
            status_code=429,
        )

    username = get_username()

    # Step 4 + Step 8: SQL injection check as a WAF rule.
    sql_detected, sql_reason = detect_sql_injection(username)
    if sql_detected:
        log_request(
            ip=client_ip,
            path=request.path,
            status="BLOCKED",
            attack_type="SQL",
            details=sql_reason,
        )
        return blocked_response(
            client_ip=client_ip,
            username=username,
            attack_type="SQL INJECTION",
            reason=sql_reason,
            status_code=403,
        )

    # Step 6: XSS check as second attack protection layer.
    xss_detected, xss_reason = detect_xss(username)
    if xss_detected:
        log_request(
            ip=client_ip,
            path=request.path,
            status="BLOCKED",
            attack_type="XSS",
            details=xss_reason,
        )
        return blocked_response(
            client_ip=client_ip,
            username=username,
            attack_type="XSS",
            reason=xss_reason,
            status_code=403,
        )

    # Step 10: suspicious behavior is logged, but not blocked.
    suspicious, suspicious_reason = detect_suspicious_input(username)
    if suspicious:
        log_request(
            ip=client_ip,
            path=request.path,
            status="SUSPICIOUS",
            attack_type="SUSPICIOUS",
            details=suspicious_reason,
        )
    else:
        log_request(
            ip=client_ip,
            path=request.path,
            status="ALLOWED",
            attack_type="NONE",
            details="Request passed all WAF checks",
        )
    return None


if __name__ == "__main__":
    app.run(debug=True)
