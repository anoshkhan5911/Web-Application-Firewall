from __future__ import annotations

import csv
import io

from flask import (
    Blueprint,
    Response,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from config import Config
from logger import clear_logs, read_logs

main_bp = Blueprint("main", __name__)


def get_username() -> str:
    return request.args.get("username") or request.form.get("username") or ""


@main_bp.route("/")
def home():
    return render_template("welcome_page.html")


@main_bp.route("/project/why")
def project_why():
    return render_template("why_project.html")


@main_bp.route("/project/details")
def project_details():
    return render_template("project_details.html")


@main_bp.route("/control-center")
def control_center():
    username = get_username() or "Guest"
    return render_template("home.html", username=username)


@main_bp.route("/login", methods=["GET", "POST"])
def login():
    submitted = request.args.get("submitted") == "1"
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        mode = request.form.get("mode", "standard").strip()
        if mode == "two_step":
            session["pending_username"] = username
            return redirect(url_for("main.login_get_step"))
        if username:
            return redirect(url_for("main.login", submitted="1"))
        return redirect(url_for("main.login"))

    username = get_username().strip()
    if username:
        return redirect(url_for("main.login", submitted="1"))
    return render_template(
        "login.html",
        show_result=submitted,
    )


@main_bp.route("/login/get-step", methods=["GET"])
def login_get_step():
    pending_username = session.get("pending_username", "")
    if not pending_username:
        return redirect(url_for("main.login"))
    return render_template("login_get_step.html", pending_username=pending_username)


@main_bp.route("/login/verify", methods=["GET"])
def login_verify():
    username = (request.args.get("username") or "").strip()
    session.pop("pending_username", None)
    if not username:
        return redirect(url_for("main.login"))
    return redirect(url_for("main.login", username=username))


@main_bp.route("/dashboard")
def dashboard():
    entries = read_logs()
    total = len(entries)
    blocked = sum(1 for e in entries if e.get("status") == "BLOCKED")
    suspicious = sum(1 for e in entries if e.get("status") == "SUSPICIOUS")

    query = (request.args.get("q") or "").strip().lower()
    if query:
        entries = [
            entry
            for entry in entries
            if query in str(entry.get("ip", "")).lower()
            or query in str(entry.get("path", "")).lower()
            or query in str(entry.get("status", "")).lower()
            or query in str(entry.get("attack_type", "")).lower()
            or query in str(entry.get("details", "")).lower()
        ]

    try:
        page = max(int(request.args.get("page", "1")), 1)
    except ValueError:
        page = 1
    page_size = Config.DASHBOARD_PAGE_SIZE
    start = (page - 1) * page_size
    end = start + page_size
    paginated_entries = entries[start:end]
    total_filtered = len(entries)
    has_next = end < total_filtered

    if request.args.get("format") == "json":
        return jsonify(
            {
                "total_requests": total,
                "blocked_requests": blocked,
                "suspicious_requests": suspicious,
                "filtered_requests": total_filtered,
                "page": page,
                "page_size": page_size,
                "logs": paginated_entries,
            }
        )
    return render_template(
        "dashboard.html",
        total=total,
        blocked=blocked,
        suspicious=suspicious,
        recent_logs=paginated_entries,
        query=query,
        page=page,
        has_next=has_next,
    )


@main_bp.route("/dashboard/export.csv")
def dashboard_export_csv():
    entries = read_logs()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "ip", "path", "status", "attack_type", "details"])

    for entry in entries:
        writer.writerow(
            [
                entry.get("timestamp", ""),
                entry.get("ip", ""),
                entry.get("path", ""),
                entry.get("status", ""),
                entry.get("attack_type", ""),
                entry.get("details", ""),
            ]
        )

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=waf_logs.csv"},
    )


@main_bp.route("/dashboard/clear", methods=["POST"])
def dashboard_clear_logs():
    confirm_value = (request.form.get("confirm") or "").strip().upper()
    if confirm_value != "YES":
        return redirect(url_for("main.dashboard", clear_error="1"))
    clear_logs()
    return redirect(url_for("main.dashboard", cleared="1"))
