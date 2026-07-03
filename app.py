from __future__ import annotations

import ctypes
import json
import os
import platform
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any
import webbrowser
import threading

from flask import Flask, Response, flash, redirect, render_template, request, session, url_for
from fpdf import FPDF
from werkzeug.security import check_password_hash, generate_password_hash

from policies import DEFAULT_POLICY_VALUES, POLICY_CATEGORIES
from policy_executor import (
    apply_policies,
    apply_policy,
    category_ids,
    reset_all_policies,
    reset_policy,
    scan_all,
    verify_policy_values,
)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-secret-key")

DATA_DIR = Path(__file__).resolve().parent / "data"
RESULTS_FILE = DATA_DIR / "scan_results.json"
LOG_FILE = DATA_DIR / "activity_log.json"
VALUES_FILE = DATA_DIR / "custom_values.json"
USERS = {
    "admin": {"password": generate_password_hash("cis123"), "role": "Administrator"},
    "guest": {"password": None, "role": "Guest"},
}

CATEGORY_TITLES = (
    ("password", "Password Policies"),
    ("lockout", "Account Lockout Policies"),
    ("local_policy", "Local Policy"),
    ("services", "System Services"),
)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            flash("Sign in to access the hardening dashboard.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def administrator_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if session.get("role") != "Administrator":
            add_log_entry(
                "Authorization",
                f"Blocked modification attempt by {session.get('username', 'unknown')}.",
                "warning",
            )
            flash("Guest and Auditor accounts have read-only access.", "error")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapped


def calculate_score(results: list[dict[str, Any]]) -> float:
    if not results:
        return 0.0
    passed = len([result for result in results if result["status"] == "PASS"])
    return (passed / len(results)) * 100


def save_results(results: list[dict[str, Any]]) -> None:
    DATA_DIR.mkdir(exist_ok=True)
    payload = {
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "score": calculate_score(results),
        "results": results,
    }
    RESULTS_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def add_log_entry(
    action: str,
    message: str,
    status: str = "info",
    cis_id: str | None = None,
    **details: Any,
) -> None:
    DATA_DIR.mkdir(exist_ok=True)
    entries = read_logs()
    entries.insert(0, {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "status": status,
        "cis_id": cis_id,
        "message": message,
        **details,
    })
    LOG_FILE.write_text(json.dumps(entries[:200], indent=2), encoding="utf-8")


def read_logs() -> list[dict[str, Any]]:
    if not LOG_FILE.exists():
        return []
    try:
        data = json.loads(LOG_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    return data


def read_custom_values() -> dict[str, int]:
    try:
        data = json.loads(VALUES_FILE.read_text(encoding="utf-8"))
        return {str(key): int(value) for key, value in data.items()}
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {}


def save_custom_values(values: dict[str, int]) -> None:
    DATA_DIR.mkdir(exist_ok=True)
    VALUES_FILE.write_text(json.dumps(values, indent=2), encoding="utf-8")


def log_operation(action: str, result: dict[str, Any]) -> None:
    add_log_entry(
        action,
        str(result["message"]),
        "success" if result["success"] else "error",
        str(result["cis_id"]),
        policy_name=result.get("policy_name", ""),
        command=result.get("command", ""),
        returncode=result.get("returncode"),
        stdout=result.get("stdout", ""),
        stderr=result.get("stderr", ""),
    )


def redirect_back():
    target = request.referrer
    if target and target.startswith(request.host_url):
        return redirect(target)
    return redirect(url_for("dashboard"))


def read_saved_scan() -> tuple[list[dict[str, Any]], float, str]:
    try:
        payload = json.loads(RESULTS_FILE.read_text(encoding="utf-8"))
        scanned_at = payload.get("scanned_at")
        if isinstance(scanned_at, str):
            try:
                # Parse ISO timestamp and format as local date/time without timezone
                dt = datetime.fromisoformat(scanned_at)
                scanned_at_str = dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                scanned_at_str = scanned_at
        else:
            scanned_at_str = "No scan available"
        return (
            payload.get("results", []),
            float(payload.get("score", 0)),
            scanned_at_str,
        )
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return [], 0.0, "No scan available"


def scan() -> tuple[list[dict[str, Any]], float]:
    results = scan_all(read_custom_values())
    save_results(results)
    errors = len([result for result in results if result["status"] == "ERROR"])
    failures = len([result for result in results if result["status"] == "FAIL"])
    add_log_entry(
        "Scan",
        f"Scan completed with {failures} failed control(s) and {errors} error(s).",
        "error" if errors else "warning" if failures else "success",
    )
    return results, calculate_score(results)


def build_sections(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {result["cis_id"]: result for result in results}
    custom_values = read_custom_values()
    sections = []
    for key, title in CATEGORY_TITLES:
        section_results = []
        for policy in POLICY_CATEGORIES[key]:
            if policy["cis_id"] not in by_id:
                continue
            result = by_id[policy["cis_id"]]
            result["configured_value"] = custom_values.get(policy["cis_id"], policy["required"])
            section_results.append(result)
        sections.append({"key": key, "title": title, "results": section_results})
    return sections


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("authenticated"):
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = USERS.get(username)
        password_hash = user.get("password") if user else None
        if password_hash and check_password_hash(password_hash, password):
            session.clear()
            session["authenticated"] = True
            session["username"] = username
            session["role"] = user["role"]
            add_log_entry("Login", f"User {username} signed in.", "success")
            flash("Login successful. Welcome to the CIS dashboard.", "success")
            return redirect(url_for("dashboard"))
        add_log_entry("Login", f"Failed login attempt for {username or 'unknown user'}.", "error")
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/login-guest", methods=["POST"])
def login_guest():
    if session.get("authenticated"):
        return redirect(url_for("dashboard"))
    session.clear()
    session["authenticated"] = True
    session["username"] = "guest"
    session["role"] = "Guest"
    add_log_entry("Login", "Guest user signed in.", "success")
    flash("Login successful. Welcome to the CIS dashboard.", "success")
    return redirect(url_for("dashboard"))


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    username = session.get("username", "admin")
    session.clear()
    add_log_entry("Logout", f"User {username} signed out.", "success")
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


@app.route("/", methods=["GET"])
@login_required
def dashboard() -> str:
    if session.get("role") == "Administrator":
        results, score = scan()
        scan_time = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
    else:
        results, score, scan_time = read_saved_scan()
    sections = build_sections(results)
    passed = sum(result["status"] == "PASS" for result in results)
    failed = sum(result["status"] == "FAIL" for result in results)
    return render_template(
        "dashboard.html",
        sections=sections,
        score=score,
        total=len(results),
        passed=passed,
        failed=failed,
        scan_time=scan_time,
        username=session.get("username", "guest"),
        role=session.get("role", "Guest"),
        can_modify=session.get("role") == "Administrator",
    )


@app.route("/policies/<category>", methods=["GET"])
@login_required
def policy_category(category: str) -> str:
    if category not in POLICY_CATEGORIES:
        flash("Unknown policy category.", "error")
        return redirect(url_for("dashboard"))
    if session.get("role") == "Administrator":
        results, score = scan()
        scan_time = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
    else:
        results, score, scan_time = read_saved_scan()
    sections = build_sections(results)
    section = next(section for section in sections if section["key"] == category)
    passed = sum(result["status"] == "PASS" for result in results)
    failed = sum(result["status"] == "FAIL" for result in results)
    return render_template(
        "policy_category.html",
        sections=sections,
        section=section,
        score=score,
        total=len(results),
        passed=passed,
        failed=failed,
        scan_time=scan_time,
        username=session.get("username", "guest"),
        role=session.get("role", "Guest"),
        can_modify=session.get("role") == "Administrator",
    )


def run_apply(cis_ids: list[str], action: str) -> None:
    known_policies = {
        policy["cis_id"]: policy
        for policies in POLICY_CATEGORIES.values()
        for policy in policies
    }
    cis_ids = list(dict.fromkeys(cis_id for cis_id in cis_ids if cis_id in known_policies))
    if not cis_ids:
        flash("Select at least one valid policy to apply.", "error")
        return
    custom_values = read_custom_values()
    results = apply_policies(cis_ids, custom_values)
    expected = {
        cis_id: custom_values.get(cis_id, known_policies[cis_id]["required"])
        for cis_id in cis_ids
    }
    mismatches = verify_policy_values(expected)
    for result in results:
        if result["cis_id"] in mismatches:
            result["success"] = False
            result["message"] = (
                f"{result['message']} Verification failed: Windows reports "
                f"{mismatches[result['cis_id']]!r}."
            )
    failures = [result for result in results if not result["success"]]
    for result in results:
        log_operation(action, result)
    if failures:
        flash(f"{len(failures)} of {len(results)} policies failed to apply. Review Activity Logs.", "error")
    else:
        flash(f"Successfully applied {len(results)} policy setting(s).", "success")


@app.route("/apply-selected", methods=["POST"])
@administrator_required
def apply_selected():
    cis_ids = request.form.getlist("policies")
    if not cis_ids:
        flash("Select at least one policy to apply.", "error")
    else:
        run_apply(cis_ids, "Apply Selected")
    return redirect_back()


@app.route("/apply-all/<category>", methods=["POST"])
@administrator_required
def apply_all(category: str):
    if category == "all":
        cis_ids = []
        for policy_category, _ in CATEGORY_TITLES:
            cis_ids.extend(category_ids(policy_category))
        action = "Apply All"
    else:
        cis_ids = category_ids(category)
        action = f"Apply All {category.title()}"
    if not cis_ids:
        flash("Unknown policy category.", "error")
    else:
        run_apply(cis_ids, action)
    return redirect_back()


@app.route("/apply-all", methods=["POST"])
@administrator_required
def apply_all_everything():
    return apply_all("all")


@app.route("/customize/<cis_id>", methods=["POST"])
@administrator_required
def customize_control(cis_id: str):
    found = next(
        (policy for policies in POLICY_CATEGORIES.values() for policy in policies if policy["cis_id"] == cis_id),
        None,
    )
    if found is None:
        add_log_entry("Edit", "Unknown CIS control.", "error", cis_id)
        flash("Unknown CIS control.", "error")
        return redirect(url_for("dashboard"))
    raw_value = request.form.get("value")
    if raw_value is None or not raw_value.strip():
        add_log_entry("Edit", "Validation failed: A value is required.", "error", cis_id, policy_name=found["name"])
        flash("A value is required.", "error")
        return redirect(url_for("dashboard"))
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        add_log_entry("Edit", "Validation failed: Value must be a whole number.", "error", cis_id, policy_name=found["name"])
        flash("Value must be a whole number.", "error")
        return redirect(url_for("dashboard"))
    minimum, maximum = found.get("input_min", 0), found.get("input_max", 99999)
    if not minimum <= value <= maximum:
        add_log_entry(
            "Edit",
            f"Validation failed: Value must be between {minimum} and {maximum}.",
            "error",
            cis_id,
            policy_name=found["name"],
        )
        flash(f"Value for {found['name']} must be between {minimum} and {maximum}.", "error")
        return redirect(url_for("dashboard"))
    try:
        result = apply_policy(cis_id, value)
    except Exception as exc:
        result = {
            "cis_id": cis_id, "policy_name": found["name"], "success": False,
            "message": f"Unexpected error while applying custom value: {exc}",
            "command": "", "returncode": None, "stdout": "", "stderr": str(exc),
        }
    if result["success"]:
        values = read_custom_values()
        values[cis_id] = value
        save_custom_values(values)
        result["message"] = f"Configuration saved and applied: {found['name']} = {value}."
    log_operation("Edit", result)
    flash(result["message"], "success" if result["success"] else "error")
    return redirect_back()


@app.route("/reset/<cis_id>", methods=["POST"])
@administrator_required
def reset_control(cis_id: str):
    try:
        result = reset_policy(cis_id)
    except Exception as exc:
        result = {
            "cis_id": cis_id, "policy_name": "", "success": False,
            "message": f"Unexpected error while resetting control: {exc}",
            "command": "", "returncode": None, "stdout": "", "stderr": str(exc),
        }
    if result["success"]:
        mismatches = verify_policy_values({cis_id: DEFAULT_POLICY_VALUES[cis_id]})
        if cis_id in mismatches:
            result["success"] = False
            result["message"] = (
                f"Reset command completed, but verification failed. "
                f"Expected {DEFAULT_POLICY_VALUES[cis_id]}, found {mismatches[cis_id]}."
            )
        else:
            values = read_custom_values()
            if cis_id in values:
                del values[cis_id]
                save_custom_values(values)
    log_operation("Reset", result)
    flash(result["message"], "success" if result["success"] else "error")
    return redirect_back()


@app.route("/reset-all", methods=["POST"])
@administrator_required
def reset_all():
    save_custom_values({})
    try:
        results = reset_all_policies()
    except Exception as exc:
        add_log_entry("Reset All", f"Unexpected error while resetting all controls: {exc}", "error")
        flash("Could not reset controls because an unexpected error occurred.", "error")
        return redirect(url_for("dashboard"))

    failures = [result for result in results if not result["success"]]
    if not failures:
        mismatches = verify_policy_values(DEFAULT_POLICY_VALUES)
        if mismatches:
            for result in results:
                if result["cis_id"] in mismatches:
                    result["success"] = False
                    result["message"] = (
                        "Reset command completed, but verification failed. "
                        f"Expected {DEFAULT_POLICY_VALUES[result['cis_id']]}, "
                        f"found {mismatches[result['cis_id']]}."
                    )
            failures = [result for result in results if not result["success"]]

    if failures:
        flash(
            f"Custom values were cleared, but {len(failures)} system policies could not be reset. "
            "Run the application as Administrator and review Activity Logs.",
            "error",
        )
    else:
        flash("Configuration restored to original default values. Compliance status has been refreshed.", "success")

    for result in results:
        log_operation("Reset All", result)

    return redirect(url_for("dashboard"))


@app.route("/reset-category/<category>", methods=["POST"])
@administrator_required
def reset_category(category: str):
    cis_ids = category_ids(category)
    if not cis_ids:
        flash("Unknown policy category.", "error")
        return redirect_back()

    defaults = {
        cis_id: DEFAULT_POLICY_VALUES[cis_id]
        for cis_id in cis_ids
        if cis_id in DEFAULT_POLICY_VALUES
    }
    values = read_custom_values()
    for cis_id in defaults:
        values.pop(cis_id, None)
    save_custom_values(values)

    try:
        results = apply_policies(list(defaults), defaults, validate=False)
    except Exception as exc:
        add_log_entry("Reset Category", f"Unexpected error while resetting {category}: {exc}", "error")
        flash("Could not reset this category because an unexpected error occurred.", "error")
        return redirect_back()

    failures = [result for result in results if not result["success"]]
    if not failures:
        mismatches = verify_policy_values(defaults)
        if mismatches:
            for result in results:
                if result["cis_id"] in mismatches:
                    result["success"] = False
                    result["message"] = (
                        "Reset command completed, but verification failed. "
                        f"Expected {defaults[result['cis_id']]}, found {mismatches[result['cis_id']]}."
                    )
            failures = [result for result in results if not result["success"]]

    title = next(
        (section_title for key, section_title in CATEGORY_TITLES if key == category),
        category.title(),
    )
    if failures:
        flash(f"{len(failures)} {title} control(s) could not be reset. Review Activity Logs.", "error")
    else:
        flash(f"{title} restored to original default values.", "success")

    for result in results:
        log_operation("Reset Category", result)

    return redirect_back()


@app.route("/export-pdf", methods=["GET"])
@login_required
def export_pdf() -> Response:
    results, score, scan_time = read_saved_scan()
    sections = build_sections(results)
    system_name = platform.node() or os.environ.get("COMPUTERNAME", "Unknown")
    passed_count = sum(result.get("status") == "PASS" for result in results)
    failed_count = sum(result.get("status") == "FAIL" for result in results)
    pdf = FPDF(orientation="L", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=False)
    pdf.set_margins(12, 12, 12)
    pdf.add_page()

    def safe(value: Any) -> str:
        return str(value if value is not None else "").encode("latin-1", "replace").decode("latin-1")

    def wrapped_lines(text: Any, width: float) -> list[str]:
        text = safe(text)
        available = max(width - 3, 2)
        lines: list[str] = []
        for paragraph in text.splitlines() or [""]:
            line = ""
            for character in paragraph:
                candidate = line + character
                if line and pdf.get_string_width(candidate) > available:
                    lines.append(line.rstrip())
                    line = character.lstrip()
                else:
                    line = candidate
            lines.append(line or " ")
        return lines

    columns = (
        ("CIS ID", 18),
        ("Policy Name", 92),
        ("Required", 62),
        ("Current", 62),
        ("Status", 24),
    )
    table_width = sum(width for _, width in columns)

    def table_header() -> None:
        pdf.set_fill_color(0, 94, 184)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 8)
        for label, width in columns:
            pdf.cell(width, 8, label, border=0, fill=True)
        pdf.ln(8)

    def section_header(title: str, continued: bool = False) -> None:
        pdf.set_fill_color(238, 245, 251)
        pdf.set_text_color(0, 74, 145)
        pdf.set_font("Helvetica", "B", 11)
        suffix = " (continued)" if continued else ""
        pdf.cell(table_width, 9, safe(title + suffix), border=0, fill=True)
        pdf.ln(11)
        table_header()

    # Report masthead
    pdf.set_fill_color(205, 22, 63)
    pdf.rect(0, 0, pdf.w, 7, style="F")
    pdf.set_text_color(26, 31, 36)
    pdf.set_font("Helvetica", "B", 24)
    pdf.cell(0, 14, "CIS Compliance Report")
    pdf.ln(14)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(74, 82, 96)
    pdf.cell(0, 6, "CIS Windows 11 Benchmark - System Hardening Assessment")
    pdf.ln(6)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(0, 94, 184)
    pdf.cell(0, 6, safe(f"System Name: {system_name}"))
    pdf.ln(6)
    pdf.ln(3)

    # Summary cards
    card_gap = 5
    card_width = (table_width - card_gap * 4) / 5
    for label, value, color in (
        ("OVERALL SCORE", f"{score:.0f}%", (0, 94, 184)),
        ("PASSED", str(passed_count), (22, 131, 58)),
        ("FAILED", str(failed_count), (205, 22, 63)),
        ("TOTAL CONTROLS", str(len(results)), (22, 131, 58)),
        ("SCAN DATE / TIME", scan_time, (74, 82, 96)),
    ):
        x, y = pdf.get_x(), pdf.get_y()
        pdf.set_fill_color(248, 250, 252)
        pdf.set_draw_color(217, 222, 229)
        pdf.rect(x, y, card_width, 20, style="DF")
        pdf.set_xy(x + 4, y + 3)
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_text_color(138, 146, 155)
        pdf.cell(card_width - 8, 4, label)
        pdf.set_xy(x + 4, y + 9)
        pdf.set_font("Helvetica", "B", 13 if label != "SCAN DATE / TIME" else 10)
        pdf.set_text_color(*color)
        pdf.cell(card_width - 8, 7, safe(value))
        pdf.set_xy(x + card_width + card_gap, y)
    pdf.set_xy(12, pdf.get_y() + 25)

    if not results:
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(74, 82, 96)
        pdf.cell(0, 10, "No saved scan data is available.")

    for section in sections:
        if not section["results"]:
            continue
        if pdf.get_y() + 20 > pdf.h - 14:
            pdf.add_page()
        section_header(section["title"])
        for result in section["results"]:
            values = (
                result.get("cis_id", ""),
                result.get("name", ""),
                result.get("required", ""),
                result.get("current", ""),
                result.get("status", ""),
            )
            pdf.set_font("Helvetica", "", 8)
            line_sets = [wrapped_lines(value, width) for value, (_, width) in zip(values, columns)]
            row_height = max(8, max(len(lines) for lines in line_sets) * 4 + 3)
            if pdf.get_y() + row_height > pdf.h - 14:
                pdf.add_page()
                section_header(section["title"], continued=True)
            x, y = pdf.get_x(), pdf.get_y()
            for index, (lines, (_, width)) in enumerate(zip(line_sets, columns)):
                pdf.set_draw_color(217, 222, 229)
                pdf.set_fill_color(255, 255, 255 if index % 2 == 0 else 254)
                pdf.rect(x, y, width, row_height, style="DF")
                pdf.set_xy(x + 1.5, y + 1.5)
                status = safe(values[-1]).upper()
                if index == 4:
                    pdf.set_font("Helvetica", "B", 8)
                    pdf.set_text_color(*({"PASS": (22, 131, 58), "FAIL": (205, 22, 63), "ERROR": (180, 95, 6)}.get(status, (74, 82, 96))))
                else:
                    pdf.set_font("Helvetica", "", 8)
                    pdf.set_text_color(26, 31, 36)
                pdf.multi_cell(width - 3, 4, "\n".join(lines), border=0)
                x += width
            pdf.set_xy(12, y + row_height)
        pdf.ln(7)

    # Footer on every page
    page_count = pdf.page_no()
    for page_number in range(1, page_count + 1):
        pdf.page = page_number
        pdf.set_xy(12, pdf.h - 10)
        pdf.set_draw_color(217, 222, 229)
        pdf.line(12, pdf.h - 12, pdf.w - 12, pdf.h - 12)
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(138, 146, 155)
        pdf.cell(0, 5, f"CIS Windows 11 Hardening  |  Page {page_number} of {page_count}", align="R")

    filename = f"CIS_Compliance_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    generated = pdf.output(dest="S")
    payload = bytes(generated) if not isinstance(generated, str) else generated.encode("latin-1")
    return Response(
        payload,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/logs", methods=["GET"])
@login_required
def logs() -> str:
    return render_template(
        "logs.html",
        logs=read_logs(),
        username=session.get("username", "guest"),
        role=session.get("role", "Guest"),
    )


if __name__ == "__main__":
    try:
        elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        elevated = False
    url = "http://127.0.0.1:5000/"
    print(f"Server starting (pid={os.getpid()}) elevated={elevated} url={url}")
    # Open the default web browser shortly after the server starts
    try:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    except Exception:
        pass
    # Disable the auto-reloader to avoid a non-elevated child process on Windows
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)
