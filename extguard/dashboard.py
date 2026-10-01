# dashboard.py - Flask analyst dashboard for ExtensionGuard
#
# Turns the CLI pipeline into a browseable analyst console. Read-only by
# default; remediation actions (approve/reject) require an explicit confirm
# and only write to a queue file - they never directly mutate Chrome policy.
#
# Routes:
#   GET  /                              - case list + recent alerts
#   GET  /case/<case_id>                - case detail view
#   POST /case/<case_id>/verify         - run forensics.verify_case + display
#   POST /case/<case_id>/approve        - enqueue an approve-remediation request
#   POST /case/<case_id>/reject         - enqueue a reject (false positive)
#   GET  /api/cases                     - JSON list of cases (for JS polling)
#   GET  /api/alerts                    - JSON tail of recent alerts
#   GET  /api/health                    - readiness check (no file paths)
#
# Security model (this is a LOCAL analyst tool):
#   - Binds to 127.0.0.1 by default. Use --host 0.0.0.0 deliberately if you
#     need remote access, and put it behind a reverse proxy with auth.
#   - No built-in authentication. The threat model assumes anyone with shell
#     access to the SOC workstation is trusted (same level as `regedit`).
#     Approve / reject still require the analyst to enter their name, which is
#     recorded in the queue and the chain of custody (with REMOTE_USER when a
#     proxy provides it) - the server's own OS account says nothing about who
#     clicked the button.
#   - State-changing POSTs require a CSRF token (per-session, in-memory).
#   - case_id values are validated against a strict allow-list pattern to
#     prevent path traversal into the quarantine directory.
#   - Remediation actions write to a queue file; `extguard-remediate
#     --process-queue` is the only thing that reads it. The dashboard NEVER
#     directly modifies the Chrome blocklist.
#   - The GitHub webhook is NOT served here: it has to be reachable from the
#     internet and this app must not be. Run `extguard-webhook` for it.

import argparse
import getpass
import json
import os
import re
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from extguard import paths
from extguard.logging_setup import get_logger
from extguard.remediators import forensics
from extguard.ttp_loader import library_stats

log = get_logger(__name__)


# Strict pattern for case directory names (defined in forensics, shared with
# the remediation queue consumer). It is the primary path-traversal defence.
CASE_ID_PATTERN = forensics.CASE_ID_PATTERN

# Analyst names: letters, digits, space and . _ @ ' - (1-64 characters)
ANALYST_PATTERN = re.compile(r"^[\w .@'-]{1,64}\Z")

# How much of the alert log the dashboard reads from the end of the file
ALERT_TAIL_MAX_BYTES = 8 * 1024 * 1024


def create_app(
    quarantine_root: Path | None = None,
    alerts_log: Path | None = None,
    queue_file: Path | None = None,
) -> Flask:
    """
    Build the Flask app with the configured paths.

    Factored as a create_app() function so tests can spin up isolated instances
    with their own quarantine / log / queue paths via Flask's test client.
    """
    app = Flask(
        __name__,
        template_folder="dashboard_templates",
        static_folder="dashboard_static",
    )
    # Defaults come from extguard.paths so the dashboard shows the same
    # quarantine that `extguard-remediate` writes to.
    app.config["QUARANTINE_ROOT"] = (
        Path(quarantine_root) if quarantine_root else paths.quarantine_root()
    )
    app.config["ALERTS_LOG"] = Path(alerts_log) if alerts_log else None
    app.config["QUEUE_FILE"] = Path(queue_file) if queue_file else paths.queue_file()
    # Secret key for session-cookie signing. Generated fresh per process; CSRF
    # tokens stored in the session are invalidated when the server restarts,
    # which is the right behaviour for a local analyst tool.
    app.config["SECRET_KEY"] = secrets.token_urlsafe(32)

    # ----- Routes ----------------------------------------------------------

    @app.route("/")
    def index():
        cases = _list_cases(app.config["QUARANTINE_ROOT"])
        alerts = _tail_alerts(app.config["ALERTS_LOG"], limit=20)
        return render_template(
            "index.html",
            cases=cases,
            alerts=alerts,
            csrf_token=_get_csrf_token(),
        )

    @app.route("/case/<case_id>")
    def case_detail(case_id):
        case_dir = _resolve_case(app.config["QUARANTINE_ROOT"], case_id)
        coc = _load_coc(case_dir)
        triage = _load_optional_json(case_dir / "triage.json")
        playbook_md = _load_optional_text(case_dir / "rotation_playbook.md")
        manifest = _load_optional_json(case_dir / "manifest.json")
        return render_template(
            "case.html",
            case_id=case_id,
            case_dir=case_dir,
            coc=coc,
            triage=triage,
            playbook_md=playbook_md,
            manifest=manifest,
            csrf_token=_get_csrf_token(),
        )

    @app.route("/case/<case_id>/verify", methods=["POST"])
    def verify(case_id):
        _check_csrf()
        case_dir = _resolve_case(app.config["QUARANTINE_ROOT"], case_id)
        result = forensics.verify_case(str(case_dir))
        log.info("Verification run for case %s: ok=%s", case_id, result["ok"])
        return render_template(
            "verify_result.html",
            case_id=case_id,
            result=result,
        )

    @app.route("/case/<case_id>/approve", methods=["POST"])
    def approve(case_id):
        _check_csrf()
        case_dir = _resolve_case(app.config["QUARANTINE_ROOT"], case_id)
        action = (request.form.get("action") or "kill").strip()
        if action not in ("kill", "playbook", "resolve"):
            abort(400, f"Unknown action: {action}")
        identity = _analyst_identity()
        notes = (request.form.get("notes") or "").strip()[:1000]
        # Record the decision in the case first: if the chain of custody no
        # longer verifies, nothing gets queued
        _record_decision(
            case_dir, f"dashboard_approve_{action}", identity, notes or f"action={action}"
        )
        _enqueue_remediation(
            queue_file=app.config["QUEUE_FILE"],
            case_id=case_id,
            decision="approve",
            action=action,
            notes=notes,
            identity=identity,
        )
        return redirect(url_for("case_detail", case_id=case_id))

    @app.route("/case/<case_id>/reject", methods=["POST"])
    def reject(case_id):
        _check_csrf()
        case_dir = _resolve_case(app.config["QUARANTINE_ROOT"], case_id)
        identity = _analyst_identity()
        notes = (request.form.get("notes") or "").strip()[:1000]
        _record_decision(
            case_dir, "dashboard_reject", identity, notes or "Marked as false positive"
        )
        _enqueue_remediation(
            queue_file=app.config["QUEUE_FILE"],
            case_id=case_id,
            decision="reject",
            action="none",
            notes=notes,
            identity=identity,
        )
        return redirect(url_for("case_detail", case_id=case_id))

    # ----- JSON APIs for polling / SIEM integration -----------------------

    @app.route("/api/cases")
    def api_cases():
        return jsonify(_list_cases(app.config["QUARANTINE_ROOT"]))

    @app.route("/api/alerts")
    def api_alerts():
        try:
            limit = max(1, min(int(request.args.get("limit", 20)), 200))
        except ValueError:
            limit = 20
        return jsonify(_tail_alerts(app.config["ALERTS_LOG"], limit=limit))

    @app.route("/api/health")
    def api_health():
        """Readiness check for monitoring. Counts only - no file paths."""
        return jsonify(
            {
                "status": "ok",
                "cases": len(_list_cases(app.config["QUARANTINE_ROOT"])),
                "ttp_library": library_stats(),
                "now": datetime.now(timezone.utc).isoformat(),
            }
        )

    # ----- Error handlers --------------------------------------------------

    @app.errorhandler(404)
    def not_found(_exc):
        return render_template("error.html", code=404, message="Not found"), 404

    @app.errorhandler(400)
    def bad_request(exc):
        return render_template("error.html", code=400, message=str(exc)), 400

    @app.errorhandler(409)
    def conflict(exc):
        return render_template("error.html", code=409, message=str(exc)), 409

    return app


# ---------------------------------------------------------------------------
# Internal helpers - kept at module level for testability
# ---------------------------------------------------------------------------


def _list_cases(quarantine_root: Path) -> list:
    """
    Enumerate quarantine cases and return a list of summary dicts.
    Sorted newest first (by case directory name, which starts with timestamp).
    """
    if not quarantine_root.exists():
        return []

    cases = []
    for entry in quarantine_root.iterdir():
        if not entry.is_dir():
            continue
        if not CASE_ID_PATTERN.match(entry.name):
            continue  # Skip anything that doesn't look like a case folder

        coc = _load_optional_json(entry / "chain_of_custody.json") or {}
        ext_block = coc.get("extension", {})
        custody = coc.get("custody_log", [])

        cases.append(
            {
                "case_id": entry.name,
                "preserved_at": coc.get("preserved_at"),
                "operator": coc.get("operator"),
                "extension_id": ext_block.get("id"),
                "extension_name": ext_block.get("name"),
                "n_actions": len(custody),
                "last_action": custody[-1]["action"] if custody else None,
            }
        )

    cases.sort(key=lambda c: c["case_id"], reverse=True)
    return cases


def _tail_alerts(log_path: Path | None, limit: int = 20) -> list:
    """Return the last `limit` JSON lines from the alerts log file (newest first)."""
    if log_path is None or not log_path.exists():
        return []

    try:
        lines = _read_last_lines(log_path, limit)
    except OSError:
        return []

    alerts = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            alerts.append(json.loads(line))
        except json.JSONDecodeError:
            # Skip non-JSON lines (e.g. interleaved human-readable output)
            continue
    return list(reversed(alerts))  # newest first


def _read_last_lines(path: Path, n: int, block: int = 64 * 1024) -> list:
    """
    The last n non-empty lines of a file, read backwards from the end in
    blocks - the monitor's alert log grows forever, and the old version read
    all of it on every page load. Reads at most ALERT_TAIL_MAX_BYTES.
    """
    with path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        pos = f.tell()
        data = b""
        while pos > 0 and data.count(b"\n") <= n and len(data) < ALERT_TAIL_MAX_BYTES:
            step = min(block, pos)
            pos -= step
            f.seek(pos)
            data = f.read(step) + data
    lines = data.split(b"\n")
    if pos > 0:
        lines = lines[1:]  # the first line was cut in the middle
    text = [line.decode("utf-8", errors="replace") for line in lines if line.strip()]
    return text[-n:]


def _resolve_case(quarantine_root: Path, case_id: str) -> Path:
    """
    Validate case_id and resolve it to a Path inside quarantine_root.
    Aborts with 400 on invalid input, 404 on missing case.

    The CASE_ID_PATTERN check is the primary path-traversal defence: even
    Path resolution within quarantine_root would still allow ".." in the
    name string, so we reject before constructing a Path at all.
    """
    if not CASE_ID_PATTERN.match(case_id):
        abort(400, f"Invalid case_id format: {case_id!r}")
    case_dir = (quarantine_root / case_id).resolve()
    # Belt-and-braces: confirm the resolved path is still inside quarantine_root
    try:
        case_dir.relative_to(quarantine_root.resolve())
    except ValueError:
        abort(400, "case_id escaped the quarantine directory")
    if not case_dir.is_dir():
        abort(404)
    return case_dir


def _load_coc(case_dir: Path) -> dict:
    """Load chain_of_custody.json - abort 404 if absent (the case is malformed)."""
    coc = _load_optional_json(case_dir / "chain_of_custody.json")
    if coc is None:
        abort(404, "chain_of_custody.json missing from case folder")
    return coc


def _load_optional_json(path: Path):
    """Load a JSON file or return None if absent / malformed."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _load_optional_text(path: Path) -> str | None:
    """Load a text file or return None if absent."""
    if not path.exists():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _enqueue_remediation(
    queue_file: Path,
    case_id: str,
    decision: str,
    action: str,
    notes: str,
    identity: dict,
):
    """
    Append a remediation request to the queue file.
    `extguard-remediate --process-queue` reads from this; the dashboard never
    directly invokes registry writes or other privileged operations.
    """
    entry = {
        "queued_at": datetime.now(timezone.utc).isoformat(),
        "case_id": case_id,
        "decision": decision,
        "action": action,
        "notes": notes,
        "actor": identity["analyst"],
        "remote_user": identity["remote_user"],
        "server_account": identity["server_account"],
    }
    queue_file.parent.mkdir(parents=True, exist_ok=True)
    with queue_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    log.info(
        "Queued remediation: case=%s decision=%s action=%s",
        case_id,
        decision,
        action,
    )


def _analyst_identity() -> dict:
    """
    Who made this decision. The analyst types their name in the form (400 if
    it's missing); REMOTE_USER is added when an authenticating proxy / WSGI
    server sets it. The server's OS account is recorded separately - on a
    shared console it is the same for everyone, so it can't be the actor.
    """
    analyst = (request.form.get("analyst") or "").strip()
    if not ANALYST_PATTERN.match(analyst):
        abort(400, "Enter your name (1-64 letters, digits, spaces or . _ @ ' -)")
    try:
        server_account = getpass.getuser()
    except Exception:  # getuser() raises when no user name is available
        server_account = "unknown"
    return {
        "analyst": analyst,
        "remote_user": request.environ.get("REMOTE_USER"),
        "server_account": server_account,
    }


def _record_decision(case_dir: Path, action: str, identity: dict, notes: str):
    """Append the decision to the case's chain of custody (409 if it won't verify)."""
    actor = identity["analyst"]
    if identity["remote_user"]:
        actor += f" (remote_user={identity['remote_user']})"
    result = forensics.append_custody_action(
        case_dir=str(case_dir),
        action=action,
        actor=f"{actor} via dashboard",
        notes=notes,
    )
    if not result.get("ok"):
        abort(409, f"Case not updated: {result.get('error')}")


def _get_csrf_token() -> str:
    """
    Per-session CSRF token. Generated on first access and stored in the Flask
    session cookie. All POST routes verify it via _check_csrf().
    """
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


def _check_csrf():
    """Verify the submitted form's _csrf field matches the session token."""
    submitted = request.form.get("_csrf", "")
    expected = session.get("_csrf", "")
    if not submitted or not expected or not secrets.compare_digest(submitted, expected):
        abort(400, "CSRF token mismatch")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="ExtensionGuard analyst dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  extguard-dashboard                              # localhost:5000\n"
            "  extguard-dashboard --port 8080\n"
            "  extguard-dashboard --alerts-log alerts.jsonl    # show recent alerts\n"
        ),
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address (default: 127.0.0.1 - localhost only)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Port to listen on (default: 5000)",
    )
    parser.add_argument(
        "--quarantine",
        default=None,
        help="Path to the quarantine directory "
        "(default: $EXTGUARD_QUARANTINE or ~/.extguard/quarantine)",
    )
    parser.add_argument(
        "--alerts-log",
        default=None,
        help="Path to a JSONL alert log to tail in the UI (optional)",
    )
    parser.add_argument(
        "--queue-file",
        default=None,
        help="Path to the remediation queue file (default: ~/.extguard/remediation_queue.jsonl)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable Flask debug mode (auto-reload, debug pages). LOCAL USE ONLY.",
    )
    args = parser.parse_args()

    if args.host != "127.0.0.1":
        print(
            f"WARNING: binding to {args.host} exposes the dashboard to the network.\n"
            "  Put it behind a reverse proxy with authentication, or revert to 127.0.0.1.",
            file=sys.stderr,
        )

    app = create_app(
        quarantine_root=args.quarantine,
        alerts_log=args.alerts_log,
        queue_file=args.queue_file,
    )

    print(f"ExtensionGuard dashboard listening on http://{args.host}:{args.port}")
    print(f"  Quarantine root: {app.config['QUARANTINE_ROOT']}")
    if app.config["ALERTS_LOG"]:
        print(f"  Alerts log:      {app.config['ALERTS_LOG']}")
    print(f"  Queue file:      {app.config['QUEUE_FILE']}")
    print("  Approvals run when you execute: extguard-remediate --process-queue")
    print("  GitHub TTP webhook: run `extguard-webhook` separately (not served here)")

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
