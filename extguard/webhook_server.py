# webhook_server.py - GitHub webhook receiver for TTP library updates
#
# Why a separate server?
#   GitHub has to reach the webhook from the internet. The analyst dashboard
#   has no authentication and must stay on localhost. Serving both from one
#   app meant exposing the dashboard to receive a webhook. This app has two
#   routes and nothing else:
#
#     POST /webhook/github   - GitHub push events (HMAC-SHA256 verified)
#     GET  /healthz          - liveness check
#
# Hardening:
#   - Refuses to start without a webhook secret.
#   - X-Hub-Signature-256 is verified over the raw body (constant time).
#   - X-GitHub-Delivery IDs are remembered (and persisted), so a captured
#     request can't be replayed to trigger syncs.
#   - The sync runs in a background thread and the request returns 202 at
#     once (GitHub gives up after 10 seconds). One sync runs at a time; pushes
#     that arrive meanwhile collapse into one follow-up sync.
#   - The sync STAGES the new library; it only reaches Claude's prompt after
#     `extguard-ttp-sync --activate` (unless "auto_activate": true).
#
# Usage:
#   extguard-webhook                       # 127.0.0.1:8765, config from extguard.conf.json
#   extguard-webhook --host 0.0.0.0 --port 8765
#   Put it behind a TLS reverse proxy / tunnel and point GitHub at
#   https://<host>/webhook/github

import argparse
import json
import sys
import threading
from collections import OrderedDict
from pathlib import Path

from flask import Flask, jsonify, request

from extguard import paths
from extguard.logging_setup import get_logger, redact
from extguard.ttp_ingestor import activate_pending, sync_from_github, verify_github_signature

log = get_logger(__name__)

MAX_BODY_BYTES = 10 * 1024 * 1024  # GitHub push payloads are far smaller
MAX_REMEMBERED_DELIVERIES = 2000


class DeliveryLog:
    """
    Remembers X-GitHub-Delivery IDs already processed. A replayed request
    carries a valid signature but an old delivery ID, so it is rejected.
    """

    def __init__(self, path: Path | None, limit: int = MAX_REMEMBERED_DELIVERIES):
        self.path = path
        self.limit = limit
        self._lock = threading.Lock()
        self._seen: OrderedDict = OrderedDict()
        if path and path.exists():
            try:
                for delivery in json.loads(path.read_text(encoding="utf-8"))[-limit:]:
                    self._seen[str(delivery)] = True
            except (OSError, ValueError, TypeError):
                log.warning("Could not read %s - starting with an empty delivery log", path)

    def first_time(self, delivery_id: str) -> bool:
        """Record the ID; True if it had not been seen before."""
        with self._lock:
            if delivery_id in self._seen:
                return False
            self._seen[delivery_id] = True
            while len(self._seen) > self.limit:
                self._seen.popitem(last=False)
            self._save()
            return True

    def _save(self):
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(list(self._seen)), encoding="utf-8")
            tmp.replace(self.path)
        except OSError as exc:
            log.warning("Could not save the webhook delivery log: %s", exc)


class SyncRunner:
    """Runs one TTP sync at a time in a background thread."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._lock = threading.Lock()
        self._running = False
        self._rerun = False
        self._thread: threading.Thread | None = None
        self.last_result: dict | None = None

    def trigger(self) -> str:
        """Start a sync, or schedule one follow-up if a sync is running."""
        with self._lock:
            if self._running:
                self._rerun = True
                return "queued"
            self._running = True
            self._thread = threading.Thread(target=self._loop, name="ttp-sync", daemon=True)
            self._thread.start()
            return "started"

    def wait(self, timeout: float = 30.0) -> bool:
        """Wait for the current sync to finish (used by tests and shutdown)."""
        thread = self._thread
        if thread:
            thread.join(timeout)
            return not thread.is_alive()
        return True

    def _loop(self):
        while True:
            self.last_result = self._sync_once()
            with self._lock:
                if not self._rerun:
                    self._running = False
                    return
                self._rerun = False

    def _sync_once(self) -> dict:
        cfg = self.cfg
        try:
            result = sync_from_github(
                owner=cfg["owner"],
                repo=cfg["repo"],
                path=cfg.get("path", ""),
                branch=cfg.get("branch", "main"),
                github_token=cfg.get("token"),
                delete_orphans=cfg.get("delete_orphans", False),
                require_verified_commit=bool(cfg.get("require_verified_commit")),
            )
            if result.get("ok") and cfg.get("auto_activate"):
                result["activation"] = activate_pending()
        except Exception as exc:  # a background thread must never die silently
            result = {"ok": False, "errors": [redact(str(exc))]}
        log.info("Webhook-triggered TTP sync finished: ok=%s", result.get("ok"))
        return result


def create_webhook_app(cfg: dict, deliveries_file: Path | None = None) -> Flask:
    """Build the webhook app. `cfg` is the `webhook` config section."""
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES
    app.config["WEBHOOK_CFG"] = cfg or {}
    app.config["DELIVERIES"] = DeliveryLog(deliveries_file)
    app.config["SYNC_RUNNER"] = SyncRunner(cfg or {})

    @app.route("/healthz")
    def healthz():
        return jsonify({"status": "ok"})

    @app.route("/webhook/github", methods=["POST"])
    def webhook_github():
        cfg = app.config["WEBHOOK_CFG"]
        if not cfg.get("secret") or not cfg.get("owner") or not cfg.get("repo"):
            log.warning("Webhook hit but secret / owner / repo not configured - rejecting")
            return jsonify({"error": "webhook not configured"}), 503

        signature = request.headers.get("X-Hub-Signature-256", "")
        payload = request.get_data()  # raw bytes - HMAC needs the unmodified body
        if not verify_github_signature(payload, signature, cfg["secret"]):
            log.warning("Webhook signature verification FAILED")
            return jsonify({"error": "invalid signature"}), 401

        # Replay defence - only after the signature check, so unauthenticated
        # requests can't fill the delivery log
        delivery = request.headers.get("X-GitHub-Delivery", "").strip()
        if not delivery or len(delivery) > 100:
            return jsonify({"error": "missing X-GitHub-Delivery header"}), 400
        if not app.config["DELIVERIES"].first_time(delivery):
            log.warning("Replayed webhook delivery %s rejected", delivery)
            return jsonify({"error": "delivery already processed"}), 409

        event = request.headers.get("X-GitHub-Event", "")
        if event == "ping":
            # GitHub sends a ping when the webhook is first set up
            return jsonify({"ok": True, "message": "pong"})
        if event != "push":
            return jsonify({"ok": True, "ignored": event}), 200

        # Parse the exact bytes that were signed (the webhook must be set to
        # content type application/json)
        try:
            body = json.loads(payload)
        except ValueError:
            body = {}
        ref_pushed = body.get("ref", "") if isinstance(body, dict) else ""
        target_branch = cfg.get("branch", "main")
        if ref_pushed != f"refs/heads/{target_branch}":
            return jsonify({"ok": True, "ignored_ref": ref_pushed}), 200

        state = app.config["SYNC_RUNNER"].trigger()
        log.info("Webhook %s: TTP sync %s", delivery, state)
        return jsonify(
            {
                "ok": True,
                "sync": state,
                "activation": "automatic" if cfg.get("auto_activate") else "pending review",
            }
        ), 202

    return app


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="ExtensionGuard GitHub webhook receiver (TTP library updates)",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="Port (default 8765)")
    parser.add_argument("--config", default=None, help="Config file with a `webhook` section")
    args = parser.parse_args(argv)

    cfg = paths.load_config_section("webhook", args.config) or {}
    missing = [key for key in ("secret", "owner", "repo") if not cfg.get(key)]
    if missing:
        print(
            f"The webhook section of extguard.conf.json is missing: {', '.join(missing)}",
            file=sys.stderr,
        )
        return 2

    app = create_webhook_app(cfg, deliveries_file=paths.webhook_deliveries_file())
    print(f"ExtensionGuard webhook listening on http://{args.host}:{args.port}/webhook/github")
    print(f"  Repo:        {cfg['owner']}/{cfg['repo']}@{cfg.get('branch', 'main')}")
    print(
        "  Activation:  "
        + ("automatic" if cfg.get("auto_activate") else "manual (extguard-ttp-sync --activate)")
    )
    print("  Serve it over HTTPS (reverse proxy or tunnel) - GitHub sends the payload in clear.")
    app.run(host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
