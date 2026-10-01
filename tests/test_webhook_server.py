# tests/test_webhook_server.py - the standalone GitHub webhook receiver
#
# The webhook moved out of the dashboard (which must stay on localhost).
# These tests cover signature checks, replay protection, the 202 + background
# sync, and that the dashboard no longer serves the route at all.

import hashlib
import hmac
import itertools
import threading
from unittest.mock import patch

import pytest

from extguard.webhook_server import DeliveryLog, SyncRunner, create_webhook_app

SECRET = "test-secret"
CFG = {"owner": "test", "repo": "ttp", "branch": "main", "secret": SECRET}
_delivery_ids = itertools.count(1)


def _signed(body: bytes, event: str = "push", delivery: str | None = None) -> dict:
    sig = "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    return {
        "X-Hub-Signature-256": sig,
        "X-GitHub-Event": event,
        "X-GitHub-Delivery": delivery or f"delivery-{next(_delivery_ids)}",
    }


@pytest.fixture
def app(tmp_path):
    app = create_webhook_app(dict(CFG), deliveries_file=tmp_path / "deliveries.json")
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


OK_SYNC = {"ok": True, "fetched": 1, "skipped": 0, "deleted": 0, "errors": [], "files": ["a.md"]}


class TestAuthentication:
    def test_no_signature_rejected_401(self, client):
        resp = client.post("/webhook/github", data=b'{"ref":"refs/heads/main"}')
        assert resp.status_code == 401

    def test_bad_signature_rejected_401(self, client):
        resp = client.post(
            "/webhook/github",
            data=b'{"ref":"refs/heads/main"}',
            headers={"X-Hub-Signature-256": "sha256=00000000", "X-GitHub-Delivery": "x"},
        )
        assert resp.status_code == 401

    def test_no_secret_returns_503(self, tmp_path):
        app = create_webhook_app({}, deliveries_file=None)
        resp = app.test_client().post("/webhook/github", data=b"{}")
        assert resp.status_code == 503

    def test_missing_delivery_id_rejected(self, client):
        body = b'{"ref":"refs/heads/main"}'
        headers = _signed(body)
        del headers["X-GitHub-Delivery"]
        resp = client.post("/webhook/github", data=body, headers=headers)
        assert resp.status_code == 400


class TestEvents:
    def test_ping_returns_pong(self, client):
        body = b'{"zen": "Always test"}'
        resp = client.post("/webhook/github", data=body, headers=_signed(body, "ping"))
        assert resp.status_code == 200
        assert b"pong" in resp.data

    def test_non_push_event_ignored(self, client):
        body = b'{"action":"opened"}'
        resp = client.post("/webhook/github", data=body, headers=_signed(body, "pull_request"))
        assert resp.status_code == 200
        assert b"ignored" in resp.data

    def test_push_to_wrong_branch_ignored(self, client):
        body = b'{"ref":"refs/heads/feature-branch"}'
        with patch("extguard.webhook_server.sync_from_github") as mock_sync:
            resp = client.post("/webhook/github", data=body, headers=_signed(body))
        assert resp.status_code == 200
        assert b"ignored_ref" in resp.data
        mock_sync.assert_not_called()

    def test_push_returns_202_and_syncs_in_background(self, app, client):
        body = b'{"ref":"refs/heads/main"}'
        with patch("extguard.webhook_server.sync_from_github", return_value=OK_SYNC) as mock_sync:
            resp = client.post("/webhook/github", data=body, headers=_signed(body))
            assert resp.status_code == 202
            assert resp.get_json()["activation"] == "pending review"
            assert app.config["SYNC_RUNNER"].wait(5)

        mock_sync.assert_called_once()
        kwargs = mock_sync.call_args.kwargs
        assert kwargs["owner"] == "test"
        assert kwargs["repo"] == "ttp"
        assert kwargs["branch"] == "main"
        assert app.config["SYNC_RUNNER"].last_result["ok"] is True

    def test_auto_activate_activates_after_sync(self, tmp_path):
        app = create_webhook_app(dict(CFG, auto_activate=True), deliveries_file=None)
        body = b'{"ref":"refs/heads/main"}'
        with (
            patch("extguard.webhook_server.sync_from_github", return_value=dict(OK_SYNC)),
            patch("extguard.webhook_server.activate_pending", return_value={"ok": True}) as act,
        ):
            resp = app.test_client().post("/webhook/github", data=body, headers=_signed(body))
            assert resp.status_code == 202
            assert app.config["SYNC_RUNNER"].wait(5)
        act.assert_called_once()


class TestReplay:
    def test_replayed_delivery_rejected(self, client):
        body = b'{"zen": "hi"}'
        headers = _signed(body, "ping", delivery="same-id")
        assert client.post("/webhook/github", data=body, headers=headers).status_code == 200
        assert client.post("/webhook/github", data=body, headers=headers).status_code == 409

    def test_delivery_log_survives_restart(self, tmp_path):
        path = tmp_path / "deliveries.json"
        assert DeliveryLog(path).first_time("abc") is True
        assert DeliveryLog(path).first_time("abc") is False

    def test_delivery_log_is_bounded(self, tmp_path):
        log = DeliveryLog(tmp_path / "d.json", limit=3)
        for i in range(5):
            log.first_time(str(i))
        # The oldest IDs were forgotten, the newest remembered
        assert log.first_time("0") is True
        assert log.first_time("4") is False


class TestSyncRunner:
    def test_pushes_during_a_sync_collapse_into_one_rerun(self):
        started = threading.Event()
        release = threading.Event()
        calls = []

        def slow_sync(**kwargs):
            calls.append(1)
            started.set()
            release.wait(5)
            return dict(OK_SYNC)

        runner = SyncRunner(dict(CFG))
        with patch("extguard.webhook_server.sync_from_github", side_effect=slow_sync):
            assert runner.trigger() == "started"
            assert started.wait(5)
            assert runner.trigger() == "queued"
            assert runner.trigger() == "queued"
            release.set()
            assert runner.wait(5)
        assert len(calls) == 2  # the running sync + one follow-up

    def test_sync_exception_is_captured(self):
        runner = SyncRunner(dict(CFG))
        with patch("extguard.webhook_server.sync_from_github", side_effect=RuntimeError("boom")):
            runner.trigger()
            assert runner.wait(5)
        assert runner.last_result["ok"] is False


class TestSeparation:
    def test_dashboard_no_longer_serves_the_webhook(self, tmp_path):
        from extguard.dashboard import create_app

        app = create_app(quarantine_root=tmp_path / "quarantine")
        body = b'{"ref":"refs/heads/main"}'
        resp = app.test_client().post("/webhook/github", data=body, headers=_signed(body))
        assert resp.status_code in (404, 405)

    def test_webhook_app_has_no_dashboard_routes(self, client):
        assert client.get("/").status_code == 404
        assert client.get("/api/cases").status_code == 404
        assert client.get("/healthz").status_code == 200

    def test_cli_refuses_to_start_without_secret(self, tmp_path, capsys):
        from extguard.webhook_server import main

        cfg = tmp_path / "extguard.conf.json"
        cfg.write_text('{"webhook": {"owner": "o", "repo": "r"}}')
        assert main(["--config", str(cfg)]) == 2
        assert "secret" in capsys.readouterr().err
