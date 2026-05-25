# tests/test_dashboard.py - Flask analyst dashboard tests
#
# Uses Flask's built-in test client - no real HTTP server needed. Each test
# spins up a fresh app with its own tmp_path-based quarantine + queue file
# so they're fully isolated.

import json
import re
from pathlib import Path

import pytest

from dashboard import CASE_ID_PATTERN, create_app
from remediators import forensics

# ---------------------------------------------------------------------------
# Shared test scaffolding
# ---------------------------------------------------------------------------


@pytest.fixture
def quarantine_dir(tmp_path):
    """An empty quarantine directory the dashboard can list."""
    d = tmp_path / "quarantine"
    d.mkdir()
    return d


@pytest.fixture
def queue_file(tmp_path):
    return tmp_path / "queue.jsonl"


@pytest.fixture
def alerts_log(tmp_path):
    return tmp_path / "alerts.jsonl"


@pytest.fixture
def app(quarantine_dir, alerts_log, queue_file):
    app = create_app(
        quarantine_root=quarantine_dir,
        alerts_log=alerts_log,
        queue_file=queue_file,
    )
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def real_case(quarantine_dir, benign_manifest_raw):
    """A real preserved case folder we can navigate to via the dashboard."""
    result = forensics.preserve(
        extension_id="abcdefghijklmnopqrstuvwxyzabcdef",
        extension_name="Test Extension",
        crx_bytes=b"fake-crx-bytes",
        manifest=benign_manifest_raw,
        triage_result={
            "extension_name": "Test Extension",
            "risk_level": "high",
            "ai_risk_score": 75,
            "composite_score": 75,
            "iocs": ["test IOC"],
            "mitre_techniques": ["T1176"],
            "analyst_narrative": "Test narrative",
        },
        quarantine_root=quarantine_dir,
    )
    return Path(result["case_dir"])


# ---------------------------------------------------------------------------
# Path-traversal defence (the security-critical bit)
# ---------------------------------------------------------------------------


class TestCaseIdValidation:
    """CASE_ID_PATTERN must reject anything that could escape the quarantine dir."""

    @pytest.mark.parametrize(
        "good",
        [
            # Hex short IDs (from CRX hash or name hash)
            "20260522-164620-abcdef01",
            "20260101-000000-12345678",
            "20260101-000000-deadbeef",
            "20260101-000000-12345678-2",  # collision suffix
            "20260101-000000-12345678-overflow-aBcDeF12",
            # Chrome a-p alphabet IDs (when short_id comes from extension_id)
            "20260101-000000-abcdefgh",
            "20260101-000000-ponmlkji",
        ],
    )
    def test_valid_case_ids_accepted(self, good):
        assert CASE_ID_PATTERN.match(good)

    @pytest.mark.parametrize(
        "bad",
        [
            "..",
            ".",
            "20260101",
            "20260101-000000-XYZ",  # uppercase rejected
            "20260101-000000-zzzzzzzz",  # 'z' is outside both hex and a-p
            "20260101-000000-abcdefgq",  # 'q' is outside a-p range
            "20260101-000000-abcdefg",  # only 7 chars
            "20260101-000000-deadbeef; rm -rf /",
            "20260101-000000-deadbeef$(id)",  # command injection attempt
            "..deadbeef",  # leading dots
            "",
        ],
    )
    def test_invalid_case_ids_rejected(self, bad):
        assert not CASE_ID_PATTERN.match(bad)

    def test_path_traversal_with_slashes_blocked_by_router(self, client):
        """URL-encoded slashes in the segment - Flask's router handles this
        before our handler runs and returns 404 (no route matches).
        Either 400 (we caught it) or 404 (Flask caught it) is acceptable -
        what matters is the response is NOT 200 and no file was disclosed."""
        resp = client.get("/case/..%2F..%2Fetc%2Fpasswd")
        assert resp.status_code in (400, 404)
        # And definitely no /etc/passwd content
        assert b"root:" not in resp.data

    def test_path_traversal_without_slashes_returns_400(self, client):
        """Path traversal attempts that DO reach our handler must return 400."""
        # Single dot-dot, no slashes - hits our handler
        resp = client.get("/case/..")
        assert resp.status_code == 400

        # Looks-like-a-case-id but contains shell metachars
        resp = client.get("/case/20260101-000000-deadbeef;rm")
        assert resp.status_code == 400

    def test_missing_case_returns_404(self, client):
        resp = client.get("/case/20260101-000000-deadbeef")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Read-only views
# ---------------------------------------------------------------------------


class TestIndex:
    def test_empty_dashboard_renders(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"ExtensionGuard" in resp.data

    def test_case_appears_in_index(self, client, real_case):
        resp = client.get("/")
        assert resp.status_code == 200
        assert real_case.name.encode() in resp.data
        assert b"Test Extension" in resp.data

    def test_alerts_show_up(self, client, alerts_log):
        alerts_log.write_text(
            json.dumps(
                {
                    "rule": "RULE-01",
                    "severity": "critical",
                    "alert_time": "2026-05-22T10:00:00Z",
                    "extension": {"title": "Suspect"},
                    "detail": {"description": "C2 beacon"},
                }
            )
            + "\n"
        )
        resp = client.get("/")
        assert b"RULE-01" in resp.data
        assert b"Suspect" in resp.data


class TestCaseDetail:
    def test_case_page_shows_extension_info(self, client, real_case):
        resp = client.get(f"/case/{real_case.name}")
        assert resp.status_code == 200
        assert b"Test Extension" in resp.data
        assert b"abcdefghijklmnopqrstuvwxyzabcdef" in resp.data

    def test_case_page_shows_triage(self, client, real_case):
        resp = client.get(f"/case/{real_case.name}")
        assert b"Test narrative" in resp.data
        assert b"T1176" in resp.data

    def test_case_page_shows_artifact_hashes(self, client, real_case):
        resp = client.get(f"/case/{real_case.name}")
        # sample.crx and manifest.json should both have hash rows
        assert b"sample.crx" in resp.data
        assert b"manifest.json" in resp.data


# ---------------------------------------------------------------------------
# JSON APIs
# ---------------------------------------------------------------------------


class TestApis:
    def test_health(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert "cases" in data

    def test_cases_api(self, client, real_case):
        resp = client.get("/api/cases")
        data = resp.get_json()
        assert len(data) == 1
        assert data[0]["case_id"] == real_case.name
        assert data[0]["extension_name"] == "Test Extension"

    def test_alerts_api_returns_jsonl(self, client, alerts_log):
        alerts_log.write_text(
            "\n".join(json.dumps({"rule": f"R-{i}", "severity": "high"}) for i in range(5))
        )
        resp = client.get("/api/alerts?limit=3")
        data = resp.get_json()
        assert len(data) == 3
        # Newest first
        assert data[0]["rule"] == "R-4"

    def test_alerts_api_handles_malformed_lines(self, client, alerts_log):
        alerts_log.write_text('not json\n{"rule": "R-1", "severity": "high"}\nalso not json\n')
        resp = client.get("/api/alerts")
        # Only the JSON line survives
        data = resp.get_json()
        assert len(data) == 1
        assert data[0]["rule"] == "R-1"


# ---------------------------------------------------------------------------
# State-changing routes - CSRF and queueing
# ---------------------------------------------------------------------------


class TestCsrf:
    """CSRF token enforcement on POST routes."""

    def test_post_without_csrf_token_rejected(self, client, real_case):
        resp = client.post(f"/case/{real_case.name}/verify")
        assert resp.status_code == 400

    def test_post_with_wrong_csrf_token_rejected(self, client, real_case):
        # First GET to seed a session csrf token
        client.get("/")
        resp = client.post(
            f"/case/{real_case.name}/verify",
            data={"_csrf": "wrong-token"},
        )
        assert resp.status_code == 400

    def test_post_with_correct_csrf_token_accepted(self, client, real_case):
        # Fetch case page to obtain a valid csrf token
        resp = client.get(f"/case/{real_case.name}")
        match = re.search(rb'name="_csrf" value="([^"]+)"', resp.data)
        assert match, "csrf token missing from rendered HTML"
        csrf = match.group(1).decode()

        resp = client.post(
            f"/case/{real_case.name}/verify",
            data={"_csrf": csrf},
        )
        assert resp.status_code == 200
        # The verify result page should render either OK or FAIL
        assert b"verification" in resp.data.lower()


class TestRemediationQueue:
    def test_approve_writes_queue_entry(self, client, real_case, queue_file):
        resp = client.get(f"/case/{real_case.name}")
        csrf = re.search(rb'name="_csrf" value="([^"]+)"', resp.data).group(1).decode()

        resp = client.post(
            f"/case/{real_case.name}/approve",
            data={"_csrf": csrf, "action": "kill", "notes": "confirmed beacon"},
        )
        assert resp.status_code == 302  # redirect back to case page

        assert queue_file.exists()
        entries = [json.loads(line) for line in queue_file.read_text().splitlines() if line.strip()]
        assert len(entries) == 1
        assert entries[0]["case_id"] == real_case.name
        assert entries[0]["decision"] == "approve"
        assert entries[0]["action"] == "kill"
        assert entries[0]["notes"] == "confirmed beacon"

    def test_reject_writes_queue_entry(self, client, real_case, queue_file):
        resp = client.get(f"/case/{real_case.name}")
        csrf = re.search(rb'name="_csrf" value="([^"]+)"', resp.data).group(1).decode()

        client.post(
            f"/case/{real_case.name}/reject",
            data={"_csrf": csrf, "notes": "false positive - legit extension"},
        )
        entries = [json.loads(line) for line in queue_file.read_text().splitlines() if line.strip()]
        assert entries[0]["decision"] == "reject"

    def test_invalid_action_rejected(self, client, real_case):
        resp = client.get(f"/case/{real_case.name}")
        csrf = re.search(rb'name="_csrf" value="([^"]+)"', resp.data).group(1).decode()

        resp = client.post(
            f"/case/{real_case.name}/approve",
            data={"_csrf": csrf, "action": "DROP_TABLE_users"},
        )
        assert resp.status_code == 400

    def test_approve_appends_to_chain_of_custody(self, client, real_case):
        resp = client.get(f"/case/{real_case.name}")
        csrf = re.search(rb'name="_csrf" value="([^"]+)"', resp.data).group(1).decode()

        client.post(
            f"/case/{real_case.name}/approve",
            data={"_csrf": csrf, "action": "kill", "notes": "test note"},
        )
        coc = json.loads((real_case / "chain_of_custody.json").read_text())
        actions = [e["action"] for e in coc["custody_log"]]
        assert "dashboard_approve_kill" in actions


# ---------------------------------------------------------------------------
# Verify integration
# ---------------------------------------------------------------------------


class TestVerifyIntegration:
    def test_clean_case_verifies_ok(self, client, real_case):
        resp = client.get(f"/case/{real_case.name}")
        csrf = re.search(rb'name="_csrf" value="([^"]+)"', resp.data).group(1).decode()

        resp = client.post(
            f"/case/{real_case.name}/verify",
            data={"_csrf": csrf},
        )
        assert resp.status_code == 200
        assert b"OK" in resp.data

    def test_tampered_case_reports_failure(self, client, real_case):
        # Tamper with the preserved manifest
        manifest_path = real_case / "manifest.json"
        manifest_path.write_text('{"tampered": true}')

        resp = client.get(f"/case/{real_case.name}")
        csrf = re.search(rb'name="_csrf" value="([^"]+)"', resp.data).group(1).decode()

        resp = client.post(
            f"/case/{real_case.name}/verify",
            data={"_csrf": csrf},
        )
        assert b"FAIL" in resp.data
        assert b"manifest.json" in resp.data
