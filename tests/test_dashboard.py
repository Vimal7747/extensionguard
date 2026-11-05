# tests/test_dashboard.py - Flask analyst dashboard tests
#
# Uses Flask's built-in test client - no real HTTP server needed. Each test
# spins up a fresh app with its own tmp_path-based quarantine + queue file
# so they're fully isolated.

import json
import re
from pathlib import Path

import pytest

from extguard import dashboard
from extguard.dashboard import CASE_ID_PATTERN, create_app
from extguard.remediators import forensics

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
            "20260101-000000-deadbeef\n",  # `$` would allow a trailing newline
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

    def test_health_does_not_leak_paths(self, client, quarantine_dir):
        text = client.get("/api/health").get_data(as_text=True)
        assert "quarantine_root" not in text
        assert str(quarantine_dir.name) not in text
        assert '"root"' not in text

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

    def test_alerts_api_reads_the_end_of_a_large_log(self, client, alerts_log):
        """The tail is read backwards in blocks - check across block boundaries."""
        with alerts_log.open("w") as f:
            for i in range(20000):
                f.write(json.dumps({"rule": f"R-{i}", "pad": "x" * 50}) + "\n")
        data = client.get("/api/alerts?limit=5").get_json()
        assert [a["rule"] for a in data] == [f"R-{i}" for i in range(19999, 19994, -1)]

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
            data={
                "_csrf": csrf,
                "action": "kill",
                "notes": "confirmed beacon",
                "analyst": "Priya N",
            },
        )
        assert resp.status_code == 302  # redirect back to case page

        assert queue_file.exists()
        entries = [json.loads(line) for line in queue_file.read_text().splitlines() if line.strip()]
        assert len(entries) == 1
        assert entries[0]["case_id"] == real_case.name
        assert entries[0]["decision"] == "approve"
        assert entries[0]["action"] == "kill"
        assert entries[0]["notes"] == "confirmed beacon"
        # The analyst who clicked, not the server's OS account
        assert entries[0]["actor"] == "Priya N"
        assert "server_account" in entries[0]

    def test_reject_writes_queue_entry(self, client, real_case, queue_file):
        resp = client.get(f"/case/{real_case.name}")
        csrf = re.search(rb'name="_csrf" value="([^"]+)"', resp.data).group(1).decode()

        client.post(
            f"/case/{real_case.name}/reject",
            data={"_csrf": csrf, "notes": "false positive - legit extension", "analyst": "Sam"},
        )
        entries = [json.loads(line) for line in queue_file.read_text().splitlines() if line.strip()]
        assert entries[0]["decision"] == "reject"

    def test_invalid_action_rejected(self, client, real_case):
        resp = client.get(f"/case/{real_case.name}")
        csrf = re.search(rb'name="_csrf" value="([^"]+)"', resp.data).group(1).decode()

        resp = client.post(
            f"/case/{real_case.name}/approve",
            data={"_csrf": csrf, "action": "DROP_TABLE_users", "analyst": "Sam"},
        )
        assert resp.status_code == 400

    def test_approve_appends_to_chain_of_custody(self, client, real_case):
        resp = client.get(f"/case/{real_case.name}")
        csrf = re.search(rb'name="_csrf" value="([^"]+)"', resp.data).group(1).decode()

        client.post(
            f"/case/{real_case.name}/approve",
            data={"_csrf": csrf, "action": "kill", "notes": "test note", "analyst": "Priya N"},
        )
        coc = json.loads((real_case / "chain_of_custody.json").read_text())
        actions = [e["action"] for e in coc["custody_log"]]
        assert "dashboard_approve_kill" in actions
        assert coc["custody_log"][-1]["actor"].startswith("Priya N")

    @pytest.mark.parametrize("analyst", ["", "   ", "x" * 65, "<script>", "a\nb"])
    def test_approve_requires_a_valid_analyst_name(self, client, real_case, queue_file, analyst):
        resp = client.get(f"/case/{real_case.name}")
        csrf = re.search(rb'name="_csrf" value="([^"]+)"', resp.data).group(1).decode()

        resp = client.post(
            f"/case/{real_case.name}/approve",
            data={"_csrf": csrf, "action": "kill", "analyst": analyst},
        )
        assert resp.status_code == 400
        assert not queue_file.exists()

    def test_remote_user_recorded_when_proxy_sets_it(self, client, real_case, queue_file):
        resp = client.get(f"/case/{real_case.name}")
        csrf = re.search(rb'name="_csrf" value="([^"]+)"', resp.data).group(1).decode()

        client.post(
            f"/case/{real_case.name}/reject",
            data={"_csrf": csrf, "analyst": "Sam"},
            environ_base={"REMOTE_USER": "sam@corp.example"},
        )
        entry = json.loads(queue_file.read_text().splitlines()[0])
        assert entry["remote_user"] == "sam@corp.example"

    def test_tampered_case_is_not_queued(self, client, real_case, queue_file):
        resp = client.get(f"/case/{real_case.name}")
        csrf = re.search(rb'name="_csrf" value="([^"]+)"', resp.data).group(1).decode()
        coc_path = real_case / "chain_of_custody.json"
        coc_path.write_text(coc_path.read_text().replace("Test Extension", "Other"))

        resp = client.post(
            f"/case/{real_case.name}/approve",
            data={"_csrf": csrf, "action": "kill", "analyst": "Sam"},
        )
        assert resp.status_code == 409
        assert not queue_file.exists()


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


# ---------------------------------------------------------------------------
# DNS rebinding + framing (security review, 2026-11-05)
# ---------------------------------------------------------------------------
#
# A web page can make its own domain resolve to 127.0.0.1. It is then
# same-origin with the dashboard - the CSRF token doesn't help, since the page
# simply gets a session of its own. Before the fix, a request for
# attacker.example listed every case and queued an "approve: kill". The
# browser still sends the page's domain in the Host header, so the dashboard
# now answers only to localhost, loopback addresses and configured names.

ATTACKER = "http://attacker.example:5000"


def _csrf_for(client, case_name, base_url="http://localhost"):
    page = client.get(f"/case/{case_name}", base_url=base_url)
    return re.search(rb'name="_csrf" value="([^"]+)"', page.data).group(1).decode()


class TestDnsRebinding:
    @pytest.mark.parametrize("path", ["/", "/api/cases", "/api/alerts"])
    def test_unknown_host_is_refused(self, client, path):
        assert client.get(path, base_url=ATTACKER).status_code == 400

    def test_case_page_refused_so_no_csrf_token_leaks(self, client, real_case):
        resp = client.get(f"/case/{real_case.name}", base_url=ATTACKER)
        assert resp.status_code == 400
        assert b"_csrf" not in resp.data

    def test_rebound_approve_writes_nothing(self, client, real_case, queue_file):
        csrf = _csrf_for(client, real_case.name)  # even holding a valid token
        resp = client.post(
            f"/case/{real_case.name}/approve",
            base_url=ATTACKER,
            data={"_csrf": csrf, "action": "kill", "analyst": "Mallory"},
        )
        assert resp.status_code == 400
        assert not queue_file.exists()

    @pytest.mark.parametrize(
        "base_url",
        [
            "http://localhost",
            "http://LocalHost:5000",
            "http://127.0.0.1:5000",
            "http://127.0.0.2:5000",  # all of 127.0.0.0/8 is loopback
            "http://[::1]:5000",
        ],
    )
    def test_local_names_work(self, client, base_url):
        assert client.get("/", base_url=base_url).status_code == 200

    def test_configured_name_works(self, quarantine_dir, alerts_log, queue_file):
        app = create_app(quarantine_root=quarantine_dir, alerts_log=alerts_log,
                         queue_file=queue_file, allowed_hosts=["SOC.example.com"])  # fmt: skip
        client = app.test_client()
        assert client.get("/", base_url="https://soc.example.com").status_code == 200
        assert client.get("/", base_url="https://evil.example.com").status_code == 400

    def test_health_check_answers_any_host(self, client):
        """Orchestrators probe by IP; it holds no case data."""
        assert client.get("/api/health", base_url="http://10.0.0.7:5000").status_code == 200

    @pytest.mark.parametrize(
        "header, name",
        [
            ("LocalHost:5000", "localhost"),
            ("[::1]:5000", "::1"),
            ("soc.example.com.", "soc.example.com"),
            ("127.0.0.1", "127.0.0.1"),
            ("", ""),
        ],
    )
    def test_host_name(self, header, name):
        assert dashboard.host_name(header) == name

    def test_lookalike_names_are_not_local(self):
        for host in ("localhost.attacker.example", "127.0.0.1.nip.io", "attacker.localhost.com"):
            assert not dashboard.is_allowed_host(host, set())


class TestSecurityHeaders:
    def test_pages_cannot_be_framed(self, client):
        resp = client.get("/")
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert resp.headers["Content-Security-Policy"] == "frame-ancestors 'none'"
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["Referrer-Policy"] == "no-referrer"

    def test_refused_responses_carry_them_too(self, client):
        assert client.get("/", base_url=ATTACKER).headers["X-Frame-Options"] == "DENY"


class TestDashboardCli:
    def test_debug_mode_refused_off_localhost(self, capsys):
        assert dashboard.main(["--debug", "--host", "0.0.0.0"]) == 2
        assert "debugger" in capsys.readouterr().err

    def test_allowed_hosts_from_flags_env_and_bind_address(self, monkeypatch):
        monkeypatch.setenv(dashboard.HOSTS_ENV, "proxy.example, other.example")
        hosts = dashboard.allowed_hosts_for("10.0.0.5", ["soc.example"])
        assert hosts == ["soc.example", "proxy.example", "other.example", "10.0.0.5"]

    def test_wildcard_bind_is_never_an_allowed_name(self, monkeypatch):
        monkeypatch.delenv(dashboard.HOSTS_ENV, raising=False)
        assert dashboard.allowed_hosts_for("0.0.0.0", []) == []
        assert dashboard.allowed_hosts_for("::", []) == []
