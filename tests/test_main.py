# tests/test_main.py - CLI contract tests for main.py
#
# These pin down the behaviour a pipeline depends on: --json always emits JSON,
# exit codes mean something, --offline makes no calls, and Claude can raise the
# verdict but never lower it.

import hashlib
import json
import struct
from unittest.mock import patch

import pytest

from extguard import main
from extguard.models import TriageResult


@pytest.fixture(autouse=True)
def _isolate(temp_history_file, monkeypatch):
    """Every test: private history file, no real API key, no real Claude call."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with patch(
        "extguard.main.triage_extension", side_effect=AssertionError("Claude must not be called")
    ):
        yield


def _write(tmp_path, manifest: dict, name: str = "manifest.json") -> str:
    path = tmp_path / name
    path.write_text(json.dumps(manifest))
    return str(path)


def _run_json(capsys, argv: list) -> tuple:
    code = main.main(argv + ["--json"])
    out = capsys.readouterr().out
    return code, json.loads(out)


CRITICAL_MANIFEST = {
    "name": "Bad",
    "version": "1.0",
    "manifest_version": 2,
    "permissions": ["debugger", "nativeMessaging", "cookies", "tabs", "<all_urls>"],
}


class TestJsonAlwaysEmitted:
    def test_no_api_key_still_prints_json(self, tmp_path, capsys):
        """Regression (review #13): --json with no API key printed NOTHING."""
        code, report = _run_json(capsys, [_write(tmp_path, CRITICAL_MANIFEST)])
        assert code == 0
        assert report["ai_triage"] == {"status": "skipped", "reason": "ANTHROPIC_API_KEY not set"}
        assert report["risk_level"] == "critical"
        assert report["iocs"]  # Stage 1 flags feed remediation when AI is absent

    def test_parse_error_is_json_with_exit_3(self, tmp_path, capsys):
        bad = tmp_path / "manifest.json"
        bad.write_text("[1, 2, 3]")
        code = main.main([str(bad), "--json"])
        report = json.loads(capsys.readouterr().out)
        assert code == 3
        assert report["stage"] == "1a"
        assert "must be a JSON object" in report["error"]

    def test_missing_file_is_exit_3(self, tmp_path, capsys):
        assert main.main([str(tmp_path / "nope.crx"), "--json"]) == 3

    def test_malformed_fields_are_reported_not_fatal(self, tmp_path, capsys):
        code, report = _run_json(
            capsys, [_write(tmp_path, {"name": "x", "permissions": [5, "cookies"]}), "--no-ai"]
        )
        assert code == 0
        assert report["parse_warnings"]


class TestExitCodes:
    def test_fail_on_triggers_exit_1(self, tmp_path, capsys):
        """Regression (review #14): a CRITICAL verdict used to exit 0."""
        path = _write(tmp_path, CRITICAL_MANIFEST)
        assert main.main([path, "--json", "--no-ai", "--fail-on", "high"]) == 1

    def test_below_threshold_exits_0(self, tmp_path, capsys):
        path = _write(tmp_path, {"name": "ok", "version": "1.0", "permissions": ["storage"]})
        assert main.main([path, "--json", "--no-ai", "--fail-on", "high"]) == 0

    def test_no_fail_on_means_exit_0(self, tmp_path, capsys):
        assert main.main([_write(tmp_path, CRITICAL_MANIFEST), "--json", "--no-ai"]) == 0


class TestOffline:
    def test_offline_never_calls_claude_or_network(self, tmp_path, capsys, monkeypatch):
        """Regression: --offline promised no network calls but still called Claude."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-not-real")
        with (
            patch("extguard.publisher_checker.requests.get") as cws,
            patch("extguard.osv_lookup.requests.post") as osv,
        ):
            code, report = _run_json(capsys, [_write(tmp_path, CRITICAL_MANIFEST), "--offline"])
        assert code == 0
        assert report["ai_triage"]["status"] == "skipped"
        assert "--offline" in report["ai_triage"]["reason"]
        cws.assert_not_called()
        osv.assert_not_called()


def _triage_result(score: int) -> TriageResult:
    from extguard.models import PermissionScore

    return TriageResult(
        risk_score=score,
        risk_level="low",
        iocs=["ai ioc"],
        mitre_techniques=["T1176"],
        analyst_narrative="narrative",
        permission_score=PermissionScore(0, "low", [], {}, []),
        manifest=None,
        extension_name="x",
        file_path="x",
    )


class TestVerdict:
    def test_claude_cannot_lower_the_verdict(self, tmp_path, capsys, monkeypatch):
        """A prompt-injected '0/100' from Claude must not turn a critical result green."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-not-real")
        with patch("extguard.main.triage_extension", return_value=_triage_result(0)):
            _, report = _run_json(capsys, [_write(tmp_path, CRITICAL_MANIFEST)])
        assert report["ai_risk_score"] == 0
        assert report["final_score"] == report["composite_score"]
        assert report["risk_level"] == "critical"

    def test_claude_can_raise_the_verdict(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-not-real")
        path = _write(tmp_path, {"name": "ok", "version": "1.0", "permissions": ["storage"]})
        with patch("extguard.main.triage_extension", return_value=_triage_result(95)):
            _, report = _run_json(capsys, [path])
        assert report["final_score"] == 95
        assert report["risk_level"] == "critical"

    def test_claude_failure_falls_back_to_stage1(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-not-real")
        with patch("extguard.main.triage_extension", side_effect=ValueError("cut off")):
            code, report = _run_json(capsys, [_write(tmp_path, CRITICAL_MANIFEST)])
        assert code == 0
        assert report["ai_triage"]["status"] == "failed"
        assert report["risk_level"] == "critical"

    def test_virustotal_confirmed_floor(self, tmp_path, capsys):
        vt_hit = {
            "osv_score": 30,
            "flags": [],
            "vt": {"queried": True, "found": True, "malicious": 40, "total": 70},
        }
        path = _write(tmp_path, {"name": "quiet", "version": "1.0", "permissions": ["storage"]})
        with patch("extguard.main.run_osv_checks", return_value=vt_hit):
            _, report = _run_json(capsys, [path, "--no-ai"])
        assert report["composite_score"] >= main.CONFIRMED_MALICIOUS_FLOOR
        assert "40/70" in report["composite_floor_reason"]


class TestStageFailures:
    def test_failed_stage_is_unknown_not_fatal(self, tmp_path, capsys):
        with patch("extguard.main.check_publisher", side_effect=RuntimeError("boom")):
            code, report = _run_json(capsys, [_write(tmp_path, CRITICAL_MANIFEST), "--no-ai"])
        assert code == 0
        assert "RuntimeError: boom" in report["stage_errors"]["1c"]
        assert any("result unknown" in f for f in report["stage_1_iocs"])


class TestCrxIdentityWiring:
    def test_crx3_signed_id_reaches_the_report(self, tmp_path, capsys, benign_zip_bytes):
        """Regression (review #3): the CRX header was never passed on (a TODO),
        so no .crx from the Web Store ever got an extension ID."""

        def pb(field, payload):
            def varint(v):
                out = b""
                while True:
                    b, v = v & 0x7F, v >> 7
                    if v:
                        out += bytes([b | 0x80])
                    else:
                        return out + bytes([b])

            return varint((field << 3) | 2) + varint(len(payload)) + payload

        key = b"developer-key"
        header = pb(2, pb(1, key)) + pb(10000, pb(1, hashlib.sha256(key).digest()[:16]))
        crx = b"Cr24" + struct.pack("<I", 3) + struct.pack("<I", len(header)) + header
        crx += benign_zip_bytes
        path = tmp_path / "ext.crx"
        path.write_bytes(crx)

        _, report = _run_json(capsys, [str(path), "--offline"])
        pub = report["stage_1_checks"]["publisher"]
        assert pub["id_source"] == "crx3-signed-id"
        assert pub["extension_id"] and len(pub["extension_id"]) == 32
        assert report["file_sha256"] == hashlib.sha256(crx).hexdigest()
