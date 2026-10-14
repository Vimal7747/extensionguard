# tests/test_real_extension_check.py - tools/real_extension_check.py
#
# The tool itself runs weekly against the live Web Store and a real browser
# (.github/workflows/real-extensions.yml). These tests pin the parts that
# decide what counts as PASS - so the evidence it produces can't quietly
# weaken: a download must match the store's SHA-256, a genuine extension
# rated HIGH is a failure, and silence from the monitor only counts when the
# canary was caught.

import base64
import io
import json
import struct
import zipfile
from pathlib import Path

import pytest

from extguard.behavioral_monitor import CREDENTIAL_PATTERNS
from extguard.publisher_checker import _compute_extension_id
from tools import real_extension_check as rec
from tools.real_extension_check import SetupError

RECORDED = Path(__file__).parent / "fixtures" / "recorded"
TRANSLATE_ID = "aapbdbdomjkkjkaonfhkkikfgjllcleb"
EXT = {"slug": "google-translate", "name": "Google Translate", "id": TRANSLATE_ID}


# ---------------------------------------------------------------------------
# Store reply + download: only ever test the store's exact bytes
# ---------------------------------------------------------------------------


def test_parse_update_reply_reads_a_real_store_reply():
    xml = (RECORDED / "cws_known_extension.xml").read_text(encoding="utf-8")
    build = rec.parse_update_reply(xml, TRANSLATE_ID)
    assert build["version"] == "2.0.17"
    assert build["size"] == 1145560
    assert build["sha256"].startswith("3f752c27ae39")
    assert build["url"].startswith("https://clients2.googleusercontent.com/crx/blobs/")


def test_parse_update_reply_rejects_unknown_and_garbage():
    unknown = (RECORDED / "cws_unknown_extension.xml").read_text(encoding="utf-8")
    with pytest.raises(SetupError, match="status"):
        rec.parse_update_reply(unknown, "a" * 32)
    with pytest.raises(SetupError, match="unreadable"):
        rec.parse_update_reply("<not xml", TRANSLATE_ID)
    xml = (RECORDED / "cws_known_extension.xml").read_text(encoding="utf-8")
    with pytest.raises(SetupError, match="no build"):
        rec.parse_update_reply(xml, "b" * 32)  # reply is about another ID


def test_query_store_sends_the_products_own_request(monkeypatch):
    seen = []

    def fake_urlopen(request, timeout):
        seen.append(request.full_url)
        return io.BytesIO((RECORDED / "cws_known_extension.xml").read_bytes())

    monkeypatch.setattr(rec, "urlopen", fake_urlopen)
    assert rec.query_store(TRANSLATE_ID)["version"] == "2.0.17"
    assert seen == [rec.CWS_UPDATE_TEMPLATE.format(ext_id=TRANSLATE_ID)]


@pytest.mark.parametrize(
    "url",
    [
        "http://clients2.googleusercontent.com/x.crx",  # not HTTPS
        "https://evil.example/x.crx",
        "https://googleusercontent.com.evil.example/x.crx",
        "https://evilgoogleusercontent.com/x.crx",
        "file:///etc/passwd",
    ],
)
def test_download_url_must_be_a_google_host(url):
    with pytest.raises(SetupError, match="refusing"):
        rec.check_download_url(url)


def test_download_url_accepts_the_store_cdn():
    rec.check_download_url("https://clients2.googleusercontent.com/crx/blobs/a/B_1_0.crx")


def _build(data: bytes) -> dict:
    import hashlib

    return {
        "version": "1.0",
        "url": "https://clients2.googleusercontent.com/crx/blobs/x/X_1_0.crx",
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def test_download_keeps_a_matching_file_and_reuses_it(monkeypatch, tmp_path):
    data = b"Cr24-pretend-crx-bytes"
    calls = []
    monkeypatch.setattr(rec, "urlopen", lambda req, timeout: calls.append(1) or io.BytesIO(data))

    path, source = rec.download_build(EXT, _build(data), tmp_path)
    assert source == "downloaded" and path.read_bytes() == data
    assert path.name == "google-translate-1.0.crx"

    # Second run: found by its hash, no network
    path2, source2 = rec.download_build(EXT, _build(data), tmp_path)
    assert (path2, source2) == (path, "cached") and len(calls) == 1


def test_cache_lookup_goes_by_content_not_name(tmp_path):
    data = b"some store build"
    (tmp_path / "renamed-by-hand.crx").write_bytes(data)
    (tmp_path / "decoy.crx").write_bytes(b"x" * len(data))  # same size, other bytes
    assert rec.find_cached(tmp_path, _build(data)).name == "renamed-by-hand.crx"


def test_download_with_the_wrong_hash_is_refused_and_removed(monkeypatch, tmp_path):
    build = _build(b"what the store published")
    monkeypatch.setattr(rec, "urlopen", lambda req, timeout: io.BytesIO(b"something else!!!!!!!!"))
    with pytest.raises(SetupError, match="does not match"):
        rec.download_build(EXT, build, tmp_path)
    assert list(tmp_path.iterdir()) == []  # no partial file left behind


def test_oversized_build_is_refused_before_downloading(monkeypatch, tmp_path):
    monkeypatch.setattr(rec, "urlopen", lambda *a, **k: pytest.fail("must not download"))
    build = {**_build(b"x"), "size": rec.MAX_CRX_BYTES + 1}
    with pytest.raises(SetupError, match="size limit"):
        rec.download_build(EXT, build, tmp_path)


# ---------------------------------------------------------------------------
# What counts as PASS for a genuine extension / an attack sample
# ---------------------------------------------------------------------------


def _report(**changes) -> dict:
    report = {
        "risk_level": "medium",
        "final_score": 44,
        "verdict": {"evidence": [], "anomalies": [], "verified_store_build": True},
        "stage_1_checks": {
            "publisher": {"extension_id": TRANSLATE_ID, "store_relation": "identical"}
        },
        "stage_errors": {},
    }
    report.update(changes)
    return report


def test_genuine_medium_verified_build_passes():
    assert rec.judge_genuine(EXT, _report()) == []


@pytest.mark.parametrize(
    "changes, expected",
    [
        ({"risk_level": "high", "final_score": 69}, "false positive"),
        ({"risk_level": "critical", "final_score": 100}, "false positive"),
        (
            {"verdict": {"evidence": ["obfuscated code: a.js"], "verified_store_build": True}},
            "evidence",
        ),
        ({"verdict": {"evidence": [], "verified_store_build": False}}, "verified store build"),
        ({"stage_1_checks": {"publisher": {"extension_id": "c" * 32}}}, "extension ID"),
        ({"stage_errors": {"1d": "OSV timed out"}}, "did not complete"),
        ({"scan_failed": "no JSON report (exit 3)"}, "scan failed"),
    ],
)
def test_genuine_extension_problems(changes, expected):
    problems = rec.judge_genuine(EXT, _report(**changes))
    assert any(expected in p for p in problems), problems


def test_attack_sample_must_reach_its_expected_level():
    assert rec._control_result("x", {"risk_level": "critical"}, "high")["problems"] == []
    assert rec._control_result("x", {"risk_level": "high"}, "high")["problems"] == []
    missed = rec._control_result("x", {"risk_level": "medium"}, "high")["problems"]
    assert missed and "missed attack" in missed[0]
    assert rec._control_result("x", {"scan_failed": "boom"}, "high")["problems"]


def test_scan_environment_tests_this_checkout_without_ai_or_virustotal(monkeypatch, tmp_path):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("VT_API_KEY", "vt-test")
    env = rec.scan_env(tmp_path)
    assert "ANTHROPIC_API_KEY" not in env and "VT_API_KEY" not in env
    assert env["VT_DISABLED"] == "1" and env["EXTGUARD_HOME"] == str(tmp_path)
    assert env["PYTHONPATH"].split(rec.os.pathsep)[0] == str(rec.REPO_ROOT)


# ---------------------------------------------------------------------------
# Runtime: unpacking, the canary, and judging what the browser did
# ---------------------------------------------------------------------------


def _crx3(header: bytes, files: dict) -> bytes:
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return b"Cr24" + struct.pack("<II", 3, len(header)) + header + zip_buffer.getvalue()


def test_unpacked_copy_keeps_the_real_store_id(tmp_path):
    header = (RECORDED / "crx3_header_google_translate.bin").read_bytes()
    manifest = {"manifest_version": 3, "name": "Google Translate", "version": "2.0.17"}
    crx = tmp_path / "translate.crx"
    crx.write_bytes(_crx3(header, {"manifest.json": json.dumps(manifest), "bg.js": "//"}))

    ext_id = rec.unpack_for_chrome(crx, tmp_path / "out")

    assert ext_id == TRANSLATE_ID
    written = json.loads((tmp_path / "out" / "manifest.json").read_text(encoding="utf-8"))
    # Chrome derives an unpacked extension's ID from "key": it must be the store's
    assert _compute_extension_id(base64.b64decode(written["key"])) == TRANSLATE_ID
    assert (tmp_path / "out" / "bg.js").exists()


def test_canary_sends_something_the_monitor_must_flag(tmp_path):
    rec.write_canary(tmp_path, 4321)
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    code = (tmp_path / "bg.js").read_text()
    assert manifest["name"] == rec.CANARY_NAME
    assert "http://127.0.0.1:4321/collect" in code
    # The token is assembled at run time (no secret-looking string in the
    # repo) - and the assembled value is one RULE-02 recognises.
    assert 'ghp_" + "x".repeat(36)' in code
    assert CREDENTIAL_PATTERNS["GitHub token"][0].search("token=ghp_" + "x" * 36)


def test_sink_records_the_canary_requests():
    import urllib.request

    server, hits = rec.start_sink()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/collect"
        urllib.request.urlopen(urllib.request.Request(url, data=b"token=x"), timeout=5).close()
    finally:
        server.shutdown()
        server.server_close()
    assert hits == ["/collect"]


def test_chrome_keeps_its_sandbox_except_on_linux(monkeypatch, tmp_path):
    monkeypatch.setattr(rec.sys, "platform", "win32")
    windows = rec.chrome_command(Path("chrome"), 9222, tmp_path, [tmp_path / "a", tmp_path / "b"])
    assert "--no-sandbox" not in windows
    assert f"--load-extension={tmp_path / 'a'},{tmp_path / 'b'}" in windows
    assert windows[-1] == "about:blank"
    monkeypatch.setattr(rec.sys, "platform", "linux")
    assert "--no-sandbox" in rec.chrome_command(Path("chrome"), 9222, tmp_path, [])


GENUINE = [
    {"name": "Dark Reader", "id": "e" * 32},
    {"name": "JSON Formatter", "id": "f" * 32},
]
INSTALLED = [
    {"id": "e" * 32, "name": "Dark Reader", "version": "4.9", "state": "ENABLED"},
    {"id": "f" * 32, "name": "JSON Formatter", "version": "0.1", "state": "ENABLED"},
    {"id": "c" * 32, "name": rec.CANARY_NAME, "version": "1.0", "state": "ENABLED"},
]
CANARY_ALERT = {"rule": "RULE-02", "severity": "critical", "extension": {"id": "c" * 32}}


def _alert(ext_id, rule="RULE-04"):
    return {
        "rule": rule,
        "severity": "high",
        "extension": {"id": ext_id},
        "detail": {"description": "something"},
    }


def test_runtime_passes_when_only_the_canary_is_caught():
    result = rec.judge_runtime(GENUINE, INSTALLED, [CANARY_ALERT], ["/collect"], "")
    assert result["problems"] == []
    assert result["canary"] == {
        "loaded": True,
        "requests_sent": 1,
        "alerts": 1,
        "rule02_alerts": 1,
    }
    assert all(row["loaded"] and row["alerts"] == [] for row in result["extensions"])


def test_alert_about_a_genuine_extension_is_a_false_alarm():
    result = rec.judge_runtime(
        GENUINE, INSTALLED, [CANARY_ALERT, _alert("e" * 32)], ["/collect"], ""
    )
    assert result["problems"] == ["Dark Reader: false alarm RULE-04 high: something"]


def test_silence_without_the_canary_is_not_a_pass():
    result = rec.judge_runtime(GENUINE, INSTALLED, [], ["/collect"], "")
    assert any("NOT detected" in p for p in result["problems"])
    never_ran = rec.judge_runtime(GENUINE, INSTALLED, [CANARY_ALERT], [], "")
    assert any("never ran" in p for p in never_ran["problems"])


def test_runtime_problems_for_missing_extensions_strangers_and_crashes():
    installed = [e for e in INSTALLED if e["name"] != "JSON Formatter"]
    result = rec.judge_runtime(
        GENUINE,
        installed,
        [CANARY_ALERT, _alert("9" * 32)],
        ["/collect"],
        "Traceback (most recent call last):\nRuntimeError: boom\n",
    )
    problems = " | ".join(result["problems"])
    assert "JSON Formatter did not load" in problems
    assert "unexpected extension" in problems
    assert "crashed: RuntimeError: boom" in problems


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def _full_report(passed=True) -> dict:
    return {
        "meta": {
            "date": "2026-10-14 19:00 UTC",
            "extensionguard_version": "0.4.0",
            "python": "3.13.6",
            "platform": "Linux 6.8",
        },
        "extensions": [
            {
                "name": "Weird | Name",
                "version": "1.0",
                "sha256": "ab" * 32,
                "capability_score": 79,
                "risk_level": "medium",
                "final_score": 44,
                "evidence": [],
                "problems": [] if passed else ["rated HIGH (69/100) - false positive"],
            }
        ],
        "controls": [
            {
                "label": "TeamPCP",
                "risk_level": "critical",
                "final_score": 100,
                "evidence": ["exfil"],
                "problems": [],
            }
        ],
        "runtime": {
            "chrome": "Chrome/155.0.8059.39",
            "sites": ["https://example.com/"],
            "seconds": 100,
            "extensions": [{"name": "Weird | Name", "loaded": True, "alerts": []}],
            "canary": {"loaded": True, "requests_sent": 3, "alerts": 3, "rule02_alerts": 3},
            "problems": [],
        },
        "passed": passed,
    }


def test_markdown_summary():
    text = rec.render_markdown(_full_report())
    assert "**Result: PASS**" in text
    assert "Chrome for Testing 155.0.8059.39" in text
    assert "| Weird / Name | 1.0 | `abababababab` | 79 | MEDIUM (44) | none | PASS |" in text
    assert "| TeamPCP | CRITICAL (100) | exfil | PASS |" in text
    assert f"| {rec.CANARY_NAME} (fake token, must be caught) | yes | 3 RULE-02 | PASS |" in text
    assert "### Problems" not in text


def test_markdown_lists_problems_when_failing():
    text = rec.render_markdown(_full_report(passed=False))
    assert "**Result: FAIL**" in text
    assert "- Weird / Name: rated HIGH (69/100) - false positive" in text


def test_github_job_summary_and_public_annotations(monkeypatch, tmp_path, capsys):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    report = _full_report(passed=False)
    rec.github_outputs(report, "TABLE\n")
    assert summary.read_text(encoding="utf-8") == "TABLE\n"
    assert "::error title=Real-extension check::Weird | Name: rated HIGH" in capsys.readouterr().out


def test_runtime_without_chrome_is_a_usage_error(capsys):
    assert rec.main(["--runtime"]) == 2
    assert "--chrome" in capsys.readouterr().err
