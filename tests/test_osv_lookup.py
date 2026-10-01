# tests/test_osv_lookup.py - Stage 1d tests (HTTP mocked with REAL recorded replies)

import hashlib
import io
import json
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from extguard import crx_parser, osv_lookup
from extguard.osv_lookup import (
    _npm_deps_from,
    _query_osv_packages_batch,
    _scan_zip_contents,
    run_osv_checks,
)

RECORDED = Path(__file__).parent / "fixtures" / "recorded"

PACKAGES = [
    {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
    {"name": "is-number", "version": "7.0.0", "ecosystem": "npm"},
]


def _make_zip(files: dict) -> bytes:
    """Build a ZIP archive from a {filename: content_str} dict."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _json_response(body, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = body
    return resp


def _recorded_batch() -> dict:
    return json.loads((RECORDED / "osv_querybatch_lodash_isnumber.json").read_text())


# ---------------------------------------------------------------------------
# The OSV hash query is gone - documented by a real recorded rejection
# ---------------------------------------------------------------------------


class TestNoHashLookup:
    def test_osv_really_rejects_hash_queries(self):
        """Recorded 2026-09-29: OSV answers a {"hash": ...} query with HTTP 400.
        This is why the module no longer sends one."""
        recorded = json.loads((RECORDED / "osv_hash_query_rejected.json").read_text())
        assert recorded["status_code"] == 400
        assert recorded["body"]["message"] == "invalid query"

    def test_module_no_longer_has_hash_query(self):
        assert not hasattr(osv_lookup, "_query_osv_hash")


# ---------------------------------------------------------------------------
# npm batch query
# ---------------------------------------------------------------------------


class TestNpmBatchQuery:
    def test_empty_package_list_returns_empty(self):
        assert _query_osv_packages_batch([]) == ([], None)

    def test_recorded_batch_reply_is_parsed(self):
        with patch(
            "extguard.osv_lookup.requests.post", return_value=_json_response(_recorded_batch())
        ):
            hits, error = _query_osv_packages_batch(PACKAGES)
        assert error is None
        assert hits  # lodash 4.17.20 has known advisories
        assert all(h["_package"] == "lodash@4.17.20" for h in hits)

    def test_http_error_is_reported(self):
        with patch("extguard.osv_lookup.requests.post", return_value=_json_response({}, 503)):
            assert _query_osv_packages_batch(PACKAGES) == ([], "HTTP 503")

    def test_network_error_is_reported(self):
        with patch("extguard.osv_lookup.requests.post", side_effect=OSError("down")):
            hits, error = _query_osv_packages_batch(PACKAGES)
        assert hits == []
        assert error.startswith("network error")


# ---------------------------------------------------------------------------
# npm dependency extraction
# ---------------------------------------------------------------------------


class TestNpmDeps:
    def test_package_json_exact_versions_only(self):
        pkg = {
            "dependencies": {"lodash": "^4.17.21", "axios": "~1.0.0", "x": "latest"},
            "devDependencies": {"jest": "29.0.0", "y": "git+https://github.com/a/b"},
        }
        deps = dict(_npm_deps_from(pkg, "package.json"))
        assert deps == {"lodash": "4.17.21", "axios": "1.0.0", "jest": "29.0.0"}

    def test_lockfile_v1_does_not_crash(self):
        """Regression: v1 lockfiles map name -> {version: ...}; the old code
        called .split() on that dict and crashed the whole scan."""
        lock = {"lockfileVersion": 1, "dependencies": {"lodash": {"version": "4.17.20"}}}
        assert _npm_deps_from(lock, "package-lock.json") == [("lodash", "4.17.20")]

    def test_lockfile_v3_packages(self):
        lock = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root-project"},
                "node_modules/lodash": {"version": "4.17.20"},
                "node_modules/@scope/pkg": {"version": "1.0.0"},
            },
        }
        assert set(_npm_deps_from(lock, "package-lock.json")) == {
            ("lodash", "4.17.20"),
            ("@scope/pkg", "1.0.0"),
        }

    def test_wrong_shapes_are_ignored(self):
        assert _npm_deps_from(["not", "a", "dict"], "package.json") == []
        assert _npm_deps_from({"dependencies": ["a"]}, "package.json") == []
        assert _npm_deps_from({"dependencies": {"a": 1}}, "package.json") == []


# ---------------------------------------------------------------------------
# ZIP content scanning
# ---------------------------------------------------------------------------


class TestZipScanning:
    def test_finds_npm_dependencies(self):
        zip_bytes = _make_zip(
            {
                "package.json": json.dumps(
                    {
                        "dependencies": {"lodash": "^4.17.21", "axios": "~1.0.0"},
                        "devDependencies": {"jest": "29.0.0"},
                    }
                ),
            }
        )
        npm_packages, _, errors = _scan_zip_contents(zip_bytes)
        assert {p["name"] for p in npm_packages} == {"lodash", "axios", "jest"}
        assert errors == []

    def test_finds_cdn_references_in_js(self):
        zip_bytes = _make_zip(
            {
                "background.js": (
                    'fetch("https://cdn.jsdelivr.net/npm/jquery@3/dist/jquery.min.js");\n'
                    'import("https://unpkg.com/lodash@4");\n'
                ),
            }
        )
        _, cdn_refs, _ = _scan_zip_contents(zip_bytes)
        assert any("jsdelivr" in r for r in cdn_refs)
        assert any("unpkg.com" in r for r in cdn_refs)

    def test_clean_zip_no_findings(self):
        zip_bytes = _make_zip(
            {
                "manifest.json": '{"name": "test"}',
                "background.js": 'console.log("hello world");\n',
            }
        )
        assert _scan_zip_contents(zip_bytes) == ([], [], [])

    def test_malformed_package_json_is_reported_not_silent(self):
        npm_packages, _, errors = _scan_zip_contents(_make_zip({"package.json": "not JSON"}))
        assert npm_packages == []
        assert any("not valid JSON" in e for e in errors)

    def test_oversized_file_is_skipped_and_reported(self, monkeypatch):
        monkeypatch.setattr(osv_lookup, "MAX_SCAN_FILE_BYTES", 10)
        _, _, errors = _scan_zip_contents(_make_zip({"big.js": "x" * 100}))
        assert any("over scan limit" in e for e in errors)

    def test_zip_bomb_is_reported_not_raised(self, monkeypatch):
        monkeypatch.setattr(crx_parser, "MAX_MEMBER_BYTES", 10)
        _, _, errors = _scan_zip_contents(_make_zip({"a.js": "x" * 100}))
        assert any("zip bomb" in e for e in errors)


# ---------------------------------------------------------------------------
# End-to-end run_osv_checks
# ---------------------------------------------------------------------------


class TestRunOsvChecks:
    def test_no_zip_skips_checks(self):
        result = run_osv_checks(None, {})
        assert result["file_sha256"] is None
        assert result["osv_score"] == 0

    def test_hashes_the_whole_file_not_the_zip(self):
        """Regression: VirusTotal indexes the whole .crx, so that is what we hash."""
        zip_bytes = _make_zip({"manifest.json": "{}"})
        crx_bytes = b"Cr24-header" + zip_bytes
        result = run_osv_checks(zip_bytes, {}, file_bytes=crx_bytes)
        assert result["file_sha256"] == hashlib.sha256(crx_bytes).hexdigest()
        assert result["zip_hash"] == hashlib.sha256(zip_bytes).hexdigest()

    def test_vt_is_queried_with_the_file_hash(self):
        zip_bytes = _make_zip({"manifest.json": "{}"})
        crx_bytes = b"Cr24-header" + zip_bytes
        vt_reply = {"score": 0, "flags": [], "found": False, "ok": True}
        with patch("extguard.virustotal_lookup.lookup_hash", return_value=vt_reply) as mock_vt:
            run_osv_checks(zip_bytes, {}, vt_cfg={"enabled": True}, file_bytes=crx_bytes)
        assert mock_vt.call_args[0][0] == hashlib.sha256(crx_bytes).hexdigest()

    def test_offline_scans_locally_but_makes_no_requests(self):
        zip_bytes = _make_zip(
            {
                "package.json": json.dumps({"dependencies": {"a": "1.0.0"}}),
                "bg.js": 'fetch("https://unpkg.com/x");',
            }
        )
        with (
            patch("extguard.osv_lookup.requests.post") as mock_post,
            patch("extguard.virustotal_lookup.lookup_hash") as mock_vt,
        ):
            result = run_osv_checks(zip_bytes, {}, vt_cfg={"enabled": True}, network=False)
        mock_post.assert_not_called()
        mock_vt.assert_not_called()
        assert result["osv_pkg_status"] == "skipped (offline)"
        assert result["cdn_refs"]  # the local scan still ran
        assert result["file_sha256"]

    def test_package_lookup_failure_is_unknown_not_clean(self):
        zip_bytes = _make_zip({"package.json": json.dumps({"dependencies": {"a": "1.0.0"}})})
        with patch("extguard.osv_lookup._query_osv_packages_batch", return_value=([], "HTTP 503")):
            result = run_osv_checks(zip_bytes, {})
        assert result["osv_pkg_status"] == "error: HTTP 503"
        assert any("status unknown" in f for f in result["flags"])

    def test_vulnerable_package_adds_score(self):
        zip_bytes = _make_zip({"package.json": json.dumps({"dependencies": {"a": "1.0.0"}})})
        hits = [{"id": "GHSA-x", "_package": "a@1.0.0"}]
        with patch("extguard.osv_lookup._query_osv_packages_batch", return_value=(hits, None)):
            result = run_osv_checks(zip_bytes, {})
        assert result["osv_pkg_status"] == "ok"
        assert result["osv_score"] == 10

    def test_cdn_reference_adds_score(self):
        zip_bytes = _make_zip({"background.js": 'fetch("https://unpkg.com/evil-pkg@1.0.0");'})
        result = run_osv_checks(zip_bytes, {})
        assert result["osv_score"] > 0
        assert any("unpkg.com" in flag for flag in result["flags"])

    def test_score_clamped_at_30(self):
        zip_bytes = _make_zip(
            {
                "package.json": json.dumps({"dependencies": {"a": "1.0.0"}}),
                "background.js": "\n".join(f'fetch("https://unpkg.com/p{i}");' for i in range(20)),
            }
        )
        vt_reply = {"score": 30, "flags": [], "found": True, "ok": True}
        hits = [{"id": "Y", "_package": "p"}] * 5
        with (
            patch("extguard.virustotal_lookup.lookup_hash", return_value=vt_reply),
            patch("extguard.osv_lookup._query_osv_packages_batch", return_value=(hits, None)),
        ):
            result = run_osv_checks(zip_bytes, {}, vt_cfg={"enabled": True})
        assert result["osv_score"] == 30
