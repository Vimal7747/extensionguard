# tests/test_osv_lookup.py - OSV / CVE hash-lookup tests (HTTP mocked)

import hashlib
import io
import json
import zipfile
from unittest.mock import MagicMock, patch

import pytest

from osv_lookup import (
    SUSPICIOUS_CDN_PATTERNS,
    _query_osv_hash,
    _query_osv_packages_batch,
    _scan_zip_contents,
    run_osv_checks,
)


def _make_zip(files: dict) -> bytes:
    """Build a ZIP archive from a {filename: content_str} dict."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# OSV hash query
# ---------------------------------------------------------------------------


class TestOsvHashQuery:
    def test_no_match_returns_empty_list(self):
        """An OSV response with empty vulns array should return []."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulns": []}
        with patch("osv_lookup.requests.post", return_value=mock_response):
            result = _query_osv_hash("a" * 64)
            assert result == []

    def test_match_returns_vulns(self):
        """An OSV response with vulnerabilities should return them."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulns": [{"id": "MAL-2026-001", "summary": "Compromised extension"}]
        }
        with patch("osv_lookup.requests.post", return_value=mock_response):
            result = _query_osv_hash("a" * 64)
            assert len(result) == 1
            assert result[0]["id"] == "MAL-2026-001"

    def test_network_error_returns_empty(self):
        """Network errors must not crash - return []."""
        with patch("osv_lookup.requests.post", side_effect=Exception("network")):
            assert _query_osv_hash("a" * 64) == []

    def test_500_returns_empty(self):
        mock_response = MagicMock()
        mock_response.status_code = 500
        with patch("osv_lookup.requests.post", return_value=mock_response):
            assert _query_osv_hash("a" * 64) == []


# ---------------------------------------------------------------------------
# npm batch query
# ---------------------------------------------------------------------------


class TestNpmBatchQuery:
    def test_empty_package_list_returns_empty(self):
        assert _query_osv_packages_batch([]) == []

    def test_batch_response_parsed(self):
        """OSV batch query result format: {results: [{vulns: [...]}, ...]}"""
        packages = [
            {"name": "left-pad", "version": "1.0.0", "ecosystem": "npm"},
            {"name": "is-promise", "version": "2.0.0", "ecosystem": "npm"},
        ]

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [
                {"vulns": [{"id": "CVE-2024-1234"}]},  # left-pad has 1 CVE
                {"vulns": []},  # is-promise is clean
            ]
        }
        with patch("osv_lookup.requests.post", return_value=mock_response):
            result = _query_osv_packages_batch(packages)
            assert len(result) == 1
            assert result[0]["id"] == "CVE-2024-1234"
            assert result[0]["_package"] == "left-pad"  # Annotated with pkg name


# ---------------------------------------------------------------------------
# ZIP content scanning
# ---------------------------------------------------------------------------


class TestZipScanning:
    def test_finds_npm_dependencies(self):
        """package.json deps should be extracted with cleaned version strings."""
        zip_bytes = _make_zip(
            {
                "package.json": json.dumps(
                    {
                        "name": "ext",
                        "dependencies": {"lodash": "^4.17.21", "axios": "~1.0.0"},
                        "devDependencies": {"jest": "29.0.0"},
                    }
                ),
            }
        )
        npm_packages, _ = _scan_zip_contents(zip_bytes)
        names = [p["name"] for p in npm_packages]
        assert set(names) == {"lodash", "axios", "jest"}

        # Version strings should be cleaned (no ^ ~)
        for pkg in npm_packages:
            assert pkg["version"][0].isdigit()

    def test_finds_cdn_references_in_js(self):
        """JS files loading from cdn.jsdelivr.net etc. should be flagged."""
        zip_bytes = _make_zip(
            {
                "background.js": (
                    'fetch("https://cdn.jsdelivr.net/npm/jquery@3/dist/jquery.min.js");\n'
                    'import("https://unpkg.com/lodash@4");\n'
                ),
            }
        )
        _, cdn_refs = _scan_zip_contents(zip_bytes)
        assert any("jsdelivr" in r for r in cdn_refs)
        assert any("unpkg.com" in r for r in cdn_refs)

    def test_clean_zip_no_findings(self):
        """A ZIP with just an innocent manifest should produce no findings."""
        zip_bytes = _make_zip(
            {
                "manifest.json": '{"name": "test"}',
                "background.js": 'console.log("hello world");\n',
            }
        )
        npm_packages, cdn_refs = _scan_zip_contents(zip_bytes)
        assert npm_packages == []
        assert cdn_refs == []

    def test_handles_malformed_package_json(self):
        """Broken package.json should not crash the scanner."""
        zip_bytes = _make_zip({"package.json": "this is not valid JSON"})
        npm_packages, _ = _scan_zip_contents(zip_bytes)
        assert npm_packages == []  # Skipped silently


# ---------------------------------------------------------------------------
# End-to-end run_osv_checks
# ---------------------------------------------------------------------------


class TestRunOsvChecks:
    def test_no_zip_skips_hash_checks(self):
        result = run_osv_checks(None, {})
        assert result["zip_hash"] is None
        assert result["osv_score"] == 0

    def test_hash_match_drives_score(self):
        """A hash that matches an OSV record should heavily score the extension."""
        zip_bytes = _make_zip({"manifest.json": "{}"})

        with (
            patch("osv_lookup._query_osv_hash") as mock_hash,
            patch("osv_lookup._query_osv_packages_batch", return_value=[]),
        ):
            mock_hash.return_value = [{"id": "MAL-2026-001"}]
            result = run_osv_checks(zip_bytes, {})
            assert result["osv_score"] >= 20  # Hash match contributes >= 20
            assert "MAL-2026-001" in str(result["flags"])

    def test_cdn_reference_adds_score(self):
        """JS loading from unpkg should add risk points."""
        zip_bytes = _make_zip(
            {
                "background.js": 'fetch("https://unpkg.com/evil-pkg@1.0.0");',
            }
        )
        with (
            patch("osv_lookup._query_osv_hash", return_value=[]),
            patch("osv_lookup._query_osv_packages_batch", return_value=[]),
        ):
            result = run_osv_checks(zip_bytes, {})
            assert result["osv_score"] > 0
            assert any("unpkg.com" in flag for flag in result["flags"])

    def test_score_clamped_at_30(self):
        """The osv_score contribution must be capped at 30 (was 20 before VT)."""
        zip_bytes = _make_zip(
            {
                "manifest.json": "{}",
                "background.js": "\n".join(f'fetch("https://unpkg.com/p{i}");' for i in range(20)),
            }
        )
        with (
            patch("osv_lookup._query_osv_hash", return_value=[{"id": "X"}] * 5),
            patch(
                "osv_lookup._query_osv_packages_batch",
                return_value=[{"id": "Y", "_package": "p"}] * 5,
            ),
        ):
            result = run_osv_checks(zip_bytes, {})
            assert result["osv_score"] <= 30
