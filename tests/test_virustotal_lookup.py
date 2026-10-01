# tests/test_virustotal_lookup.py - VirusTotal v3 hash lookup tests

from unittest.mock import MagicMock, patch

import pytest
import requests

from extguard.virustotal_lookup import _is_placeholder, _looks_like_sha256, lookup_hash

# Canonical test hash - SHA-256 of empty string
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestLooksLikeSha256:
    def test_valid_hash(self):
        assert _looks_like_sha256(EMPTY_SHA256)
        assert _looks_like_sha256("a" * 64)

    def test_uppercase_also_valid(self):
        """SHA-256 hex is case-insensitive."""
        assert _looks_like_sha256("A" * 64)

    def test_wrong_length(self):
        assert not _looks_like_sha256("abc")
        assert not _looks_like_sha256("a" * 63)
        assert not _looks_like_sha256("a" * 65)

    def test_non_hex_chars(self):
        assert not _looks_like_sha256("z" * 64)

    def test_none_and_non_string(self):
        assert not _looks_like_sha256(None)
        assert not _looks_like_sha256(123)


class TestPlaceholderDetection:
    def test_detects_template_string(self):
        assert _is_placeholder("YOUR-VT-API-KEY-HERE")

    def test_detects_uppercase_marker(self):
        assert _is_placeholder("YOUR_API_KEY")

    def test_empty_string_is_placeholder(self):
        assert _is_placeholder("")

    def test_real_key_not_placeholder(self):
        assert not _is_placeholder("a1b2c3d4e5f6" * 5)


# ---------------------------------------------------------------------------
# Lookup happy paths (mocked HTTP)
# ---------------------------------------------------------------------------


class TestLookupHashSuccess:
    def test_clean_file_scores_zero(self):
        """A file with 0 malicious/suspicious verdicts should add 0 to risk."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 60,
                        "undetected": 5,
                    }
                }
            }
        }
        with patch("extguard.virustotal_lookup.requests.get", return_value=mock_resp):
            result = lookup_hash(EMPTY_SHA256, cfg={"api_key": "real-key-12345"})

        assert result["ok"] is True
        assert result["found"] is True
        assert result["malicious"] == 0
        assert result["score"] == 0
        assert result["flags"] == []
        assert result["permalink"].endswith(EMPTY_SHA256)

    def test_single_engine_flag_low_score(self):
        """1-2 engines flagging = treat as possible FP, low score (10)."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 1,
                        "suspicious": 0,
                        "harmless": 50,
                        "undetected": 14,
                    }
                }
            }
        }
        with patch("extguard.virustotal_lookup.requests.get", return_value=mock_resp):
            result = lookup_hash(EMPTY_SHA256, cfg={"api_key": "x" * 32})
        assert result["score"] == 10
        assert any("possible false positive" in f for f in result["flags"])

    def test_medium_consensus_likely_malicious(self):
        """3-10 engines = multi-vendor consensus = score 20."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 0,
                        "harmless": 45,
                        "undetected": 15,
                    }
                }
            }
        }
        with patch("extguard.virustotal_lookup.requests.get", return_value=mock_resp):
            result = lookup_hash(EMPTY_SHA256, cfg={"api_key": "x" * 32})
        assert result["score"] == 20
        assert any("likely malicious" in f for f in result["flags"])

    def test_overwhelming_consensus_confirmed_malicious(self):
        """11+ engines = confirmed malicious = score 30 (the ceiling)."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 25,
                        "suspicious": 2,
                        "harmless": 30,
                        "undetected": 8,
                    }
                }
            }
        }
        with patch("extguard.virustotal_lookup.requests.get", return_value=mock_resp):
            result = lookup_hash(EMPTY_SHA256, cfg={"api_key": "x" * 32})
        assert result["score"] == 30
        assert any("CONFIRMED MALICIOUS" in f for f in result["flags"])

    def test_total_counts_only_real_verdicts(self):
        """type-unsupported / timeout / failure used to inflate the denominator."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 3,
                        "suspicious": 0,
                        "harmless": 10,
                        "undetected": 7,
                        "type-unsupported": 14,
                        "timeout": 2,
                        "failure": 1,
                    }
                }
            }
        }
        with patch("extguard.virustotal_lookup.requests.get", return_value=mock_resp):
            result = lookup_hash(EMPTY_SHA256, cfg={"api_key": "x" * 32})
        assert result["total"] == 20

    def test_404_means_not_in_vt_database(self):
        """A hash unknown to VT is a valid result, not an error."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        with patch("extguard.virustotal_lookup.requests.get", return_value=mock_resp):
            result = lookup_hash(EMPTY_SHA256, cfg={"api_key": "x" * 32})
        assert result["ok"] is True
        assert result["found"] is False
        assert result["score"] == 0


# ---------------------------------------------------------------------------
# Failure modes - each must return a clean error dict, not crash
# ---------------------------------------------------------------------------


class TestLookupHashFailures:
    def test_no_api_key_returns_skipped(self, monkeypatch):
        """No env key and no config key = skip cleanly."""
        monkeypatch.delenv("VT_API_KEY", raising=False)
        result = lookup_hash(EMPTY_SHA256, cfg={})
        assert result["ok"] is True
        assert "No VT_API_KEY" in result["error"]

    def test_placeholder_api_key_treated_as_missing(self, monkeypatch):
        monkeypatch.delenv("VT_API_KEY", raising=False)
        result = lookup_hash(EMPTY_SHA256, cfg={"api_key": "YOUR-VT-API-KEY-HERE"})
        assert result["ok"] is True
        assert "No VT_API_KEY" in result["error"]

    def test_vt_disabled_env_var(self, monkeypatch):
        """VT_DISABLED=1 is the global opt-out for confidentiality-sensitive teams."""
        monkeypatch.setenv("VT_DISABLED", "1")
        monkeypatch.setenv("VT_API_KEY", "real-key-12345")
        result = lookup_hash(EMPTY_SHA256, cfg={})
        assert result["ok"] is True
        assert "VT_DISABLED" in result["error"]

    def test_invalid_sha256_rejected(self):
        result = lookup_hash("not a hash", cfg={"api_key": "x" * 32})
        assert result["ok"] is False
        assert "Invalid SHA-256" in result["error"]

    def test_unauthorized_401(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        with patch("extguard.virustotal_lookup.requests.get", return_value=mock_resp):
            result = lookup_hash(EMPTY_SHA256, cfg={"api_key": "bad-key"})
        assert result["ok"] is False
        assert "401" in result["error"]

    def test_rate_limit_429(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        with patch("extguard.virustotal_lookup.requests.get", return_value=mock_resp):
            result = lookup_hash(EMPTY_SHA256, cfg={"api_key": "x" * 32})
        assert result["ok"] is False
        assert "rate limit" in result["error"].lower()

    def test_timeout_handled(self):
        with patch(
            "extguard.virustotal_lookup.requests.get",
            side_effect=requests.exceptions.Timeout("slow"),
        ):
            result = lookup_hash(EMPTY_SHA256, cfg={"api_key": "x" * 32})
        assert result["ok"] is False
        assert "timed out" in result["error"].lower()

    def test_connection_error_handled(self):
        with patch(
            "extguard.virustotal_lookup.requests.get",
            side_effect=requests.exceptions.ConnectionError("dns"),
        ):
            result = lookup_hash(EMPTY_SHA256, cfg={"api_key": "x" * 32})
        assert result["ok"] is False
        assert "connection" in result["error"].lower()

    def test_malformed_response_shape(self):
        """A 200 with unexpected JSON shape should not crash."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"unexpected": "structure"}
        with patch("extguard.virustotal_lookup.requests.get", return_value=mock_resp):
            result = lookup_hash(EMPTY_SHA256, cfg={"api_key": "x" * 32})
        assert result["ok"] is False
        assert "shape" in result["error"].lower()


# ---------------------------------------------------------------------------
# Env-var precedence
# ---------------------------------------------------------------------------


class TestApiKeyPrecedence:
    def test_env_var_used_when_present(self, monkeypatch):
        """VT_API_KEY env var should be preferred over cfg.api_key."""
        monkeypatch.setenv("VT_API_KEY", "env-key-1234567890")

        captured_headers = {}

        def _fake_get(url, headers=None, timeout=None):
            captured_headers.update(headers or {})
            mock = MagicMock()
            mock.status_code = 404
            return mock

        with patch("extguard.virustotal_lookup.requests.get", side_effect=_fake_get):
            lookup_hash(EMPTY_SHA256, cfg={"api_key": "config-key-9999"})

        # The env var should win
        assert captured_headers["x-apikey"] == "env-key-1234567890"

    def test_cfg_key_used_when_env_absent(self, monkeypatch):
        monkeypatch.delenv("VT_API_KEY", raising=False)

        captured_headers = {}

        def _fake_get(url, headers=None, timeout=None):
            captured_headers.update(headers or {})
            mock = MagicMock()
            mock.status_code = 404
            return mock

        with patch("extguard.virustotal_lookup.requests.get", side_effect=_fake_get):
            lookup_hash(EMPTY_SHA256, cfg={"api_key": "config-only-key-12345"})

        assert captured_headers["x-apikey"] == "config-only-key-12345"


# ---------------------------------------------------------------------------
# Integration with osv_lookup
# ---------------------------------------------------------------------------


class TestOsvIntegration:
    """Confirm run_osv_checks correctly merges VT score and flags."""

    def test_vt_not_queried_when_cfg_absent(self):
        """Backwards compatible: no vt_cfg means VT isn't called."""
        import io
        import zipfile

        from extguard.osv_lookup import run_osv_checks

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("manifest.json", "{}")

        with (
            patch("extguard.osv_lookup._query_osv_packages_batch", return_value=([], None)),
        ):
            result = run_osv_checks(buf.getvalue(), {}, vt_cfg=None)

        assert result["vt"]["queried"] is False

    def test_vt_not_queried_when_disabled(self):
        import io
        import zipfile

        from extguard.osv_lookup import run_osv_checks

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("manifest.json", "{}")

        with (
            patch("extguard.osv_lookup._query_osv_packages_batch", return_value=([], None)),
        ):
            result = run_osv_checks(
                buf.getvalue(),
                {},
                vt_cfg={"enabled": False, "api_key": "x" * 32},
            )

        assert result["vt"]["queried"] is False

    def test_vt_score_flows_into_osv_total(self, monkeypatch):
        """When VT fires and adds 30 points, osv_score reflects it."""
        import io
        import zipfile

        from extguard.osv_lookup import run_osv_checks

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("manifest.json", "{}")

        monkeypatch.setenv("VT_API_KEY", "real-key-12345")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 20,
                        "suspicious": 0,
                        "harmless": 30,
                        "undetected": 5,
                    }
                }
            }
        }
        with (
            patch("extguard.osv_lookup._query_osv_packages_batch", return_value=([], None)),
            patch("extguard.virustotal_lookup.requests.get", return_value=mock_resp),
        ):
            result = run_osv_checks(
                buf.getvalue(),
                {},
                vt_cfg={"enabled": True},
            )

        assert result["vt"]["queried"] is True
        assert result["vt"]["malicious"] == 20
        assert result["osv_score"] >= 30
        # The VT-confirmed flag should be in the merged flags list
        assert any("CONFIRMED MALICIOUS" in f for f in result["flags"])
