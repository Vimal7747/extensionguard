# tests/test_config_schema.py - Config validation tests

import pytest

from config_schema import format_errors, validate

# ---------------------------------------------------------------------------
# Empty / disabled adapters: should always pass
# ---------------------------------------------------------------------------


class TestDisabledAdapters:
    def test_empty_config_is_valid(self):
        assert validate({}) == []

    def test_all_disabled_is_valid(self):
        cfg = {
            "sentinel": {"enabled": False},
            "splunk": {"enabled": False},
            "pagerduty": {"enabled": False},
            "slack": {"enabled": False},
        }
        assert validate(cfg) == []

    def test_disabled_adapter_with_garbage_creds_still_valid(self):
        """We only validate enabled adapters - keeps developers from being
        nagged about a Splunk section they're not using."""
        cfg = {"splunk": {"enabled": False, "hec_url": "not a url"}}
        assert validate(cfg) == []


# ---------------------------------------------------------------------------
# Required credentials when enabled
# ---------------------------------------------------------------------------


class TestRequiredKeys:
    def test_enabled_sentinel_needs_workspace_and_key(self):
        cfg = {"sentinel": {"enabled": True}}
        errors = validate(cfg)
        keys = {e["key"] for e in errors if e["section"] == "sentinel"}
        assert "workspace_id" in keys
        assert "shared_key" in keys

    def test_enabled_splunk_needs_url_and_token(self):
        cfg = {"splunk": {"enabled": True}}
        errors = validate(cfg)
        keys = {e["key"] for e in errors if e["section"] == "splunk"}
        assert "hec_url" in keys
        assert "hec_token" in keys

    def test_enabled_pagerduty_needs_integration_key(self):
        cfg = {"pagerduty": {"enabled": True}}
        errors = validate(cfg)
        keys = {e["key"] for e in errors if e["section"] == "pagerduty"}
        assert "integration_key" in keys

    def test_enabled_slack_needs_webhook_url(self):
        cfg = {"slack": {"enabled": True}}
        errors = validate(cfg)
        keys = {e["key"] for e in errors if e["section"] == "slack"}
        assert "webhook_url" in keys


# ---------------------------------------------------------------------------
# Placeholder detection
# ---------------------------------------------------------------------------


class TestPlaceholders:
    def test_unedited_placeholder_flagged(self):
        cfg = {
            "sentinel": {
                "enabled": True,
                "workspace_id": "YOUR-WORKSPACE-ID-HERE",
                "shared_key": "dGVzdA==",
            }
        }
        errors = validate(cfg)
        assert any("placeholder" in e["problem"] for e in errors)

    def test_real_value_not_flagged(self):
        cfg = {
            "sentinel": {
                "enabled": True,
                "workspace_id": "real-workspace-uuid-1234",
                "shared_key": "dGVzdA==",
            }
        }
        errors = validate(cfg)
        assert errors == []


# ---------------------------------------------------------------------------
# Type checking
# ---------------------------------------------------------------------------


class TestTypeChecks:
    def test_wrong_type_for_credential_flagged(self):
        cfg = {
            "splunk": {
                "enabled": True,
                "hec_url": "https://splunk.example.com/services/collector/event",
                "hec_token": 12345,  # should be a string
            }
        }
        errors = validate(cfg)
        assert any(e["key"] == "hec_token" and "expected str" in e["problem"] for e in errors)

    def test_adapter_section_must_be_object(self):
        cfg = {"splunk": "not an object"}
        errors = validate(cfg)
        assert any(e["section"] == "splunk" for e in errors)


# ---------------------------------------------------------------------------
# Severity values
# ---------------------------------------------------------------------------


class TestSeverityValidation:
    def test_invalid_severity_flagged(self):
        cfg = {
            "slack": {
                "enabled": True,
                "webhook_url": "https://hooks.slack.com/services/X/Y/realsecret",
                "min_severity": "extreme",  # not one of the valid four
            }
        }
        errors = validate(cfg)
        assert any(e["key"] == "min_severity" for e in errors)

    def test_dispatch_min_severity_validated(self):
        cfg = {"dispatch": {"min_severity": "ultra"}}
        errors = validate(cfg)
        assert any(e["section"] == "dispatch" and e["key"] == "min_severity" for e in errors)


# ---------------------------------------------------------------------------
# URL format
# ---------------------------------------------------------------------------


class TestUrlValidation:
    def test_url_must_have_scheme(self):
        cfg = {
            "splunk": {
                "enabled": True,
                "hec_url": "splunk.example.com:8088",  # no scheme
                "hec_token": "real-token-not-placeholder",
            }
        }
        errors = validate(cfg)
        assert any(e["key"] == "hec_url" and "http" in e["problem"] for e in errors)

    def test_valid_https_url_passes(self):
        cfg = {
            "splunk": {
                "enabled": True,
                "hec_url": "https://splunk.example.com:8088/services/collector/event",
                "hec_token": "real-token",
            }
        }
        errors = validate(cfg)
        assert all(e["key"] != "hec_url" for e in errors)


# ---------------------------------------------------------------------------
# Dispatch settings
# ---------------------------------------------------------------------------


class TestDispatchValidation:
    def test_negative_ttl_flagged(self):
        cfg = {"dispatch": {"dedup_ttl_seconds": -5}}
        errors = validate(cfg)
        assert any(e["key"] == "dedup_ttl_seconds" for e in errors)

    def test_zero_escalation_threshold_flagged(self):
        cfg = {"dispatch": {"escalation_threshold": 0}}
        errors = validate(cfg)
        assert any(e["key"] == "escalation_threshold" for e in errors)

    def test_score_out_of_range_flagged(self):
        cfg = {"dispatch": {"triage_min_score": 150}}
        errors = validate(cfg)
        assert any(e["key"] == "triage_min_score" for e in errors)

    def test_valid_dispatch_section(self):
        cfg = {
            "dispatch": {
                "dedup_ttl_seconds": 300,
                "escalation_threshold": 3,
                "min_severity": "low",
                "triage_min_score": 45,
            }
        }
        assert validate(cfg) == []


# ---------------------------------------------------------------------------
# Error formatting
# ---------------------------------------------------------------------------


class TestFormatErrors:
    def test_empty_errors_returns_ok_message(self):
        assert "OK" in format_errors([])

    def test_formats_section_and_key(self):
        errors = [{"section": "splunk", "key": "hec_url", "problem": "missing"}]
        msg = format_errors(errors)
        assert "splunk" in msg
        assert "hec_url" in msg
        assert "missing" in msg
