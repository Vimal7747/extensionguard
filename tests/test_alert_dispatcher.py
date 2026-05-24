# tests/test_alert_dispatcher.py - Tests for the Stage 4 dispatcher
#
# Covers dedup TTL, escalation threshold, source normalisation, and severity filtering.
# We don't dispatch to real adapters here - that's in test_adapters.py.

import copy
import time

import pytest

from alert_dispatcher import (
    SAMPLE_ALERT,
    AlertState,
    _fingerprint,
    _severity_meets_minimum,
    _strip_comments,
    enrich,
    load_config,
    normalise_alert,
)

# ---------------------------------------------------------------------------
# Fingerprinting - the deduplication key
# ---------------------------------------------------------------------------

class TestFingerprint:
    def test_uses_rule_and_extension_id(self, sample_alert):
        fp = _fingerprint(sample_alert)
        assert "RULE-01" in fp
        assert sample_alert["extension"]["id"] in fp

    def test_falls_back_to_title_if_no_id(self):
        alert = {"rule": "RULE-01", "extension": {"title": "Some Ext"}}
        fp = _fingerprint(alert)
        assert "Some Ext" in fp

    def test_same_alert_same_fingerprint(self, sample_alert):
        a = copy.deepcopy(sample_alert)
        b = copy.deepcopy(sample_alert)
        # Even with different alert_time / details, fingerprint stays stable
        b["alert_time"] = "2030-01-01T00:00:00Z"
        assert _fingerprint(a) == _fingerprint(b)

    def test_different_rule_different_fingerprint(self, sample_alert):
        a = copy.deepcopy(sample_alert)
        b = copy.deepcopy(sample_alert)
        b["rule"] = "RULE-02"
        assert _fingerprint(a) != _fingerprint(b)


# ---------------------------------------------------------------------------
# Severity comparison
# ---------------------------------------------------------------------------

class TestSeverityMeetsMinimum:
    def test_critical_meets_all_floors(self):
        for floor in ("low", "medium", "high", "critical"):
            assert _severity_meets_minimum("critical", floor)

    def test_low_only_meets_low(self):
        assert _severity_meets_minimum("low", "low")
        assert not _severity_meets_minimum("low", "medium")
        assert not _severity_meets_minimum("low", "high")
        assert not _severity_meets_minimum("low", "critical")

    def test_unknown_severity_passes(self):
        """Defensive: unknown severity strings should not silently drop alerts."""
        assert _severity_meets_minimum("blue", "low")


# ---------------------------------------------------------------------------
# Dedup + escalation state machine
# ---------------------------------------------------------------------------

class TestAlertState:
    def test_first_alert_is_sent(self, sample_alert):
        state = AlertState(dedup_ttl=300, escalation_threshold=3)
        send, escalated, _ = state.should_send(sample_alert)
        assert send is True
        assert escalated is False

    def test_immediate_duplicate_suppressed(self, sample_alert):
        state = AlertState(dedup_ttl=300, escalation_threshold=3)
        state.should_send(sample_alert)
        send, _, reason = state.should_send(sample_alert)
        assert send is False
        assert "Duplicate" in reason

    def test_escalation_fires_at_threshold(self, sample_alert):
        """Bypass dedup with ttl=0 to test the escalation counter."""
        state = AlertState(dedup_ttl=0, escalation_threshold=3)
        for _ in range(2):
            _, escalated, _ = state.should_send(sample_alert)
            assert not escalated

        # 3rd send should trigger escalation
        _, escalated, _ = state.should_send(sample_alert)
        assert escalated is True

    def test_escalation_only_fires_once(self, sample_alert):
        """The 4th, 5th, ... sends should not re-fire escalation."""
        state = AlertState(dedup_ttl=0, escalation_threshold=3)
        for _ in range(3):
            state.should_send(sample_alert)
        # 4th and 5th: still sends, but no new escalation
        for _ in range(2):
            _, escalated, _ = state.should_send(sample_alert)
            assert escalated is False

    def test_different_extensions_dont_collide(self, sample_alert):
        """Two different extensions hitting the same rule shouldn't dedup-collide."""
        state = AlertState(dedup_ttl=300, escalation_threshold=3)
        state.should_send(sample_alert)

        other = copy.deepcopy(sample_alert)
        other["extension"]["id"] = "differentextensionidhere12345678"
        send, _, _ = state.should_send(other)
        assert send is True


# ---------------------------------------------------------------------------
# Alert normalisation (monitor vs triage source)
# ---------------------------------------------------------------------------

class TestNormalisation:
    def test_monitor_alert_passthrough(self, sample_alert):
        result = normalise_alert(sample_alert, "monitor")
        assert result == sample_alert

    def test_monitor_alert_without_rule_dropped(self):
        bad = {"severity": "high"}   # missing rule
        assert normalise_alert(bad, "monitor") is None

    def test_triage_low_risk_dropped(self):
        """We don't page on LOW-risk pre-install scans."""
        low_triage = {
            "extension_name":  "Benign",
            "composite_score": 5,
            "risk_level":      "low",
            "ai_triage":       None,
        }
        assert normalise_alert(low_triage, "triage") is None

    def test_triage_critical_converted_to_alert(self, sample_triage_result):
        """A critical triage should become a STAGE2-TRIAGE alert."""
        alert = normalise_alert(sample_triage_result, "triage")
        assert alert is not None
        assert alert["rule"] == "STAGE2-TRIAGE"
        assert alert["severity"] == "critical"
        assert alert["extension"]["title"] == sample_triage_result["extension_name"]
        assert "T1176" in alert["mitre"]


# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------

class TestEnrich:
    def test_adds_sensor_host(self, sample_alert):
        enriched = enrich(sample_alert, escalated=False)
        assert "sensor_host" in enriched
        assert enriched["sensor_host"]   # not empty

    def test_escalation_promotes_severity(self, sample_alert):
        sample_alert["severity"] = "high"
        enriched = enrich(sample_alert, escalated=True)
        assert enriched["severity"] == "critical"
        assert enriched["escalated"] is True
        assert "escalation_note" in enriched

    def test_no_escalation_preserves_severity(self, sample_alert):
        enriched = enrich(sample_alert, escalated=False)
        assert enriched["severity"] == sample_alert["severity"]
        assert "escalated" not in enriched

    def test_adds_recommendation(self, sample_alert):
        enriched = enrich(sample_alert, escalated=False)
        assert "BLOCK IMMEDIATELY" in enriched["recommendation"]   # critical -> block

    def test_does_not_mutate_input(self, sample_alert):
        """Enrichment must work on a copy - original alert untouched."""
        original = copy.deepcopy(sample_alert)
        enrich(sample_alert, escalated=True)
        assert sample_alert == original


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

class TestStdinAutoDetect:
    """The triage stdin reader must handle both line-mode and document-mode."""

    def test_document_mode_pretty_printed_json(self, monkeypatch, sample_triage_result):
        """main.py --json output is multi-line pretty JSON - should parse fine."""
        import io
        import json as _json

        from alert_dispatcher import _read_triage_stdin

        pretty = _json.dumps(sample_triage_result, indent=2)
        monkeypatch.setattr("sys.stdin", io.StringIO(pretty))

        results = list(_read_triage_stdin(verbose=False))
        assert len(results) == 1
        assert results[0]["extension_name"] == sample_triage_result["extension_name"]

    def test_line_mode_jsonl(self, monkeypatch):
        """A user piping behavioral_monitor --output-json by mistake should
        still get every alert parsed correctly (one per line)."""
        import io

        from alert_dispatcher import _read_triage_stdin

        lines = (
            '{"rule": "RULE-01", "severity": "high"}\n'
            '{"rule": "RULE-02", "severity": "medium"}\n'
        )
        monkeypatch.setattr("sys.stdin", io.StringIO(lines))

        results = list(_read_triage_stdin(verbose=False))
        assert len(results) == 2
        assert results[0]["rule"] == "RULE-01"
        assert results[1]["rule"] == "RULE-02"

    def test_empty_stdin_returns_nothing(self, monkeypatch):
        import io

        from alert_dispatcher import _read_triage_stdin
        monkeypatch.setattr("sys.stdin", io.StringIO(""))
        assert list(_read_triage_stdin(verbose=False)) == []


class TestConfigLoading:
    def test_strips_comment_keys(self):
        """Keys starting with _ (like _comment) should be removed."""
        raw = {
            "sentinel": {
                "_comment": "this is documentation",
                "enabled":  True,
                "workspace_id": "abc",
            },
        }
        clean = _strip_comments(raw)
        assert "_comment" not in clean["sentinel"]
        assert clean["sentinel"]["enabled"] is True

    def test_load_config_missing_file_returns_defaults(self, tmp_path):
        """A missing config file should not crash - return all-disabled defaults."""
        cfg = load_config(tmp_path / "nonexistent.json")
        assert cfg["sentinel"]["enabled"] is False
        assert cfg["splunk"]["enabled"] is False
        assert cfg["pagerduty"]["enabled"] is False
        assert cfg["slack"]["enabled"] is False

    def test_load_config_malformed_json_returns_defaults(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{this is not valid json")
        cfg = load_config(bad)
        # Defaults, not a crash
        assert cfg["sentinel"]["enabled"] is False

    def test_load_config_valid_file(self, tmp_path):
        good = tmp_path / "good.json"
        good.write_text('{"sentinel": {"enabled": true, "workspace_id": "x"}}')
        cfg = load_config(good)
        assert cfg["sentinel"]["enabled"] is True
        assert cfg["sentinel"]["workspace_id"] == "x"
