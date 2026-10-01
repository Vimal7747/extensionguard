# tests/test_adapters.py - Tests for the four destination adapters
#
# All HTTP calls are mocked - we test our payload-building and response-handling
# logic, not the real Sentinel / Splunk / PagerDuty / Slack APIs.

import base64
import copy
import hashlib
import hmac
import json
from unittest.mock import MagicMock, patch

import pytest

from extguard.adapters import pagerduty, sentinel, slack, splunk

# ---------------------------------------------------------------------------
# Sentinel - HMAC-SHA256 signed Log Analytics API
# ---------------------------------------------------------------------------


class TestSentinelAdapter:
    @pytest.fixture
    def cfg(self):
        return {
            "workspace_id": "test-workspace-id",
            # 'test' base64-encoded - real workspaces use a 64-byte base64 key
            "shared_key": base64.b64encode(b"super-secret-key-bytes").decode(),
            "log_type": "ExtensionGuardAlert",
            "timeout_sec": 5,
        }

    def test_successful_send(self, cfg, sample_alert):
        mock_response = MagicMock()
        mock_response.status_code = 200
        with patch(
            "extguard.adapters.http_retry.requests.post", return_value=mock_response
        ) as mock_post:
            result = sentinel.send(sample_alert, cfg)
            assert result["ok"] is True
            mock_post.assert_called_once()

    def test_failed_send_returns_error(self, cfg, sample_alert):
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.text = "Forbidden"
        with patch("extguard.adapters.http_retry.requests.post", return_value=mock_response):
            result = sentinel.send(sample_alert, cfg)
            assert result["ok"] is False
            assert "403" in result["error"]

    def test_network_error_returns_error(self, cfg, sample_alert):
        """After retries are exhausted, surface a clear error.

        We mock at adapters.http_retry (the layer that actually issues the
        request) and also patch the sleep so the test doesn't wait through
        the real backoff."""
        import requests

        with (
            patch(
                "extguard.adapters.http_retry.requests.post",
                side_effect=requests.exceptions.ConnectionError("down"),
            ),
            patch("extguard.adapters.http_retry.time.sleep"),
        ):
            result = sentinel.send(sample_alert, cfg)
            assert result["ok"] is False
            assert "exhausted" in result["error"].lower()

    def test_payload_includes_required_headers(self, cfg, sample_alert):
        """Sentinel requires Authorization, x-ms-date, Log-Type headers."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        with patch(
            "extguard.adapters.http_retry.requests.post", return_value=mock_response
        ) as mock_post:
            sentinel.send(sample_alert, cfg)
            call_kwargs = mock_post.call_args.kwargs
            headers = call_kwargs["headers"]
            assert "Authorization" in headers
            assert "x-ms-date" in headers
            assert headers["Log-Type"] == "ExtensionGuardAlert"
            assert headers["Authorization"].startswith("SharedKey test-workspace-id:")

    def test_auth_signature_is_deterministic(self, cfg):
        """Same inputs must produce the same HMAC signature."""
        sig1 = sentinel._build_auth_header(
            workspace_id="ws",
            shared_key=cfg["shared_key"],
            date="Fri, 01 Jan 2026 00:00:00 GMT",
            content_len=100,
            content_type="application/json",
            resource="/api/logs",
        )
        sig2 = sentinel._build_auth_header(
            workspace_id="ws",
            shared_key=cfg["shared_key"],
            date="Fri, 01 Jan 2026 00:00:00 GMT",
            content_len=100,
            content_type="application/json",
            resource="/api/logs",
        )
        assert sig1 == sig2

    def test_flatten_alert_handles_nesting(self, sample_alert):
        flat = sentinel._flatten_alert(sample_alert)
        # Nested dict keys should be joined with _
        assert "extension_id" in flat
        assert "extension_title" in flat
        assert "detail_description" in flat
        # Lists should be comma-joined strings
        assert isinstance(flat["mitre"], str)
        assert "T1176" in flat["mitre"]


# ---------------------------------------------------------------------------
# Splunk HEC adapter
# ---------------------------------------------------------------------------


class TestSplunkAdapter:
    @pytest.fixture
    def cfg(self):
        return {
            "hec_url": "https://splunk.example.com:8088/services/collector/event",
            "hec_token": "00000000-0000-0000-0000-000000000000",
            "index": "security",
            "sourcetype": "extguard:alert",
            "ssl_verify": True,
            "timeout_sec": 5,
        }

    def test_successful_send(self, cfg, sample_alert):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b'{"text":"Success","code":0}'
        mock_response.json.return_value = {"text": "Success", "code": 0}
        with patch("extguard.adapters.http_retry.requests.post", return_value=mock_response):
            result = splunk.send(sample_alert, cfg)
            assert result["ok"] is True

    def test_failed_response_returns_error(self, cfg, sample_alert):
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.content = b'{"text":"Invalid token","code":4}'
        mock_response.json.return_value = {"text": "Invalid token", "code": 4}
        with patch("extguard.adapters.http_retry.requests.post", return_value=mock_response):
            result = splunk.send(sample_alert, cfg)
            assert result["ok"] is False
            assert "code=4" in result["error"]

    def test_auth_header_format(self, cfg, sample_alert):
        """Splunk HEC requires 'Authorization: Splunk <token>' header."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b'{"text":"Success","code":0}'
        mock_response.json.return_value = {"text": "Success", "code": 0}
        with patch(
            "extguard.adapters.http_retry.requests.post", return_value=mock_response
        ) as mock_post:
            splunk.send(sample_alert, cfg)
            headers = mock_post.call_args.kwargs["headers"]
            assert headers["Authorization"] == f"Splunk {cfg['hec_token']}"

    def test_payload_wraps_alert_in_event(self, cfg, sample_alert):
        """Splunk HEC expects {time, source, sourcetype, index, event} structure."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b'{"text":"Success","code":0}'
        mock_response.json.return_value = {"text": "Success", "code": 0}
        with patch(
            "extguard.adapters.http_retry.requests.post", return_value=mock_response
        ) as mock_post:
            splunk.send(sample_alert, cfg)
            payload = mock_post.call_args.kwargs["json"]
            assert payload["event"] == sample_alert
            assert payload["sourcetype"] == "extguard:alert"
            assert payload["index"] == "security"
            assert isinstance(payload["time"], float)

    def test_iso_to_epoch_handles_invalid(self):
        """A malformed ISO timestamp should fall back to current time, not crash."""
        epoch = splunk._iso_to_epoch("not a timestamp")
        import time

        assert abs(epoch - time.time()) < 5  # Close to "now"


# ---------------------------------------------------------------------------
# PagerDuty Events v2 adapter
# ---------------------------------------------------------------------------


class TestPagerDutyAdapter:
    @pytest.fixture
    def cfg(self):
        return {
            "integration_key": "12345abcdef67890",
            "min_severity": "high",
            "timeout_sec": 5,
        }

    def test_critical_alert_dispatched(self, cfg, sample_alert):
        mock_response = MagicMock()
        mock_response.status_code = 202
        mock_response.content = b'{"status":"success","dedup_key":"x"}'
        mock_response.json.return_value = {"status": "success", "dedup_key": "x"}
        with patch("extguard.adapters.http_retry.requests.post", return_value=mock_response):
            result = pagerduty.send(sample_alert, cfg)
            assert result["ok"] is True
            assert "incident_key" in result

    def test_low_severity_alert_skipped(self, cfg):
        """min_severity=high means low and medium alerts are skipped, not dispatched."""
        low_alert = {
            "rule": "RULE-99",
            "severity": "low",
            "extension": {"id": "abc", "title": "X"},
            "detail": {"description": "noisy"},
            "mitre": [],
        }
        # Even without mocking, this should not hit the network
        with patch("extguard.adapters.http_retry.requests.post") as mock_post:
            result = pagerduty.send(low_alert, cfg)
            assert result.get("skipped") is True
            mock_post.assert_not_called()

    def test_dedup_key_format(self, cfg, sample_alert):
        """dedup_key should be extguard-<rule>-<ext_id> so re-fires update incidents."""
        mock_response = MagicMock()
        mock_response.status_code = 202
        mock_response.content = b'{"status":"success"}'
        mock_response.json.return_value = {"status": "success"}
        with patch(
            "extguard.adapters.http_retry.requests.post", return_value=mock_response
        ) as mock_post:
            pagerduty.send(sample_alert, cfg)
            payload = mock_post.call_args.kwargs["json"]
            assert payload["dedup_key"] == f"extguard-RULE-01-{sample_alert['extension']['id']}"

    def test_severity_mapping(self, cfg, sample_alert):
        """ExtensionGuard critical -> PD critical."""
        mock_response = MagicMock()
        mock_response.status_code = 202
        mock_response.content = b'{"status":"success"}'
        mock_response.json.return_value = {"status": "success"}
        with patch(
            "extguard.adapters.http_retry.requests.post", return_value=mock_response
        ) as mock_post:
            pagerduty.send(sample_alert, cfg)
            payload = mock_post.call_args.kwargs["json"]
            assert payload["payload"]["severity"] == "critical"

    def test_resolve_sends_resolve_event(self, cfg):
        """The resolve() function should send event_action=resolve."""
        mock_response = MagicMock()
        mock_response.status_code = 202
        with patch(
            "extguard.adapters.http_retry.requests.post", return_value=mock_response
        ) as mock_post:
            result = pagerduty.resolve("RULE-01", "abc-ext-id", cfg)
            assert result["ok"] is True
            payload = mock_post.call_args.kwargs["json"]
            assert payload["event_action"] == "resolve"
            assert payload["dedup_key"] == "extguard-RULE-01-abc-ext-id"

    def test_acknowledge_keeps_incident_open(self, cfg):
        mock_response = MagicMock()
        mock_response.status_code = 202
        with patch(
            "extguard.adapters.http_retry.requests.post", return_value=mock_response
        ) as mock_post:
            assert pagerduty.acknowledge("RULE-01", "x", cfg)["ok"] is True
            assert mock_post.call_args.kwargs["json"]["event_action"] == "acknowledge"

    def test_resolve_is_retried(self, cfg):
        """resolve() used a bare requests.post with no retry."""
        bad, good = MagicMock(status_code=503, text="busy"), MagicMock(status_code=202)
        with (
            patch(
                "extguard.adapters.http_retry.requests.post", side_effect=[bad, good]
            ) as mock_post,
            patch("extguard.adapters.http_retry.time.sleep"),
        ):
            assert pagerduty.resolve("RULE-01", "x", cfg)["ok"] is True
            assert mock_post.call_count == 2


# ---------------------------------------------------------------------------
# Slack Incoming Webhook adapter
# ---------------------------------------------------------------------------


class TestSlackAdapter:
    @pytest.fixture
    def cfg(self):
        return {
            "webhook_url": "https://hooks.slack.com/services/T0/B0/X",
            "min_severity": "medium",
            "channel": "#security",
            "timeout_sec": 5,
        }

    def test_successful_send(self, cfg, sample_alert):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "ok"
        with patch("extguard.adapters.http_retry.requests.post", return_value=mock_response):
            result = slack.send(sample_alert, cfg)
            assert result["ok"] is True

    def test_below_min_severity_skipped(self, cfg):
        """min_severity=medium means low alerts are skipped."""
        low_alert = {
            "alert_time": "2026-01-01T00:00:00Z",
            "rule": "X",
            "severity": "low",
            "extension": {"title": "X"},
            "detail": {"description": "x"},
            "mitre": [],
        }
        with patch("extguard.adapters.http_retry.requests.post") as mock_post:
            result = slack.send(low_alert, cfg)
            assert result.get("skipped") is True
            mock_post.assert_not_called()

    def test_payload_uses_block_kit(self, cfg, sample_alert):
        """Slack payload should have 'attachments' with a coloured stripe."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "ok"
        with patch(
            "extguard.adapters.http_retry.requests.post", return_value=mock_response
        ) as mock_post:
            slack.send(sample_alert, cfg)
            payload = mock_post.call_args.kwargs["json"]
            assert "attachments" in payload
            attachment = payload["attachments"][0]
            assert "color" in attachment
            assert "blocks" in attachment

    def test_critical_uses_red_colour(self, cfg, sample_alert):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "ok"
        with patch(
            "extguard.adapters.http_retry.requests.post", return_value=mock_response
        ) as mock_post:
            slack.send(sample_alert, cfg)
            colour = mock_post.call_args.kwargs["json"]["attachments"][0]["color"]
            assert colour.upper() == "#FF0000"

    def test_non_ok_response_returns_error(self, cfg, sample_alert):
        """If Slack returns anything but 200+'ok', adapter must surface the failure."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "invalid_payload"  # Slack error sentinel
        with patch("extguard.adapters.http_retry.requests.post", return_value=mock_response):
            result = slack.send(sample_alert, cfg)
            assert result["ok"] is False


class TestSlackEscaping:
    """The extension name/description/URL come from a possibly malicious extension."""

    def _payload_text(self, alert) -> str:
        return json.dumps(slack._build_message(alert))

    def test_mention_and_disguised_link_are_neutralised(self, sample_alert):
        """Regression: an extension named like this used to ping the whole SOC
        channel and show a disguised phishing link."""
        alert = copy.deepcopy(sample_alert)
        alert["extension"]["title"] = "<!channel> <https://evil.example|Click to remediate>"
        alert["detail"]["description"] = "<@U12345> please approve"
        text = self._payload_text(alert)
        assert "<!channel>" not in text
        assert "<https://evil.example|" not in text
        assert "<@U12345>" not in text
        assert "&lt;!channel&gt;" in text

    def test_backtick_cannot_escape_code_span(self, sample_alert):
        alert = copy.deepcopy(sample_alert)
        alert["detail"]["url"] = "https://x.example/`*bold*`"
        text = self._payload_text(alert)
        assert "`*bold*`" not in text

    def test_long_description_is_truncated_not_rejected(self, sample_alert):
        """Slack rejects sections > 3000 chars; a rejected message = a lost alert."""
        alert = copy.deepcopy(sample_alert)
        alert["detail"]["description"] = "A" * 10_000
        blocks = slack._build_message(alert)["attachments"][0]["blocks"]
        for block in blocks:
            text = block.get("text", {}).get("text", "")
            assert len(text) < 3000

    def test_escape_helper(self):
        assert slack._slack_escape("a & <b>") == "a &amp; &lt;b&gt;"
