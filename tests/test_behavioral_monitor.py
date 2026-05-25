# tests/test_behavioral_monitor.py - Stage 3 CDP detection rule tests
#
# Strategy: every test that touches the async pipeline drives the rule
# handlers directly with hand-crafted CDP event payloads, then drains the
# asyncio.Queue and inspects what came out. This avoids needing a real
# WebSocket or live Chrome at any point.
#
# The synchronous helpers (_make_alert, _rule_to_mitre, get_extension_targets)
# are tested directly with mocked requests.

import asyncio
import time
from unittest.mock import MagicMock, patch

import pytest

import behavioral_monitor as bm

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_target():
    """A canned CDP target descriptor (background service worker)."""
    return {
        "id": "tab-id-xyz",
        "title": "Suspect Extension",
        "url": "chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef/sw.js",
        "type": "service_worker",
        "_ext_id": "abcdefghijklmnopqrstuvwxyzabcdef",
    }


@pytest.fixture(autouse=True)
def reset_beacon_tracker():
    """Make sure beacon-frequency state doesn't leak between tests."""
    bm._beacon_tracker.clear()
    yield
    bm._beacon_tracker.clear()


@pytest.fixture
def alert_queue():
    return asyncio.Queue()


def _drain(queue):
    """Return all alerts currently in the queue as a list."""
    out = []
    while not queue.empty():
        out.append(queue.get_nowait())
    return out


# ---------------------------------------------------------------------------
# Synchronous helpers
# ---------------------------------------------------------------------------


class TestMakeAlert:
    def test_minimal_alert_has_required_keys(self, fake_target):
        alert = bm._make_alert("RULE-01", "critical", fake_target, {})
        assert alert["rule"] == "RULE-01"
        assert alert["severity"] == "critical"
        assert alert["extension"]["id"] == fake_target["id"]
        assert alert["extension"]["title"] == fake_target["title"]
        assert "alert_time" in alert
        assert "mitre" in alert

    def test_detail_passed_through(self, fake_target):
        detail = {"description": "test", "url": "https://x.example/y"}
        alert = bm._make_alert("RULE-02", "high", fake_target, detail)
        assert alert["detail"] == detail

    def test_mitre_techniques_populated(self, fake_target):
        """Each rule must map to at least one MITRE technique."""
        for rule in ("RULE-01", "RULE-02", "RULE-03", "RULE-04", "RULE-05", "RULE-06"):
            alert = bm._make_alert(rule, "high", fake_target, {})
            assert isinstance(alert["mitre"], list)
            assert len(alert["mitre"]) >= 1
            # Every technique ID should look like "T#####" or "T#####.###"
            for technique in alert["mitre"]:
                assert technique.startswith("T")


class TestRuleToMitre:
    @pytest.mark.parametrize(
        "rule,expected_first",
        [
            ("RULE-01", "T1071.001"),
            ("RULE-02", "T1555.003"),
            ("RULE-03", "T1530"),
            ("RULE-04", "T1555.003"),
            ("RULE-05", "T1176"),
            ("RULE-06", "T1059.007"),
        ],
    )
    def test_known_rule_maps_to_expected_technique(self, rule, expected_first):
        techniques = bm._rule_to_mitre(rule)
        assert techniques[0] == expected_first

    def test_unknown_rule_falls_back_to_t1176(self):
        """Default: anything browser-extension-related maps to T1176."""
        assert bm._rule_to_mitre("RULE-99-FUTURE") == ["T1176"]


# ---------------------------------------------------------------------------
# Target enumeration
# ---------------------------------------------------------------------------


class TestGetExtensionTargets:
    def test_filters_extension_background_workers(self):
        """Only chrome-extension:// URLs of the right type should be returned."""
        cdp_response = [
            {
                "type": "service_worker",
                "url": "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/sw.js",
            },
            {"type": "page", "url": "https://github.com/"},  # Should be filtered
            {
                "type": "background_page",
                "url": "chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/bg.html",
            },
            {"type": "worker", "url": "chrome-extension://cccccccccccccccccccccccccccccccc/sw.js"},
            {
                "type": "iframe",
                "url": "chrome-extension://dddddddddddddddddddddddddddddddd/iframe.html",
            },
            # iframe type is NOT in the allowed types - should be filtered
        ]
        mock_resp = MagicMock()
        mock_resp.json.return_value = cdp_response
        mock_resp.raise_for_status.return_value = None

        with patch("behavioral_monitor.requests.get", return_value=mock_resp):
            targets = bm.get_extension_targets()

        ext_ids = {t["_ext_id"] for t in targets}
        assert ext_ids == {"a" * 32, "b" * 32, "c" * 32}
        # iframe (d*32) should NOT be in the result
        assert "d" * 32 not in ext_ids

    def test_filter_by_specific_ext_id(self):
        """When target_ext_id is given, only that extension's targets return."""
        cdp_response = [
            {
                "type": "service_worker",
                "url": "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/sw.js",
            },
            {
                "type": "service_worker",
                "url": "chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/sw.js",
            },
        ]
        mock_resp = MagicMock()
        mock_resp.json.return_value = cdp_response
        mock_resp.raise_for_status.return_value = None

        with patch("behavioral_monitor.requests.get", return_value=mock_resp):
            targets = bm.get_extension_targets(target_ext_id="a" * 32)

        assert len(targets) == 1
        assert targets[0]["_ext_id"] == "a" * 32

    def test_chrome_not_running_raises_runtime_error(self):
        """ConnectionError must become a clear RuntimeError with instructions."""
        import requests

        with patch(
            "behavioral_monitor.requests.get",
            side_effect=requests.exceptions.ConnectionError("refused"),
        ):
            with pytest.raises(RuntimeError, match="localhost:9222"):
                bm.get_extension_targets()

    def test_empty_cdp_response_returns_empty_list(self):
        """Chrome with no extensions installed shouldn't crash."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = []
        mock_resp.raise_for_status.return_value = None
        with patch("behavioral_monitor.requests.get", return_value=mock_resp):
            assert bm.get_extension_targets() == []


# ---------------------------------------------------------------------------
# RULE-01: C2 beacon detection
# ---------------------------------------------------------------------------


class TestRule01C2Beacon:
    """The TeamPCP exfil pattern: periodic POSTs to *.workers.dev / *.pages.dev."""

    @pytest.mark.asyncio
    async def test_single_post_to_workers_dev_flagged_high(self, fake_target, alert_queue):
        """First POST is high (not critical) - we need a second to confirm beacon."""
        params = {
            "request": {
                "url": "https://evil.workers.dev/collect",
                "method": "POST",
                "headers": {},
            }
        }
        await bm._handle_network_request(params, fake_target, "ext-id-1", alert_queue)
        alerts = _drain(alert_queue)
        rule01 = [a for a in alerts if a["rule"] == "RULE-01"]
        assert len(rule01) == 1
        assert rule01[0]["severity"] == "high"
        assert "evil.workers.dev" in rule01[0]["detail"]["host"]

    @pytest.mark.asyncio
    async def test_two_close_posts_escalate_to_critical(self, fake_target, alert_queue):
        """Two POSTs within BEACON_INTERVAL_SEC = a confirmed beacon = CRITICAL."""
        params = {
            "request": {
                "url": "https://evil.workers.dev/collect",
                "method": "POST",
                "headers": {},
            }
        }
        # First POST: high severity
        await bm._handle_network_request(params, fake_target, "ext-id-1", alert_queue)
        # Second POST 30 seconds later - well within beacon window
        # We have to fake the timestamp here since beacon tracking uses time.time()
        # The implementation puts now into the tracker, so a second real call
        # made immediately should produce interval < BEACON_INTERVAL_SEC
        await bm._handle_network_request(params, fake_target, "ext-id-1", alert_queue)

        alerts = _drain(alert_queue)
        rule01 = [a for a in alerts if a["rule"] == "RULE-01"]
        # Two alerts: first was 'high', second is 'critical' because interval < limit
        assert len(rule01) == 2
        assert rule01[0]["severity"] == "high"
        assert rule01[1]["severity"] == "critical"
        assert rule01[1]["detail"]["post_count"] == 2

    @pytest.mark.asyncio
    async def test_get_request_to_workers_dev_not_flagged(self, fake_target, alert_queue):
        """RULE-01 fires on POST only - GET to *.workers.dev is just suspicious browsing."""
        params = {
            "request": {
                "url": "https://example.workers.dev/page",
                "method": "GET",
                "headers": {"Accept": "text/html"},
            }
        }
        await bm._handle_network_request(params, fake_target, "ext-id-1", alert_queue)
        alerts = _drain(alert_queue)
        rule01 = [a for a in alerts if a["rule"] == "RULE-01"]
        assert rule01 == []

    @pytest.mark.asyncio
    async def test_post_to_pages_dev_also_flagged(self, fake_target, alert_queue):
        """Cloudflare Pages is the other half of the TeamPCP exfil pattern."""
        params = {
            "request": {
                "url": "https://attacker.pages.dev/exfil",
                "method": "POST",
                "headers": {},
            }
        }
        await bm._handle_network_request(params, fake_target, "ext-id-1", alert_queue)
        rule01 = [a for a in _drain(alert_queue) if a["rule"] == "RULE-01"]
        assert len(rule01) >= 1

    @pytest.mark.asyncio
    async def test_post_to_clean_domain_not_flagged(self, fake_target, alert_queue):
        """POST to a normal first-party API endpoint doesn't fire RULE-01."""
        params = {
            "request": {
                "url": "https://api.example.com/v1/users",
                "method": "POST",
                "headers": {},
            }
        }
        await bm._handle_network_request(params, fake_target, "ext-id-1", alert_queue)
        rule01 = [a for a in _drain(alert_queue) if a["rule"] == "RULE-01"]
        assert rule01 == []

    @pytest.mark.asyncio
    async def test_separate_extensions_dont_share_beacon_tracker(self, fake_target, alert_queue):
        """Two different extensions hitting the same domain should each be at
        'first POST' state - one extension's history shouldn't escalate another's."""
        params = {
            "request": {
                "url": "https://evil.workers.dev/x",
                "method": "POST",
                "headers": {},
            }
        }
        await bm._handle_network_request(params, fake_target, "ext-A", alert_queue)
        await bm._handle_network_request(params, fake_target, "ext-B", alert_queue)

        alerts = [a for a in _drain(alert_queue) if a["rule"] == "RULE-01"]
        # Both should be the FIRST-occurrence high-severity alert,
        # not the beacon-pattern critical one
        assert all(a["severity"] == "high" for a in alerts)


# ---------------------------------------------------------------------------
# RULE-02: Session cookie exfil
# ---------------------------------------------------------------------------


class TestRule02CookieExfil:
    @pytest.mark.asyncio
    async def test_cookie_posted_to_github_flagged(self, fake_target, alert_queue):
        """POST with a session cookie to github.com = credential exfil."""
        params = {
            "request": {
                "url": "https://github.com/api/exfil",
                "method": "POST",
                "headers": {
                    "Cookie": (
                        "user_session=abc123def456ghi789jklmnopqrstuvwxyz1234567890; _octo=xyz"
                    ),
                },
            }
        }
        await bm._handle_network_request(params, fake_target, "ext-id", alert_queue)
        rule02 = [a for a in _drain(alert_queue) if a["rule"] == "RULE-02"]
        assert len(rule02) == 1
        assert rule02[0]["severity"] == "high"

    @pytest.mark.asyncio
    async def test_short_cookie_value_not_flagged(self, fake_target, alert_queue):
        """A non-session-shaped cookie (short) shouldn't trip RULE-02."""
        params = {
            "request": {
                "url": "https://github.com/api/x",
                "method": "POST",
                "headers": {"Cookie": "lang=en; theme=dark"},  # No 32+ char token
            }
        }
        await bm._handle_network_request(params, fake_target, "ext-id", alert_queue)
        rule02 = [a for a in _drain(alert_queue) if a["rule"] == "RULE-02"]
        assert rule02 == []

    @pytest.mark.asyncio
    async def test_no_cookie_header_not_flagged(self, fake_target, alert_queue):
        """No Cookie header at all - obviously not exfil."""
        params = {
            "request": {
                "url": "https://github.com/api/x",
                "method": "POST",
                "headers": {},
            }
        }
        await bm._handle_network_request(params, fake_target, "ext-id", alert_queue)
        rule02 = [a for a in _drain(alert_queue) if a["rule"] == "RULE-02"]
        assert rule02 == []


# ---------------------------------------------------------------------------
# RULE-03: High-value domain access
# ---------------------------------------------------------------------------


class TestRule03HighValueDomain:
    @pytest.mark.asyncio
    async def test_post_to_github_api_flagged(self, fake_target, alert_queue):
        params = {
            "request": {
                "url": "https://api.github.com/user/keys",
                "method": "POST",
                "headers": {},
            }
        }
        await bm._handle_network_request(params, fake_target, "ext-id", alert_queue)
        rule03 = [a for a in _drain(alert_queue) if a["rule"] == "RULE-03"]
        assert len(rule03) == 1
        assert rule03[0]["severity"] == "medium"

    @pytest.mark.asyncio
    async def test_get_with_json_accept_to_high_value_flagged(self, fake_target, alert_queue):
        """GET request that ASKS for JSON = API call = flagged."""
        params = {
            "request": {
                "url": "https://api.github.com/user",
                "method": "GET",
                "headers": {"Accept": "application/json"},
            }
        }
        await bm._handle_network_request(params, fake_target, "ext-id", alert_queue)
        rule03 = [a for a in _drain(alert_queue) if a["rule"] == "RULE-03"]
        assert len(rule03) == 1

    @pytest.mark.asyncio
    async def test_get_html_page_not_flagged(self, fake_target, alert_queue):
        """User browsing github.com pages from an extension is normal."""
        params = {
            "request": {
                "url": "https://github.com/torvalds",
                "method": "GET",
                "headers": {"Accept": "text/html"},
            }
        }
        await bm._handle_network_request(params, fake_target, "ext-id", alert_queue)
        rule03 = [a for a in _drain(alert_queue) if a["rule"] == "RULE-03"]
        assert rule03 == []

    @pytest.mark.asyncio
    async def test_aws_api_flagged(self, fake_target, alert_queue):
        """*.aws.amazon.com is in HIGH_VALUE_DOMAINS."""
        params = {
            "request": {
                "url": "https://iam.aws.amazon.com/x",
                "method": "POST",
                "headers": {},
            }
        }
        await bm._handle_network_request(params, fake_target, "ext-id", alert_queue)
        rule03 = [a for a in _drain(alert_queue) if a["rule"] == "RULE-03"]
        assert len(rule03) == 1


# ---------------------------------------------------------------------------
# RULE-06: Obfuscated eval (via console messages)
# ---------------------------------------------------------------------------


class TestRule06ObfuscatedEval:
    @pytest.mark.asyncio
    async def test_eval_atob_pattern_flagged(self, fake_target, alert_queue):
        """The Shai-Hulud signature: eval(atob(...))."""
        params = {
            "args": [
                {"value": "eval(atob('YWxlcnQoIngiKQ=='))"},
            ]
        }
        await bm._handle_console_call(params, fake_target, "ext-id", alert_queue)
        rule06 = [a for a in _drain(alert_queue) if a["rule"] == "RULE-06"]
        assert len(rule06) == 1
        assert rule06[0]["severity"] == "high"

    @pytest.mark.asyncio
    async def test_eval_string_fromcharcode_flagged(self, fake_target, alert_queue):
        """eval(String.fromCharCode(...)) - another obfuscation pattern."""
        params = {
            "args": [
                {"value": "eval(String.fromCharCode(97,108))"},
            ]
        }
        await bm._handle_console_call(params, fake_target, "ext-id", alert_queue)
        assert len([a for a in _drain(alert_queue) if a["rule"] == "RULE-06"]) == 1

    @pytest.mark.asyncio
    async def test_eval_unescape_flagged(self, fake_target, alert_queue):
        params = {"args": [{"value": "eval(unescape('%61%6c%65%72%74'))"}]}
        await bm._handle_console_call(params, fake_target, "ext-id", alert_queue)
        assert len([a for a in _drain(alert_queue) if a["rule"] == "RULE-06"]) == 1

    @pytest.mark.asyncio
    async def test_plain_console_log_not_flagged(self, fake_target, alert_queue):
        """A normal console.log() must not fire RULE-06."""
        params = {"args": [{"value": "user clicked button #42"}]}
        await bm._handle_console_call(params, fake_target, "ext-id", alert_queue)
        rule06 = [a for a in _drain(alert_queue) if a["rule"] == "RULE-06"]
        assert rule06 == []

    @pytest.mark.asyncio
    async def test_only_first_matching_arg_fires_alert(self, fake_target, alert_queue):
        """If multiple args contain eval(atob), we should still only get one alert."""
        params = {
            "args": [
                {"value": "eval(atob('x'))"},
                {"value": "eval(atob('y'))"},
                {"value": "eval(atob('z'))"},
            ]
        }
        await bm._handle_console_call(params, fake_target, "ext-id", alert_queue)
        rule06 = [a for a in _drain(alert_queue) if a["rule"] == "RULE-06"]
        # The handler `break`s after the first match - one alert per call
        assert len(rule06) == 1


# ---------------------------------------------------------------------------
# Robustness: malformed CDP payloads must not crash the handler
# ---------------------------------------------------------------------------


class TestMalformedInput:
    @pytest.mark.asyncio
    async def test_missing_request_dict(self, fake_target, alert_queue):
        """A CDP event with no 'request' key should silently noop, not crash."""
        await bm._handle_network_request({}, fake_target, "ext-id", alert_queue)
        # No exception - and (because there's no URL) no alerts either
        assert _drain(alert_queue) == []

    @pytest.mark.asyncio
    async def test_non_string_url_handled(self, fake_target, alert_queue):
        """Some CDP events emit url=None when the request is malformed."""
        params = {"request": {"url": None, "method": "POST", "headers": {}}}
        # urlparse(None) -> AttributeError, handler must swallow it
        await bm._handle_network_request(params, fake_target, "ext-id", alert_queue)
        assert _drain(alert_queue) == []

    @pytest.mark.asyncio
    async def test_empty_console_args_handled(self, fake_target, alert_queue):
        await bm._handle_console_call({"args": []}, fake_target, "ext-id", alert_queue)
        assert _drain(alert_queue) == []

    @pytest.mark.asyncio
    async def test_console_arg_without_value_handled(self, fake_target, alert_queue):
        """An arg missing the 'value' key shouldn't crash."""
        params = {"args": [{}, {"type": "object"}]}
        await bm._handle_console_call(params, fake_target, "ext-id", alert_queue)
        assert _drain(alert_queue) == []


# ---------------------------------------------------------------------------
# Severity threshold helper
# ---------------------------------------------------------------------------


class TestRegexPatterns:
    """The compiled detection regexes themselves."""

    def test_c2_pattern_catches_known_hosts(self):
        for host in (
            "evil.workers.dev",
            "x.pages.dev",
            "ANY.NGROK.IO",
            "tunnel.trycloudflare.com",
            "test.netlify.app",
        ):
            assert bm.C2_HOST_PATTERNS.search(host), f"Missed: {host}"

    def test_c2_pattern_ignores_clean_hosts(self):
        for host in ("api.github.com", "example.com", "cdn.example.org"):
            assert not bm.C2_HOST_PATTERNS.search(host), f"False positive: {host}"

    def test_high_value_domains_match(self):
        for host in (
            "github.com",
            "api.github.com",
            "registry.npmjs.com",
            "team.slack.com",
            "iam.aws.amazon.com",
        ):
            assert bm.HIGH_VALUE_DOMAINS.search(host), f"Missed: {host}"

    def test_obfuscated_eval_regex(self):
        assert bm.OBFUSCATED_EVAL.search("eval(atob('x'))")
        assert bm.OBFUSCATED_EVAL.search("eval(String.fromCharCode(1))")
        assert not bm.OBFUSCATED_EVAL.search("regular function call")
