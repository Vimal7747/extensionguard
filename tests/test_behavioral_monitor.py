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
import base64
import json
import time
from unittest.mock import MagicMock, patch

import pytest

from extguard import behavioral_monitor as bm

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
    """Make sure beacon-frequency / rate-limit state doesn't leak between tests."""
    bm._beacon_tracker.clear()
    bm._rule03_last.clear()
    yield
    bm._beacon_tracker.clear()
    bm._rule03_last.clear()


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
        # Regression: extension.id used to be the CDP TAB id ("tab-id-xyz"), so
        # dedup, PagerDuty keys and remediation never saw the real extension ID
        assert alert["extension"]["id"] == fake_target["_ext_id"]
        assert alert["extension"]["target_id"] == fake_target["id"]
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

        with patch("extguard.behavioral_monitor.requests.get", return_value=mock_resp):
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

        with patch("extguard.behavioral_monitor.requests.get", return_value=mock_resp):
            targets = bm.get_extension_targets(target_ext_id="a" * 32)

        assert len(targets) == 1
        assert targets[0]["_ext_id"] == "a" * 32

    def test_chrome_not_running_raises_runtime_error(self):
        """ConnectionError must become a clear RuntimeError with instructions."""
        import requests

        with patch(
            "extguard.behavioral_monitor.requests.get",
            side_effect=requests.exceptions.ConnectionError("refused"),
        ):
            with pytest.raises(RuntimeError, match="localhost:9222"):
                bm.get_extension_targets()

    def test_empty_cdp_response_returns_empty_list(self):
        """Chrome with no extensions installed shouldn't crash."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = []
        mock_resp.raise_for_status.return_value = None
        with patch("extguard.behavioral_monitor.requests.get", return_value=mock_resp):
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

    async def _posts_at(self, times, fake_target, alert_queue, monkeypatch):
        """Send one POST to a C2 host at each fake timestamp; return RULE-01 alerts."""
        params = {
            "request": {"url": "https://evil.workers.dev/collect", "method": "POST", "headers": {}}
        }
        clock = iter(times)
        monkeypatch.setattr(bm.time, "time", lambda: next(clock))
        for _ in times:
            await bm._handle_network_request(params, fake_target, "ext-id-1", alert_queue)
        return [a for a in _drain(alert_queue) if a["rule"] == "RULE-01"]

    @pytest.mark.asyncio
    async def test_sixty_second_beacon_goes_critical(self, fake_target, alert_queue, monkeypatch):
        """Regression (review harness #7): the TeamPCP 60 s beacon never went
        critical, because the old rule needed two POSTs < 55 s apart."""
        alerts = await self._posts_at([0, 60, 120, 180], fake_target, alert_queue, monkeypatch)
        assert [a["severity"] for a in alerts] == ["high", "critical", "critical"]
        assert alerts[1]["detail"]["interval_sec"] == 60.0
        assert alerts[1]["detail"]["post_count"] == 3

    @pytest.mark.asyncio
    async def test_jittered_beacon_still_detected(self, fake_target, alert_queue, monkeypatch):
        alerts = await self._posts_at([0, 58, 121, 179, 240], fake_target, alert_queue, monkeypatch)
        assert "critical" in [a["severity"] for a in alerts]

    @pytest.mark.asyncio
    async def test_irregular_posts_are_not_a_beacon(self, fake_target, alert_queue, monkeypatch):
        alerts = await self._posts_at([0, 5, 300, 310], fake_target, alert_queue, monkeypatch)
        assert [a["severity"] for a in alerts] == ["high"]

    @pytest.mark.asyncio
    async def test_two_posts_are_not_enough(self, fake_target, alert_queue, monkeypatch):
        alerts = await self._posts_at([0, 60], fake_target, alert_queue, monkeypatch)
        assert [a["severity"] for a in alerts] == ["high"]

    @pytest.mark.asyncio
    async def test_slow_beacon_detected_too(self, fake_target, alert_queue, monkeypatch):
        """A 5-minute check-in is still clockwork - the old rule couldn't see it."""
        alerts = await self._posts_at([0, 300, 600], fake_target, alert_queue, monkeypatch)
        assert alerts[-1]["severity"] == "critical"

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


def _post(url, body="", headers=None):
    return {"request": {"url": url, "method": "POST", "headers": headers or {}, "postData": body}}


GH_TOKEN = "ghp_" + "A1b2C3d4E5" * 4
COOKIE_DUMP = (
    '[{"domain":".github.com","hostOnly":false,"httpOnly":true,"name":"user_session",'
    '"sameSite":"lax","storeId":"0","value":"abc123def456ghi789jkl"}]'
)


class TestRule02CredentialExfil:
    """
    RULE-02 used to fire when a GitHub cookie was sent TO github.com - that is
    just the browser's normal session. Exfiltration is credential material
    leaving for a host it doesn't belong to.
    """

    @pytest.mark.asyncio
    async def test_cookie_dump_to_third_party(self, fake_target, alert_queue):
        await bm._handle_network_request(
            _post("https://stats.evil.example/c", COOKIE_DUMP), fake_target, "ext", alert_queue
        )
        rule02 = [a for a in _drain(alert_queue) if a["rule"] == "RULE-02"]
        assert len(rule02) == 1
        assert rule02[0]["severity"] == "high"
        assert "browser cookie dump" in rule02[0]["detail"]["credentials"]

    @pytest.mark.asyncio
    async def test_token_to_exfil_hosting_is_critical(self, fake_target, alert_queue):
        body = json.dumps({"t": GH_TOKEN})
        await bm._handle_network_request(
            _post("https://x.workers.dev/c", body), fake_target, "ext", alert_queue
        )
        rule02 = [a for a in _drain(alert_queue) if a["rule"] == "RULE-02"]
        assert rule02[0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_token_in_url_query(self, fake_target, alert_queue):
        params = {"request": {"url": f"https://evil.example/p?k={GH_TOKEN}", "method": "GET"}}
        await bm._handle_network_request(params, fake_target, "ext", alert_queue)
        assert [a for a in _drain(alert_queue) if a["rule"] == "RULE-02"]

    @pytest.mark.asyncio
    async def test_github_token_forwarded_in_authorization_header(self, fake_target, alert_queue):
        headers = {"Authorization": f"token {GH_TOKEN}"}
        await bm._handle_network_request(
            _post("https://evil.example/api", "", headers), fake_target, "ext", alert_queue
        )
        rule02 = [a for a in _drain(alert_queue) if a["rule"] == "RULE-02"]
        assert "Authorization header" in rule02[0]["detail"]["credentials"][0]

    @pytest.mark.asyncio
    async def test_token_sent_to_its_own_service_is_normal(self, fake_target, alert_queue):
        headers = {"Authorization": f"token {GH_TOKEN}"}
        await bm._handle_network_request(
            _post("https://api.github.com/user", "", headers), fake_target, "ext", alert_queue
        )
        assert [a for a in _drain(alert_queue) if a["rule"] == "RULE-02"] == []

    @pytest.mark.asyncio
    async def test_session_cookie_header_to_its_own_domain_is_not_exfil(
        self, fake_target, alert_queue
    ):
        """The old rule flagged exactly this - the browser's own session."""
        headers = {"Cookie": "user_session=abc123def456ghi789jklmnopqrstuvwxyz1234567890"}
        await bm._handle_network_request(
            _post("https://github.com/api/x", "", headers), fake_target, "ext", alert_queue
        )
        assert [a for a in _drain(alert_queue) if a["rule"] == "RULE-02"] == []

    @pytest.mark.asyncio
    async def test_ordinary_body_not_flagged(self, fake_target, alert_queue):
        await bm._handle_network_request(
            _post("https://api.example.com/v1", '{"theme": "dark"}'),
            fake_target,
            "ext",
            alert_queue,
        )
        assert [a for a in _drain(alert_queue) if a["rule"] == "RULE-02"] == []


def _jwt(claims: dict) -> str:
    """An unsigned-looking JWT with the given payload claims."""

    def part(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    return f"{part({'alg': 'RS256', 'typ': 'JWT'})}.{part(claims)}.c2lnbmF0dXJlLXZhbHVl"


async def _rule02(url, body="", headers=None, fake_target=None, alert_queue=None):
    await bm._handle_network_request(_post(url, body, headers), fake_target, "ext", alert_queue)
    return [a for a in _drain(alert_queue) if a["rule"] == "RULE-02"]


class TestRule02Jwt:
    """
    Real-extension test: Grammarly sent its own login JWT to its own API
    (gateway.grammarly.com) and got four "credential sent to a third-party
    host" alerts. A JWT names its home in the iss / aud claims.
    """

    GRAMMARLY = {"iss": "https://auth.grammarly.com", "sub": "u1", "exp": 4102444800}

    @pytest.mark.asyncio
    async def test_own_token_to_own_service_is_normal(self, fake_target, alert_queue):
        headers = {"Authorization": "Bearer " + _jwt(self.GRAMMARLY)}
        assert await _rule02("https://gateway.grammarly.com/x", "", headers,
                             fake_target, alert_queue) == []  # fmt: skip

    @pytest.mark.asyncio
    async def test_same_token_sent_elsewhere_is_exfil(self, fake_target, alert_queue):
        body = json.dumps({"stolen": _jwt(self.GRAMMARLY)})
        alerts = await _rule02("https://collector.evil.example/u", body, None,
                               fake_target, alert_queue)  # fmt: skip
        assert alerts and "JWT" in alerts[0]["detail"]["credentials"]

    @pytest.mark.asyncio
    async def test_token_forwarded_as_header_to_another_site(self, fake_target, alert_queue):
        headers = {"Authorization": "Bearer " + _jwt(self.GRAMMARLY)}
        alerts = await _rule02("https://evil.example/api", "", headers, fake_target, alert_queue)
        assert alerts

    @pytest.mark.asyncio
    async def test_audience_also_counts_as_home(self, fake_target, alert_queue):
        token = _jwt({"iss": "https://login.example-idp.com", "aud": ["api.myservice.co.uk"]})
        headers = {"Authorization": "Bearer " + token}
        assert await _rule02("https://eu.myservice.co.uk/v1", "", headers,
                             fake_target, alert_queue) == []  # fmt: skip

    @pytest.mark.asyncio
    async def test_token_without_issuer_is_normal_as_bearer(self, fake_target, alert_queue):
        headers = {"Authorization": "Bearer " + _jwt({"sub": "u1", "exp": 1})}
        assert await _rule02("https://api.example.com/v1", "", headers,
                             fake_target, alert_queue) == []  # fmt: skip

    @pytest.mark.asyncio
    async def test_token_without_issuer_in_body_is_flagged(self, fake_target, alert_queue):
        body = "t=" + _jwt({"sub": "u1", "exp": 1})
        assert await _rule02("https://evil.example/c", body, None, fake_target, alert_queue)

    def test_site_handles_two_part_suffixes(self):
        assert bm._site("a.b.example.co.uk") == "example.co.uk"
        assert bm._site("gateway.grammarly.com") == "grammarly.com"

    def test_garbage_jwt_payload_names_no_host(self):
        assert bm._jwt_claim_hosts("eyJhbGciOi.eyJ!!!notbase64.sig") == set()


class TestAuthenticatedRequests:
    @pytest.mark.asyncio
    async def test_state_changing_request_with_session_is_session_riding(
        self, fake_target, alert_queue
    ):
        params = _post("https://api.github.com/user/keys", "{}")
        extra = {"associatedCookies": [{"blockedReasons": [], "cookie": {"name": "user_session"}}]}
        await bm._handle_authenticated_request(params, extra, fake_target, "ext", alert_queue)
        alerts = _drain(alert_queue)
        assert alerts[0]["rule"] == "RULE-03" and alerts[0]["severity"] == "high"

    @pytest.mark.asyncio
    async def test_blocked_cookies_do_not_count(self, fake_target, alert_queue):
        params = _post("https://api.github.com/user/keys", "{}")
        extra = {"associatedCookies": [{"blockedReasons": ["SameSiteLax"], "cookie": {}}]}
        await bm._handle_authenticated_request(params, extra, fake_target, "ext", alert_queue)
        assert _drain(alert_queue) == []


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

    @pytest.mark.parametrize(
        "host",
        ["notgithub.com", "github.com.attacker.net", "evil-slack.com", "workers.dev.evil.io"],
    )
    def test_lookalike_hosts_do_not_match(self, host):
        """Regression: the patterns were unanchored substrings."""
        assert not bm.HIGH_VALUE_DOMAINS.search(host)
        assert not bm.C2_HOST_PATTERNS.search(host)


# ---------------------------------------------------------------------------
# RULE-03 noise control
# ---------------------------------------------------------------------------


class TestRule03RateLimit:
    @pytest.mark.asyncio
    async def test_repeat_calls_to_same_host_alert_once(self, fake_target, alert_queue):
        params = {
            "request": {"url": "https://api.github.com/user", "method": "POST", "headers": {}}
        }
        for _ in range(5):
            await bm._handle_network_request(params, fake_target, "ext", alert_queue)
        assert len([a for a in _drain(alert_queue) if a["rule"] == "RULE-03"]) == 1


# ---------------------------------------------------------------------------
# RULE-04 / 05 / 07 - reports from the in-context hooks
# ---------------------------------------------------------------------------


async def _hook(kind, data, fake_target, alert_queue):
    await bm._handle_hook_event({"kind": kind, "data": data}, fake_target, "ext", alert_queue)
    return _drain(alert_queue)


class TestHookEvents:
    @pytest.mark.asyncio
    async def test_storage_staging_base64(self, fake_target, alert_queue):
        alerts = await _hook(
            "storage.set",
            {
                "area": "local",
                "keys": ["s_cache"],
                "size": 1300,
                "sample": '{"s_cache":"' + "QUJD" * 300 + '"}',
            },
            fake_target,
            alert_queue,
        )
        # A blob on its own is a weak signal: medium (credentials make it critical)
        assert alerts[0]["rule"] == "RULE-04" and alerts[0]["severity"] == "medium"

    @pytest.mark.asyncio
    async def test_small_encoded_values_ignored(self, fake_target, alert_queue):
        """Encrypted vault entries, hashes, IDs: base64, but not staged data."""
        sample = '{"vault":"2.' + "QUJD" * 150 + "|" + "WFla" * 20 + '"}'
        assert await _hook("storage.set", {"size": len(sample), "sample": sample},
                           fake_target, alert_queue) == []  # fmt: skip

    @pytest.mark.asyncio
    async def test_cached_image_data_url_ignored(self, fake_target, alert_queue):
        """Real-extension test: Dark Reader caches image details in localStorage."""
        sample = '{"src":"x.svg","dataURL":"data:image/svg+xml;base64,' + "PHN2" * 400 + '"}'
        assert await _hook("localStorage.setItem", {"size": len(sample), "sample": sample},
                           fake_target, alert_queue) == []  # fmt: skip

    @pytest.mark.asyncio
    async def test_extension_storing_its_own_login_token_is_normal(self, fake_target, alert_queue):
        """Real-extension test: Grammarly keeps its OAuth JWT in chrome.storage."""
        token = _jwt({"iss": "https://auth.grammarly.com", "sub": "u" * 900})
        sample = json.dumps({"gr-oauth-key": token})
        assert await _hook("storage.set", {"size": len(sample), "sample": sample},
                           fake_target, alert_queue) == []  # fmt: skip

    @pytest.mark.asyncio
    async def test_staging_a_google_identity_token_is_critical(self, fake_target, alert_queue):
        token = _jwt({"iss": "https://accounts.google.com", "aud": "x.apps.googleusercontent.com"})
        sample = json.dumps({"loot": token})
        alerts = await _hook("storage.set", {"size": len(sample), "sample": sample},
                             fake_target, alert_queue)  # fmt: skip
        assert alerts[0]["severity"] == "critical"
        assert "high-value identity provider" in alerts[0]["detail"]["description"]

    @pytest.mark.asyncio
    async def test_storage_staging_credentials_is_critical(self, fake_target, alert_queue):
        alerts = await _hook(
            "storage.set", {"size": 300, "sample": COOKIE_DUMP}, fake_target, alert_queue
        )
        assert alerts[0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_ordinary_settings_write_ignored(self, fake_target, alert_queue):
        alerts = await _hook(
            "storage.set", {"size": 20, "sample": '{"theme":"dark"}'}, fake_target, alert_queue
        )
        assert alerts == []

    @pytest.mark.asyncio
    async def test_disabling_another_extension(self, fake_target, alert_queue):
        alerts = await _hook(
            "management.setEnabled", {"id": "p" * 32, "enabled": False}, fake_target, alert_queue
        )
        assert alerts[0]["rule"] == "RULE-05" and alerts[0]["severity"] == "critical"
        assert alerts[0]["detail"]["victim_extension"] == "p" * 32

    @pytest.mark.asyncio
    async def test_enabling_is_not_lateral_movement(self, fake_target, alert_queue):
        assert (
            await _hook(
                "management.setEnabled", {"id": "x", "enabled": True}, fake_target, alert_queue
            )
            == []
        )

    @pytest.mark.asyncio
    async def test_uninstalling_another_extension(self, fake_target, alert_queue):
        alerts = await _hook("management.uninstall", {"id": "p" * 32}, fake_target, alert_queue)
        assert alerts[0]["rule"] == "RULE-05"

    @pytest.mark.asyncio
    async def test_bulk_cookie_read(self, fake_target, alert_queue):
        alerts = await _hook(
            "cookies.getAll",
            {"details": "{}", "count": 312, "domains": [".github.com", ".google.com"]},
            fake_target,
            alert_queue,
        )
        assert alerts[0]["rule"] == "RULE-07"
        assert ".github.com" in alerts[0]["detail"]["high_value_domains"]

    @pytest.mark.asyncio
    async def test_narrow_cookie_read_ignored(self, fake_target, alert_queue):
        alerts = await _hook(
            "cookies.getAll",
            {"details": '{"domain":"myapp.example"}', "count": 2, "domains": ["myapp.example"]},
            fake_target,
            alert_queue,
        )
        assert alerts == []

    @pytest.mark.asyncio
    async def test_document_cookie_on_high_value_site(self, fake_target, alert_queue):
        alerts = await _hook(
            "document.cookie", {"host": "github.com", "size": 900}, fake_target, alert_queue
        )
        assert alerts[0]["rule"] == "RULE-07" and alerts[0]["severity"] == "medium"

    @pytest.mark.asyncio
    async def test_unknown_hook_kind_ignored(self, fake_target, alert_queue):
        assert await _hook("something.else", {}, fake_target, alert_queue) == []


class TestDynamicScripts:
    @pytest.mark.asyncio
    async def test_plain_eval_is_medium(self, fake_target, alert_queue):
        await bm._handle_dynamic_script('console.log("hi")', fake_target, alert_queue)
        assert _drain(alert_queue)[0]["severity"] == "medium"

    @pytest.mark.asyncio
    async def test_obfuscated_eval_is_high(self, fake_target, alert_queue):
        src = ";".join(f"var _0x{i:04x}=1" for i in range(20))
        await bm._handle_dynamic_script(src, fake_target, alert_queue)
        assert _drain(alert_queue)[0]["severity"] == "high"


class TestInitiatingExtension:
    def test_content_script_frame_in_stack(self):
        initiator = {
            "type": "script",
            "stack": {
                "callFrames": [{"url": "https://site.example/app.js"}],
                "parent": {
                    "callFrames": [{"url": "chrome-extension://" + "b" * 32 + "/content.js"}]
                },
            },
        }
        assert bm._initiating_extension(initiator) == "b" * 32

    def test_page_own_request(self):
        assert bm._initiating_extension({"type": "parser", "url": "https://site.example/"}) is None

    def test_malformed(self):
        assert bm._initiating_extension(None) is None
        assert bm._initiating_extension({"stack": "nope"}) is None


# ---------------------------------------------------------------------------
# ExtensionMonitor protocol behaviour (fake socket)
# ---------------------------------------------------------------------------

EXT = "c" * 32


class FakeSocket:
    """Records sent commands; replies to some methods, never to others."""

    def __init__(self, monitor_ref, silent=("Runtime.addBinding",), ext_name="Test Extension"):
        self.sent = []
        self.monitor_ref = monitor_ref
        self.silent = set(silent)
        self.ext_name = ext_name
        self.script_sources = {}  # scriptId -> source, for Debugger.getScriptSource

    async def send(self, raw):
        msg = json.loads(raw)
        self.sent.append(msg)
        if msg["method"] in self.silent:
            return  # like a paused worker: no reply until it runs
        result = {}
        if msg["method"] == "Debugger.getScriptSource":
            result = {"scriptSource": self.script_sources.get(msg["params"]["scriptId"], "")}
        if msg["method"] == "Runtime.evaluate":
            if "getManifest" in msg["params"].get("expression", ""):
                result = {"result": {"value": self.ext_name}}  # the name lookup
            else:
                result = {"result": {"value": "installed"}}  # the hook install
        if msg["method"] == "Debugger.setInstrumentationBreakpoint":
            result = {"breakpointId": "bp-1"}
        future = self.monitor_ref[0]._pending.get(msg["id"])
        if future and not future.done():
            future.set_result(result)

    def methods(self, session=None):
        return [m["method"] for m in self.sent if session is None or m.get("sessionId") == session]


def _monitor(**kw):
    holder = []
    ws = FakeSocket(holder)
    mon = bm.ExtensionMonitor(ws, asyncio.Queue(), output_json=True, **kw)
    holder.append(mon)
    return mon, ws


def _attached(session, kind, url, waiting=True, target_id=None):
    return {
        "method": "Target.attachedToTarget",
        "params": {
            "sessionId": session,
            "waitingForDebugger": waiting,
            "targetInfo": {
                "targetId": target_id or session + "-t",
                "type": kind,
                "url": url,
                "title": "T",
            },
        },
    }


class TestExtensionMonitor:
    @pytest.mark.asyncio
    async def test_paused_worker_is_resumed_even_if_setup_never_answers(self):
        """Real-Chrome regression: awaiting Runtime.addBinding on a paused
        worker never returns - the worker must still be resumed."""
        mon, ws = _monitor()
        await asyncio.wait_for(
            mon.dispatch(_attached("S1", "service_worker", f"chrome-extension://{EXT}/sw.js")),
            timeout=2,
        )
        sent = ws.methods("S1")
        assert "Runtime.runIfWaitingForDebugger" in sent
        # Monitoring is enabled BEFORE the worker is allowed to run
        resume = sent.index("Runtime.runIfWaitingForDebugger")
        for needed in ("Network.enable", "Runtime.enable", "Debugger.setInstrumentationBreakpoint"):
            assert sent.index(needed) < resume

    @pytest.mark.asyncio
    async def test_instrumentation_pause_installs_hooks_then_resumes(self):
        mon, ws = _monitor()
        await mon.dispatch(_attached("S1", "service_worker", f"chrome-extension://{EXT}/sw.js"))
        await mon.dispatch(
            {
                "method": "Debugger.paused",
                "sessionId": "S1",
                "params": {"reason": "instrumentation"},
            }
        )
        tail = ws.methods("S1")[-4:]
        assert tail == [
            "Runtime.evaluate",
            "Debugger.removeBreakpoint",
            "Debugger.setSkipAllPauses",
            "Debugger.resume",
        ]

    @pytest.mark.asyncio
    async def test_duplicate_session_resumes_after_primary_then_detaches(self):
        """Real-Chrome regression: not resuming a duplicate froze the worker."""
        mon, ws = _monitor()
        url = f"chrome-extension://{EXT}/sw.js"
        await mon.dispatch(_attached("S1", "service_worker", url, target_id="T"))
        await mon.dispatch(_attached("S2", "service_worker", url, target_id="T"))
        assert ws.methods("S2") == ["Runtime.runIfWaitingForDebugger"]
        detach = [m for m in ws.sent if m["method"] == "Target.detachFromTarget"]
        assert detach[-1]["params"]["sessionId"] == "S2"
        assert list(mon.sessions) == ["S1"]

    @pytest.mark.asyncio
    async def test_uninteresting_target_is_released(self):
        mon, ws = _monitor(watch_pages=False)
        await mon.dispatch(_attached("S9", "page", "https://news.example/"))
        assert "S9" not in mon.sessions
        assert ws.methods("S9") == ["Runtime.runIfWaitingForDebugger"]

    @pytest.mark.asyncio
    async def test_component_extensions_ignored(self):
        mon, _ = _monitor()
        url = "chrome-extension://nkeimhogjdpnpccoofpliimaahmaaome/background.html"
        await mon.dispatch(_attached("S1", "background_page", url))
        assert mon.sessions == {}

    @pytest.mark.asyncio
    async def test_forged_hook_report_is_dropped(self):
        mon, _ = _monitor()
        await mon.dispatch(_attached("S1", "service_worker", f"chrome-extension://{EXT}/sw.js"))
        entry = mon.sessions["S1"]
        payload = json.dumps(
            {"token": "wrong", "kind": "management.uninstall", "data": {"id": "x"}}
        )
        await mon.dispatch(
            {
                "method": "Runtime.bindingCalled",
                "sessionId": "S1",
                "params": {"name": entry["binding"], "payload": payload},
            }
        )
        assert mon.alert_queue.empty()
        assert mon.stats["forged_reports_dropped"] == 1

        good = json.dumps(
            {"token": entry["token"], "kind": "management.uninstall", "data": {"id": "x"}}
        )
        await mon.dispatch(
            {
                "method": "Runtime.bindingCalled",
                "sessionId": "S1",
                "params": {"name": entry["binding"], "payload": good},
            }
        )
        alert = mon.alert_queue.get_nowait()
        assert alert["rule"] == "RULE-05" and alert["extension"]["id"] == EXT

    @pytest.mark.asyncio
    async def test_content_script_request_is_attributed(self):
        mon, _ = _monitor()
        await mon.dispatch(_attached("P1", "page", "https://github.com/", waiting=False))
        initiator = {
            "type": "script",
            "stack": {"callFrames": [{"url": f"chrome-extension://{EXT}/cs.js"}]},
        }
        await mon.dispatch(
            {
                "method": "Network.requestWillBeSent",
                "sessionId": "P1",
                "params": {
                    "requestId": "r1",
                    "initiator": initiator,
                    "request": {
                        "url": "https://drop.evil.example/c",
                        "method": "POST",
                        "postData": COOKIE_DUMP,
                    },
                },
            }
        )
        alert = mon.alert_queue.get_nowait()
        assert alert["rule"] == "RULE-02"
        assert alert["extension"]["id"] == EXT
        assert alert["extension"]["context"] == "content_script"

    @pytest.mark.asyncio
    async def test_page_own_requests_are_ignored(self):
        mon, _ = _monitor()
        await mon.dispatch(_attached("P1", "page", "https://site.example/", waiting=False))
        await mon.dispatch(
            {
                "method": "Network.requestWillBeSent",
                "sessionId": "P1",
                "params": {
                    "requestId": "r1",
                    "initiator": {"type": "script", "url": "https://site.example/app.js"},
                    "request": {
                        "url": "https://x.workers.dev/c",
                        "method": "POST",
                        "postData": COOKIE_DUMP,
                    },
                },
            }
        )
        assert mon.alert_queue.empty()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("extra_first", [True, False])
    async def test_extra_info_correlates_in_either_order(self, extra_first):
        mon, _ = _monitor()
        await mon.dispatch(_attached("S1", "service_worker", f"chrome-extension://{EXT}/sw.js"))
        req = {
            "method": "Network.requestWillBeSent",
            "sessionId": "S1",
            "params": {
                "requestId": "r7",
                "request": {"url": "https://api.github.com/user/keys", "method": "POST"},
            },
        }
        extra = {
            "method": "Network.requestWillBeSentExtraInfo",
            "sessionId": "S1",
            "params": {
                "requestId": "r7",
                "associatedCookies": [{"blockedReasons": [], "cookie": {}}],
            },
        }
        for msg in (extra, req) if extra_first else (req, extra):
            await mon.dispatch(msg)
        rules = []
        while not mon.alert_queue.empty():
            a = mon.alert_queue.get_nowait()
            rules.append((a["rule"], a["severity"]))
        assert ("RULE-03", "high") in rules


# ---------------------------------------------------------------------------
# run_monitor shutdown (real-extension test: Chrome for Testing closing)
# ---------------------------------------------------------------------------


class _FakeConnection:
    async def __aenter__(self):
        return object()

    async def __aexit__(self, *exc):
        return False


class TestRunMonitorShutdown:
    """
    With --output-json, stdout IS the alert stream extguard-dispatch reads.
    Closing the browser at the end of a --once run printed
    "[ERROR] no close frame received or sent" into it and exited 1.
    """

    @pytest.mark.asyncio
    async def test_browser_closing_after_a_session_is_a_clean_end(self, monkeypatch, capsys):
        class ClosingMonitor:
            def __init__(self, ws, alert_queue, *args):
                self.alert_queue = alert_queue

            async def run(self):
                # An alert raised just before Chrome went away must still print
                await self.alert_queue.put({"rule": "RULE-01", "severity": "high"})
                raise bm.websockets.exceptions.ConnectionClosedError(None, None)

        monkeypatch.setattr(bm, "get_browser_ws_url", lambda: "ws://127.0.0.1:9/devtools")
        monkeypatch.setattr(bm.websockets, "connect", lambda *a, **k: _FakeConnection())
        monkeypatch.setattr(bm, "ExtensionMonitor", ClosingMonitor)

        await bm.run_monitor(None, output_json=True, once=True)  # must not raise

        out, err = capsys.readouterr()
        lines = [line for line in out.splitlines() if line.strip()]
        assert [json.loads(line)["rule"] for line in lines] == ["RULE-01"]
        assert "no close frame" in err and "closed the connection" in err

    @pytest.mark.asyncio
    async def test_chrome_never_reachable_is_still_an_error(self, monkeypatch, capsys):
        def unreachable():
            raise RuntimeError("Cannot connect to Chrome at 127.0.0.1:9222")

        monkeypatch.setattr(bm, "get_browser_ws_url", unreachable)
        with pytest.raises(RuntimeError, match="Chrome not reachable"):
            await bm.run_monitor(None, output_json=True, once=True)
        assert capsys.readouterr().out == ""


# ---------------------------------------------------------------------------
# Extension names in alerts (real-extension test: alerts only showed
# "Service Worker chrome-extension://dmkbhg..." - or a web page's title)
# ---------------------------------------------------------------------------


async def _settle():
    for _ in range(5):
        await asyncio.sleep(0)


class TestExtensionNames:
    @pytest.mark.asyncio
    async def test_worker_alert_carries_the_extension_name(self):
        mon, _ = _monitor()
        await mon.dispatch(
            _attached("S1", "service_worker", f"chrome-extension://{EXT}/sw.js", waiting=False)
        )
        await _settle()
        assert mon.ext_names[EXT] == "Test Extension"

        await mon.dispatch(
            {
                "method": "Network.requestWillBeSent",
                "sessionId": "S1",
                "params": {
                    "requestId": "r1",
                    "request": {"url": "https://x.workers.dev/c", "method": "POST"},
                },
            }
        )
        ext = mon.alert_queue.get_nowait()["extension"]
        assert ext["name"] == ext["title"] == "Test Extension"
        assert ext["id"] == EXT and ext["target_title"] == "T"

    @pytest.mark.asyncio
    async def test_content_script_alert_names_the_extension_not_the_page(self):
        mon, _ = _monitor()
        await mon.dispatch(
            _attached("S1", "service_worker", f"chrome-extension://{EXT}/sw.js", waiting=False)
        )
        await mon.dispatch(_attached("P1", "page", "https://github.com/", waiting=False))
        await _settle()
        initiator = {
            "type": "script",
            "stack": {"callFrames": [{"url": f"chrome-extension://{EXT}/cs.js"}]},
        }
        await mon.dispatch(
            {
                "method": "Network.requestWillBeSent",
                "sessionId": "P1",
                "params": {
                    "requestId": "r1",
                    "initiator": initiator,
                    "request": {
                        "url": "https://drop.evil.example/c",
                        "method": "POST",
                        "postData": COOKIE_DUMP,
                    },
                },
            }
        )
        ext = mon.alert_queue.get_nowait()["extension"]
        assert ext["context"] == "content_script"
        assert ext["title"] == "Test Extension"

    @pytest.mark.asyncio
    async def test_name_is_a_sanitised_label(self):
        holder = []
        ws = FakeSocket(holder, ext_name="Evil\x1b[31m\nName" + "x" * 300)
        mon = bm.ExtensionMonitor(ws, asyncio.Queue(), output_json=True)
        holder.append(mon)
        await mon.dispatch(
            _attached("S1", "service_worker", f"chrome-extension://{EXT}/sw.js", waiting=False)
        )
        await _settle()
        name = mon.ext_names[EXT]
        assert "\x1b" not in name and "\n" not in name and len(name) <= 120

    def test_unknown_name_falls_back_without_using_the_page_title(self):
        worker = {"_ext_id": EXT, "title": "Service Worker x", "_context": "extension"}
        in_page = {"_ext_id": EXT, "title": "Some Web Page", "_context": "content_script"}
        assert bm._make_alert("RULE-01", "high", worker, {})["extension"]["title"] == (
            "Service Worker x"
        )
        assert bm._make_alert("RULE-01", "high", in_page, {})["extension"]["title"] is None


class TestOwnScriptsAndRule06:
    """
    RULE-06 alerts on code compiled at runtime (a script with no URL). The
    monitor's own injected scripts must not count - and an extension must
    not be able to hide its eval() by copying a marker it can see.
    """

    async def _parsed(self, source):
        mon, ws = _monitor()
        await mon.dispatch(
            _attached("S1", "service_worker", f"chrome-extension://{EXT}/sw.js", waiting=False)
        )
        await _settle()
        while not mon.alert_queue.empty():
            mon.alert_queue.get_nowait()
        entry = mon.sessions["S1"]
        ws.script_sources["sc1"] = source(entry) if callable(source) else source
        await mon.dispatch(
            {
                "method": "Debugger.scriptParsed",
                "sessionId": "S1",
                "params": {"scriptId": "sc1", "url": ""},
            }
        )
        return [a for a in _drain(mon.alert_queue) if a["rule"] == "RULE-06"]

    @pytest.mark.asyncio
    async def test_monitors_own_name_lookup_is_not_an_eval_alert(self):
        """Real-extension re-test: every extension got RULE-06 for this."""
        alerts = await self._parsed(
            lambda e: bm._tag_own_script(bm.EXTENSION_NAME_SCRIPT, e["own_url"])
        )
        assert alerts == []

    @pytest.mark.asyncio
    async def test_monitors_own_hook_is_not_an_eval_alert(self):
        alerts = await self._parsed(
            lambda e: bm.build_hook_script(e["binding"], e["token"], e["mark"], e["own_url"])
        )
        assert alerts == []

    @pytest.mark.asyncio
    async def test_extension_eval_is_an_alert(self):
        assert await self._parsed("fetch(atob('aHR0cHM6Ly9ldmls'))")

    @pytest.mark.asyncio
    async def test_copying_the_visible_marker_does_not_hide_eval(self):
        """MARK is a property on globalThis - any extension can read it."""
        alerts = await self._parsed(lambda e: f"/*{e['mark']}*/ fetch(atob('aHR0cHM6Ly9ldmls'))")
        assert alerts
