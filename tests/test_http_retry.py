# tests/test_http_retry.py - Tests for the adapter HTTP retry helper
#
# We mock requests.post and pass a no-op sleep_fn so tests don't actually wait.

from unittest.mock import MagicMock, patch

import pytest
import requests

from adapters.http_retry import RETRIABLE_STATUS, post_with_retry


def _no_sleep(_seconds):
    """Inject as sleep_fn so tests don't actually pause."""
    pass


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestSuccessfulFirstAttempt:
    def test_returns_response_on_200(self):
        mock_resp = MagicMock(status_code=200)
        with patch("adapters.http_retry.requests.post", return_value=mock_resp) as mock_post:
            resp, err = post_with_retry("http://x", sleep_fn=_no_sleep)
            assert resp is mock_resp
            assert err is None
            # No retries - single call
            assert mock_post.call_count == 1

    def test_returns_4xx_response_immediately_no_retry(self):
        """4xx errors are NOT retriable - one call then return."""
        mock_resp = MagicMock(status_code=404)
        with patch("adapters.http_retry.requests.post", return_value=mock_resp) as mock_post:
            resp, err = post_with_retry("http://x", sleep_fn=_no_sleep)
            assert resp is mock_resp
            assert err is None
            assert mock_post.call_count == 1


# ---------------------------------------------------------------------------
# Retry logic
# ---------------------------------------------------------------------------


class TestRetries:
    @pytest.mark.parametrize("status", sorted(RETRIABLE_STATUS))
    def test_retriable_status_triggers_retry(self, status):
        """5xx and 429 should all be retried up to max_attempts."""
        mock_resp = MagicMock(status_code=status)
        with patch("adapters.http_retry.requests.post", return_value=mock_resp) as mock_post:
            resp, err = post_with_retry(
                "http://x",
                max_attempts=3,
                sleep_fn=_no_sleep,
            )
            assert mock_post.call_count == 3  # All 3 attempts used
            assert resp is None
            assert err is not None
            assert "exhausted" in err

    def test_recovers_after_transient_500(self):
        """First call 500, second call 200 - should succeed on attempt 2."""
        responses = [MagicMock(status_code=500), MagicMock(status_code=200)]
        with patch("adapters.http_retry.requests.post", side_effect=responses) as mock_post:
            resp, err = post_with_retry("http://x", sleep_fn=_no_sleep)
            assert resp.status_code == 200
            assert err is None
            assert mock_post.call_count == 2

    def test_timeout_is_retried(self):
        with patch(
            "adapters.http_retry.requests.post",
            side_effect=requests.exceptions.Timeout("slow"),
        ) as mock_post:
            resp, err = post_with_retry(
                "http://x",
                max_attempts=2,
                sleep_fn=_no_sleep,
            )
            assert mock_post.call_count == 2
            assert resp is None
            assert "exhausted" in err

    def test_connection_error_is_retried(self):
        with patch(
            "adapters.http_retry.requests.post",
            side_effect=requests.exceptions.ConnectionError("refused"),
        ) as mock_post:
            resp, err = post_with_retry(
                "http://x",
                max_attempts=2,
                sleep_fn=_no_sleep,
            )
            assert mock_post.call_count == 2
            assert "exhausted" in err

    def test_other_request_exception_not_retried(self):
        """Generic RequestException should fail fast - it indicates a bug."""
        with patch(
            "adapters.http_retry.requests.post",
            side_effect=requests.exceptions.InvalidURL("bad url"),
        ) as mock_post:
            resp, err = post_with_retry("http://x", sleep_fn=_no_sleep)
            assert mock_post.call_count == 1
            assert resp is None
            assert "request error" in err


# ---------------------------------------------------------------------------
# Sleep behaviour
# ---------------------------------------------------------------------------


class TestSleepBehaviour:
    def test_sleeps_between_attempts(self):
        """We should sleep between attempts but NOT after the final one."""
        sleeps = []

        def record_sleep(s):
            sleeps.append(s)

        with patch("adapters.http_retry.requests.post", return_value=MagicMock(status_code=500)):
            post_with_retry("http://x", max_attempts=3, sleep_fn=record_sleep)

        # 3 attempts -> 2 sleeps (between 1->2 and 2->3, none after 3)
        assert len(sleeps) == 2

    def test_no_sleep_on_immediate_success(self):
        sleeps = []
        with patch("adapters.http_retry.requests.post", return_value=MagicMock(status_code=200)):
            post_with_retry("http://x", sleep_fn=lambda s: sleeps.append(s))
        assert sleeps == []

    def test_backoff_grows(self):
        """Each sleep should be roughly 2x the previous (within jitter)."""
        sleeps = []
        with patch("adapters.http_retry.requests.post", return_value=MagicMock(status_code=500)):
            post_with_retry(
                "http://x",
                max_attempts=4,
                base_delay=1.0,
                sleep_fn=lambda s: sleeps.append(s),
            )
        # 4 attempts -> 3 sleeps. Base 1.0, factor 2.0, jitter +/-25%.
        # Expected: ~1.0, ~2.0, ~4.0
        assert len(sleeps) == 3
        # Check ordering (allowing jitter)
        assert sleeps[0] < sleeps[1] < sleeps[2]


# ---------------------------------------------------------------------------
# Argument pass-through
# ---------------------------------------------------------------------------


class TestArgPassThrough:
    def test_json_data_passed_through(self):
        with patch(
            "adapters.http_retry.requests.post", return_value=MagicMock(status_code=200)
        ) as mock_post:
            post_with_retry(
                "http://x",
                json={"hello": "world"},
                headers={"X-Foo": "bar"},
                timeout=42,
                sleep_fn=_no_sleep,
            )
            kwargs = mock_post.call_args.kwargs
            assert kwargs["json"] == {"hello": "world"}
            assert kwargs["headers"] == {"X-Foo": "bar"}
            assert kwargs["timeout"] == 42

    def test_data_bytes_passed_through(self):
        with patch(
            "adapters.http_retry.requests.post", return_value=MagicMock(status_code=200)
        ) as mock_post:
            post_with_retry(
                "http://x",
                data=b"raw-bytes",
                sleep_fn=_no_sleep,
            )
            assert mock_post.call_args.kwargs["data"] == b"raw-bytes"
