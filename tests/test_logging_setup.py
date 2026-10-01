# tests/test_logging_setup.py - Secret redaction tests
#
# These tests are security-critical: if a credential pattern slips through the
# redaction filter, it can end up in shipped log files. We test:
#   1. Each known secret shape is scrubbed by redact()
#   2. The SecretRedactionFilter applies to both .msg and .args
#   3. Realistic mistakes (token in error message, webhook URL in exception)
#      are caught
#   4. Non-secret data is left alone

import logging

import pytest

from extguard.logging_setup import (
    JsonFormatter,
    SecretRedactionFilter,
    redact,
)

# ---------------------------------------------------------------------------
# Redaction patterns - one test per credential type
# ---------------------------------------------------------------------------


class TestNewRedactionPatterns:
    @pytest.mark.parametrize(
        "leak,secret",
        [
            ("x-apikey: " + "f" * 64, "f" * 64),
            ('"api_key": "vt-real-key-1234567890"', "vt-real-key-1234567890"),
            ("webhook_secret=hunter2hunter2", "hunter2hunter2"),
            ("EXTGUARD_COC_KEY=abcdef0123456789", "abcdef0123456789"),
        ],
    )
    def test_labelled_secrets(self, leak, secret):
        from extguard.logging_setup import redact

        assert secret not in redact(leak)

    def test_short_values_left_alone(self):
        from extguard.logging_setup import redact

        assert redact("password=abc") == "password=abc"  # too short to be a real secret


class TestRedactionPatterns:
    def test_redacts_anthropic_api_key(self):
        text = "set ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890"
        result = redact(text)
        assert "abcdefghijklmnop" not in result
        assert "sk-ant-[REDACTED]" in result

    def test_redacts_slack_webhook_url(self):
        text = "POST https://hooks.slack.com/services/T12AB/B34CD/secrettokenshere"
        result = redact(text)
        assert "secrettokenshere" not in result
        assert "[REDACTED]" in result
        # The hostname prefix is preserved so logs are still debuggable
        assert "hooks.slack.com/services/" in result

    def test_redacts_bearer_token(self):
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature"
        result = redact(text)
        assert "eyJhbGciOiJIUzI1NiJ9" not in result
        assert "[REDACTED]" in result

    def test_redacts_splunk_hec_token(self):
        text = "Authorization: Splunk 12345678-1234-1234-1234-123456789abc"
        result = redact(text)
        assert "12345678-1234" not in result

    def test_redacts_pagerduty_integration_key(self):
        text = '{"integration_key": "1234567890abcdef1234567890abcdef", "event": "x"}'
        result = redact(text)
        assert "1234567890abcdef1234567890abcdef" not in result

    def test_redacts_sentinel_shared_key(self):
        text = 'shared_key="abc123def456ghi789jkl012mno345pqr678stuv=="'
        result = redact(text)
        assert "abc123def456ghi789jkl012mno345" not in result

    def test_redacts_aws_access_key_id(self):
        for prefix in ("AKIA", "ASIA"):
            text = f"using key {prefix}IOSFODNN7EXAMPLE for s3 upload"
            result = redact(text)
            assert "IOSFODNN7EXAMPLE" not in result
            assert f"{prefix}[REDACTED]" in result

    def test_redacts_github_pat_classic(self):
        text = "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789AB"
        result = redact(text)
        assert "abcdefghijklmnop" not in result
        assert "ghp_[REDACTED]" in result

    def test_redacts_github_pat_fine_grained(self):
        text = "token=github_pat_11ABCDEFG_qrstuvwxyz0123456789ABCDEFGHIJ"
        result = redact(text)
        assert "11ABCDEFG_qrstuvwxyz" not in result

    def test_redacts_npm_token(self):
        text = "//registry.npmjs.org/:_authToken=npm_1234567890abcdefghijklmnopqrstuvwxyz"
        result = redact(text)
        assert "1234567890abcdefghij" not in result


class TestRealisticLeakShapes:
    """
    Lock in the realistic shapes we MUST catch. These come from how secrets
    appear in real logs - environment variable dumps, header values, JSON
    payloads, error messages.
    """

    @pytest.mark.parametrize(
        "shape",
        [
            "TOKEN=ghp_abcdefghijklmnopqrstuv",
            "TOKEN: ghp_abcdefghijklmnopqrstuv",
            "Authorization: token ghp_abcdefghijklmnopqrstuv",
            '"token": "ghp_abcdefghijklmnopqrstuv"',
            "(ghp_abcdefghijklmnopqrstuv)",
            "[ghp_abcdefghijklmnopqrstuv]",
            "{ghp_abcdefghijklmnopqrstuv}",
            ",ghp_abcdefghijklmnopqrstuv,",
            # Newline-separated (e.g., a token on its own line)
            "\nghp_abcdefghijklmnopqrstuv\n",
        ],
    )
    def test_realistic_pat_shapes_all_redacted(self, shape):
        result = redact(shape)
        assert "abcdefghijkl" not in result, f"Leak in shape: {shape!r}"
        assert "ghp_[REDACTED]" in result

    @pytest.mark.parametrize(
        "shape",
        [
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
            "key 'AKIAIOSFODNN7EXAMPLE'",
            "AKIAIOSFODNN7EXAMPLE expired",
        ],
    )
    def test_realistic_aws_key_shapes_all_redacted(self, shape):
        result = redact(shape)
        assert "IOSFODNN7" not in result, f"Leak in shape: {shape!r}"

    def test_documented_non_coverage_wedged_in_identifier(self):
        """
        Document what we DON'T redact: tokens directly concatenated to
        identifier characters. `_ghp_xxx` could be a legit identifier name
        like `_ghp_internal_handler`, so we deliberately don't redact.
        Future devs can extend this if they observe a real leak shape that
        requires the looser boundary.
        """
        # These remain unredacted - that's the current (documented) behaviour
        assert "abcdefghijkl" in redact("_ghp_abcdefghijklmnopqrstuv")
        # If this assertion ever flips (someone tightens the regex), update
        # the docstring on SECRET_PATTERNS and remove this test.

    def test_multiple_secrets_in_one_message(self):
        """A log line with multiple secrets must scrub all of them."""
        text = (
            "Failed: GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuv "
            "and AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        )
        result = redact(text)
        assert "abcdefghijkl" not in result
        assert "IOSFODNN7" not in result
        assert "ghp_[REDACTED]" in result
        assert "AKIA[REDACTED]" in result


# ---------------------------------------------------------------------------
# Non-secret data must pass through unchanged
# ---------------------------------------------------------------------------


class TestNoOverRedaction:
    def test_plain_text_unchanged(self):
        assert redact("Hello, world!") == "Hello, world!"

    def test_extension_id_not_redacted(self):
        """Chrome extension IDs are public identifiers - never sensitive."""
        ext_id = "abcdefghijklmnopqrstuvwxyzabcdef"
        text = f"blocking extension {ext_id}"
        assert ext_id in redact(text)

    def test_normal_url_not_redacted(self):
        text = "fetching https://api.osv.dev/v1/query for hash lookup"
        assert "api.osv.dev" in redact(text)

    def test_non_string_input_returned_as_is(self):
        """redact() of an int or dict should pass through unchanged."""
        assert redact(42) == 42
        assert redact({"a": 1}) == {"a": 1}


# ---------------------------------------------------------------------------
# SecretRedactionFilter integration with the logging module
# ---------------------------------------------------------------------------


class TestRedactionFilter:
    @pytest.fixture
    def filter(self):
        return SecretRedactionFilter()

    def test_filter_returns_true_always(self, filter):
        """A redaction filter must never DROP records - just modify them."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="hello",
            args=(),
            exc_info=None,
        )
        assert filter.filter(record) is True

    def test_redacts_msg_string(self, filter):
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="key sk-ant-api03-abc123def456ghi789jkl012mno",
            args=(),
            exc_info=None,
        )
        filter.filter(record)
        assert "abc123def456" not in record.msg

    def test_redacts_args_tuple(self, filter):
        """log.info('token: %s', secret) should scrub the % arg too."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="token: %s",
            args=("sk-ant-api03-abcdefghijklmnopqrstuv",),
            exc_info=None,
        )
        filter.filter(record)
        assert "abcdefghijkl" not in record.args[0]

    def test_redacts_args_dict(self, filter):
        """log.info('%(t)s', {'t': secret}) should also be scrubbed.

        Python 3.13's LogRecord constructor rejects dict args passed directly,
        so we go through logger.log() which is the real call path used by
        application code.
        """
        captured = []

        class CaptureHandler(logging.Handler):
            def emit(self, record):
                captured.append(record)

        handler = CaptureHandler()
        handler.addFilter(filter)
        logger = logging.getLogger("test_dict_args")
        logger.handlers = [handler]
        logger.setLevel(logging.DEBUG)
        logger.propagate = False

        # Real call path: %-style with a dict arg
        logger.info("%(t)s", {"t": "sk-ant-api03-abcdefghijklmnopqrstuv"})

        assert len(captured) == 1
        rendered = captured[0].getMessage()
        assert "abcdefghijkl" not in rendered
        assert "[REDACTED]" in rendered


# ---------------------------------------------------------------------------
# End-to-end: build a logger with the filter, capture output, check redaction
# ---------------------------------------------------------------------------


class TestEndToEnd:
    def test_logger_with_filter_redacts(self, caplog):
        """Use pytest's caplog to capture log output and verify redaction."""
        logger = logging.getLogger("test_e2e")
        logger.setLevel(logging.DEBUG)

        # Apply our filter to caplog's handler so pytest sees the redacted version
        for handler in logging.getLogger().handlers + [caplog.handler]:
            handler.addFilter(SecretRedactionFilter())

        with caplog.at_level(logging.DEBUG, logger="test_e2e"):
            logger.error("Auth failed for token sk-ant-api03-abcdefghijklmnopqrstuv")

        # caplog.text contains the formatted message including any redaction
        assert "abcdefghijkl" not in caplog.text
        assert "[REDACTED]" in caplog.text


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------


class TestJsonFormatter:
    def test_emits_valid_json(self):
        import json

        fmt = JsonFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="hello %s",
            args=("world",),
            exc_info=None,
        )
        out = fmt.format(record)
        parsed = json.loads(out)
        assert parsed["msg"] == "hello world"
        assert parsed["level"] == "INFO"
        assert parsed["logger"] == "test"
