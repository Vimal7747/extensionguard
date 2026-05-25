# logging_setup.py - Centralised logger configuration with secret redaction
#
# Why a custom module instead of stock logging?
#   1. SOC tools end up shipping logs to other systems (Splunk, ELK, files).
#      Bare print() can't be filtered, formatted, or routed.
#   2. We process credentials (ANTHROPIC_API_KEY, Splunk HEC tokens,
#      PagerDuty integration keys, Slack webhook URLs). Even a single
#      accidental log line containing a token is a compliance incident.
#      The SecretRedactionFilter scrubs known secret patterns from every
#      log record BEFORE the message reaches a handler.
#
# How to use:
#   from logging_setup import get_logger
#   log = get_logger(__name__)
#   log.info("dispatched to splunk")
#   log.error("failed: %s", exc)
#
# Environment variables that influence behaviour:
#   EXTGUARD_LOG_LEVEL   "DEBUG" / "INFO" / "WARNING" / "ERROR"  (default: INFO)
#   EXTGUARD_LOG_FILE    Path to also log to a file (default: stderr only)
#   EXTGUARD_LOG_JSON    If "1", emit JSON-line format (default: human-readable)

import json
import logging
import logging.handlers
import os
import re
import sys

# ---------------------------------------------------------------------------
# Secret patterns to redact
# Add new patterns here when new credential types enter the codebase.
# ---------------------------------------------------------------------------

# A note on \b boundaries:
#   We use \b (word boundary: transition between [A-Za-z0-9_] and anything else)
#   for token prefix patterns. This correctly handles realistic leak shapes:
#       TOKEN=ghp_xxx        ('=' is non-word, \b fires)
#       Bearer ghp_xxx       (space is non-word, \b fires)
#       "ghp_xxx"            (quote is non-word, \b fires)
#       Authorization: ghp_xxx
#       (ghp_xxx)            (paren is non-word, \b fires)
#   It deliberately does NOT match `_ghp_xxx` or `xxxghp_xxx` because in those
#   shapes we can't tell whether `ghp_xxx` is a token or part of a longer
#   identifier. Over-redacting plain identifiers would break log readability.
#   If you observe a real token leak that \b misses, prefer adding the specific
#   shape as a NEW pattern over loosening boundaries here.

# Order matters: more-specific patterns (URL with secret inside) should come
# before more-generic ones (bare token shapes) so the right capture wins.
SECRET_PATTERNS = [
    # Slack webhook URLs: https://hooks.slack.com/services/T.../B.../<token>
    # The whole token segment is sensitive, not just one field.
    (re.compile(r"(https://hooks\.slack\.com/services/)[A-Za-z0-9/_-]+"), r"\1[REDACTED]"),
    # Anthropic API keys: sk-ant-api03-... and sk-ant-...
    (re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"), "sk-ant-[REDACTED]"),
    # Generic Bearer tokens in Authorization headers
    (
        re.compile(r"(Authorization\s*[:=]\s*['\"]?Bearer\s+)[A-Za-z0-9._-]+", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
    # Splunk HEC tokens: GUID-shaped, often in Authorization: Splunk <token>
    (
        re.compile(r"(Authorization\s*[:=]\s*['\"]?Splunk\s+)[A-Za-z0-9-]+", re.IGNORECASE),
        r"\1[REDACTED]",
    ),
    # PagerDuty integration keys: 32-char alphanumeric, often labelled
    (re.compile(r"(integration_key['\"]?\s*[:=]\s*['\"]?)[A-Za-z0-9]{20,}"), r"\1[REDACTED]"),
    # Sentinel shared key: base64-shaped, often labelled
    (re.compile(r"(shared_key['\"]?\s*[:=]\s*['\"]?)[A-Za-z0-9+/]{20,}={0,2}"), r"\1[REDACTED]"),
    # AWS access key IDs: AKIA / ASIA prefix + 16 alphanumeric chars
    (re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"), r"\1[REDACTED]"),
    # GitHub PATs: classic (ghp_..., gho_..., ghu_..., ghs_..., ghr_...)
    (re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}"), r"\1_[REDACTED]"),
    # GitHub fine-grained PATs: github_pat_...
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), "github_pat_[REDACTED]"),
    # npm tokens: npm_... prefix
    (re.compile(r"\bnpm_[A-Za-z0-9]{20,}"), "npm_[REDACTED]"),
]


def redact(text: str) -> str:
    """
    Apply every secret pattern to a string and return the redacted version.
    Public so adapters can use it to scrub error messages before they're logged
    or written to disk (e.g. to chain_of_custody.json).
    """
    if not isinstance(text, str):
        return text
    out = text
    for pattern, replacement in SECRET_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


# ---------------------------------------------------------------------------
# SecretRedactionFilter - applied to every log handler
# ---------------------------------------------------------------------------


class SecretRedactionFilter(logging.Filter):
    """
    A logging.Filter that scrubs known credential shapes from log messages
    BEFORE they reach a handler. Catches both:
      - log.info("token is %s", token)   (args)
      - log.info(f"token is {token}")    (message)

    Caveat: this is defence in depth, not a primary control. The first line
    of defence is to never pass secrets to log calls in the first place.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        # Redact the formatted message
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)

        # Redact each positional arg (used by lazy %-formatting)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: redact(str(v)) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    redact(str(a)) if isinstance(a, str) else a for a in record.args
                )

        return True  # Don't drop the record - just modify it


# ---------------------------------------------------------------------------
# Optional JSON formatter (for SOC log shipping)
# ---------------------------------------------------------------------------


class JsonFormatter(logging.Formatter):
    """One JSON object per line - what Splunk / ELK / Loki expect."""

    def format(self, record: logging.LogRecord) -> str:
        obj = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            obj["exc"] = self.formatException(record.exc_info)
        return json.dumps(obj)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_CONFIGURED = False


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger configured with the global ExtensionGuard setup.
    Lazy-initialises the root configuration on first call.

    Always use this instead of `logging.getLogger(name)` directly so
    every logger in the codebase gets the redaction filter automatically.
    """
    global _CONFIGURED
    if not _CONFIGURED:
        _configure_root()
        _CONFIGURED = True
    return logging.getLogger(name)


def _configure_root():
    """Set up the root logger once, applying env-var overrides."""
    level_name = os.environ.get("EXTGUARD_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)

    # Wipe any pre-existing handlers (e.g. from a stray basicConfig call)
    root.handlers.clear()

    # --- Console / stderr handler -----------------------------------------
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(level)

    if os.environ.get("EXTGUARD_LOG_JSON") == "1":
        stderr_handler.setFormatter(JsonFormatter())
    else:
        stderr_handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s %(levelname)-7s %(name)-20s %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )

    # The redaction filter goes on the HANDLER, not the logger, so every
    # message routed through this handler is scrubbed regardless of which
    # logger emitted it.
    stderr_handler.addFilter(SecretRedactionFilter())
    root.addHandler(stderr_handler)

    # --- Optional file handler --------------------------------------------
    log_file = os.environ.get("EXTGUARD_LOG_FILE")
    if log_file:
        # Rotating file handler so logs don't grow unbounded.
        # Keeps 5 backups of 10 MB each.
        file_handler = logging.handlers.RotatingFileHandler(
            filename=log_file,
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(JsonFormatter())  # Always JSON to file
        file_handler.addFilter(SecretRedactionFilter())
        root.addHandler(file_handler)


def shutdown():
    """Flush and close all handlers - call from CLI atexit if needed."""
    logging.shutdown()
