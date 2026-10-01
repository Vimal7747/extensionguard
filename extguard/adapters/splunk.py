# adapters/splunk.py - Splunk HTTP Event Collector (HEC) adapter
#
# Splunk HEC is the simplest way to push events from external sources.
# Enable it in Splunk Web: Settings > Data Inputs > HTTP Event Collector.
# Generate a token and optionally assign it to a specific index.
#
# After ingestion, search in Splunk:
#   index=security sourcetype="extguard:alert"
#   | where severity="critical"
#   | table _time, extension_title, rule, description, mitre
#
# Splunk event format:
#   {
#     "time":       1234567890.123,   -- epoch float
#     "source":     "extguard",
#     "sourcetype": "extguard:alert",
#     "index":      "security",
#     "event":      { ...the alert dict... }
#   }

import time
from datetime import datetime

from extguard.adapters.http_retry import post_with_retry
from extguard.logging_setup import get_logger

log = get_logger(__name__)


def send(alert: dict, cfg: dict) -> dict:
    """
    POST one alert to the Splunk HTTP Event Collector.

    Args:
        alert: Standard ExtensionGuard alert dict
        cfg:   The "splunk" block from extguard.conf.json

    Returns {"ok": True} or {"ok": False, "error": "reason"}.
    """
    hec_url = cfg["hec_url"]
    hec_token = cfg["hec_token"]
    index = cfg.get("index", "security")
    sourcetype = cfg.get("sourcetype", "extguard:alert")
    ssl_verify = cfg.get("ssl_verify", True)
    timeout = cfg.get("timeout_sec", 10)

    # Convert ISO 8601 alert_time to Unix epoch float for Splunk's _time field
    epoch_time = _iso_to_epoch(alert.get("alert_time", ""))

    # Splunk HEC wrapper — the actual alert goes inside "event"
    payload = {
        "time": epoch_time,
        "source": "extguard",
        "sourcetype": sourcetype,
        "index": index,
        "event": alert,
    }

    headers = {
        "Authorization": f"Splunk {hec_token}",
        "Content-Type": "application/json",
    }

    # post_with_retry handles transient 5xx and network errors with backoff
    resp, err = post_with_retry(
        hec_url,
        json=payload,
        headers=headers,
        timeout=timeout,
        verify=ssl_verify,
    )

    if err is not None:
        log.warning("Splunk HEC failed after retries: %s", err)
        return {"ok": False, "error": err}

    try:
        data = resp.json() if resp.content else {}
    except (ValueError, KeyError) as exc:
        log.warning("Splunk HEC bad response shape: %s", exc)
        return {"ok": False, "error": f"Unexpected response format: {exc}"}

    if resp.status_code == 200 and data.get("code") == 0:
        log.debug("Splunk HEC ingest OK (index=%s)", index)
        return {"ok": True}
    else:
        e = f"HTTP {resp.status_code} code={data.get('code')} {data.get('text', '')}"
        log.warning("Splunk HEC ingest failed: %s", e)
        return {"ok": False, "error": e}


def _iso_to_epoch(iso_str: str) -> float:
    """
    Convert an ISO 8601 timestamp (e.g. '2026-05-21T10:30:00+00:00') to Unix epoch float.
    Falls back to current time if parsing fails.
    """
    try:
        dt = datetime.fromisoformat(iso_str)
        return dt.timestamp()
    except (ValueError, AttributeError):
        return time.time()
