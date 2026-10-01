# adapters/slack.py - Slack Incoming Webhook adapter
#
# Sends richly formatted Block Kit alerts to a Slack channel.
# Create a webhook at:  https://api.slack.com/apps > Incoming Webhooks
#
# Alert appearance in Slack:
#
#  [CRITICAL] RULE-01 - C2 Beacon Detected
#  ----------------------------------------
#  Extension:   Nx Console (abcdefghijklmnop)
#  Description: Periodic POST to known exfil domain - C2 beacon pattern
#  URL:         https://malicious.workers.dev/collect
#  MITRE:       T1071.001, T1176
#  Time:        2026-05-21 10:30:00 UTC

from datetime import datetime, timezone

from extguard.adapters.http_retry import post_with_retry
from extguard.logging_setup import get_logger

log = get_logger(__name__)


# Slack colours for the alert attachment sidebar stripe
SEVERITY_COLOURS = {
    "critical": "#FF0000",  # Red
    "high": "#FF6600",  # Orange
    "medium": "#FFB300",  # Amber
    "low": "#36A64F",  # Green
}

# Emoji prefix for the header — no Unicode box chars, just emoji which Slack handles fine
SEVERITY_EMOJI = {
    "critical": ":rotating_light:",
    "high": ":warning:",
    "medium": ":mag:",
    "low": ":white_check_mark:",
}


def send(alert: dict, cfg: dict) -> dict:
    """
    POST a formatted Block Kit message to a Slack Incoming Webhook.

    Args:
        alert: Standard ExtensionGuard alert dict
        cfg:   The "slack" block from extguard.conf.json

    Returns {"ok": True} or {"ok": False, "error": "reason"}.
    """
    webhook_url = cfg["webhook_url"]
    min_severity = cfg.get("min_severity", "medium")
    timeout = cfg.get("timeout_sec", 10)

    # Respect the minimum severity filter
    if not _severity_meets_minimum(alert.get("severity", "low"), min_severity):
        return {"ok": True, "skipped": True, "reason": "Below min_severity threshold"}

    message = _build_message(alert, cfg.get("channel"))

    resp, err = post_with_retry(
        webhook_url,
        json=message,
        timeout=timeout,
    )

    if err is not None:
        log.warning("Slack failed after retries: %s", err)
        return {"ok": False, "error": err}

    # Slack Incoming Webhooks return the plain text "ok" on success
    if resp.status_code == 200 and resp.text == "ok":
        log.debug("Slack webhook delivered")
        return {"ok": True}
    else:
        e = f"HTTP {resp.status_code}: {resp.text[:200]}"
        log.warning("Slack webhook failed: %s", e)
        return {"ok": False, "error": e}


# ---------------------------------------------------------------------------
# Block Kit message builder
# ---------------------------------------------------------------------------


# Slack rejects a section whose text is over 3000 characters - and a rejected
# message means a LOST alert. Keep every interpolated value well under that.
SLACK_FIELD_LIMIT = 1500


def _slack_escape(value, limit: int = SLACK_FIELD_LIMIT, code: bool = False) -> str:
    """
    Make an untrusted value safe to put in Slack mrkdwn.

    The extension name, description, and URL can come straight from a
    malicious extension. Unescaped, a name like
        <!channel> <https://evil.example|Click here to remediate>
    would ping the whole SOC channel with a disguised phishing link.
    Slack's rule: escape & < > as &amp; &lt; &gt; (that disables mentions,
    links and special commands). Inside `code` spans we also drop backticks
    so the value can't close the span early.
    """
    text = str(value) if value is not None else ""
    if len(text) > limit:
        text = text[:limit] + "... [truncated]"
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    if code:
        text = text.replace("`", "'")
    return text


def _build_message(alert: dict, channel=None) -> dict:
    """Build a Slack Block Kit payload for the given alert."""
    sev = str(alert.get("severity", "low"))
    rule = _slack_escape(alert.get("rule", "?"), limit=100)
    ext = alert.get("extension", {})
    detail = alert.get("detail", {})
    mitre = [_slack_escape(t, limit=50) for t in alert.get("mitre", [])]
    ts = str(alert.get("alert_time", _now_iso()))

    ext_name = _slack_escape(ext.get("title") or ext.get("id") or "Unknown Extension", limit=200)
    ext_id = _slack_escape(ext.get("id", ""), limit=100, code=True)
    desc = _slack_escape(detail.get("description", ""))
    url = _slack_escape(detail.get("url", ""), limit=500, code=True)
    colour = SEVERITY_COLOURS.get(sev, "#808080")
    emoji = SEVERITY_EMOJI.get(sev, ":bell:")
    ts_short = _slack_escape(ts[:19].replace("T", " "), limit=40) + " UTC"
    sev = _slack_escape(sev, limit=20)

    # Header line
    header_text = f"{emoji} *[{sev.upper()}] {rule}*"

    # Build the fields list
    fields = [
        {"type": "mrkdwn", "text": f"*Extension:*\n{ext_name}"},
    ]
    if ext_id:
        fields.append({"type": "mrkdwn", "text": f"*Extension ID:*\n`{ext_id}`"})
    if mitre:
        fields.append({"type": "mrkdwn", "text": f"*MITRE ATT&CK:*\n{', '.join(mitre)}"})
    fields.append({"type": "mrkdwn", "text": f"*Time:*\n{ts_short}"})

    # Main blocks
    blocks = [
        # Header
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": header_text},
        },
        # Divider
        {"type": "divider"},
        # Description
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Description:*\n{desc}"},
        },
    ]

    # Suspicious URL (only if present)
    if url:
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Suspicious URL:*\n`{url}`"},
            }
        )

    # Fields row (extension name, MITRE, time)
    blocks.append(
        {
            "type": "section",
            "fields": fields,
        }
    )

    # Recommendation footer
    rec = _severity_recommendation(sev)
    blocks.append(
        {
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f":information_source: *Recommendation:* {rec}"}
            ],
        }
    )

    # Slack attachment for the colour stripe — attachments are "legacy" but
    # the colour side-stripe still only works via attachments, not blocks
    payload = {
        "text": f"ExtensionGuard Alert: {sev.upper()} - {rule} on {ext_name}",
        "attachments": [
            {
                "color": colour,
                "blocks": blocks,
            }
        ],
    }

    if channel:
        payload["channel"] = channel

    return payload


def _severity_recommendation(sev: str) -> str:
    return {
        "critical": "BLOCK IMMEDIATELY - initiate remediation playbook",
        "high": "QUARANTINE - escalate to Tier-2 analyst",
        "medium": "REVIEW - monitor for additional suspicious behaviour",
        "low": "LOW RISK - continue standard monitoring",
    }.get(sev, "Review and triage")


def _severity_meets_minimum(severity: str, minimum: str) -> bool:
    order = ["low", "medium", "high", "critical"]
    try:
        return order.index(severity) >= order.index(minimum)
    except ValueError:
        return True


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
