# adapters/pagerduty.py - PagerDuty Events API v2 adapter
#
# Creates PD incidents for high/critical alerts and auto-resolves when the
# same extension is later cleared. Uses the dedup_key to tie trigger/resolve
# events together so analysts don't get duplicate pages.
#
# PagerDuty severity mapping:
#   ExtensionGuard  ->  PagerDuty
#   critical            critical
#   high                error
#   medium              warning
#   low                 info
#
# Create a PD service integration:
#   PagerDuty > Services > <your service> > Integrations > Add > Events API v2
#   Copy the "Integration Key" into extguard.conf.json
#
# After an alert fires, the on-call engineer gets paged with:
#   - Summary: e.g. "[CRITICAL] C2 Beacon - Nx Console"
#   - Custom details: full ExtensionGuard alert JSON
#   - MITRE techniques as a comma-separated field

import json
from datetime import datetime, timezone

import requests

from adapters.http_retry import post_with_retry
from logging_setup import get_logger

log = get_logger(__name__)


PD_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

# Map ExtensionGuard severity to PagerDuty's four-tier model
PD_SEVERITY_MAP = {
    "critical": "critical",
    "high":     "error",
    "medium":   "warning",
    "low":      "info",
}


def send(alert: dict, cfg: dict) -> dict:
    """
    Trigger a PagerDuty incident for the given alert.

    Uses alert fingerprint (rule + extension_id) as the dedup_key so that
    repeated alerts for the same issue update the existing incident rather
    than creating a new one.

    Args:
        alert: Standard ExtensionGuard alert dict
        cfg:   The "pagerduty" block from extguard.conf.json

    Returns {"ok": True, "incident_key": "..."} or {"ok": False, "error": "..."}.
    """
    integration_key = cfg["integration_key"]
    min_severity    = cfg.get("min_severity", "high")
    timeout         = cfg.get("timeout_sec", 10)

    # Skip if this alert is below the configured minimum severity for PD
    if not _severity_meets_minimum(alert.get("severity", "low"), min_severity):
        return {"ok": True, "skipped": True, "reason": "Below min_severity threshold"}

    ext   = alert.get("extension", {})
    rule  = alert.get("rule", "UNKNOWN")
    sev   = alert.get("severity", "low")
    mitre = ", ".join(alert.get("mitre", []))
    detail = alert.get("detail", {})

    # Build a human-readable summary for the PD incident title
    ext_name = ext.get("title") or ext.get("id") or "Unknown Extension"
    summary  = f"[{sev.upper()}] {rule} - {ext_name}"
    if detail.get("description"):
        # Truncate to 255 chars (PD summary limit)
        summary = f"{summary}: {detail['description']}"[:255]

    # dedup_key ties this alert to a specific extension+rule so multiple
    # firings of the same rule update (rather than re-create) the incident
    ext_id   = ext.get("id") or ext.get("title") or "unknown"
    dedup_key = f"extguard-{rule}-{ext_id}"

    payload = {
        "routing_key":  integration_key,
        "event_action": "trigger",
        "dedup_key":    dedup_key,
        "payload": {
            "summary":   summary,
            "severity":  PD_SEVERITY_MAP.get(sev, "warning"),
            "source":    "ExtensionGuard",
            "timestamp": alert.get("alert_time", _now_iso()),
            "component": "browser_extension_monitor",
            "group":     "supply_chain_security",
            "class":     rule,
            "custom_details": {
                "extension_id":    ext.get("id"),
                "extension_name":  ext.get("title"),
                "rule":            rule,
                "mitre_techniques": mitre,
                "description":     detail.get("description", ""),
                "url":             detail.get("url", ""),
                "full_alert":      json.dumps(alert, indent=2),
            },
        },
        # Links allow analysts to jump to related resources
        "links": _build_links(alert),
    }

    resp, err = post_with_retry(
        PD_EVENTS_URL,
        json    = payload,
        timeout = timeout,
    )

    if err is not None:
        log.warning("PagerDuty failed after retries: %s", err)
        return {"ok": False, "error": err}

    data = resp.json() if resp.content else {}

    if resp.status_code == 202 and data.get("status") == "success":
        log.info("PagerDuty incident triggered: %s", dedup_key)
        return {
            "ok":           True,
            "incident_key": data.get("dedup_key") or dedup_key,
        }
    else:
        e = f"HTTP {resp.status_code}: {data.get('message', resp.text[:200])}"
        log.warning("PagerDuty trigger failed: %s", e)
        return {"ok": False, "error": e}


def resolve(rule: str, extension_id: str, cfg: dict) -> dict:
    """
    Resolve (auto-close) an existing PD incident when the threat is cleared.
    Matches by the same dedup_key used during trigger.

    Call this from the remediation module (Stage 5) after kill/quarantine.
    """
    integration_key = cfg["integration_key"]
    dedup_key       = f"extguard-{rule}-{extension_id}"

    payload = {
        "routing_key":  integration_key,
        "event_action": "resolve",
        "dedup_key":    dedup_key,
        "payload": {
            "summary":  f"Resolved by ExtensionGuard: {rule} - {extension_id}",
            "severity": "info",
            "source":   "ExtensionGuard",
        },
    }

    try:
        resp = requests.post(PD_EVENTS_URL, json=payload, timeout=cfg.get("timeout_sec", 10))
        if resp.status_code == 202:
            return {"ok": True}
        return {"ok": False, "error": f"HTTP {resp.status_code}"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _severity_meets_minimum(severity: str, minimum: str) -> bool:
    """Return True if `severity` is >= `minimum` in the four-tier scale."""
    order = ["low", "medium", "high", "critical"]
    try:
        return order.index(severity) >= order.index(minimum)
    except ValueError:
        return True  # Unknown severity — send it


def _build_links(alert: dict) -> list:
    """Build PD alert links for quick analyst pivot."""
    links = [
        {
            "href": "https://attack.mitre.org/",
            "text": "MITRE ATT&CK: " + ", ".join(alert.get("mitre", [])),
        }
    ]
    url = alert.get("detail", {}).get("url", "")
    if url:
        links.append({"href": url, "text": f"Suspicious URL: {url}"})
    return links


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
