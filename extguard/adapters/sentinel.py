# adapters/sentinel.py - Microsoft Sentinel Log Analytics Workspace adapter
#
# Sends alerts to a Log Analytics Workspace (LAW) using the HTTP Data Collector API.
# The alert appears in Sentinel under a custom table named <log_type>_CL.
#
# Authentication uses HMAC-SHA256:
#   1. Build a canonical string from HTTP method, content length, content type,
#      the x-ms-date header, and the resource path
#   2. Sign it with the workspace shared key (base64-decoded)
#   3. Base64-encode the result → put in the Authorization header
#
# After ingestion you can query in KQL:
#   ExtensionGuardAlert_CL
#   | where severity_s == "critical"
#   | project TimeGenerated, extension_title_s, rule_s, mitre_s, description_s

import base64
import hashlib
import hmac
import json
import re
from email.utils import formatdate  # For RFC 1123 date formatting

from extguard.adapters.http_retry import post_with_retry
from extguard.logging_setup import get_logger

log = get_logger(__name__)


# Log Analytics Data Collector API endpoint template
LAW_ENDPOINT = "https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"


def send(alert: dict, cfg: dict) -> dict:
    """
    Send one alert to Microsoft Sentinel via the Log Analytics HTTP Data Collector API.

    Args:
        alert: Standard ExtensionGuard alert dict (see behavioral_monitor._make_alert)
        cfg:   The "sentinel" block from extguard.conf.json

    Returns a result dict:
      {"ok": True}  on success
      {"ok": False, "error": "reason"}  on failure
    """
    workspace_id = cfg["workspace_id"]
    shared_key = cfg["shared_key"]
    log_type = cfg.get("log_type", "ExtensionGuardAlert")
    timeout = cfg.get("timeout_sec", 10)

    # Flatten the nested alert dict into a flat structure.
    # Log Analytics custom columns are named like "extension_title_s" (s = string).
    # Nested JSON objects would need to be stringified — flattening is cleaner for KQL.
    flat_record = _flatten_alert(alert)

    # Log Analytics accepts a JSON *array* of records
    body_json = json.dumps([flat_record])
    body_bytes = body_json.encode("utf-8")
    content_len = len(body_bytes)

    # Build the RFC 1123 date string required in both the Authorization header
    # and the x-ms-date header
    rfc1123_date = formatdate(usegmt=True)

    # Build the HMAC-SHA256 Authorization header
    try:
        auth_header = _build_auth_header(
            workspace_id=workspace_id,
            shared_key=shared_key,
            date=rfc1123_date,
            content_len=content_len,
            content_type="application/json",
            resource="/api/logs",
        )
    except Exception as exc:
        return {"ok": False, "error": f"Failed to build auth header: {exc}"}

    headers = {
        "Content-Type": "application/json",
        "Authorization": auth_header,
        "Log-Type": log_type,
        "x-ms-date": rfc1123_date,
        # Optional: set TimeStampField so Sentinel uses our alert_time
        "time-generated-field": "alert_time",
    }

    url = LAW_ENDPOINT.format(workspace_id=workspace_id)

    resp, err = post_with_retry(
        url,
        data=body_bytes,
        headers=headers,
        timeout=timeout,
    )

    if err is not None:
        log.warning("Sentinel ingest failed after retries: %s", err)
        return {"ok": False, "error": err}

    # HTTP 200 means the data was accepted for ingestion.
    # It may take a few minutes to appear in the workspace.
    if resp.status_code == 200:
        log.debug("Sentinel ingest OK for workspace %s", workspace_id)
        return {"ok": True}
    else:
        e = f"HTTP {resp.status_code}: {resp.text[:200]}"
        log.warning("Sentinel ingest failed: %s", e)
        return {"ok": False, "error": e}


# ---------------------------------------------------------------------------
# HMAC-SHA256 signing
# ---------------------------------------------------------------------------


def _build_auth_header(
    workspace_id: str,
    shared_key: str,
    date: str,
    content_len: int,
    content_type: str,
    resource: str,
) -> str:
    """
    Build the SharedKey Authorization header required by the Log Analytics API.

    The canonical string to sign is:
      {method}\\n{content_length}\\n{content_type}\\nx-ms-date:{date}\\n{resource}
    """
    string_to_sign = "\n".join(
        [
            "POST",
            str(content_len),
            content_type,
            f"x-ms-date:{date}",
            resource,
        ]
    )

    # Decode the base64 shared key into raw bytes before HMAC signing
    raw_key = base64.b64decode(shared_key)

    signature = base64.b64encode(
        hmac.new(raw_key, string_to_sign.encode("utf-8"), digestmod=hashlib.sha256).digest()
    ).decode("utf-8")

    return f"SharedKey {workspace_id}:{signature}"


# ---------------------------------------------------------------------------
# Alert flattening for KQL-friendly column names
# ---------------------------------------------------------------------------

# Bounded recursion depth for _flatten_alert. Real alerts nest at most ~4
# levels deep (alert > extension > id). 10 leaves comfortable headroom for
# future schema growth while preventing a malicious deeply-nested payload
# from triggering RecursionError (RECURSIONLIMIT defaults to 1000, way above
# what we ever need).
_MAX_FLATTEN_DEPTH = 10


def _flatten_alert(alert: dict) -> dict:
    """
    Flatten a nested alert dict into a flat dict.
    Nested keys are joined with '_', e.g. extension.title -> extension_title.
    Arrays are JSON-stringified so Log Analytics can store them.

    Bounded by _MAX_FLATTEN_DEPTH to prevent stack overflow on hostile input.
    Values past the depth limit are stringified and stored at the truncation point.
    """
    flat = {}

    def _walk(obj, prefix, depth):
        if depth > _MAX_FLATTEN_DEPTH:
            # Hit the depth limit - store as opaque string and stop recursing
            flat[prefix.rstrip("_")] = f"[truncated at depth {_MAX_FLATTEN_DEPTH}]"
            return

        if isinstance(obj, dict):
            for k, v in obj.items():
                # Strip _comment fields and non-alphanumeric characters from key names
                clean_key = re.sub(r"[^a-zA-Z0-9_]", "_", k)
                _walk(v, f"{prefix}{clean_key}_" if prefix else f"{clean_key}_", depth + 1)
        elif isinstance(obj, list):
            # Store lists as a comma-separated string — simple and KQL-parseable
            flat[prefix.rstrip("_")] = ", ".join(str(x) for x in obj)
        else:
            flat[prefix.rstrip("_")] = obj

    _walk(alert, "", 0)
    return flat
