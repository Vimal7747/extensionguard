# virustotal_lookup.py - VirusTotal v3 file-hash lookup for Stage 1d
#
# Why VirusTotal in addition to OSV?
#   OSV (Open Source Vulnerabilities) focuses on package-level CVEs - npm,
#   PyPI, etc. It doesn't index Chrome extension CRX file hashes.
#   VirusTotal is a multi-engine malware aggregator that DOES have CRX hash
#   coverage and gives us cross-AV verdicts.
#
# How it fits in:
#   osv_lookup.run_osv_checks() returns a SHA-256 of the ZIP/CRX.
#   The Stage 1d orchestrator (main.py) passes that hash here to also query VT.
#   The two scores are merged into the composite Stage 1 risk.
#
# Auth model:
#   VirusTotal requires an API key. Free tier: 4 req/min, 500/day.
#   - Read from VT_API_KEY env var (preferred - never written to disk)
#   - Or from extguard.conf.json under `virustotal.api_key` (for batch runs)
#
# All HTTP goes through adapters.http_retry.post_with_retry... actually no:
#   VirusTotal uses GET for hash lookups, not POST. We use requests.get
#   directly with the same timeout convention used elsewhere.
#
# Privacy note:
#   Submitting a hash to VT does NOT upload the file - just the SHA-256.
#   But VT DOES log the lookups, so doing this against confidential
#   internal extensions reveals their existence. Set VT_DISABLED=1 to opt out.

import os

import requests

from logging_setup import get_logger

log = get_logger(__name__)


# VirusTotal v3 file endpoint - GET with the SHA-256 in the URL
VT_FILE_URL = "https://www.virustotal.com/api/v3/files/{sha256}"

# Default timeout - VT is generally fast (<2s) for cached hashes
REQUEST_TIMEOUT = 8  # seconds


def lookup_hash(sha256_hex: str, cfg: dict | None = None) -> dict:
    """
    Query VirusTotal for the file matching `sha256_hex`.

    Args:
        sha256_hex: Lowercase hex SHA-256 of the CRX / ZIP bytes
        cfg: Optional config dict (the "virustotal" block from extguard.conf.json)
             Used to read `api_key` if VT_API_KEY env var isn't set.

    Returns a result dict with stable keys:
      {
        "ok":          bool,           # True if we got a response (even "not found")
        "found":       bool,           # True if VT has this hash
        "malicious":   int,            # number of AV engines that flagged it
        "suspicious":  int,            # number of "suspicious" verdicts
        "harmless":    int,            # number of "clean" verdicts
        "undetected":  int,            # number of engines that didn't return a result
        "total":       int,            # total engines that scanned it
        "permalink":   str or None,    # URL to the VT report
        "score":       int,            # 0-30 risk contribution
        "flags":       list[str],
        "error":       str or None,    # populated only when ok=False
      }
    """
    cfg = cfg or {}
    result = {
        "ok": False,
        "found": False,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "total": 0,
        "permalink": None,
        "score": 0,
        "flags": [],
        "error": None,
    }

    # Opt-out toggle - some teams can't legally send hashes to VT
    if os.environ.get("VT_DISABLED") == "1":
        result["ok"] = True
        result["error"] = "VT_DISABLED=1 environment variable set"
        return result

    api_key = os.environ.get("VT_API_KEY") or cfg.get("api_key")
    if not api_key or _is_placeholder(api_key):
        # No usable key. Treat as "skipped successfully" so the caller can
        # decide whether to surface this to the user.
        result["ok"] = True
        result["error"] = "No VT_API_KEY set (env or config)"
        return result

    if not _looks_like_sha256(sha256_hex):
        result["error"] = f"Invalid SHA-256: {sha256_hex!r}"
        return result

    url = VT_FILE_URL.format(sha256=sha256_hex.lower())
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }

    try:
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.Timeout:
        log.warning("VirusTotal request timed out")
        result["error"] = "Request timed out"
        return result
    except requests.exceptions.ConnectionError as exc:
        log.warning("VirusTotal connection error: %s", exc)
        result["error"] = f"Connection error: {exc}"
        return result

    if resp.status_code == 404:
        # Hash not in VT's database - that's a valid "not found", not an error
        result["ok"] = True
        result["found"] = False
        log.debug("VirusTotal: hash %s not found", sha256_hex[:12])
        return result

    if resp.status_code == 401:
        result["error"] = "VirusTotal rejected the API key (HTTP 401)"
        log.warning(result["error"])
        return result

    if resp.status_code == 429:
        # Rate limit - the caller might want to retry, but we don't here
        # because VT free tier is so slow that a retry would just hit again
        result["error"] = "VirusTotal rate limit (HTTP 429) - try again later"
        log.warning(result["error"])
        return result

    if resp.status_code != 200:
        result["error"] = f"VirusTotal HTTP {resp.status_code}: {resp.text[:200]}"
        log.warning(result["error"])
        return result

    # 200 OK - parse the v3 response shape
    try:
        body = resp.json()
        attrs = body["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
    except (ValueError, KeyError) as exc:
        result["error"] = f"Unexpected VT response shape: {exc}"
        return result

    result["ok"] = True
    result["found"] = True
    result["malicious"] = stats.get("malicious", 0)
    result["suspicious"] = stats.get("suspicious", 0)
    result["harmless"] = stats.get("harmless", 0)
    result["undetected"] = stats.get("undetected", 0)
    result["total"] = sum(stats.values())
    result["permalink"] = f"https://www.virustotal.com/gui/file/{sha256_hex.lower()}"

    # Score contribution: scaled to a 0-30 contribution to match the OSV
    # adapter's ceiling. Reasoning:
    #   - 0 malicious: 0 points
    #   - 1-2 malicious: 10 points (single-engine FPs happen; not conclusive)
    #   - 3-10 malicious: 20 points (multi-engine consensus, very likely real)
    #   - 11+ malicious: 30 points (overwhelming consensus, treat as confirmed)
    m = result["malicious"]
    if m >= 11:
        result["score"] = 30
        result["flags"].append(
            f"VirusTotal: {m}/{result['total']} engines flagged this hash - CONFIRMED MALICIOUS"
        )
    elif m >= 3:
        result["score"] = 20
        result["flags"].append(
            f"VirusTotal: {m}/{result['total']} engines flagged this hash - likely malicious"
        )
    elif m >= 1:
        result["score"] = 10
        result["flags"].append(
            f"VirusTotal: {m}/{result['total']} engines flagged this hash - "
            f"possible false positive but worth investigating"
        )
    # m == 0: no points, no flag

    # Suspicious adds half-weight
    if result["suspicious"] >= 3:
        bonus = min(10, result["suspicious"] * 2)
        result["score"] = min(30, result["score"] + bonus)
        result["flags"].append(f"VirusTotal: {result['suspicious']} engines flagged as suspicious")

    log.info(
        "VirusTotal lookup: hash=%s mal=%d susp=%d total=%d score=+%d",
        sha256_hex[:12],
        result["malicious"],
        result["suspicious"],
        result["total"],
        result["score"],
    )
    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _looks_like_sha256(s: str) -> bool:
    """A SHA-256 hex digest is exactly 64 lowercase hex chars."""
    if not isinstance(s, str) or len(s) != 64:
        return False
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def _is_placeholder(value: str) -> bool:
    """Match the same placeholder convention used in extguard.conf.json."""
    if not isinstance(value, str):
        return False
    if "YOUR" in value and ("HERE" in value or "API" in value.upper()):
        return True
    if value in ("", "YOUR-VT-API-KEY-HERE"):
        return True
    return False
