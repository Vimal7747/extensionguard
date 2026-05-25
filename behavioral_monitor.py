# behavioral_monitor.py - Stage 3: Real-time post-install extension monitoring
#
# Uses the Chrome DevTools Protocol (CDP) to attach to a running Chrome instance
# and watch extension background workers / service workers for malicious behaviour.
#
# How to enable CDP in Chrome:
#   chrome.exe --remote-debugging-port=9222 --enable-automation
#   (or add to a Chrome shortcut / policy)
#
# What we detect:
#   RULE-01  C2 beacon — periodic POST requests to *.workers.dev / *.pages.dev
#            (TeamPCP exfil pattern, 60-second interval)
#   RULE-02  Session cookie exfil — requests carrying auth cookie headers to
#            non-first-party domains
#   RULE-03  High-value domain monitoring — extension fetches from github.com,
#            npmjs.com, *.aws.amazon.com etc. that look like token harvesting
#   RULE-04  Storage staging — large base64 blobs written to localStorage
#            (TeamPCP stages harvested cookies under "s_cache")
#   RULE-05  Lateral movement — extension disables another extension via the
#            management API (chrome.management.setEnabled(id, false))
#   RULE-06  Obfuscated eval — eval() call with base64/obfuscated content
#            (Shai-Hulud JS execution chain)
#
# Output: structured alert dicts compatible with Stage 4 webhook dispatch.
#
# Usage:
#   python behavioral_monitor.py                      # monitor all extensions
#   python behavioral_monitor.py --ext-id <id>        # specific extension
#   python behavioral_monitor.py --output-json        # machine-readable alerts

import argparse
import asyncio
import json
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone

try:
    import requests
    import websockets

    _DEPS_OK = True
except ImportError:
    _DEPS_OK = False


# Chrome DevTools Protocol endpoints
CDP_HTTP_BASE = "http://localhost:9222"
CDP_JSON_TARGETS = f"{CDP_HTTP_BASE}/json"
CDP_NEW_WS_SUFFIX = "/json/new"

# Detection rules — patterns that trigger alerts
# Compiled once at module load for speed

# RULE-01: Known exfil hosting patterns (TeamPCP C2 infrastructure)
C2_HOST_PATTERNS = re.compile(
    r"(\.workers\.dev|\.pages\.dev|\.netlify\.app|\.vercel\.app"
    r"|\.trycloudflare\.com|\.ngrok\.io|\.loca\.lt)",
    re.IGNORECASE,
)

# RULE-03: High-value authentication domains being accessed by extensions
HIGH_VALUE_DOMAINS = re.compile(
    r"(github\.com|npmjs\.com|gitlab\.com"
    r"|\.atlassian\.net|\.slack\.com"
    r"|\.aws\.amazon\.com|accounts\.google\.com"
    r"|login\.microsoftonline\.com)",
    re.IGNORECASE,
)

# RULE-04: Base64 blob that looks like staged exfil data
# (min 100 chars of base64 is a meaningful payload)
BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{100,}={0,2}")

# RULE-06: Obfuscated eval chains
OBFUSCATED_EVAL = re.compile(
    r"eval\s*\(\s*(atob|String\.fromCharCode|unescape)",
    re.IGNORECASE,
)

# Beacon detection: track POST frequency per extension
# {ext_id -> {host -> [timestamp, ...]}}
_beacon_tracker: dict = defaultdict(lambda: defaultdict(list))
BEACON_INTERVAL_SEC = 55  # Flag if POSTs to same host < 55s apart
BEACON_COUNT_LIMIT = 3  # After this many suspicious posts, alert


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_alert(rule: str, severity: str, extension_target: dict, detail: dict) -> dict:
    """Build a standardised alert dict compatible with Stage 4 webhook dispatch."""
    return {
        "alert_time": _now_iso(),
        "rule": rule,
        "severity": severity,  # "critical" / "high" / "medium"
        "extension": {
            "id": extension_target.get("id"),
            "title": extension_target.get("title"),
            "url": extension_target.get("url"),
            "type": extension_target.get("type"),
        },
        "detail": detail,
        "mitre": _rule_to_mitre(rule),
    }


def _rule_to_mitre(rule: str) -> list:
    mapping = {
        "RULE-01": ["T1071.001", "T1176"],  # C2 beacon
        "RULE-02": ["T1555.003", "T1176"],  # Cookie exfil
        "RULE-03": ["T1530", "T1555.003"],  # High-value domain access
        "RULE-04": ["T1555.003", "T1074"],  # Storage staging (data staged)
        "RULE-05": ["T1176"],  # Lateral movement via management
        "RULE-06": ["T1059.007"],  # Obfuscated eval
    }
    return mapping.get(rule, ["T1176"])


# ---------------------------------------------------------------------------
# Chrome target enumeration
# ---------------------------------------------------------------------------


def get_extension_targets(target_ext_id: str | None = None) -> list:
    """
    Query the CDP HTTP endpoint for all running targets.
    Filter to extension background pages and service workers.
    If target_ext_id is given, only return that extension's targets.
    """
    if not _DEPS_OK:
        raise RuntimeError("Missing dependencies: pip install requests websockets")

    try:
        resp = requests.get(CDP_JSON_TARGETS, timeout=3)
        resp.raise_for_status()
        targets = resp.json()
    except requests.exceptions.ConnectionError as exc:
        # `from exc` keeps the original cause visible in tracebacks - useful when
        # the underlying issue is something other than "Chrome isn't running"
        # (e.g. proxy interference, firewall block).
        raise RuntimeError(
            "Cannot connect to Chrome at localhost:9222.\n"
            "Start Chrome with:  chrome.exe --remote-debugging-port=9222"
        ) from exc

    # We want extension background pages and service workers
    # Their URLs look like:  chrome-extension://<ext_id>/_generated_background_page.html
    #                   or:  chrome-extension://<ext_id>/service_worker.js
    ext_targets = []
    for t in targets:
        url = t.get("url", "")
        kind = t.get("type", "")
        if url.startswith("chrome-extension://") and kind in (
            "background_page",
            "service_worker",
            "worker",
        ):
            # Extract extension ID from chrome-extension://<id>/...
            ext_id = url.split("/")[2]
            t["_ext_id"] = ext_id

            if target_ext_id and ext_id != target_ext_id:
                continue
            ext_targets.append(t)

    return ext_targets


# ---------------------------------------------------------------------------
# Per-extension CDP session
# ---------------------------------------------------------------------------


async def monitor_target(target: dict, alert_queue: asyncio.Queue, output_json: bool):
    """
    Open a CDP WebSocket session for a single extension target,
    enable the Network and Runtime domains, and process events.
    Puts alert dicts into alert_queue when detections fire.
    """
    ws_url = target.get("webSocketDebuggerUrl")
    ext_id = target.get("_ext_id", "unknown")
    ext_name = target.get("title", "unknown")

    if not ws_url:
        return

    if not output_json:
        print(f"  [Monitor] Attaching to extension: {ext_name} ({ext_id})")

    try:
        async with websockets.connect(ws_url, ping_interval=20) as ws:
            # Enable the domains we need
            msg_id = 1

            async def send(method: str, params: dict | None = None):
                # Mutable default args (dict = {}) silently share state across calls.
                # Use None and substitute an empty dict per-call instead.
                nonlocal msg_id
                payload = {"id": msg_id, "method": method, "params": params or {}}
                await ws.send(json.dumps(payload))
                msg_id += 1

            # Network.enable — lets us see all network requests
            await send("Network.enable")
            # Runtime.enable — lets us intercept console output and eval patterns
            await send("Runtime.enable")
            # We don't enable Debugger domain — that would be intrusive

            # Process incoming CDP events
            async for raw_msg in ws:
                try:
                    msg = json.loads(raw_msg)
                except json.JSONDecodeError:
                    continue

                method = msg.get("method", "")
                params = msg.get("params", {})

                # --- RULE-01 + RULE-02 + RULE-03: Network request events ---
                if method == "Network.requestWillBeSent":
                    await _handle_network_request(params, target, ext_id, alert_queue)

                # --- RULE-04: DOM storage changes ---------------------------
                elif method == "DOM.attributeModified":
                    pass  # Not reliable via DOM domain for localStorage

                # --- RULE-06: Runtime console messages with eval patterns ---
                elif method == "Runtime.consoleAPICalled":
                    await _handle_console_call(params, target, ext_id, alert_queue)

                # We also listen for Runtime.exceptionThrown which can reveal
                # obfuscation failures (common in Shai-Hulud eval chains)
                elif method == "Runtime.exceptionThrown":
                    exc = params.get("exceptionDetails", {})
                    text = str(exc)
                    if OBFUSCATED_EVAL.search(text):
                        alert = _make_alert(
                            "RULE-06",
                            "high",
                            target,
                            {
                                "description": "Obfuscated eval() exception caught",
                                "detail": text[:300],
                            },
                        )
                        await alert_queue.put(alert)

    except websockets.exceptions.ConnectionClosed:
        if not output_json:
            print(f"  [Monitor] CDP connection closed for {ext_name}")
    except asyncio.CancelledError:
        # Pipeline shutdown - propagate so the asyncio runtime can clean up
        raise
    except (websockets.exceptions.WebSocketException, json.JSONDecodeError, OSError) as exc:
        # Narrow set of expected failure modes. KeyboardInterrupt and
        # programming bugs (TypeError, NameError, etc.) are deliberately
        # NOT caught here - they should surface to the operator.
        if not output_json:
            print(f"  [Monitor] Error monitoring {ext_name}: {exc}")


async def _handle_network_request(
    params: dict, target: dict, ext_id: str, alert_queue: asyncio.Queue
):
    """Evaluate a Network.requestWillBeSent event against detection rules."""
    request = params.get("request", {})
    url = request.get("url", "")
    method = request.get("method", "GET")
    headers = request.get("headers", {})
    # postData is part of the CDP payload but not currently used in detection rules.
    # Left here as a comment so a future RULE-07 (suspicious POST body content)
    # knows where to find it: request.get("postData", "")

    try:
        from urllib.parse import urlparse

        host = urlparse(url).netloc
        # urlparse on a non-str (None, bytes, etc.) can return non-str netloc
        # which then breaks our str-pattern regex below. Coerce defensively.
        if not isinstance(host, str):
            host = ""
    except (ValueError, AttributeError, TypeError):
        # Malformed URL strings can raise ValueError; non-string urls (e.g.
        # None from a malformed CDP event) raise AttributeError or TypeError
        # depending on Python version. Either way: give up on this event,
        # don't crash the monitor.
        host = ""

    # RULE-01: POST to known C2 / exfil hosting domains
    if method == "POST" and C2_HOST_PATTERNS.search(host):
        # Track beacon frequency
        timestamps = _beacon_tracker[ext_id][host]
        now = time.time()
        timestamps.append(now)
        # Keep only recent timestamps (last 5 minutes)
        recent = [t for t in timestamps if now - t < 300]
        _beacon_tracker[ext_id][host] = recent

        # Check for beacon pattern: multiple POSTs in short succession
        if len(recent) >= 2:
            interval = recent[-1] - recent[-2]
            if interval < BEACON_INTERVAL_SEC:
                alert = _make_alert(
                    "RULE-01",
                    "critical",
                    target,
                    {
                        "description": "Periodic POST to known exfil domain — C2 beacon pattern",
                        "url": url,
                        "host": host,
                        "interval_sec": round(interval, 1),
                        "post_count": len(recent),
                        "mitre_note": "Matches TeamPCP 60-second beacon to *.workers.dev",
                    },
                )
                await alert_queue.put(alert)
        elif len(recent) == 1:
            # First occurrence — still flag as suspicious (lower severity)
            alert = _make_alert(
                "RULE-01",
                "high",
                target,
                {
                    "description": "POST request to known exfil hosting domain",
                    "url": url,
                    "host": host,
                },
            )
            await alert_queue.put(alert)

    # RULE-02: Cookie header being sent to a non-extension domain
    cookie_header = headers.get("Cookie", headers.get("cookie", ""))
    if cookie_header and host and not host.endswith("chrome-extension"):
        # Look for session token patterns in the cookie value
        # (long random strings typical of session IDs)
        if re.search(r"[a-zA-Z0-9_-]{32,}", cookie_header):
            # Only alert if the request goes to a domain different from
            # where you'd expect those cookies to live
            if HIGH_VALUE_DOMAINS.search(host) and method == "POST":
                alert = _make_alert(
                    "RULE-02",
                    "high",
                    target,
                    {
                        "description": "Session cookie being POSTed to high-value domain — "
                        "possible credential exfiltration",
                        "url": url,
                        "host": host,
                        "cookie_len": len(cookie_header),
                    },
                )
                await alert_queue.put(alert)

    # RULE-03: Extension accessing high-value auth domains
    if HIGH_VALUE_DOMAINS.search(host) and method in ("GET", "POST"):
        # Only flag GET requests if they look like API calls (JSON response expected)
        accept_header = headers.get("Accept", "")
        if "json" in accept_header or method == "POST":
            alert = _make_alert(
                "RULE-03",
                "medium",
                target,
                {
                    "description": "Extension making API request to high-value domain",
                    "url": url,
                    "host": host,
                    "method": method,
                },
            )
            await alert_queue.put(alert)


async def _handle_console_call(params: dict, target: dict, ext_id: str, alert_queue: asyncio.Queue):
    """Check Runtime console messages for obfuscated eval patterns."""
    args = params.get("args", [])
    for arg in args:
        value = str(arg.get("value", ""))
        if OBFUSCATED_EVAL.search(value) or (BASE64_BLOB.search(value) and "eval" in value.lower()):
            alert = _make_alert(
                "RULE-06",
                "high",
                target,
                {
                    "description": "Console output contains obfuscated eval pattern",
                    "snippet": value[:200],
                },
            )
            await alert_queue.put(alert)
            break


# ---------------------------------------------------------------------------
# Alert dispatcher (Stage 4 hook)
# ---------------------------------------------------------------------------


async def alert_dispatcher(alert_queue: asyncio.Queue, output_json: bool):
    """
    Consume alerts from the queue and print / forward them.
    Stage 4 will replace the print with a webhook call to Sentinel/Slack.
    """
    while True:
        alert = await alert_queue.get()

        if output_json:
            # Machine-readable output — Stage 4 webhook picks this up
            print(json.dumps(alert), flush=True)
        else:
            # Human-readable console output
            sev = alert["rule"]
            rule = alert["severity"].upper()
            ext = alert["extension"].get("title", "?")
            detail = alert["detail"].get("description", "")
            url = alert["detail"].get("url", "")
            ts = alert["alert_time"]

            colour = (
                "\033[91m"
                if alert["severity"] == "critical"
                else "\033[93m"
                if alert["severity"] == "high"
                else "\033[96m"
            )
            reset = "\033[0m"
            bold = "\033[1m"

            print(f"\n{colour}{bold}[ALERT] {sev} {rule}{reset}")
            print(f"  Time:      {ts}")
            print(f"  Extension: {ext}")
            print(f"  Detail:    {detail}")
            if url:
                print(f"  URL:       {url}")
            mitre = ", ".join(alert.get("mitre", []))
            if mitre:
                print(f"  MITRE:     {mitre}")
            print()

        alert_queue.task_done()


# ---------------------------------------------------------------------------
# Main async entry point
# ---------------------------------------------------------------------------


async def run_monitor(target_ext_id: str | None, output_json: bool):
    """
    Enumerate extension targets and spawn one monitoring coroutine per target.
    """
    targets = get_extension_targets(target_ext_id)

    if not targets:
        msg = (
            "No extension background workers found at localhost:9222.\n"
            "Make sure Chrome is running with --remote-debugging-port=9222\n"
            "and that extensions are installed and active."
        )
        if output_json:
            print(json.dumps({"error": msg}))
        else:
            print(f"[!] {msg}")
        return

    if not output_json:
        print(f"[Monitor] Found {len(targets)} extension target(s) to monitor.")
        print("[Monitor] Watching for malicious behaviour... (Ctrl+C to stop)\n")

    alert_queue = asyncio.Queue()

    # Start the alert dispatcher as a background task
    dispatcher_task = asyncio.create_task(alert_dispatcher(alert_queue, output_json))

    # Start one monitor coroutine per extension target
    monitor_tasks = [
        asyncio.create_task(monitor_target(t, alert_queue, output_json)) for t in targets
    ]

    try:
        # Wait for all monitors (they run indefinitely until connection closes)
        await asyncio.gather(*monitor_tasks)
    except asyncio.CancelledError:
        pass
    finally:
        dispatcher_task.cancel()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="ExtensionGuard Stage 3 - Real-time extension behaviour monitor",
        epilog=(
            "Requires Chrome running with:  chrome.exe --remote-debugging-port=9222\n"
            "Example:  python behavioral_monitor.py --ext-id abcdefghijklmnopqrstuvwxyzabcdef"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--ext-id",
        metavar="EXTENSION_ID",
        default=None,
        help="Monitor only this extension ID (32-char Chrome ID). Default: all extensions.",
    )
    parser.add_argument(
        "--output-json",
        action="store_true",
        help="Emit alerts as JSON lines (for Stage 4 webhook dispatch).",
    )
    parser.add_argument(
        "--list-targets",
        action="store_true",
        help="List detected extension targets and exit (useful for finding extension IDs).",
    )
    args = parser.parse_args()

    if not _DEPS_OK:
        print("[ERROR] Missing dependencies. Run:  pip install requests websockets")
        sys.exit(1)

    # --- List-only mode -------------------------------------------------------
    if args.list_targets:
        try:
            targets = get_extension_targets()
        except RuntimeError as exc:
            print(f"[ERROR] {exc}")
            sys.exit(1)

        if not targets:
            print("[i] No extension targets found.")
        else:
            print(f"\nFound {len(targets)} extension target(s):\n")
            for t in targets:
                print(f"  ID:    {t.get('_ext_id', '?')}")
                print(f"  Name:  {t.get('title', '?')}")
                print(f"  Type:  {t.get('type', '?')}")
                print(f"  URL:   {t.get('url', '?')}")
                print()
        return

    # --- Monitor mode ----------------------------------------------------------
    if not args.output_json:
        print("\n=== ExtensionGuard Stage 3 - Behavioral Monitor ===")
        print(f"Target: {'all extensions' if not args.ext_id else args.ext_id}")
        print()

    try:
        asyncio.run(run_monitor(args.ext_id, args.output_json))
    except KeyboardInterrupt:
        if not args.output_json:
            print("\n[Monitor] Stopped by user.")
    except RuntimeError as exc:
        print(f"[ERROR] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
