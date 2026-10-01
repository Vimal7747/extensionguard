# behavioral_monitor.py - Stage 3: Real-time extension behaviour monitoring
#
# Uses the Chrome DevTools Protocol (CDP) to watch what extensions DO at
# runtime - in their background service workers / pages AND in the content
# scripts they inject into websites.
#
# How to run it safely:
#   Start a SEPARATE Chrome instance with its own profile, e.g.
#     chrome.exe --user-data-dir=C:\extguard-sandbox --remote-debugging-port=9222
#   Chrome 136+ refuses remote debugging on your default profile (a defence
#   against cookie theft over this very protocol), and exposing port 9222 on
#   your everyday browser would hand every local process your sessions. Use it
#   as a detonation sandbox: install / load the extension under test there.
#   (Chrome for Testing and Chromium still accept --load-extension=<dir>.)
#
# How it attaches:
#   One browser-level connection. Target.setDiscoverTargets + a flattened
#   Target.setAutoAttach with waitForDebuggerOnStart, so every NEW extension
#   service worker is paused until our hooks are in place, and workers that
#   restart (MV3 workers stop after ~30 s idle) are picked up again. The
#   monitor keeps running when no extension is active and reconnects if
#   Chrome restarts.
#
# What we detect:
#   RULE-01  C2 beacon - POSTs to exfil-style hosting (*.workers.dev ...)
#            at a regular interval (TeamPCP: every 60 s)
#   RULE-02  Credential exfiltration - tokens, session cookies, cookie dumps or
#            JWTs in a request body / URL / Authorization header, sent to a
#            host that is not the credential's own service
#   RULE-03  High-value site access - API calls to github.com, npm, AWS...
#            (high when authenticated and state-changing = session riding)
#   RULE-04  Storage staging - large base64 blobs or credential material
#            written to chrome.storage / localStorage
#   RULE-05  Lateral movement - chrome.management.setEnabled(id, false) /
#            uninstall() against another extension
#   RULE-06  Dynamic / obfuscated code - eval / new Function / obfuscated
#            scripts executed in an extension context
#   RULE-07  Cookie harvesting - chrome.cookies.getAll bulk reads, content
#            scripts reading document.cookie on high-value sites
#
# RULE-04/05/07 come from small hooks installed into each extension context
# (Runtime.evaluate). They report through a CDP binding whose name and
# per-session token are random, so a web page cannot forge alerts. Malware
# that inspects its own environment could spot or undo the hooks - treat
# their silence as "no evidence", not as proof of innocence.
#
# Output: structured alert dicts compatible with Stage 4 (extguard-dispatch).
#
# Usage:
#   extguard-monitor                      # monitor all extensions
#   extguard-monitor --ext-id <id>        # one extension
#   extguard-monitor --output-json        # JSON lines for extguard-dispatch
#   extguard-monitor --list-targets       # what is running right now
#   extguard-monitor --snapshot-storage <id> --out storage.json

import argparse
import asyncio
import itertools
import json
import re
import secrets
import statistics
import sys
import time
from collections import OrderedDict, defaultdict
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    import requests
    import websockets

    _DEPS_OK = True
except ImportError:
    _DEPS_OK = False


# Chrome DevTools Protocol endpoints (overridden by --host / --port)
CDP_HTTP_BASE = "http://localhost:9222"
CDP_JSON_TARGETS = f"{CDP_HTTP_BASE}/json"

# ---------------------------------------------------------------------------
# Detection patterns - compiled once. Host patterns are ANCHORED so that
# "github.com.attacker.net" or "notgithub.com" don't match.
# ---------------------------------------------------------------------------

# RULE-01: exfil-style hosting (TeamPCP C2 infrastructure and friends)
C2_HOST_PATTERNS = re.compile(
    r"\.(workers\.dev|pages\.dev|netlify\.app|vercel\.app|trycloudflare\.com"
    r"|ngrok\.io|ngrok-free\.app|loca\.lt|glitch\.me|repl\.co)$",
    re.IGNORECASE,
)

# RULE-03: high-value authentication / developer domains (domain or subdomain)
HIGH_VALUE_DOMAINS = re.compile(
    r"(^|\.)(github\.com|npmjs\.com|npmjs\.org|gitlab\.com|atlassian\.net"
    r"|slack\.com|aws\.amazon\.com|accounts\.google\.com|login\.microsoftonline\.com)$",
    re.IGNORECASE,
)

# RULE-04: base64 blob that looks like staged exfil data
BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{100,}={0,2}")

# RULE-06: obfuscated eval chains
OBFUSCATED_EVAL = re.compile(
    r"eval\s*\(\s*(atob|String\.fromCharCode|unescape)",
    re.IGNORECASE,
)
_OBFUSCATION_MARKERS = re.compile(r"\b_0x[0-9a-f]{4,6}\b|(?:\\x[0-9a-fA-F]{2}){8,}")

# RULE-02 / RULE-04: credential material, and the service each one belongs to
# (a credential sent to its own service is normal; anywhere else is exfil)
CREDENTIAL_PATTERNS = {
    "GitHub token": (
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})"),
        ("github.com", "githubusercontent.com"),
    ),
    "npm token": (re.compile(r"\bnpm_[A-Za-z0-9]{30,}"), ("npmjs.org", "npmjs.com")),
    "AWS access key": (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), ("amazonaws.com",)),
    "Slack token": (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), ("slack.com",)),
    "JWT": (
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}"),
        (),
    ),
    "session cookie": (
        re.compile(
            r"\b(?:user_session|_gh_sess|__Secure-\w*PSID\w*|SAPISID|sessionid|connect\.sid"
            r"|JSESSIONID|laravel_session|_session_id)=[^;\s&\"]{16,}"
        ),
        (),
    ),
    # The object shape chrome.cookies.getAll() returns - a dumped cookie jar
    "browser cookie dump": (
        re.compile(r"\"(?:hostOnly|storeId|sameSite)\"\s*:.{0,400}\"value\"\s*:", re.DOTALL),
        (),
    ),
}

# Beacon detection: track POST times per extension and host
# {ext_id -> {host -> [timestamp, ...]}}
#
# A C2 beacon is recognised by its REGULARITY, not its speed: malware checks
# in on a clock (TeamPCP: every 60 s). With at least BEACON_MIN_POSTS in the
# window, if the gaps between them vary by no more than BEACON_MAX_JITTER
# (standard deviation / mean), it is a beacon - whether the period is 5 s or 5 min.
_beacon_tracker: dict = defaultdict(lambda: defaultdict(list))
BEACON_WINDOW_SEC = 900  # remember POSTs for 15 minutes
BEACON_MIN_POSTS = 3  # 3 POSTs = 2 intervals = the minimum to judge regularity
BEACON_MAX_INTERVALS = 6  # judge regularity over the most recent 6 gaps
BEACON_MAX_JITTER = 0.25  # gaps within +/-25% of each other count as clockwork
BEACON_MAX_HOSTS_PER_EXT = 200  # memory bound

# RULE-03 fires at most once per (extension, host, method) in this window
RULE03_WINDOW_SEC = 600
_rule03_last: dict = {}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_alert(rule: str, severity: str, extension_target: dict, detail: dict) -> dict:
    """
    Build a standardised alert dict compatible with Stage 4 webhook dispatch.
    extension.id is the 32-letter EXTENSION ID (what dedup, PagerDuty keys and
    remediation need) - the CDP target id is kept separately as target_id.
    """
    return {
        "alert_time": _now_iso(),
        "rule": rule,
        "severity": severity,  # "critical" / "high" / "medium"
        "extension": {
            "id": extension_target.get("_ext_id") or extension_target.get("id"),
            "title": extension_target.get("title"),
            "url": extension_target.get("url"),
            "type": extension_target.get("type"),
            "target_id": extension_target.get("id"),
            "context": extension_target.get("_context", "extension"),
        },
        "detail": detail,
        "mitre": _rule_to_mitre(rule),
    }


def _rule_to_mitre(rule: str) -> list:
    mapping = {
        "RULE-01": ["T1071.001", "T1176"],  # C2 beacon
        "RULE-02": ["T1555.003", "T1041", "T1176"],  # Credential exfil over C2
        "RULE-03": ["T1530", "T1185"],  # High-value access / session riding
        "RULE-04": ["T1555.003", "T1074"],  # Storage staging (data staged)
        "RULE-05": ["T1176", "T1562.001"],  # Disable other extensions (impair defences)
        "RULE-06": ["T1059.007", "T1027"],  # Dynamic / obfuscated JavaScript
        "RULE-07": ["T1539", "T1555.003"],  # Steal web session cookies
    }
    return mapping.get(rule, ["T1176"])


def _host_of(url) -> str:
    """Hostname of a URL, or "" for anything malformed (never raises)."""
    try:
        host = urlparse(url).hostname
    except (ValueError, AttributeError, TypeError):
        return ""
    return host if isinstance(host, str) else ""


def _host_in(host: str, domains) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def find_credentials(text: str, destination_host: str) -> list:
    """
    Names of credential types in `text` that do NOT belong to
    `destination_host` (sending a GitHub token to github.com is normal).
    """
    found = []
    if not text:
        return found
    for name, (regex, home_domains) in CREDENTIAL_PATTERNS.items():
        if regex.search(text) and not (home_domains and _host_in(destination_host, home_domains)):
            found.append(name)
    return found


# ---------------------------------------------------------------------------
# Chrome target enumeration (HTTP endpoint - used by --list-targets)
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
        raise RuntimeError(
            f"Cannot connect to Chrome at {CDP_HTTP_BASE.split('//')[1]}.\n"
            "Start a separate Chrome with:  "
            "chrome.exe --user-data-dir=<sandbox dir> --remote-debugging-port=9222"
        ) from exc

    ext_targets = []
    for t in targets:
        url = t.get("url", "")
        kind = t.get("type", "")
        if url.startswith("chrome-extension://") and kind in (
            "background_page",
            "service_worker",
            "worker",
        ):
            ext_id = url.split("/")[2]
            t["_ext_id"] = ext_id
            if target_ext_id and ext_id != target_ext_id:
                continue
            ext_targets.append(t)

    return ext_targets


def get_browser_ws_url() -> str:
    """The browser-level DevTools websocket URL (from /json/version)."""
    try:
        resp = requests.get(f"{CDP_HTTP_BASE}/json/version", timeout=3)
        resp.raise_for_status()
        return resp.json()["webSocketDebuggerUrl"]
    except (requests.exceptions.RequestException, KeyError, ValueError) as exc:
        raise RuntimeError(
            f"Cannot reach Chrome's DevTools endpoint at {CDP_HTTP_BASE}: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Rule handlers - pure logic on CDP event payloads (unit-testable)
# ---------------------------------------------------------------------------


async def _handle_network_request(
    params: dict, target: dict, ext_id: str, alert_queue: asyncio.Queue
):
    """Evaluate a Network.requestWillBeSent event against RULE-01/02/03."""
    request = params.get("request") or {}
    url = request.get("url", "")
    method = request.get("method", "GET")
    headers = request.get("headers") or {}
    host = _host_of(url)
    if not host:
        return

    # RULE-01: POST to exfil-style hosting, and beacon timing
    if method == "POST" and C2_HOST_PATTERNS.search(host):
        now = time.time()
        hosts = _beacon_tracker[ext_id]
        recent = [t for t in hosts[host] if now - t < BEACON_WINDOW_SEC]
        recent.append(now)
        hosts[host] = recent
        _prune_beacon_tracker(ext_id, now)

        if len(recent) == 1:
            await alert_queue.put(
                _make_alert(
                    "RULE-01",
                    "high",
                    target,
                    {
                        "description": "POST request to exfil-style hosting",
                        "url": url,
                        "host": host,
                    },
                )
            )
        else:
            beacon = _beacon_pattern(recent)
            if beacon:
                await alert_queue.put(
                    _make_alert(
                        "RULE-01",
                        "critical",
                        target,
                        {
                            "description": "POSTs to exfil-style hosting at a regular interval "
                            "— C2 beacon pattern",
                            "url": url,
                            "host": host,
                            "interval_sec": beacon["interval_sec"],
                            "jitter": beacon["jitter"],
                            "post_count": len(recent),
                            "mitre_note": "TeamPCP beacons every 60 s to *.workers.dev",
                        },
                    )
                )

    # RULE-02: credential material leaving for a host it doesn't belong to
    body = request.get("postData") or ""
    auth = headers.get("Authorization") or headers.get("authorization") or ""
    carried = find_credentials(body, host) + find_credentials(url, host)
    carried += [f"{c} (Authorization header)" for c in find_credentials(auth, host)]
    if carried:
        severity = "critical" if C2_HOST_PATTERNS.search(host) else "high"
        await alert_queue.put(
            _make_alert(
                "RULE-02",
                severity,
                target,
                {
                    "description": "Credential material sent to a third-party host - "
                    "possible session / token exfiltration",
                    "url": url,
                    "host": host,
                    "method": method,
                    "credentials": sorted(set(carried)),
                    "body_bytes": len(body),
                },
            )
        )

    # RULE-03: API-style request to a high-value site (rate-limited)
    if HIGH_VALUE_DOMAINS.search(host) and method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        accept = headers.get("Accept", "") or headers.get("accept", "")
        if "json" in accept or method != "GET":
            key = (ext_id, host, method)
            now = time.time()
            if now - _rule03_last.get(key, 0) >= RULE03_WINDOW_SEC:
                _rule03_last[key] = now
                await alert_queue.put(
                    _make_alert(
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
                )


async def _handle_authenticated_request(
    params: dict, extra: dict, target: dict, ext_id: str, alert_queue: asyncio.Queue
):
    """
    Network.requestWillBeSentExtraInfo carries the cookies Chrome actually
    attached. A state-changing request an extension makes to a high-value
    site WITH the user's session is session riding (T1185).
    """
    request = params.get("request") or {}
    host = _host_of(request.get("url", ""))
    method = request.get("method", "GET")
    cookies = [c for c in (extra.get("associatedCookies") or []) if not c.get("blockedReasons")]
    if cookies and method != "GET" and HIGH_VALUE_DOMAINS.search(host):
        await alert_queue.put(
            _make_alert(
                "RULE-03",
                "high",
                target,
                {
                    "description": "Extension made an AUTHENTICATED state-changing request "
                    "to a high-value site using the user's session (session riding)",
                    "url": request.get("url"),
                    "host": host,
                    "method": method,
                    "cookies_attached": len(cookies),
                },
            )
        )


async def _handle_console_call(params: dict, target: dict, ext_id: str, alert_queue: asyncio.Queue):
    """Check Runtime console messages for obfuscated eval patterns."""
    for arg in params.get("args", []) or []:
        value = str(arg.get("value", ""))
        if OBFUSCATED_EVAL.search(value) or (BASE64_BLOB.search(value) and "eval" in value.lower()):
            await alert_queue.put(
                _make_alert(
                    "RULE-06",
                    "high",
                    target,
                    {
                        "description": "Console output contains obfuscated eval pattern",
                        "snippet": value[:200],
                    },
                )
            )
            break


async def _handle_dynamic_script(source: str, target: dict, alert_queue: asyncio.Queue):
    """
    RULE-06: a script with no URL was compiled in an extension context -
    that is eval() / new Function(). MV3 extension pages and workers forbid
    this by CSP, so it is notable on its own and serious when obfuscated.
    """
    obfuscated = bool(
        OBFUSCATED_EVAL.search(source)
        or len(_OBFUSCATION_MARKERS.findall(source)) >= 10
        or BASE64_BLOB.search(source)
    )
    await alert_queue.put(
        _make_alert(
            "RULE-06",
            "high" if obfuscated else "medium",
            target,
            {
                "description": (
                    "Obfuscated code generated at runtime (eval / new Function)"
                    if obfuscated
                    else "Code generated at runtime (eval / new Function) in an extension context"
                ),
                "snippet": source[:300],
                "length": len(source),
            },
        )
    )


async def _handle_hook_event(event: dict, target: dict, ext_id: str, alert_queue: asyncio.Queue):
    """Turn a report from the in-context hooks into RULE-04 / 05 / 07 alerts."""
    kind = event.get("kind")
    data = event.get("data") or {}

    if kind in ("storage.set", "localStorage.setItem"):
        sample = str(data.get("sample", ""))
        size = int(data.get("size", 0) or 0)
        creds = find_credentials(sample, "")
        reasons = []
        if creds:
            reasons.append("credential material: " + ", ".join(creds))
        if BASE64_BLOB.search(sample):
            reasons.append("large base64 blob")
        if size >= 50_000:
            reasons.append(f"{size:,} bytes in one write")
        if reasons:
            await alert_queue.put(
                _make_alert(
                    "RULE-04",
                    "critical" if creds else "high",
                    target,
                    {
                        "description": "Data staged in extension storage - " + "; ".join(reasons),
                        "api": kind,
                        "area": data.get("area"),
                        "keys": data.get("keys", [])[:20],
                        "size": size,
                    },
                )
            )

    elif kind == "management.setEnabled" and data.get("enabled") is False:
        await alert_queue.put(
            _make_alert(
                "RULE-05",
                "critical",
                target,
                {
                    "description": "Extension DISABLED another extension "
                    "(chrome.management.setEnabled) - security tools are a typical target",
                    "victim_extension": data.get("id"),
                },
            )
        )

    elif kind == "management.uninstall":
        await alert_queue.put(
            _make_alert(
                "RULE-05",
                "critical",
                target,
                {
                    "description": "Extension tried to UNINSTALL another extension",
                    "victim_extension": data.get("id"),
                },
            )
        )

    elif kind == "cookies.getAll":
        count = int(data.get("count", 0) or 0)
        domains = [d for d in data.get("domains", []) if isinstance(d, str)]
        high_value = [d for d in domains if HIGH_VALUE_DOMAINS.search(d.lstrip("."))]
        details = str(data.get("details", ""))
        everything = details.strip() in ("{}", "", "null", "undefined")
        if everything or count >= 20 or high_value:
            await alert_queue.put(
                _make_alert(
                    "RULE-07",
                    "high",
                    target,
                    {
                        "description": "Bulk cookie read via chrome.cookies.getAll"
                        + (" - ALL cookies requested" if everything else ""),
                        "cookies_returned": count,
                        "high_value_domains": high_value[:10],
                        "filter": details[:200],
                    },
                )
            )

    elif kind == "document.cookie":
        host = str(data.get("host", "")).split(":")[0]
        if HIGH_VALUE_DOMAINS.search(host):
            await alert_queue.put(
                _make_alert(
                    "RULE-07",
                    "medium",
                    target,
                    {
                        "description": "Content script read document.cookie on a high-value site",
                        "host": host,
                        "cookie_bytes": data.get("size"),
                    },
                )
            )


def _beacon_pattern(timestamps: list) -> dict | None:
    """
    Decide whether a list of POST times looks like a clockwork beacon.

    Returns {"interval_sec", "jitter"} when there are at least BEACON_MIN_POSTS
    and the gaps between them are regular (jitter = standard deviation / mean
    of the gaps, at most BEACON_MAX_JITTER). Otherwise returns None.
    """
    if len(timestamps) < BEACON_MIN_POSTS:
        return None
    # Pair each POST with the next one; the lists differ in length by design
    pairs = zip(timestamps, timestamps[1:], strict=False)
    gaps = [b - a for a, b in pairs][-BEACON_MAX_INTERVALS:]
    mean = sum(gaps) / len(gaps)
    if mean <= 0:
        return None
    jitter = statistics.pstdev(gaps) / mean
    if jitter > BEACON_MAX_JITTER:
        return None
    return {"interval_sec": round(mean, 1), "jitter": round(jitter, 2)}


def _prune_beacon_tracker(ext_id: str, now: float):
    """Drop hosts with no recent POSTs so memory stays bounded on long runs."""
    hosts = _beacon_tracker[ext_id]
    for host in [h for h, ts in hosts.items() if not ts or now - ts[-1] >= BEACON_WINDOW_SEC]:
        del hosts[host]
    while len(hosts) > BEACON_MAX_HOSTS_PER_EXT:
        oldest = min(hosts, key=lambda h: hosts[h][-1])
        del hosts[oldest]


# ---------------------------------------------------------------------------
# In-context hooks (RULE-04 / 05 / 07)
# ---------------------------------------------------------------------------

# __BINDING__ and __TOKEN__ are replaced per session with random values. The
# hook reports via the binding; the Python side drops any report without the
# right token (a web page's main world can call a binding too).
HOOK_SCRIPT = r"""
(() => {
  const TOKEN = "__TOKEN__", BINDING = "__BINDING__", MARK = "__MARK__";
  if (globalThis[MARK]) return "already-installed";
  try { Object.defineProperty(globalThis, MARK, {value: true}); } catch (e) {}
  const report = (kind, data) => {
    try { globalThis[BINDING](JSON.stringify({token: TOKEN, kind, data})); } catch (e) {}
  };
  const text = (v) => {
    try { const s = typeof v === "string" ? v : JSON.stringify(v); return s == null ? "" : s; }
    catch (e) { return ""; }
  };
  const chromeApi = globalThis.chrome;

  // RULE-04: chrome.storage.{local,sync,session}.set
  try {
    for (const area of ["local", "sync", "session"]) {
      const sa = chromeApi && chromeApi.storage && chromeApi.storage[area];
      if (!sa || typeof sa.set !== "function") continue;
      const orig = sa.set;
      sa.set = function (items, ...rest) {
        const t = text(items);
        report("storage.set", {area, keys: Object.keys(items || {}).slice(0, 20),
                               size: t.length, sample: t.slice(0, 4000)});
        return orig.call(this, items, ...rest);
      };
    }
  } catch (e) {}

  // RULE-04: localStorage (MV2 background pages, extension pages)
  try {
    if (globalThis.Storage && Storage.prototype.setItem) {
      const orig = Storage.prototype.setItem;
      Storage.prototype.setItem = function (k, v) {
        const t = String(v);
        report("localStorage.setItem", {keys: [String(k)], size: t.length, sample: t.slice(0, 4000)});
        return orig.call(this, k, v);
      };
    }
  } catch (e) {}

  // RULE-05: chrome.management against other extensions
  try {
    const m = chromeApi && chromeApi.management;
    if (m && typeof m.setEnabled === "function") {
      const orig = m.setEnabled;
      m.setEnabled = function (id, enabled, ...rest) {
        report("management.setEnabled", {id: String(id), enabled: !!enabled});
        return orig.call(this, id, enabled, ...rest);
      };
    }
    if (m && typeof m.uninstall === "function") {
      const orig = m.uninstall;
      m.uninstall = function (id, ...rest) {
        report("management.uninstall", {id: String(id)});
        return orig.call(this, id, ...rest);
      };
    }
  } catch (e) {}

  // RULE-07: chrome.cookies.getAll (count what came back)
  try {
    const c = chromeApi && chromeApi.cookies;
    if (c && typeof c.getAll === "function") {
      const orig = c.getAll;
      c.getAll = function (details, cb) {
        const rep = (cookies) => {
          const list = Array.isArray(cookies) ? cookies : [];
          report("cookies.getAll", {details: text(details).slice(0, 300), count: list.length,
                  domains: [...new Set(list.map((x) => x && x.domain))].slice(0, 30)});
        };
        if (typeof cb === "function") {
          return orig.call(this, details, (res) => { rep(res); return cb(res); });
        }
        const p = orig.call(this, details);
        if (p && typeof p.then === "function") p.then(rep, () => {});
        return p;
      };
    }
  } catch (e) {}

  // RULE-07: document.cookie reads (content scripts, isolated world)
  try {
    if (globalThis.Document && globalThis.location) {
      const desc = Object.getOwnPropertyDescriptor(Document.prototype, "cookie");
      if (desc && desc.get && desc.set) {
        let last = 0;
        Object.defineProperty(Document.prototype, "cookie", {
          configurable: true, enumerable: desc.enumerable,
          get() {
            const v = desc.get.call(this);
            const now = Date.now();
            if (now - last > 10000) { last = now; report("document.cookie", {host: location.host, size: v.length}); }
            return v;
          },
          set(v) { return desc.set.call(this, v); },
        });
      }
    }
  } catch (e) {}
  return "installed";
})()
"""


def build_hook_script(binding: str, token: str, mark: str) -> str:
    return (
        HOOK_SCRIPT.replace("__BINDING__", binding)
        .replace("__TOKEN__", token)
        .replace("__MARK__", mark)
    )


# ---------------------------------------------------------------------------
# The browser-level monitor
# ---------------------------------------------------------------------------

EXTENSION_TARGET_TYPES = (
    "service_worker",
    "background_page",
    "worker",
    "shared_worker",
    "page",  # extension pages: popup, options, offscreen documents
    "iframe",  # extension UI injected into a web page
)
PAGE_TYPES = ("page", "iframe")

# Extensions built into Chrome itself (seen as chrome-extension:// targets in
# every profile). Watching them only adds noise; pass --ext-id to watch one.
COMPONENT_EXTENSION_IDS = {
    "nkeimhogjdpnpccoofpliimaahmaaome",  # Google Hangouts / WebRTC logging
    "fignfifoniblkonapihmkfakmlgkbkcf",  # Chrome built-in (seen in Chrome 148)
    "mhjfbmdgcfjbbpaeojofohoefgiehjai",  # Chrome PDF Viewer
    "neajdppkdcdipfabeoofebfddakdcjhd",  # Google Network Speech
    "pkedcjkdefgpdelpbcmbmeomcjbeemfm",  # Chrome Media Router
    "ghbmnnjooekpmoecnnnilnnbdlolhkhi",  # Google Docs Offline (preinstalled)
}
MAX_PENDING_REQUESTS = 2000


class ExtensionMonitor:
    """
    One browser-level CDP connection that follows every extension context.

    Sessions (flattened) come in two kinds:
      - extension contexts (chrome-extension://<id>/...): everything they do
        belongs to that extension; hooks are installed here.
      - web pages: only requests whose initiator stack contains a
        chrome-extension:// frame (i.e. content scripts) are attributed;
        hooks are installed into each extension's isolated world.
    """

    def __init__(
        self,
        ws,
        alert_queue: asyncio.Queue,
        target_ext_id: str | None = None,
        watch_pages: bool = True,
        output_json: bool = False,
    ):
        self.ws = ws
        self.alert_queue = alert_queue
        self.target_ext_id = target_ext_id
        self.watch_pages = watch_pages
        self.output_json = output_json
        self._ids = itertools.count(1)
        self._pending: dict = {}  # message id -> Future
        self.sessions: dict = {}  # sessionId -> session info dict
        self._requests: OrderedDict = OrderedDict()  # (session, requestId) -> (params, target, ext)
        self._extra: OrderedDict = OrderedDict()  # (session, requestId) -> ExtraInfo params
        self.stats = defaultdict(int)

    # ----- plumbing --------------------------------------------------------

    async def send(
        self,
        method: str,
        params: dict | None = None,
        session: str | None = None,
        timeout: float = 15,
    ):
        """Send a command and wait for its result (or raise RuntimeError)."""
        msg_id = next(self._ids)
        message = {"id": msg_id, "method": method, "params": params or {}}
        if session:
            message["sessionId"] = session
        future = asyncio.get_running_loop().create_future()
        self._pending[msg_id] = future
        await self.ws.send(json.dumps(message))
        try:
            return await asyncio.wait_for(future, timeout=timeout)
        finally:
            self._pending.pop(msg_id, None)

    async def send_quiet(self, method, params=None, session=None, timeout: float = 15):
        """send() that turns failures into None - for best-effort setup steps."""
        try:
            return await self.send(method, params, session, timeout)
        except (RuntimeError, asyncio.TimeoutError):
            return None

    async def run(self):
        """Start watching; returns when the browser connection closes."""
        reader = asyncio.create_task(self._read_loop())
        try:
            await self.send("Target.setDiscoverTargets", {"discover": True})
            await self.send(
                "Target.setAutoAttach",
                {"autoAttach": True, "waitForDebuggerOnStart": True, "flatten": True},
            )
            infos = (await self.send("Target.getTargets")).get("targetInfos", [])
            for info in infos:
                await self._maybe_attach(info)
            await reader
        finally:
            reader.cancel()

    async def _read_loop(self):
        async for raw in self.ws:
            try:
                msg = json.loads(raw)
            except (ValueError, TypeError):
                continue
            if "id" in msg:
                future = self._pending.pop(msg["id"], None)
                if future and not future.done():
                    if "error" in msg:
                        future.set_exception(RuntimeError(str(msg["error"])))
                    else:
                        future.set_result(msg.get("result", {}))
                continue
            # Events are handled in their own tasks so a slow handler (which
            # may itself send commands) never blocks the reader
            asyncio.create_task(self._safe_dispatch(msg))

    async def _safe_dispatch(self, msg: dict):
        try:
            await self.dispatch(msg)
        except Exception as exc:  # one bad event must not stop the monitor
            self.stats["handler_errors"] += 1
            if not self.output_json:
                print(f"  [Monitor] handler error on {msg.get('method')}: {exc}", file=sys.stderr)

    # ----- event routing ---------------------------------------------------

    async def dispatch(self, msg: dict):
        method = msg.get("method", "")
        params = msg.get("params", {}) or {}
        session = msg.get("sessionId")

        if method in ("Target.targetCreated", "Target.targetInfoChanged"):
            await self._maybe_attach(params.get("targetInfo", {}))
        elif method == "Target.attachedToTarget":
            await self._on_attached(params)
        elif method == "Target.detachedFromTarget":
            self.sessions.pop(params.get("sessionId"), None)
        elif session and session in self.sessions:
            await self._on_session_event(self.sessions[session], method, params)

    def _extension_id_of(self, url: str) -> str | None:
        if isinstance(url, str) and url.startswith("chrome-extension://"):
            return url.split("/")[2]
        return None

    def _wanted(self, ext_id: str | None) -> bool:
        if ext_id is None:
            return False
        if self.target_ext_id is not None:
            return ext_id == self.target_ext_id
        return ext_id not in COMPONENT_EXTENSION_IDS

    async def _maybe_attach(self, info: dict):
        """Attach to an existing / newly discovered target we care about."""
        if info.get("attached") or info.get("targetId") in {
            s["target_id"] for s in self.sessions.values()
        }:
            return
        ext_id = self._extension_id_of(info.get("url", ""))
        is_ext_context = self._wanted(ext_id) and info.get("type") in EXTENSION_TARGET_TYPES
        is_page = self.watch_pages and info.get("type") in PAGE_TYPES and ext_id is None
        if is_ext_context or is_page:
            await self.send_quiet(
                "Target.attachToTarget", {"targetId": info.get("targetId"), "flatten": True}
            )

    async def _on_attached(self, params: dict):
        session = params.get("sessionId")
        info = params.get("targetInfo", {}) or {}
        waiting = params.get("waitingForDebugger", False)
        ext_id = self._extension_id_of(info.get("url", ""))
        kind = info.get("type")

        primary = next(
            (s for s in self.sessions.values() if s["target_id"] == info.get("targetId")), None
        )
        if primary is not None:
            # A second session for a target we already watch (browser-level
            # auto-attach AND a parent page's auto-attach both deliver new
            # workers). Chrome keeps a paused target paused until EVERY
            # session that paused it resumes it - so we must resume this one
            # too, but only after the primary session has finished its setup
            # (resuming earlier lets the worker run unobserved; never resuming
            # freezes it for good - both verified against real Chrome).
            if waiting:
                try:
                    await asyncio.wait_for(primary["ready"].wait(), timeout=10)
                except asyncio.TimeoutError:
                    pass
                await self.send_quiet("Runtime.runIfWaitingForDebugger", session=session)
            await self.send_quiet("Target.detachFromTarget", {"sessionId": session})
            return
        if self._wanted(ext_id) and kind in EXTENSION_TARGET_TYPES:
            role = "extension"
        elif self.watch_pages and kind in PAGE_TYPES and ext_id is None:
            role = "page"
        else:
            # Auto-attached but not interesting: let it run and let it go
            if waiting:
                await self.send_quiet("Runtime.runIfWaitingForDebugger", session=session)
            await self.send_quiet("Target.detachFromTarget", {"sessionId": session})
            return

        entry = {
            "session": session,
            "target_id": info.get("targetId"),
            "role": role,
            "ext_id": ext_id,
            "binding": "__eg_" + secrets.token_hex(6),
            "token": secrets.token_hex(16),
            "mark": "__egm_" + secrets.token_hex(6),
            "contexts": {},  # executionContextId -> extension id (pages: isolated worlds)
            "ready": asyncio.Event(),  # set once domains + hooks are in place
            "target": {
                "id": info.get("targetId"),
                "_ext_id": ext_id,
                "title": info.get("title"),
                "url": info.get("url"),
                "type": kind,
                "_context": role,
            },
        }
        self.sessions[session] = entry
        self.stats[f"attached_{role}"] += 1
        if not self.output_json and role == "extension":
            print(f"  [Monitor] Watching {kind} of extension {ext_id} ({info.get('title')})")

        # Queue the whole setup WITHOUT waiting for the replies. A worker that is
        # paused at start does not answer some commands (Runtime.addBinding)
        # until it runs - awaiting them froze it for good (seen on real Chrome).
        # The target processes commands in order, so everything queued here is
        # in effect before the resume at the end.
        is_document = kind in ("page", "iframe", "background_page")
        hook = build_hook_script(entry["binding"], entry["token"], entry["mark"])
        auto = {"autoAttach": True, "waitForDebuggerOnStart": True, "flatten": True}
        await self._fire("Target.setAutoAttach", auto, session)  # its dedicated workers too
        await self._fire("Runtime.addBinding", {"name": entry["binding"]}, session)
        await self._fire("Runtime.enable", None, session)
        await self._fire("Network.enable", None, session)
        hook_before_first_script = False
        if role == "extension":
            await self._fire("Debugger.enable", None, session)
            if is_document:
                # Documents: hook EVERY new document before its own scripts
                # run. Chrome ignores the registration unless Page is enabled.
                await self._fire("Page.enable", None, session)
                await self._fire("Page.addScriptToEvaluateOnNewDocument", {"source": hook}, session)
            if waiting and not is_document:
                # Workers: pause just before the first script executes, hook
                # there, then carry on (see the Debugger.paused handler)
                entry["hook_bp"] = await self._fire(
                    "Debugger.setInstrumentationBreakpoint",
                    {"instrumentation": "beforeScriptExecution"},
                    session,
                )
                hook_before_first_script = True
            else:
                # Never let a `debugger;` statement in the extension freeze it
                await self._fire("Debugger.setSkipAllPauses", {"skip": True}, session)
        entry["ready"].set()  # duplicate sessions may now let the target run too
        if waiting:
            await self._fire("Runtime.runIfWaitingForDebugger", None, session)
        if role == "extension" and not hook_before_first_script:
            # Already-running contexts (and documents, as a backstop).
            # Installing twice is harmless - the hook checks its marker.
            await self._install_hooks(entry, context_id=None)

    async def _fire(self, method: str, params: dict | None, session: str | None):
        """
        Write a command to the socket and return its reply Future WITHOUT
        awaiting the reply. Writes are awaited one by one, so order is kept.
        """
        msg_id = next(self._ids)
        message = {"id": msg_id, "method": method, "params": params or {}}
        if session:
            message["sessionId"] = session
        future = asyncio.get_running_loop().create_future()
        self._pending[msg_id] = future
        await self.ws.send(json.dumps(message))
        return future

    async def _on_instrumentation_pause(self, entry: dict, params: dict):
        """
        A worker paused just before its first script. Install the hooks now -
        evaluation works during a debugger pause - then remove the
        breakpoint, stop honouring any further pauses, and resume.
        """
        session = entry["session"]
        if params.get("reason") == "instrumentation" and not entry.get("hooked"):
            entry["hooked"] = True
            await self._install_hooks(entry, context_id=None, timeout=5)
            try:
                bp = await asyncio.wait_for(entry["hook_bp"], timeout=5)
            except (asyncio.TimeoutError, RuntimeError, KeyError):
                bp = None
            if bp and bp.get("breakpointId"):
                await self._fire(
                    "Debugger.removeBreakpoint", {"breakpointId": bp["breakpointId"]}, session
                )
            await self._fire("Debugger.setSkipAllPauses", {"skip": True}, session)
        # Whatever the reason, never leave the extension frozen
        await self._fire("Debugger.resume", None, session)

    async def _install_hooks(self, entry: dict, context_id: int | None, timeout: float = 15):
        params = {
            "expression": build_hook_script(entry["binding"], entry["token"], entry["mark"]),
            "silent": True,
        }
        if context_id is not None:
            params["contextId"] = context_id
        result = await self.send_quiet(
            "Runtime.evaluate", params, session=entry["session"], timeout=timeout
        )
        if result and (result.get("result") or {}).get("value") in (
            "installed",
            "already-installed",
        ):
            self.stats["hooks_installed"] += 1

    async def _on_session_event(self, entry: dict, method: str, params: dict):
        target = entry["target"]

        if method == "Runtime.executionContextCreated" and entry["role"] == "page":
            # Content scripts run in an isolated world whose origin is the extension
            ctx = params.get("context", {}) or {}
            aux = ctx.get("auxData", {}) or {}
            ext_id = self._extension_id_of(ctx.get("origin", ""))
            if aux.get("type") == "isolated" and self._wanted(ext_id):
                entry["contexts"][ctx.get("id")] = ext_id
                await self._install_hooks(entry, context_id=ctx.get("id"))
            return

        if method == "Runtime.bindingCalled" and params.get("name") == entry["binding"]:
            try:
                event = json.loads(params.get("payload", ""))
            except (ValueError, TypeError):
                return
            if not isinstance(event, dict) or event.get("token") != entry["token"]:
                self.stats["forged_reports_dropped"] += 1
                return
            ext_id = entry["ext_id"] or entry["contexts"].get(params.get("executionContextId"))
            if ext_id is None:
                return
            await _handle_hook_event(
                event, self._attributed(target, ext_id), ext_id, self.alert_queue
            )
            return

        if method == "Network.requestWillBeSent":
            self.stats["requests_seen"] += 1
            ext_id = entry["ext_id"] or _initiating_extension(params.get("initiator"))
            if not self._wanted(ext_id):
                return
            attributed = self._attributed(target, ext_id)
            request = params.get("request") or {}
            if request.get("hasPostData") and not request.get("postData"):
                body = await self.send_quiet(
                    "Network.getRequestPostData",
                    {"requestId": params.get("requestId")},
                    session=entry["session"],
                )
                if body and "postData" in body:
                    params = {**params, "request": {**request, "postData": body["postData"]}}
            self.stats["requests_attributed"] += 1
            await _handle_network_request(params, attributed, ext_id, self.alert_queue)
            key = (entry["session"], params.get("requestId"))
            self._remember(self._requests, key, (params, attributed, ext_id))
            if key in self._extra:
                await _handle_authenticated_request(
                    params, self._extra.pop(key), attributed, ext_id, self.alert_queue
                )
            return

        if method == "Network.requestWillBeSentExtraInfo":
            # Can arrive before or after requestWillBeSent - correlate both ways
            key = (entry["session"], params.get("requestId"))
            if key in self._requests:
                req_params, attributed, ext_id = self._requests.pop(key)
                await _handle_authenticated_request(
                    req_params, params, attributed, ext_id, self.alert_queue
                )
            else:
                self._remember(self._extra, key, params)
            return

        if entry["role"] != "extension":
            return  # the rest only matters inside extension contexts

        if method == "Debugger.paused":
            await self._on_instrumentation_pause(entry, params)
        elif method == "Debugger.scriptParsed" and not params.get("url"):
            # A script with no URL is eval() / new Function()
            src = await self.send_quiet(
                "Debugger.getScriptSource", {"scriptId": params.get("scriptId")}, entry["session"]
            )
            source = (src or {}).get("scriptSource", "")
            if source and entry["mark"] not in source:  # ignore our own hook script
                await _handle_dynamic_script(source, target, self.alert_queue)
        elif method == "Runtime.consoleAPICalled":
            await _handle_console_call(params, target, entry["ext_id"], self.alert_queue)
        elif method == "Runtime.exceptionThrown":
            text = str(params.get("exceptionDetails", {}))
            if OBFUSCATED_EVAL.search(text):
                await self.alert_queue.put(
                    _make_alert(
                        "RULE-06",
                        "high",
                        target,
                        {"description": "Obfuscated eval() exception caught", "detail": text[:300]},
                    )
                )

    def _attributed(self, target: dict, ext_id: str) -> dict:
        if target.get("_ext_id") == ext_id:
            return target
        # A content-script action inside a web page: credit the extension
        return {**target, "_ext_id": ext_id, "_context": "content_script"}

    @staticmethod
    def _remember(store: OrderedDict, key, value):
        store[key] = value
        while len(store) > MAX_PENDING_REQUESTS:
            store.popitem(last=False)


def _initiating_extension(initiator) -> str | None:
    """
    For a request made from a web page, find the extension whose script
    started it (content scripts show chrome-extension:// frames in the
    initiator stack). Returns None for the page's own requests.
    """
    if not isinstance(initiator, dict):
        return None
    urls = [initiator.get("url", "")]
    stack = initiator.get("stack") or {}
    while isinstance(stack, dict):
        urls += [f.get("url", "") for f in stack.get("callFrames", []) or []]
        stack = stack.get("parent")
    for url in urls:
        if isinstance(url, str) and url.startswith("chrome-extension://"):
            return url.split("/")[2]
    return None


# ---------------------------------------------------------------------------
# Alert output (Stage 4 hook)
# ---------------------------------------------------------------------------


async def _alert_printer(alert_queue: asyncio.Queue, output_json: bool):
    """Consume alerts from the queue and print them (JSON lines or human-readable)."""
    while True:
        alert = await alert_queue.get()

        if output_json:
            # Machine-readable output — extguard-dispatch reads this
            print(json.dumps(alert), flush=True)
        else:
            rule = alert["rule"]
            severity = alert["severity"].upper()
            ext = alert["extension"]
            detail = alert["detail"]
            colour = (
                "\033[91m"
                if alert["severity"] == "critical"
                else "\033[93m"
                if alert["severity"] == "high"
                else "\033[96m"
            )
            reset, bold = "\033[0m", "\033[1m"
            print(f"\n{colour}{bold}[ALERT] {rule} {severity}{reset}")
            print(f"  Time:      {alert['alert_time']}")
            print(
                f"  Extension: {ext.get('title', '?')} ({ext.get('id')}) via {ext.get('context')}"
            )
            print(f"  Detail:    {detail.get('description', '')}")
            if detail.get("url"):
                print(f"  URL:       {detail['url']}")
            mitre = ", ".join(alert.get("mitre", []))
            if mitre:
                print(f"  MITRE:     {mitre}")
            print()

        alert_queue.task_done()


# ---------------------------------------------------------------------------
# Main async entry point
# ---------------------------------------------------------------------------


async def run_monitor(
    target_ext_id: str | None,
    output_json: bool,
    watch_pages: bool = True,
    once: bool = False,
):
    """
    Connect to the browser and watch until interrupted. If Chrome goes away,
    wait and reconnect (unless once=True).
    """
    alert_queue: asyncio.Queue = asyncio.Queue()
    printer = asyncio.create_task(_alert_printer(alert_queue, output_json))
    delay = 2
    try:
        while True:
            try:
                ws_url = get_browser_ws_url()
                async with websockets.connect(ws_url, max_size=None, ping_interval=20) as ws:
                    delay = 2
                    if not output_json:
                        print(
                            "[Monitor] Connected. Watching extension workers and content scripts "
                            "(waiting for extensions to become active is normal)... Ctrl+C to stop\n"
                        )
                    monitor = ExtensionMonitor(
                        ws, alert_queue, target_ext_id, watch_pages, output_json
                    )
                    await monitor.run()
            except (RuntimeError, OSError, websockets.exceptions.WebSocketException) as exc:
                if once:
                    raise RuntimeError(str(exc)) from exc
                if not output_json:
                    print(f"[Monitor] Chrome not reachable ({exc}); retrying in {delay}s")
            if once:
                return
            await asyncio.sleep(delay)
            delay = min(delay * 2, 60)
    finally:
        printer.cancel()


# ---------------------------------------------------------------------------
# Storage snapshot (evidence for Stage 5)
# ---------------------------------------------------------------------------


async def snapshot_storage(ext_id: str) -> dict:
    """
    Dump chrome.storage.local + sync from a running extension context, for
    `extguard-remediate --storage-snapshot`. The extension's worker / page
    must be running (open its popup to wake an idle MV3 worker).
    """
    targets = get_extension_targets(ext_id)
    if not targets:
        raise RuntimeError(
            f"No running context for extension {ext_id} - open the extension (popup / "
            "options page) to wake its worker, then retry"
        )
    expression = (
        "Promise.all([chrome.storage.local.get(null),"
        " chrome.storage.sync ? chrome.storage.sync.get(null) : {}])"
        ".then(([local, sync]) => ({local, sync}))"
    )
    async with websockets.connect(targets[0]["webSocketDebuggerUrl"], max_size=None) as ws:
        await ws.send(
            json.dumps(
                {
                    "id": 1,
                    "method": "Runtime.evaluate",
                    "params": {
                        "expression": expression,
                        "awaitPromise": True,
                        "returnByValue": True,
                    },
                }
            )
        )
        async for raw in ws:
            msg = json.loads(raw)
            if msg.get("id") == 1:
                result = msg.get("result", {})
                if "exceptionDetails" in result or "error" in msg:
                    raise RuntimeError(f"Snapshot failed: {msg.get('error') or result}")
                return {
                    "extension_id": ext_id,
                    "captured_at": _now_iso(),
                    "target_url": targets[0].get("url"),
                    "storage": result.get("result", {}).get("value"),
                }
    raise RuntimeError("Connection closed before the snapshot completed")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _configure_endpoint(host: str, port: int):
    global CDP_HTTP_BASE, CDP_JSON_TARGETS
    CDP_HTTP_BASE = f"http://{host}:{port}"
    CDP_JSON_TARGETS = f"{CDP_HTTP_BASE}/json"


def main():
    parser = argparse.ArgumentParser(
        description="ExtensionGuard Stage 3 - Real-time extension behaviour monitor",
        epilog=(
            "Run it against a SEPARATE Chrome used as a sandbox, e.g.:\n"
            "  chrome.exe --user-data-dir=C:\\extguard-sandbox --remote-debugging-port=9222\n"
            "Example:  extguard-monitor --ext-id abcdefghijklmnopabcdefghijklmnop"
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
        help="Emit alerts as JSON lines (for extguard-dispatch).",
    )
    parser.add_argument(
        "--list-targets",
        action="store_true",
        help="List detected extension targets and exit (useful for finding extension IDs).",
    )
    parser.add_argument(
        "--no-pages",
        action="store_true",
        help="Don't watch web pages (content scripts); lower overhead, less coverage.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Exit when Chrome disconnects instead of waiting to reconnect.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="DevTools host (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9222, help="DevTools port (default 9222)")
    parser.add_argument(
        "--snapshot-storage",
        metavar="EXTENSION_ID",
        help="Dump the extension's chrome.storage to --out and exit (forensic evidence).",
    )
    parser.add_argument("--out", metavar="PATH", help="Output file for --snapshot-storage")
    args = parser.parse_args()

    if not _DEPS_OK:
        print("[ERROR] Missing dependencies. Run:  pip install requests websockets")
        sys.exit(1)
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(
            f"WARNING: connecting to DevTools on {args.host}. Anyone who can reach that port "
            "controls that browser and every session in it.",
            file=sys.stderr,
        )
    _configure_endpoint(args.host, args.port)

    # --- Storage snapshot mode ----------------------------------------------
    if args.snapshot_storage:
        if not args.out:
            parser.error("--snapshot-storage needs --out <file>")
        try:
            snap = asyncio.run(snapshot_storage(args.snapshot_storage))
        except RuntimeError as exc:
            print(f"[ERROR] {exc}")
            sys.exit(1)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(snap, f, indent=2)
        print(f"Storage snapshot written to {args.out}")
        return

    # --- List-only mode -------------------------------------------------------
    if args.list_targets:
        try:
            targets = get_extension_targets()
        except RuntimeError as exc:
            print(f"[ERROR] {exc}")
            sys.exit(1)

        if not targets:
            print("[i] No extension targets running right now (idle MV3 workers stop after ~30 s).")
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
        asyncio.run(
            run_monitor(
                args.ext_id, args.output_json, watch_pages=not args.no_pages, once=args.once
            )
        )
    except KeyboardInterrupt:
        if not args.output_json:
            print("\n[Monitor] Stopped by user.")
    except RuntimeError as exc:
        print(f"[ERROR] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
