# permission_scorer.py - Local (no-API) permission risk scoring
#
# Runs before the Claude API call so we can:
#   1. Give Claude pre-computed context to anchor its scoring
#   2. Catch obvious threats even if the API is unavailable
#   3. Set the floor of the final verdict (Claude can raise it, never lower it)
#
# Scoring philosophy:
#   - Individual dangerous permissions add base points
#   - Broad host access (can reach any site) adds significant points
#   - Known attack COMBOS (permission sets that map to specific TTPs) get bonus points
#   - OPTIONAL permissions count at half weight: they need a runtime prompt,
#     but they are one click away, and attackers use them to look harmless
#     at install time. They still complete attack combos (at half bonus).
#   - Host patterns are PARSED (scheme / host / path), not compared as
#     strings, so "https://github.com/*" is recognised as GitHub access just
#     like "*://*.github.com/*".
#   - Final score is clamped to 0–100

from extguard.models import ManifestInfo, PermissionScore

# ---------------------------------------------------------------------------
# Weight table for individual named permissions
# Calibrated against known campaigns:
#   TeamPCP used: cookies + tabs + storage + webRequest + <all_urls>
#   Shai-Hulud used: debugger + nativeMessaging for deep host persistence
# ---------------------------------------------------------------------------

PERMISSION_WEIGHTS: dict = {
    # ---- Critical (35 pts) ------------------------------------------------
    # debugger: attach a JS debugger to ANY tab → full memory read, CSP bypass,
    #           extract credentials from in-memory React/Angular state
    "debugger": 35,
    # nativeMessaging: spawn a native OS process → complete host compromise,
    #                  used by Shai-Hulud for persistence after browser restart
    "nativeMessaging": 35,
    # ---- High (20-25 pts) -------------------------------------------------
    # userScripts: run arbitrary script strings in pages - the one MV3 API
    #              that can execute code the extension fetched at runtime
    "userScripts": 25,
    # scripting: MV3's code-injection API (chrome.scripting.executeScript) -
    #            with host access it can run code in every matching page
    "scripting": 20,
    # webRequestBlocking: intercept AND modify HTTP/S responses mid-flight
    "webRequestBlocking": 20,
    # webRequestAuthProvider: answer HTTP auth prompts - sees the credentials
    "webRequestAuthProvider": 20,
    # cookies: read session cookies for any domain the host_permissions cover
    #          TeamPCP primary TTP - used to harvest github.com / npm tokens
    "cookies": 20,
    # browsingData: clear history, cookies, cache - used to cover exfil tracks
    "browsingData": 20,
    # management: enable/disable/uninstall other extensions
    #             can silence EDR or security extensions
    "management": 20,
    # proxy: reroute ALL browser traffic through attacker-controlled proxy
    "proxy": 20,
    # tabCapture / desktopCapture: record tabs or the screen (T1113)
    "tabCapture": 20,
    "desktopCapture": 20,
    # ---- Medium (8-12 pts) ------------------------------------------------
    "webRequest": 12,  # Inspect (but not modify) all requests
    "tabs": 12,  # Read URLs + titles of every open tab
    "history": 12,  # Full browsing history access
    "clipboardRead": 12,  # Clipboard sniffing (passwords copy-pasted)
    "identity": 12,  # Fetch OAuth2 tokens for the signed-in user
    "pageCapture": 12,  # Save any page (content included) as MHTML
    "privacy": 12,  # Turn off Safe Browsing and other protections
    "contentSettings": 12,  # Allow JS/popups/camera/mic per site
    "declarativeNetRequest": 10,  # Rewrite requests, strip security headers (CSP)
    "declarativeNetRequestWithHostAccess": 10,
    "webNavigation": 8,  # Sees every URL navigated to
    "sessions": 8,  # Recently closed tabs + other devices' sessions
    # ---- Low (1-5 pts) ----------------------------------------------------
    "storage": 5,  # Browser local/sync storage (exfil staging)
    "unlimitedStorage": 3,
    "downloads": 5,  # Initiate or intercept downloads
    "geolocation": 5,
    "offscreen": 3,  # Hidden DOM document (clipboard, audio) for the worker
    "clipboardWrite": 3,
    "bookmarks": 3,
    "topSites": 3,
    "notifications": 2,
    "contextMenus": 1,
}

# Points for each broad host pattern ("<all_urls>", "*://*/*", "https://*/*"...)
BROAD_HOST_POINTS = 15

# Hosts whose cookies / pages are worth stealing. A pattern matches a group
# when its host is the domain itself or any subdomain of it.
HIGH_VALUE_DOMAINS = {
    "GitHub": ("github.com", "githubusercontent.com"),
    "npm": ("npmjs.com", "npmjs.org"),
    "GitLab": ("gitlab.com",),
    "Bitbucket": ("bitbucket.org",),
    "Atlassian": ("atlassian.net", "atlassian.com"),
    "Google accounts": ("google.com",),
    "AWS": ("aws.amazon.com", "amazonaws.com"),
    "Microsoft login": ("microsoftonline.com", "live.com"),
    "Slack": ("slack.com",),
    "Okta": ("okta.com",),
}

# Common two-part public suffixes - "*.co.uk" is as broad as "*.com"
_TWO_PART_SUFFIXES = {"co.uk", "com.au", "co.jp", "co.in", "com.br", "co.nz", "com.cn"}

# Pseudo-permissions used inside combo rules
ALL_SITES = "<all-sites host access>"
HIGH_VALUE = "<high-value site access>"

# ---------------------------------------------------------------------------
# Combo bonuses - awarded when a set of permissions maps to a known attack chain
# Format: (required_permission_set, bonus_points, human_readable_description)
# ---------------------------------------------------------------------------

COMBO_BONUSES = [
    # Session token harvesting - TeamPCP's exact permission profile
    (
        {"cookies", "tabs", "storage"},
        15,
        "Session token harvesting combo - matches TeamPCP TTP (T1555.003)",
    ),
    # Cookie access aimed at developer / identity sites
    (
        {"cookies", HIGH_VALUE},
        15,
        "Cookie access to high-value developer/identity sites - session theft (T1555.003)",
    ),
    # Full traffic interception pipeline
    ({"webRequest", "cookies"}, 10, "Traffic intercept + cookie theft pipeline (T1071 + T1555)"),
    # Silent extension management - disable security tools
    (
        {"management", "storage"},
        10,
        "Extension management abuse - can disable EDR/security extensions (T1176)",
    ),
    # Debugger-assisted credential extraction - Shai-Hulud signature
    (
        {"debugger", "tabs"},
        20,
        "Debugger + tabs = in-memory credential extraction (T1555 via T1059.007)",
    ),
    # Proxy + broad access = full MITM
    (
        {"proxy", "webRequest"},
        15,
        "Proxy control + request inspection = full MITM capability (T1071)",
    ),
    # MV3 code injection into every site
    (
        {"scripting", ALL_SITES},
        15,
        "Code injection into every site - chrome.scripting + all-sites access (T1059.007)",
    ),
    # Header stripping on every site
    (
        {"declarativeNetRequest", ALL_SITES},
        8,
        "Can strip security headers (CSP, frame options) on every site",
    ),
]


def score_permissions(manifest: ManifestInfo) -> PermissionScore:
    """
    Score the extension's permissions locally (no API call needed).

    Layers:
      1. Named API permissions (required full weight, optional half weight)
      2. Broad host access patterns (e.g. "<all_urls>", "https://*/*")
      3. High-value target hosts (GitHub, npm, identity providers...)
      4. Dangerous permission combos mapped to known TTPs
      5. Content scripts on all sites / in the page's MAIN world
      6. Persistent background page
      7. Other manifest red flags (externally_connectable, CSP, parse warnings)

    Returns a PermissionScore with a 0–100 total and analyst notes.
    """
    breakdown: dict = {}
    notes: list = []
    flagged: list = []

    required_perms = set(manifest.permissions)
    optional_perms = set(manifest.optional_permissions) - required_perms

    # --- Layer 1: Named API permissions ------------------------------------
    for perm, weight in PERMISSION_WEIGHTS.items():
        if perm in required_perms:
            breakdown[perm] = weight
            flagged.append(perm)
        elif perm in optional_perms:
            breakdown[f"optional:{perm}"] = _half(weight)
            flagged.append(f"{perm} (optional)")
    optional_scored = [p for p in optional_perms if p in PERMISSION_WEIGHTS]
    if optional_scored:
        notes.append(
            "Optional permissions requested at runtime: "
            f"{', '.join(sorted(optional_scored))} - one prompt away from granted"
        )

    # --- Layer 2: Broad host access ----------------------------------------
    broad_required = [p for p in manifest.host_permissions if _is_broad(p)]
    broad_optional = [
        p
        for p in manifest.optional_host_permissions
        if _is_broad(p) and p not in manifest.host_permissions
    ]
    for pattern in broad_required:
        breakdown[f"host:{pattern}"] = BROAD_HOST_POINTS
        flagged.append(pattern)
        notes.append(f"Broad host access granted: {pattern} (exfil surface area)")
    for pattern in broad_optional:
        breakdown[f"optional_host:{pattern}"] = _half(BROAD_HOST_POINTS)
        flagged.append(f"{pattern} (optional)")
        notes.append(f"Broad host access requested at runtime: {pattern}")

    # Multiple broad patterns is almost never legitimate
    if len(broad_required) >= 2:
        breakdown["broad_host_combo"] = 10
        notes.append("Multiple broad host patterns - unlikely to be accidental")

    # --- Layer 3: High-value targets ----------------------------------------
    hv_required = _high_value_groups(manifest.host_permissions)
    hv_optional = _high_value_groups(manifest.optional_host_permissions) - hv_required
    if hv_required:
        breakdown["high_value_hosts"] = min(len(hv_required) * 5, 20)
        flagged += sorted(hv_required)
        notes.append(f"High-value targets in host_permissions: {', '.join(sorted(hv_required))}")
    if hv_optional:
        breakdown["optional_high_value_hosts"] = min(len(hv_optional) * 3, 10)
        notes.append(f"High-value targets requested at runtime: {', '.join(sorted(hv_optional))}")

    # --- Layer 4: Dangerous combos -----------------------------------------
    # Capabilities the extension has now, and the ones it can get with a prompt
    have_now = set(required_perms)
    have_later = required_perms | optional_perms
    if broad_required:
        have_now.add(ALL_SITES)
    if broad_required or broad_optional:
        have_later.add(ALL_SITES)
    if hv_required or broad_required:
        have_now.add(HIGH_VALUE)
    if hv_required or hv_optional or broad_required or broad_optional:
        have_later.add(HIGH_VALUE)

    for required, bonus, description in COMBO_BONUSES:
        combo_key = "combo:" + "+".join(sorted(required))
        if required.issubset(have_now):
            breakdown[combo_key] = bonus
            notes.append(f"Dangerous combo detected: {description}")
        elif required.issubset(have_later):
            breakdown[combo_key] = _half(bonus)
            notes.append(f"Dangerous combo one prompt away (optional permissions): {description}")

    # --- Layer 5: Content scripts ------------------------------------------
    for cs in manifest.content_scripts:
        matches = cs.get("matches", [])
        if any(_is_broad(m) for m in matches) and "content_scripts_all_urls" not in breakdown:
            breakdown["content_scripts_all_urls"] = 15
            notes.append(
                "Content script injected into ALL pages - DOM/form/credential access on every site"
            )
        if cs.get("world") == "MAIN" and "content_scripts_main_world" not in breakdown:
            breakdown["content_scripts_main_world"] = 8
            notes.append(
                "Content script runs in the page's MAIN world - can hook the page's own "
                "JavaScript and read in-memory tokens"
            )
        hv_cs = _high_value_groups(matches) - hv_required
        if hv_cs and "content_scripts_high_value" not in breakdown:
            breakdown["content_scripts_high_value"] = 5
            notes.append(
                f"Content script injected into high-value sites: {', '.join(sorted(hv_cs))}"
            )

    # --- Layer 6: Persistent background page (MV2 only, but still dangerous) -
    if manifest.background.get("persistent", False) is True:
        breakdown["persistent_background"] = 8
        notes.append(
            "Persistent background page - always-on monitoring, "
            "survives tab close (deprecated but still functional in MV2)"
        )

    # --- Layer 7: Other manifest red flags ----------------------------------
    _score_other_signals(manifest, breakdown, notes)

    # --- Clamp total to 0–100 ----------------------------------------------
    total = max(0, min(100, sum(breakdown.values())))

    return PermissionScore(
        total_score=total,
        risk_level=_score_to_level(total),
        flagged_permissions=flagged,
        breakdown=breakdown,
        notes=notes,
    )


def _score_other_signals(manifest: ManifestInfo, breakdown: dict, notes: list):
    """externally_connectable, content security policy, parse warnings."""
    raw = manifest.raw if isinstance(manifest.raw, dict) else {}

    ext_conn = raw.get("externally_connectable")
    if isinstance(ext_conn, dict):
        matches = ext_conn.get("matches")
        if isinstance(matches, list) and any(isinstance(m, str) and _is_broad(m) for m in matches):
            breakdown["externally_connectable_all_sites"] = 8
            notes.append(
                "externally_connectable lets ANY website message this extension - "
                "a ready-made remote command channel"
            )
        ids = ext_conn.get("ids")
        if isinstance(ids, list) and "*" in ids:
            breakdown["externally_connectable_any_extension"] = 5
            notes.append("externally_connectable accepts messages from ANY extension")

    csp_text = _csp_text(raw.get("content_security_policy"))
    if "unsafe-eval" in csp_text:
        breakdown["csp_unsafe_eval"] = 10
        notes.append("Content Security Policy allows 'unsafe-eval' - runtime code generation")
    if _csp_allows_remote_script(csp_text):
        breakdown["csp_remote_script"] = 10
        notes.append("Content Security Policy allows scripts from remote origins")

    if manifest.parse_warnings:
        breakdown["malformed_manifest"] = 5
        notes.append(
            f"Malformed manifest ({len(manifest.parse_warnings)} field problem(s)) - Chrome "
            "would reject most of these; may be crafted to confuse scanners"
        )


# ---------------------------------------------------------------------------
# Match-pattern helpers
# ---------------------------------------------------------------------------


def _split_pattern(pattern: str):
    """
    Split a Chrome match pattern into (scheme, host). Returns None for
    anything that isn't a scheme://host/path pattern.
    "<all_urls>" -> ("*", "*").
    """
    if pattern == "<all_urls>":
        return "*", "*"
    if "://" not in pattern:
        return None
    scheme, rest = pattern.split("://", 1)
    host = rest.split("/", 1)[0].split(":", 1)[0].lower()
    return scheme.lower(), host


def _is_broad(pattern: str) -> bool:
    """
    True if the pattern reaches (nearly) every website: "<all_urls>",
    "*://*/*", "https://*/*", or a whole top-level domain like "*://*.com/*".
    """
    parts = _split_pattern(pattern)
    if parts is None:
        return False
    scheme, host = parts
    if scheme == "file":
        return False  # local files - noted elsewhere, not network reach
    if host == "*":
        return True
    # "*.com" / "*.co.uk": a wildcard over a whole top-level domain.
    # ("*.github.io" is one site's subdomains - NOT broad.)
    if host.startswith("*."):
        suffix = host[2:]
        return "." not in suffix or suffix in _TWO_PART_SUFFIXES
    return False


def _high_value_groups(patterns: list) -> set:
    """Names of HIGH_VALUE_DOMAINS groups that the patterns can reach (broad excluded)."""
    groups = set()
    for pattern in patterns:
        if _is_broad(pattern):
            continue  # broad access is scored separately and implies everything
        parts = _split_pattern(pattern)
        if parts is None:
            continue
        host = parts[1].removeprefix("*.")
        for group, domains in HIGH_VALUE_DOMAINS.items():
            if any(host == d or host.endswith("." + d) for d in domains):
                groups.add(group)
    return groups


def _csp_text(csp) -> str:
    """MV2 CSP is a string; MV3 is {"extension_pages": ..., "sandbox": ...}."""
    if isinstance(csp, str):
        return csp
    if isinstance(csp, dict):
        return " ".join(v for v in csp.values() if isinstance(v, str))
    return ""


def _csp_allows_remote_script(csp_text: str) -> bool:
    """Does any script-src directive list an http(s) origin?"""
    for directive in csp_text.split(";"):
        tokens = directive.split()
        if tokens and tokens[0] in ("script-src", "script-src-elem"):
            if any(t.startswith(("http:", "https:")) or t == "*" for t in tokens[1:]):
                return True
    return False


def _half(points: int) -> int:
    return (points + 1) // 2


def _score_to_level(score: int) -> str:
    """Map a numeric score to a four-tier risk label."""
    if score >= 70:
        return "critical"
    elif score >= 45:
        return "high"
    elif score >= 20:
        return "medium"
    else:
        return "low"
