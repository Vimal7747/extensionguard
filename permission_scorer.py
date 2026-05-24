# permission_scorer.py - Local (no-API) permission risk scoring
#
# Runs before the Claude API call so we can:
#   1. Give Claude pre-computed context to anchor its scoring
#   2. Catch obvious threats even if the API is unavailable
#   3. Gate whether we bother calling the API at all (e.g. skip score < 10)
#
# Scoring philosophy:
#   - Individual dangerous permissions add base points
#   - Broad host access (can reach any site) adds significant points
#   - Known attack COMBOS (permission sets that map to specific TTPs) get bonus points
#   - Final score is clamped to 0–100

from models import ManifestInfo, PermissionScore

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
    "debugger":            35,

    # nativeMessaging: spawn a native OS process → complete host compromise,
    #                  used by Shai-Hulud for persistence after browser restart
    "nativeMessaging":     35,

    # ---- High (20 pts) ----------------------------------------------------
    # webRequestBlocking: intercept AND modify HTTP/S responses mid-flight
    "webRequestBlocking":  20,

    # cookies: read session cookies for any domain the host_permissions cover
    #          TeamPCP primary TTP - used to harvest github.com / npm tokens
    "cookies":             20,

    # browsingData: clear history, cookies, cache - used to cover exfil tracks
    "browsingData":        20,

    # management: enable/disable/uninstall other extensions
    #             can silence EDR or security extensions
    "management":          20,

    # proxy: reroute ALL browser traffic through attacker-controlled proxy
    "proxy":               20,

    # ---- Medium (12 pts) --------------------------------------------------
    "webRequest":          12,   # Inspect (but not modify) all requests
    "tabs":                12,   # Read URLs + titles of every open tab
    "history":             12,   # Full browsing history access
    "clipboardRead":       12,   # Clipboard sniffing (passwords copy-pasted)
    "identity":            12,   # Fetch OAuth2 tokens for the signed-in user

    # ---- Low (5 pts) ------------------------------------------------------
    "storage":              5,   # Browser local/sync storage (exfil staging)
    "downloads":            5,   # Initiate or intercept downloads
    "bookmarks":            3,
    "notifications":        2,
    "contextMenus":         1,
}

# URL patterns that grant access to ALL sites - the key exfil enabler
BROAD_HOST_PATTERNS = [
    "<all_urls>",
    "*://*/*",
    "http://*/*",
    "https://*/*",
]

# Specific high-value targets seen in supply chain campaigns
HIGH_VALUE_HOST_PATTERNS = [
    "*://*.github.com/*",
    "*://github.com/*",
    "*://*.npmjs.com/*",
    "*://*.atlassian.net/*",
    "*://*.google.com/*",   # Google auth cookies
    "*://*.gitlab.com/*",
]

# ---------------------------------------------------------------------------
# Combo bonuses - awarded when a set of permissions maps to a known attack chain
# Format: (required_permission_set, bonus_points, human_readable_description)
# ---------------------------------------------------------------------------

COMBO_BONUSES = [
    # Session token harvesting - TeamPCP's exact permission profile
    ({"cookies", "tabs", "storage"},
     15,
     "Session token harvesting combo - matches TeamPCP TTP (T1555.003)"),

    # Full traffic interception pipeline
    ({"webRequest", "cookies"},
     10,
     "Traffic intercept + cookie theft pipeline (T1071 + T1555)"),

    # Silent extension management - disable security tools
    ({"management", "storage"},
     10,
     "Extension management abuse - can disable EDR/security extensions (T1176)"),

    # Debugger-assisted credential extraction - Shai-Hulud signature
    ({"debugger", "tabs"},
     20,
     "Debugger + tabs = in-memory credential extraction (T1555 via T1059.007)"),

    # Proxy + broad access = full MITM
    ({"proxy", "webRequest"},
     15,
     "Proxy control + request inspection = full MITM capability (T1071)"),
]


def score_permissions(manifest: ManifestInfo) -> PermissionScore:
    """
    Score the extension's permissions locally (no API call needed).

    Works through four layers:
      1. Named API permissions (e.g. "cookies", "debugger")
      2. Broad host access patterns (e.g. "<all_urls>")
      3. High-value target host patterns (GitHub, npm, etc.)
      4. Dangerous permission combos mapped to known TTPs
      5. Content scripts injected into all pages
      6. Persistent background page

    Returns a PermissionScore with a 0–100 total and analyst notes.
    """
    breakdown: dict = {}
    notes:     list = []
    flagged:   list = []

    # Combine all permissions into one set for easy membership checks
    all_perms    = set(manifest.permissions)
    all_patterns = set(manifest.host_permissions)

    # --- Layer 1: Named API permissions ------------------------------------
    for perm, weight in PERMISSION_WEIGHTS.items():
        if perm in all_perms:
            breakdown[perm] = weight
            flagged.append(perm)

    # --- Layer 2: Broad host access ----------------------------------------
    broad_count = 0
    for pattern in BROAD_HOST_PATTERNS:
        if pattern in all_patterns:
            broad_count += 1
            key = f"host:{pattern}"
            breakdown[key] = 15
            flagged.append(pattern)
            notes.append(f"Broad host access granted: {pattern} (exfil surface area)")

    # Multiple broad patterns is almost never legitimate
    if broad_count >= 2:
        breakdown["broad_host_combo"] = 10
        notes.append("Multiple broad host patterns - unlikely to be accidental")

    # --- Layer 3: High-value targets ----------------------------------------
    hv_matches = [p for p in all_patterns if p in HIGH_VALUE_HOST_PATTERNS]
    if hv_matches:
        points = min(len(hv_matches) * 5, 20)   # cap at 20 pts
        breakdown["high_value_hosts"] = points
        flagged += hv_matches
        notes.append(
            f"High-value targets in host_permissions: {', '.join(hv_matches)}"
        )

    # --- Layer 4: Dangerous combos -----------------------------------------
    for required, bonus, description in COMBO_BONUSES:
        if required.issubset(all_perms | all_patterns):
            combo_key = "combo:" + "+".join(sorted(required))
            breakdown[combo_key] = bonus
            notes.append(f"Dangerous combo detected: {description}")

    # --- Layer 5: Content scripts injected into all pages ------------------
    for cs in manifest.content_scripts:
        matches = cs.get("matches", [])
        if "<all_urls>" in matches or "*://*/*" in matches:
            if "content_scripts_all_urls" not in breakdown:
                breakdown["content_scripts_all_urls"] = 15
                notes.append(
                    "Content script injected into ALL pages - "
                    "DOM/form/credential access on every site"
                )

    # --- Layer 6: Persistent background page (MV2 only, but still dangerous) -
    bg = manifest.background
    if bg.get("persistent", False):
        breakdown["persistent_background"] = 8
        notes.append(
            "Persistent background page - always-on monitoring, "
            "survives tab close (deprecated but still functional in MV2)"
        )

    # --- Clamp total to 0–100 ----------------------------------------------
    total = sum(breakdown.values())
    total = max(0, min(100, total))

    return PermissionScore(
        total_score         = total,
        risk_level          = _score_to_level(total),
        flagged_permissions = flagged,
        breakdown           = breakdown,
        notes               = notes,
    )


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
