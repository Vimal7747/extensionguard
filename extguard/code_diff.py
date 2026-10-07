# code_diff.py - Stage 1f: static code analysis + version-to-version code diff
#
# Why this stage exists:
#   A hijacked update of a legitimate extension (Cyberhaven, Dec 2024; the
#   TeamPCP / Nx Console scenario) usually keeps the SAME permissions and the
#   same name, and ships as an ordinary patch bump. Every manifest-level check
#   scores it exactly like the clean version before it. The change is in the
#   JavaScript - so this stage reads the JavaScript.
#
# Two kinds of findings:
#   1. Absolute (no history needed) - code that talks to exfil-style
#      destinations (Discord/Telegram webhooks, throwaway hosting like
#      *.workers.dev), heavily obfuscated files, remote code loading.
#   2. Diff against the last ACCEPTED build of the same extension - new
#      network endpoints, newly used credential/injection APIs, newly
#      obfuscated files, how much of the package changed.
#
# Baselines ("code profiles") are stored per extension in
#   $EXTGUARD_HOME/code_profiles/<key>.json
# and only written by main.py when the final verdict is low/medium, so a
# malicious build can't become the reference for the next comparison.
#
# This is pattern matching, not a JavaScript parser: minified or obfuscated
# code can hide what it does. That is exactly why obfuscation itself is a signal.

import hashlib
import io
import json
import re
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from extguard import paths
from extguard.crx_parser import MAX_MEMBER_BYTES, check_zip_limits, read_zip_member
from extguard.update_velocity import history_key

PROFILE_DIR = paths.data_dir() / "code_profiles"

# Files we read, and the scanning budget
CODE_SUFFIXES = (".js", ".mjs", ".cjs", ".html", ".htm")
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_TOTAL_BYTES = 200 * 1024 * 1024

# Hosting / services that attackers use as drop points. A legitimate
# extension almost never hard-codes these.
EXFIL_HOST_PATTERNS = [
    r"\.workers\.dev$",
    r"\.pages\.dev$",
    r"\.trycloudflare\.com$",
    r"\.ngrok\.io$",
    r"\.ngrok-free\.app$",
    r"\.loca\.lt$",
    r"\.glitch\.me$",
    r"\.repl\.co$",
    r"\.vercel\.app$",
    r"\.netlify\.app$",
    r"(^|\.)webhook\.site$",
    r"(^|\.)requestbin\.",
    r"(^|\.)pipedream\.net$",
    r"(^|\.)m\.pipedream\.net$",
    r"(^|\.)api\.telegram\.org$",
    r"(^|\.)discord(app)?\.com$",  # only counted when the path is /api/webhooks
]
_EXFIL_RE = [re.compile(p, re.IGNORECASE) for p in EXFIL_HOST_PATTERNS]

# Hosts that appear in comments, licences and doc links in almost every bundle
IGNORED_HOSTS = {
    "www.w3.org",
    "w3.org",
    "schema.org",
    "json-schema.org",
    "reactjs.org",
    "react.dev",
    "fb.me",
    "developer.mozilla.org",
    "mozilla.org",
    "developer.chrome.com",
    "opensource.org",
    "www.apache.org",
    "apache.org",
    "example.com",
    "www.example.com",
    "localhost",
    "127.0.0.1",
    "github.com",
    "npms.io",
    "tc39.es",
    "html.spec.whatwg.org",
    "feross.org",
    "jquery.org",
    "lodash.com",
    "underscorejs.org",
    "momentjs.com",
}

# Sensitive capabilities: name -> (regex, points when NEWLY used in an update)
SENSITIVE_APIS = {
    "chrome.cookies": (r"\bchrome\.cookies\.(?:get|getAll|set|getAllCookieStores)\b", 10),
    "document.cookie": (r"\bdocument\.cookie\b", 8),
    "chrome.scripting.executeScript": (r"\bchrome\.scripting\.executeScript\b", 10),
    "chrome.debugger": (r"\bchrome\.debugger\.(?:attach|sendCommand)\b", 10),
    "chrome.management": (r"\bchrome\.management\.(?:setEnabled|uninstall|getAll)\b", 8),
    "chrome.identity.getAuthToken": (r"\bchrome\.identity\.getAuthToken\b", 8),
    "chrome.webRequest listener": (r"\bchrome\.webRequest\.on\w+\.addListener\b", 6),
    "eval": (r"(?<![\w.])eval\s*\(", 8),
    "new Function": (r"\bnew\s+Function\s*\(", 8),
    "WebSocket": (r"\bnew\s+WebSocket\s*\(", 6),
    "navigator.sendBeacon": (r"\bnavigator\.sendBeacon\s*\(", 6),
    "remote importScripts": (r"\bimportScripts\s*\(\s*['\"`]https?://", 10),
    "remote <script src>": (r"<script[^>]+src\s*=\s*['\"]https?://", 10),
}
_API_RE = {name: re.compile(rx) for name, (rx, _) in SENSITIVE_APIS.items()}

_URL_RE = re.compile(r"""https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?::\d+)?(/[^\s'"`<>)\\]*)?""")

# A URL inside a CSS attribute selector - [href^="https://bad.example/"] - is
# something a content blocker HIDES, not a place the extension sends data.
# uBlock Origin Lite ships thousands of these; counting them as endpoints
# flagged it for "exfil to *.pages.dev" and made every filter-list update look
# like new destinations.
_SELECTOR_CONTEXT = re.compile(r"""\[\s*[\w:-]+\s*[\^$*|~]?=\s*(?:\\*["'])?$""")

# Obfuscation fingerprints
_OBF_HEX_IDENT = re.compile(r"\b_0x[0-9a-f]{4,6}\b")  # javascript-obfuscator
_OBF_HEX_ESCAPE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")
_OBF_LONG_B64 = re.compile(r"['\"`][A-Za-z0-9+/]{400,}={0,2}['\"`]")
# A long base64 string on its own is NOT obfuscation - bundles embed protobuf
# descriptors, fonts and images that way (Grammarly, Bitwarden). It only
# counts when the file also decodes-and-runs: eval(atob(..)), Function(atob(..))
# or the classic eval(function(p,a,c,k,e,..)) packer.
_OBF_DECODE_AND_RUN = re.compile(
    r"\b(?:eval|Function)\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\("
    r"|\beval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,"
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyse_code(
    zip_bytes: bytes | None,
    extension_id: str | None,
    extension_name: str | None,
    version: str,
    file_sha256: str | None = None,
) -> dict:
    """
    Profile the package's code and compare it with the stored baseline.

    Returns dict with keys:
      profile          dict  (what record_profile() would save)
      baseline_version str or None
      new_hosts        list  endpoints not present in the baseline
      new_apis         list  sensitive APIs not used by the baseline
      new_exfil_endpoints list  exfil-style endpoints the baseline didn't use
      review_needed    bool  the update changed endpoints / APIs / obfuscation,
                             so it must not silently become the new baseline
      changed_files    int   files added/removed/modified vs baseline
      code_score       int   0-30 risk contribution
      flags            list[str]
    Never raises: problems reading the archive are reported in flags.
    """
    result = {
        "profile": None,
        "baseline_version": None,
        "new_hosts": [],
        "new_apis": [],
        "new_exfil_endpoints": [],
        "review_needed": False,
        "changed_files": 0,
        "code_score": 0,
        "flags": [],
    }
    if zip_bytes is None:
        result["flags"].append("No archive - code analysis skipped (bare manifest)")
        return result

    profile, errors = build_profile(zip_bytes, version, file_sha256)
    result["profile"] = profile
    for err in errors:
        result["flags"].append(f"Code scan incomplete: {err}")

    score = 0

    # --- 1. Absolute findings ---------------------------------------------
    if profile["exfil_endpoints"]:
        score += min(15 * len(profile["exfil_endpoints"]), 20)
        for endpoint in profile["exfil_endpoints"]:
            result["flags"].append(
                f"Code sends data to an exfil-style destination: {endpoint} "
                "(webhook / throwaway hosting, rarely used by legitimate extensions)"
            )
    if profile["obfuscated_files"]:
        score += 10
        result["flags"].append(
            f"Heavily obfuscated code in {len(profile['obfuscated_files'])} file(s): "
            + ", ".join(profile["obfuscated_files"][:5])
        )
    for remote in ("remote importScripts", "remote <script src>"):
        if profile["apis"].get(remote):
            score += 10
            result["flags"].append(
                f"Loads code from a remote server ({remote}) - Manifest V3 forbids this"
            )

    # --- 2. Diff against the accepted baseline -----------------------------
    baseline = load_profile(extension_id, extension_name)
    if baseline and baseline.get("files") != profile["files"]:
        result["baseline_version"] = baseline.get("version")
        score += _diff_findings(baseline, profile, result)

    result["code_score"] = min(score, 30)
    return result


def build_profile(zip_bytes: bytes, version: str, file_sha256: str | None = None) -> tuple:
    """Scan the package once. Returns (profile_dict, list_of_errors)."""
    files: dict = {}
    hosts: set = set()
    exfil: set = set()
    apis: dict = {}
    obfuscated: list = []
    errors: list = []
    scanned = 0

    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            check_zip_limits(zf)
            for info in zf.infolist():
                if info.is_dir():
                    continue
                name = info.filename
                is_code = name.lower().endswith(CODE_SUFFIXES)
                # Every file is hashed (to see what changed between versions);
                # only code is scanned. Non-code files - source maps, images,
                # fonts - only need the archive's normal per-file limit:
                # Bitwarden's 12 MB .map files are not "unscanned code".
                limit = MAX_FILE_BYTES + 1 if is_code else MAX_MEMBER_BYTES
                try:
                    data = read_zip_member(zf, info, limit)
                except (ValueError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as exc:
                    errors.append(f"{name}: {exc}")
                    continue
                files[name] = hashlib.sha256(data).hexdigest()

                if not is_code:
                    continue
                if len(data) > MAX_FILE_BYTES:
                    errors.append(f"{name} too large to scan ({len(data):,} bytes)")
                    continue
                if scanned + len(data) > MAX_TOTAL_BYTES:
                    errors.append("scan budget reached - remaining files not scanned")
                    break
                scanned += len(data)
                text = data.decode("utf-8", errors="ignore")
                _scan_text(name, text, hosts, exfil, apis, obfuscated)
    except (ValueError, zipfile.BadZipFile) as exc:
        errors.append(str(exc))

    profile = {
        "version": version,
        "file_sha256": file_sha256,
        "created": datetime.now(timezone.utc).isoformat(),
        "files": files,
        "hosts": sorted(hosts),
        "exfil_endpoints": sorted(exfil),
        "apis": apis,
        "obfuscated_files": sorted(obfuscated),
    }
    return profile, errors


def record_profile(extension_id: str | None, extension_name: str | None, profile: dict) -> bool:
    """Save a profile as the accepted baseline (atomic write). False if no identity."""
    path = _profile_path(extension_id, extension_name)
    if path is None or not profile:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False, suffix=".tmp"
    ) as tmp:
        json.dump(profile, tmp, indent=1)
    Path(tmp.name).replace(path)
    return True


def load_profile(extension_id: str | None, extension_name: str | None) -> dict | None:
    path = _profile_path(extension_id, extension_name)
    if path is None or not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _scan_text(name, text, hosts, exfil, apis, obfuscated):
    for match in _URL_RE.finditer(text):
        host = match.group(1).lower().rstrip(".")
        path = match.group(2) or ""
        if host in IGNORED_HOSTS:
            continue
        if _SELECTOR_CONTEXT.search(text[max(0, match.start() - 24) : match.start()]):
            continue  # a CSS selector naming a link to hide, not a destination
        hosts.add(host)
        if _is_exfil(host, path):
            exfil.add(host + (path[:60] if "webhook" in path or "bot" in path else ""))

    for api, regex in _API_RE.items():
        count = len(regex.findall(text))
        if count:
            apis[api] = apis.get(api, 0) + count

    if (
        len(_OBF_HEX_IDENT.findall(text)) >= 25
        or len(_OBF_HEX_ESCAPE.findall(text)) >= 10
        or (_OBF_LONG_B64.search(text) and _OBF_DECODE_AND_RUN.search(text))
    ):
        obfuscated.append(name)


def _is_exfil(host: str, path: str) -> bool:
    for regex in _EXFIL_RE:
        if regex.search(host):
            if "discord" in regex.pattern:
                return "/api/webhooks" in path
            if "telegram" in regex.pattern:
                return "/bot" in path
            return True
    return False


def _diff_findings(baseline: dict, profile: dict, result: dict) -> int:
    score = 0
    old_files = baseline.get("files", {}) or {}
    new_files = profile["files"]
    changed = sum(1 for f in new_files if old_files.get(f) != new_files[f])
    changed += sum(1 for f in old_files if f not in new_files)
    result["changed_files"] = changed

    base_label = baseline.get("version", "?")
    # An update that STARTS sending data to exfil-style hosting is the
    # Cyberhaven pattern: main.py raises the verdict to at least HIGH for it
    result["new_exfil_endpoints"] = sorted(
        set(profile["exfil_endpoints"]) - set(baseline.get("exfil_endpoints", []))
    )
    new_hosts = sorted(set(profile["hosts"]) - set(baseline.get("hosts", [])))
    if new_hosts:
        result["new_hosts"] = new_hosts
        score += 10 if len(new_hosts) < 3 else 15
        result["flags"].append(
            f"Update talks to {len(new_hosts)} endpoint(s) not in {base_label}: "
            + ", ".join(new_hosts[:8])
        )

    old_apis = baseline.get("apis", {}) or {}
    new_apis = sorted(a for a in profile["apis"] if not old_apis.get(a))
    if new_apis:
        result["new_apis"] = new_apis
        score += min(sum(SENSITIVE_APIS[a][1] for a in new_apis if a in SENSITIVE_APIS), 20)
        result["flags"].append(
            f"Update starts using sensitive APIs not used by {base_label}: " + ", ".join(new_apis)
        )

    newly_obfuscated = sorted(
        set(profile["obfuscated_files"]) - set(baseline.get("obfuscated_files", []))
    )
    if newly_obfuscated:
        score += 10
        result["flags"].append("Update adds obfuscated code: " + ", ".join(newly_obfuscated[:5]))

    if (new_hosts or new_apis) and changed:
        result["flags"].append(
            f"{changed} file(s) changed since {base_label} - new endpoints / capabilities "
            "in an update is the shape of a hijacked release"
        )
    # Changes like these must be reviewed before this build replaces the
    # baseline - otherwise the next scan compares against the attacker's code
    result["review_needed"] = bool(new_hosts or new_apis or newly_obfuscated)
    return score


def _profile_path(extension_id: str | None, extension_name: str | None) -> Path | None:
    key = history_key(extension_id, extension_name)
    if key is None:
        return None
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", key)[:100]
    return PROFILE_DIR / f"{safe}.json"
