# osv_lookup.py - OSV / CVE hash-based threat intelligence lookup
#
# Three checks in this module:
#   1. SHA-256 hash the extension ZIP and query OSV.dev for known malicious hashes
#   2. Scan the extension's bundled files for npm package references,
#      then check those package versions against OSV
#   3. Flag suspicious external JS CDN URLs (an alternate supply chain vector)
#
# OSV API docs: https://google.github.io/osv.dev/api/
# Endpoint:     POST https://api.osv.dev/v1/query
#
# Why OSV and not VirusTotal?
#   OSV is free, requires no API key, and focuses on supply chain vulnerabilities.
#   VirusTotal is better for binary malware — add as an optional enhancement
#   once you have a VT key.

import hashlib
import io
import json
import re
import zipfile

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False


OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

# CDN domains that commonly host third-party JS — unusual in production extensions
# (legitimate extensions bundle their dependencies rather than loading from CDN)
SUSPICIOUS_CDN_PATTERNS = [
    r"cdn\.jsdelivr\.net",
    r"unpkg\.com",
    r"cdnjs\.cloudflare\.com",
    r"code\.jquery\.com",
    r"ajax\.googleapis\.com",
    r"raw\.githubusercontent\.com",
    r"gist\.githubusercontent\.com",
]

# File extensions we'll scan inside the ZIP for npm package metadata
JS_PACKAGE_FILES = {"package.json", "package-lock.json"}

# Request timeout — OSV API is generally fast
REQUEST_TIMEOUT = 8   # seconds


def run_osv_checks(
    zip_bytes: bytes | None,
    manifest_raw: dict,
    vt_cfg: dict | None = None,
) -> dict:
    """
    Run all OSV / hash checks and return a result summary.

    Args:
        zip_bytes:    Raw ZIP bytes of the extension archive (None for bare manifests).
        manifest_raw: The raw parsed manifest dict.
        vt_cfg:       Optional VirusTotal config dict. When provided AND a
                      usable API key is available (env or cfg), also queries VT.

    Returns dict with keys:
      zip_hash          str    SHA-256 hex of the ZIP
      osv_zip_matches   list   OSV findings for the ZIP hash
      npm_packages      list   Package refs found inside the extension
      osv_pkg_matches   list   OSV findings for those packages
      cdn_refs          list   Suspicious CDN URLs found in JS files
      vt                dict   VirusTotal result (always present, may be empty)
      osv_score         int    0-30 risk contribution from this module
      flags             list[str]
    """
    result = {
        "zip_hash":        None,
        "osv_zip_matches": [],
        "npm_packages":    [],
        "osv_pkg_matches": [],
        "cdn_refs":        [],
        "vt":              {"queried": False},
        "osv_score":       0,
        "flags":           [],
    }

    if zip_bytes is None:
        result["flags"].append("No ZIP bytes available — skipping hash checks (bare manifest)")
        return result

    # --- 1. Hash the full ZIP archive -------------------------------------
    zip_sha256 = hashlib.sha256(zip_bytes).hexdigest()
    result["zip_hash"] = zip_sha256

    # --- 2. Query OSV for the ZIP hash ------------------------------------
    if _REQUESTS_AVAILABLE:
        zip_hits = _query_osv_hash(zip_sha256)
        result["osv_zip_matches"] = zip_hits
        if zip_hits:
            result["osv_score"] += 30   # Direct hash match = confirmed threat
            result["flags"].append(
                f"CONFIRMED: Extension ZIP hash matches {len(zip_hits)} OSV record(s): "
                + ", ".join(h.get("id", "?") for h in zip_hits)
            )

    # --- 2b. Query VirusTotal for the ZIP hash (optional) -----------------
    # OSV doesn't index most CRX hashes; VT does. Only runs when caller passed
    # a vt_cfg dict (signalling they want VT lookups) AND a key is available.
    if vt_cfg is not None and vt_cfg.get("enabled", False) and _REQUESTS_AVAILABLE:
        # Lazy import to keep the module loadable when virustotal_lookup is absent
        from virustotal_lookup import lookup_hash as _vt_lookup
        vt_result = _vt_lookup(zip_sha256, vt_cfg)
        result["vt"] = dict(vt_result)
        result["vt"]["queried"] = True
        # VT contributes its own 0-30 score; cap the combined total at 30 so
        # we don't double-count when both OSV and VT agree
        if vt_result["score"]:
            result["osv_score"] = min(30, result["osv_score"] + vt_result["score"])
        for flag in vt_result.get("flags", []):
            result["flags"].append(flag)

    # --- 3. Scan ZIP contents for npm packages and CDN refs ---------------
    npm_packages, cdn_refs = _scan_zip_contents(zip_bytes)
    result["npm_packages"] = npm_packages
    result["cdn_refs"]     = cdn_refs

    if cdn_refs:
        result["osv_score"] += min(len(cdn_refs) * 5, 15)
        for ref in cdn_refs:
            result["flags"].append(
                f"External CDN JS reference: {ref} — "
                "extension loads code from outside its own package"
            )

    # --- 4. Check npm packages against OSV --------------------------------
    if npm_packages and _REQUESTS_AVAILABLE:
        pkg_hits = _query_osv_packages_batch(npm_packages)
        result["osv_pkg_matches"] = pkg_hits
        if pkg_hits:
            result["osv_score"] += 10
            for hit in pkg_hits:
                pkg   = hit.get("_package", "unknown")
                vuln  = hit.get("id", "unknown")
                result["flags"].append(
                    f"Bundled npm package {pkg} has known vulnerability {vuln}"
                )

    # Ceiling: 30 total points from this module (OSV + VT combined).
    # OSV-only used to cap at 20; we raised to 30 to make headroom for VT
    # without changing the overall Stage 1 composite scaling.
    result["osv_score"] = min(result["osv_score"], 30)
    return result


# ---------------------------------------------------------------------------
# ZIP scanning
# ---------------------------------------------------------------------------

def _scan_zip_contents(zip_bytes: bytes) -> tuple:
    """
    Open the extension ZIP and:
      - Parse any package.json files to find npm dependencies
      - Scan JS files for external CDN URL references
    Returns (npm_packages, cdn_refs).
    """
    npm_packages = []   # list of {"name": str, "version": str, "ecosystem": "npm"}
    cdn_refs     = []   # list of suspicious CDN URL strings

    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            for name in zf.namelist():
                # --- npm package metadata ---
                basename = name.split("/")[-1]
                if basename in JS_PACKAGE_FILES:
                    try:
                        pkg_data = json.loads(zf.read(name))
                        # Collect direct + dev dependencies
                        deps = {}
                        deps.update(pkg_data.get("dependencies", {}))
                        deps.update(pkg_data.get("devDependencies", {}))
                        for pkg_name, version_spec in deps.items():
                            # Strip semver range prefixes like ^, ~, >=
                            version = re.sub(r"[^0-9.]", "", version_spec.split(" ")[0])
                            if version:
                                npm_packages.append({
                                    "name":      pkg_name,
                                    "version":   version,
                                    "ecosystem": "npm",
                                })
                    except (json.JSONDecodeError, KeyError):
                        pass

                # --- CDN URL scanning in JS files ---
                if name.endswith(".js") or name.endswith(".ts"):
                    try:
                        content = zf.read(name).decode("utf-8", errors="ignore")
                        for pattern in SUSPICIOUS_CDN_PATTERNS:
                            matches = re.findall(
                                r'https?://' + pattern + r'[^\s\'"]+',
                                content
                            )
                            cdn_refs.extend(matches)
                    except Exception:
                        pass

    except zipfile.BadZipFile:
        pass

    return npm_packages, list(set(cdn_refs))   # deduplicate CDN refs


# ---------------------------------------------------------------------------
# OSV API queries
# ---------------------------------------------------------------------------

def _query_osv_hash(sha256_hex: str) -> list:
    """
    Query OSV for a specific file hash.
    Returns list of OSV vulnerability records (may be empty).
    """
    payload = {
        "hash": {
            "type":  "sha256",
            "value": sha256_hex,
        }
    }
    return _post_osv(OSV_QUERY_URL, payload)


def _query_osv_packages_batch(packages: list) -> list:
    """
    Batch-query OSV for a list of npm packages.
    Uses the /querybatch endpoint to minimise round trips.
    Returns a flat list of OSV findings, each with an added '_package' field.
    """
    # Build batch query — OSV limits to ~1000 queries per batch, we're fine
    queries = []
    for pkg in packages[:50]:   # Cap at 50 to avoid huge requests
        queries.append({
            "package": {
                "name":      pkg["name"],
                "ecosystem": pkg["ecosystem"],
            },
            "version": pkg["version"],
        })

    if not queries:
        return []

    payload  = {"queries": queries}
    all_hits = []

    try:
        resp = requests.post(OSV_BATCH_URL, json=payload, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            return []

        data    = resp.json()
        results = data.get("results", [])

        for i, result_set in enumerate(results):
            vulns = result_set.get("vulns", [])
            for vuln in vulns:
                pkg_name = packages[i]["name"] if i < len(packages) else "unknown"
                vuln["_package"] = pkg_name
                all_hits.append(vuln)

    except Exception:
        pass

    return all_hits


def _post_osv(url: str, payload: dict) -> list:
    """
    POST to the OSV API and return the vulns array.
    Returns empty list on error or no matches.
    """
    try:
        resp = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            return []
        data = resp.json()
        return data.get("vulns", [])
    except Exception:
        return []
