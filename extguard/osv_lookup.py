# osv_lookup.py - Stage 1d: known-bad lookups for the extension package
#
# Checks in this module:
#   1. SHA-256 of the input FILE, looked up on VirusTotal (optional, needs a key).
#      We hash the whole file as given - for a .crx that includes the CRX
#      header - because that is what VirusTotal and the Chrome Web Store index.
#   2. Bundled npm packages (from package.json / package-lock.json inside the
#      extension) checked against OSV.dev for known vulnerabilities.
#   3. External JS CDN URLs in the extension's scripts (remote code loading).
#
# What we deliberately DON'T do any more:
#   OSV.dev has no "look up this file hash" query - POST /v1/query with a
#   {"hash": ...} body returns HTTP 400 "invalid query". An earlier version
#   sent it anyway and reported every extension as "no OSV hash matches".
#   OSV is used here only for what it actually supports: package versions.
#
# Honesty rule: a lookup that fails is reported as "error" (result unknown),
# never as a clean result.
#
# OSV API docs: https://google.github.io/osv.dev/api/

import hashlib
import io
import json
import re
import zipfile

from extguard.crx_parser import check_zip_limits, read_zip_member

try:
    import requests

    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False


OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

# OSV accepts up to 1000 queries per batch request
MAX_OSV_QUERIES = 1000

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

# Files inside the ZIP we read for npm package metadata
JS_PACKAGE_FILES = {"package.json", "package-lock.json"}

# Scanning budget: skip any single file bigger than this, and stop reading
# once this many bytes have been scanned in total.
MAX_SCAN_FILE_BYTES = 10 * 1024 * 1024
MAX_SCAN_TOTAL_BYTES = 200 * 1024 * 1024

# Request timeout — OSV API is generally fast
REQUEST_TIMEOUT = 8  # seconds

# An exact semver at the start of a dependency spec: "^1.2.3", "~1.2.3", "1.2.3-beta.1"
_EXACT_VERSION = re.compile(r"^\s*(?:[\^~]|>=|=|v)?\s*(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)")


def run_osv_checks(
    zip_bytes: bytes | None,
    manifest_raw: dict,
    vt_cfg: dict | None = None,
    file_bytes: bytes | None = None,
    network: bool = True,
) -> dict:
    """
    Run all Stage 1d checks and return a result summary.

    Args:
        zip_bytes:    ZIP payload of the extension (None for bare manifests).
        manifest_raw: The raw parsed manifest dict.
        vt_cfg:       Optional VirusTotal config dict. When provided AND a
                      usable API key is available (env or cfg), also queries VT.
        file_bytes:   The input file exactly as given (ParsedExtension.file_bytes).
                      Hashed for VirusTotal. Falls back to zip_bytes.
        network:      False = offline mode: hash and scan the archive locally,
                      but make no VirusTotal / OSV requests.

    Returns dict with keys:
      file_sha256       str    SHA-256 of the file as given (what VT indexes)
      zip_hash          str    SHA-256 of the ZIP payload
      npm_packages      list   Package refs found inside the extension
      osv_pkg_matches   list   OSV findings for those packages
      osv_pkg_status    str    "not_applicable" / "skipped" / "ok" / "error: ..."
      cdn_refs          list   Suspicious CDN URLs found in JS files
      vt                dict   VirusTotal result (always present)
      scan_errors       list   Problems reading the archive (result may be partial)
      osv_score         int    0-30 risk contribution from this module
      flags             list[str]
    """
    result = {
        "file_sha256": None,
        "zip_hash": None,
        "npm_packages": [],
        "osv_pkg_matches": [],
        "osv_pkg_status": "not_applicable",
        "cdn_refs": [],
        "vt": {"queried": False},
        "scan_errors": [],
        "osv_score": 0,
        "flags": [],
    }

    if zip_bytes is None:
        result["flags"].append("No archive available - skipping hash and package checks")
        return result

    result["zip_hash"] = hashlib.sha256(zip_bytes).hexdigest()
    result["file_sha256"] = hashlib.sha256(
        file_bytes if file_bytes is not None else zip_bytes
    ).hexdigest()

    # --- 1. VirusTotal lookup on the whole-file hash (optional) -----------
    if network and vt_cfg is not None and vt_cfg.get("enabled", False) and _REQUESTS_AVAILABLE:
        # Lazy import to keep the module loadable when virustotal_lookup is absent
        from extguard.virustotal_lookup import lookup_hash as _vt_lookup

        vt_result = _vt_lookup(result["file_sha256"], vt_cfg)
        result["vt"] = dict(vt_result)
        result["vt"]["queried"] = True
        result["osv_score"] += vt_result["score"]
        result["flags"].extend(vt_result.get("flags", []))

    # --- 2. Scan ZIP contents for npm packages and CDN refs ---------------
    npm_packages, cdn_refs, scan_errors = _scan_zip_contents(zip_bytes)
    result["npm_packages"] = npm_packages
    result["cdn_refs"] = cdn_refs
    result["scan_errors"] = scan_errors
    for err in scan_errors:
        result["flags"].append(f"Archive scan incomplete: {err}")

    if cdn_refs:
        result["osv_score"] += min(len(cdn_refs) * 5, 15)
        for ref in cdn_refs:
            result["flags"].append(
                f"External CDN JS reference: {ref} — "
                "extension loads code from outside its own package"
            )

    # --- 3. Check bundled npm packages against OSV ------------------------
    if npm_packages:
        if not network:
            result["osv_pkg_status"] = "skipped (offline)"
        elif not _REQUESTS_AVAILABLE:
            result["osv_pkg_status"] = "skipped (requests not installed)"
        else:
            pkg_hits, error = _query_osv_packages_batch(npm_packages)
            if error:
                result["osv_pkg_status"] = f"error: {error}"
                result["flags"].append(
                    f"OSV package lookup failed ({error}) - vulnerability status unknown"
                )
            else:
                result["osv_pkg_status"] = "ok"
                result["osv_pkg_matches"] = pkg_hits
                if pkg_hits:
                    result["osv_score"] += 10
                    for hit in pkg_hits:
                        result["flags"].append(
                            f"Bundled npm package {hit.get('_package', 'unknown')} has known "
                            f"vulnerability {hit.get('id', 'unknown')}"
                        )

    # Ceiling: 30 total points from this module (VT + packages + CDN combined)
    result["osv_score"] = min(result["osv_score"], 30)
    return result


# ---------------------------------------------------------------------------
# ZIP scanning
# ---------------------------------------------------------------------------


def _scan_zip_contents(zip_bytes: bytes) -> tuple:
    """
    Open the extension ZIP and:
      - Parse any package.json / package-lock.json files for npm dependencies
      - Scan JS files for external CDN URL references
    Returns (npm_packages, cdn_refs, scan_errors). Never raises - a problem
    reading the archive is reported in scan_errors instead.
    """
    npm_packages: list = []  # list of {"name", "version", "ecosystem": "npm"}
    cdn_refs: list = []
    errors: list = []
    seen: set = set()
    scanned_total = 0

    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            check_zip_limits(zf)
            for info in zf.infolist():
                name = info.filename
                basename = name.split("/")[-1]
                is_pkg = basename in JS_PACKAGE_FILES
                is_js = name.endswith((".js", ".mjs", ".ts"))
                if not (is_pkg or is_js):
                    continue
                if info.file_size > MAX_SCAN_FILE_BYTES:
                    errors.append(f"{name} skipped ({info.file_size:,} bytes, over scan limit)")
                    continue
                if scanned_total + info.file_size > MAX_SCAN_TOTAL_BYTES:
                    errors.append("total scan budget reached - remaining files not scanned")
                    break

                try:
                    data = read_zip_member(zf, info, MAX_SCAN_FILE_BYTES)
                except (ValueError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as exc:
                    errors.append(f"{name}: {exc}")
                    continue
                scanned_total += len(data)

                if is_pkg:
                    try:
                        pkg_data = json.loads(data)
                    except (ValueError, RecursionError):
                        errors.append(f"{name} is not valid JSON")
                        continue
                    for pkg_name, version in _npm_deps_from(pkg_data, basename):
                        if (pkg_name, version) not in seen:
                            seen.add((pkg_name, version))
                            npm_packages.append(
                                {"name": pkg_name, "version": version, "ecosystem": "npm"}
                            )

                if is_js:
                    content = data.decode("utf-8", errors="ignore")
                    for pattern in SUSPICIOUS_CDN_PATTERNS:
                        cdn_refs.extend(re.findall(r"https?://" + pattern + r"[^\s'\"]+", content))

    except (ValueError, zipfile.BadZipFile) as exc:
        errors.append(str(exc))

    return npm_packages, sorted(set(cdn_refs)), errors


def _npm_deps_from(pkg_data, basename: str) -> list:
    """
    Pull (name, exact_version) pairs out of a parsed package file.
      package-lock.json v2/v3: "packages": {"node_modules/x": {"version": "1.2.3"}}
      package-lock.json v1:    "dependencies": {"x": {"version": "1.2.3"}}
      package.json:            "dependencies": {"x": "^1.2.3"}  (only exact-ish specs)
    Anything with an unexpected shape is skipped rather than crashing.
    """
    deps: list = []
    if not isinstance(pkg_data, dict):
        return deps

    if basename == "package-lock.json":
        packages = pkg_data.get("packages")
        if isinstance(packages, dict):
            for path, info in packages.items():
                if not path or not isinstance(info, dict):
                    continue  # "" is the root project itself
                name = info.get("name") or path.rsplit("node_modules/", 1)[-1]
                version = info.get("version")
                if isinstance(name, str) and isinstance(version, str):
                    deps.append((name, version))
        legacy = pkg_data.get("dependencies")
        if not packages and isinstance(legacy, dict):
            for name, info in legacy.items():
                if isinstance(info, dict) and isinstance(info.get("version"), str):
                    deps.append((name, info["version"]))
        return deps

    for section in ("dependencies", "devDependencies"):
        block = pkg_data.get(section)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            if isinstance(name, str) and isinstance(spec, str):
                match = _EXACT_VERSION.match(spec)
                if match:
                    deps.append((name, match.group(1)))
    return deps


# ---------------------------------------------------------------------------
# OSV API queries
# ---------------------------------------------------------------------------


def _query_osv_packages_batch(packages: list) -> tuple:
    """
    Batch-query OSV for a list of npm packages via /v1/querybatch.

    Returns (hits, error):
      hits  - flat list of OSV findings, each with an added '_package' field
      error - None on success, or a short string describing what went wrong
    """
    queries_for = packages[:MAX_OSV_QUERIES]
    queries = [
        {
            "package": {"name": pkg["name"], "ecosystem": pkg["ecosystem"]},
            "version": pkg["version"],
        }
        for pkg in queries_for
    ]
    if not queries:
        return [], None

    try:
        resp = requests.post(OSV_BATCH_URL, json={"queries": queries}, timeout=REQUEST_TIMEOUT)
    except Exception as exc:  # network down, timeout, DNS, TLS...
        return [], f"network error: {type(exc).__name__}"
    if resp.status_code != 200:
        return [], f"HTTP {resp.status_code}"
    try:
        results = resp.json().get("results", [])
    except (ValueError, AttributeError):
        return [], "unparseable reply"

    hits = []
    for i, result_set in enumerate(results):
        if i >= len(queries_for) or not isinstance(result_set, dict):
            continue
        for vuln in result_set.get("vulns", []) or []:
            if isinstance(vuln, dict):
                pkg = queries_for[i]
                hits.append({**vuln, "_package": f"{pkg['name']}@{pkg['version']}"})
    return hits, None
