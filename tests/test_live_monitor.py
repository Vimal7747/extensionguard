# tests/test_live_monitor.py - the behavioural monitor against a REAL Chrome
#
# The unit tests drive the monitor with synthetic CDP events. They cannot
# catch protocol-level mistakes - and this code had three that only a real
# browser revealed:
#   1. resuming a duplicate auto-attach session let workers run unobserved;
#   2. NOT resuming it froze new workers forever;
#   3. awaiting Runtime.addBinding on a paused worker never returned.
#
# Branded Chrome can't load an unpacked extension, so a local origin stands
# in for one (the monitor is told to treat it as extension "aaaa..."). Every
# code path still runs for real: auto-attach with pause-on-start, the
# before-first-script hook, bindings, Network + getRequestPostData,
# Debugger.scriptParsed.
#
# Opt-in:  EXTGUARD_LIVE_TESTS=1  (and Chrome installed; set EXTGUARD_CHROME
# to its path if it isn't found automatically). Headless, throwaway profile.

import asyncio
import functools
import http.server
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("EXTGUARD_LIVE_TESTS") != "1",
        reason="live tests are opt-in: set EXTGUARD_LIVE_TESTS=1",
    ),
]

websockets = pytest.importorskip("websockets")

from extguard import behavioral_monitor as bm  # noqa: E402

FAKE_EXT = "a" * 32

PAGE = """<!doctype html><title>stand-in extension page</title>
<script>
localStorage.setItem("s_cache", "A".repeat(300));
fetch("/collect", {method: "POST", body: JSON.stringify({t: "ghp_" + "x".repeat(36)})});
eval(atob("Y29uc29sZS5sb2coImR5bmFtaWMiKQ=="));
navigator.serviceWorker.register("/sw.js");
</script>"""

WORKER = """self.addEventListener("install", () => self.skipWaiting());
fetch("/collect?from=worker", {method: "POST",
  body: "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk"});
"""


def _find_chrome():
    candidates = [
        os.environ.get("EXTGUARD_CHROME"),
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        shutil.which("google-chrome"),
        shutil.which("google-chrome-stable"),
        shutil.which("chromium"),
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    ]
    return next((c for c in candidates if c and Path(c).exists()), None)


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def site(tmp_path):
    (tmp_path / "index.html").write_text(PAGE)
    (tmp_path / "sw.js").write_text(WORKER)
    hits = []

    class Handler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            hits.append(self.path)
            self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
            self.send_response(204)
            self.end_headers()

    port = _free_port()
    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", port), functools.partial(Handler, directory=str(tmp_path))
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}/", hits
    server.shutdown()
    server.server_close()


@pytest.fixture
def chrome():
    exe = _find_chrome()
    if not exe:
        pytest.skip("Chrome not found - set EXTGUARD_CHROME")
    port = _free_port()
    profile = tempfile.mkdtemp()
    proc = subprocess.Popen(
        [
            exe,
            "--headless=new",
            f"--user-data-dir={profile}",
            f"--remote-debugging-port={port}",
            "--remote-debugging-address=127.0.0.1",
            "--no-first-run",
            "--no-default-browser-check",
            "--no-sandbox" if os.name != "nt" else "--disable-gpu",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    bm._configure_endpoint("127.0.0.1", port)
    for _ in range(60):
        try:
            yield bm.get_browser_ws_url()
            break
        except RuntimeError:
            time.sleep(0.25)
    proc.kill()
    time.sleep(0.5)
    shutil.rmtree(profile, ignore_errors=True)


def test_monitor_against_real_chrome(chrome, site, monkeypatch):
    origin, hits = site
    real = bm.ExtensionMonitor._extension_id_of
    monkeypatch.setattr(
        bm.ExtensionMonitor,
        "_extension_id_of",
        lambda self, url: (
            FAKE_EXT if isinstance(url, str) and url.startswith(origin) else real(self, url)
        ),
    )

    async def scenario():
        queue: asyncio.Queue = asyncio.Queue()
        async with websockets.connect(chrome, max_size=None) as ws:
            mon = bm.ExtensionMonitor(ws, queue, output_json=True)
            task = asyncio.create_task(mon.run())
            await asyncio.sleep(1.5)
            await mon.send("Target.createTarget", {"url": origin + "index.html"})
            await asyncio.sleep(8)
            await mon.send_quiet("Browser.close")
            task.cancel()
        alerts = []
        while not queue.empty():
            alerts.append(queue.get_nowait())
        return alerts

    alerts = asyncio.run(scenario())
    seen = {(a["rule"], a["extension"]["type"]) for a in alerts}

    # The worker was paused, hooked and then RESUMED (not frozen): it ran
    assert "/collect?from=worker" in hits, "service worker never ran - it was left paused"
    # ...and its request was observed from the start
    assert ("RULE-02", "service_worker") in seen
    # Document hook installed before the page's own script ran
    assert ("RULE-04", "page") in seen
    assert ("RULE-02", "page") in seen
    # eval() seen via Debugger.scriptParsed
    assert ("RULE-06", "page") in seen
    assert all(a["extension"]["id"] == FAKE_EXT for a in alerts)
