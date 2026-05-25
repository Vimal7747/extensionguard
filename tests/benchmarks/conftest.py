# tests/benchmarks/conftest.py - Fixtures for the perf benchmark suite
#
# Kept separate from the unit-test conftest so benchmark runs don't pull in
# the heavier unit-test fixtures, and so we can give the benchmark fixtures
# real-world-sized payloads (a full CRX, not a 3-line manifest).

import io
import json
import struct
import sys
import zipfile
from pathlib import Path

import pytest

# Put project root on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ---------------------------------------------------------------------------
# Representative payloads
# ---------------------------------------------------------------------------


@pytest.fixture
def teamccp_manifest() -> dict:
    """The TeamPCP malicious manifest profile used throughout the test suite."""
    return {
        "manifest_version": 2,
        "name": "Nx Console (SIMULATED MALICIOUS)",
        "version": "17.3.1",
        "description": "Compromised Nx Console build",
        "background": {"scripts": ["background.js"], "persistent": True},
        "permissions": [
            "cookies",
            "tabs",
            "storage",
            "webRequest",
            "webRequestBlocking",
            "history",
            "<all_urls>",
        ],
        "content_scripts": [
            {
                "matches": ["<all_urls>"],
                "js": ["content.js"],
                "run_at": "document_idle",
            }
        ],
        "update_url": "https://clients2.google.com/service/update2/crx",
    }


@pytest.fixture
def medium_crx_bytes(teamccp_manifest) -> bytes:
    """
    A realistic-sized CRX (~50 KB inner ZIP). Contains the malicious manifest
    plus a 40 KB padding file so the parser does some actual work, not just
    handle a 200-byte stub.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(teamccp_manifest))
        zf.writestr("background.js", "// fake bg script\n" * 100)
        # 40 KB of padding to simulate a real extension's JS bundle
        zf.writestr("bundle.js", "x" * (40 * 1024))

    crx = (
        b"Cr24"
        + struct.pack("<I", 3)  # version
        + struct.pack("<I", 0)  # header_length (no signing for bench)
        + buf.getvalue()
    )
    return crx


@pytest.fixture
def sample_alert() -> dict:
    """A realistic Stage 3 alert used to benchmark Stage 4 dispatch."""
    return {
        "alert_time": "2026-05-23T10:30:00+00:00",
        "rule": "RULE-01",
        "severity": "critical",
        "extension": {
            "id": "abcdefghijklmnopqrstuvwxyzabcdef",
            "title": "Nx Console (SIMULATED MALICIOUS)",
            "url": "chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef/sw.js",
            "type": "service_worker",
        },
        "detail": {
            "description": "Periodic POST to known exfil domain - C2 beacon pattern",
            "url": "https://evil-tenant.workers.dev/collect",
            "host": "evil-tenant.workers.dev",
            "interval_sec": 60.1,
            "post_count": 4,
            "mitre_note": "Matches TeamPCP 60-second beacon to *.workers.dev",
        },
        "mitre": ["T1071.001", "T1176"],
    }
