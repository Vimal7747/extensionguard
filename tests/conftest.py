# tests/conftest.py - Shared pytest fixtures for the ExtensionGuard test suite
#
# Fixtures defined here are automatically available to every test file in the
# tests/ directory. We use this to:
#   1. Add the project root to sys.path so tests can `import crx_parser` etc.
#   2. Provide canned manifests / CRX bytes that match real-world attack patterns
#   3. Provide a temp quarantine dir per-test so file IO doesn't bleed across tests

import io
import json
import struct
import sys
import zipfile
from pathlib import Path

import pytest

# --- Put the project root on sys.path so `import crx_parser` works -----------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ---------------------------------------------------------------------------
# Canned manifest fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def benign_manifest_raw() -> dict:
    """A boring MV3 dark-mode extension - should score LOW."""
    return {
        "manifest_version": 3,
        "name": "Dark Mode for Docs",
        "version": "2.1.0",
        "description": "Applies dark mode to Google Docs",
        "background": {"service_worker": "background.js"},
        "permissions": ["storage"],
        "host_permissions": ["*://docs.google.com/*"],
        "content_scripts": [
            {
                "matches": ["*://docs.google.com/*"],
                "js": ["content.js"],
                "run_at": "document_idle",
            }
        ],
        "update_url": "https://clients2.google.com/service/update2/crx",
    }


@pytest.fixture
def teamccp_manifest_raw() -> dict:
    """The TeamPCP supply-chain attack permission profile - should score CRITICAL."""
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
def shai_hulud_manifest_raw() -> dict:
    """The Shai-Hulud malware family profile - debugger + nativeMessaging."""
    return {
        "manifest_version": 2,
        "name": "React DevTools (TYPOSQUAT)",
        "version": "0.0.5",
        "background": {"scripts": ["background.js"], "persistent": True},
        "permissions": ["debugger", "nativeMessaging", "tabs", "storage"],
        "host_permissions": [],
    }


@pytest.fixture
def suspicious_update_url_manifest_raw() -> dict:
    """Manifest with a Cloudflare Workers update URL - red flag."""
    return {
        "manifest_version": 3,
        "name": "Definitely Not Malware",
        "version": "1.0.0",
        "permissions": ["storage"],
        "host_permissions": ["<all_urls>"],
        "update_url": "https://evil-tenant.workers.dev/update",
    }


# ---------------------------------------------------------------------------
# Real ZIP bytes for CRX-parsing tests
# ---------------------------------------------------------------------------


@pytest.fixture
def benign_zip_bytes(benign_manifest_raw) -> bytes:
    """A valid ZIP archive containing manifest.json - what's inside a CRX."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("manifest.json", json.dumps(benign_manifest_raw))
        zf.writestr("background.js", "// noop\n")
    return buf.getvalue()


@pytest.fixture
def crx3_bytes(benign_zip_bytes) -> bytes:
    """
    A minimally-valid CRX3 file:
      [4] "Cr24" magic
      [4] version=3 (little-endian uint32)
      [4] header_length=0 (skip signing proto for tests)
      [N] ZIP archive
    The header_length=0 case is valid - no signing data, just go straight to ZIP.
    """
    magic = b"Cr24"
    version = struct.pack("<I", 3)
    header_length = struct.pack("<I", 0)
    return magic + version + header_length + benign_zip_bytes


@pytest.fixture
def crx2_bytes(benign_zip_bytes) -> bytes:
    """Legacy CRX2 format - still seen in the wild."""
    magic = b"Cr24"
    version = struct.pack("<I", 2)
    pubkey_len = struct.pack("<I", 0)
    sig_len = struct.pack("<I", 0)
    return magic + version + pubkey_len + sig_len + benign_zip_bytes


# ---------------------------------------------------------------------------
# Keep every test away from the developer's real ~/.extguard
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_extguard_home(tmp_path, monkeypatch):
    """
    Point every per-user location at a temp dir so no test ever reads or
    writes the developer's real ~/.extguard (config, quarantine, history,
    synced TTP intel, chain-of-custody key).
    Module-level constants were computed at import time, so patch those too.
    """
    from extguard import update_velocity
    from extguard.remediators import forensics

    home = tmp_path / "extguard_home"
    monkeypatch.setenv("EXTGUARD_HOME", str(home))
    for var in ("EXTGUARD_CONFIG", "EXTGUARD_QUARANTINE", "EXTGUARD_TTP_DIR"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("EXTGUARD_COC_KEY", "test-only-coc-key")
    monkeypatch.setattr(forensics, "COC_KEY_FILE", home / "coc_hmac.key")
    monkeypatch.setattr(forensics, "DEFAULT_QUARANTINE_ROOT", home / "quarantine")
    monkeypatch.setattr(update_velocity, "HISTORY_FILE", home / "version_history.json")
    # A config file in the directory pytest runs from must not leak into tests
    monkeypatch.chdir(tmp_path)


# ---------------------------------------------------------------------------
# Temp directories for stateful tests
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_quarantine(tmp_path):
    """Per-test quarantine directory - tmp_path is auto-cleaned by pytest."""
    qdir = tmp_path / "quarantine"
    qdir.mkdir()
    return qdir


@pytest.fixture
def temp_history_file(tmp_path, monkeypatch):
    """
    Redirect ~/.extguard/version_history.json to a temp file so tests don't
    pollute the developer's real history store. Uses monkeypatch so the
    override is reverted after the test.
    """
    from extguard import update_velocity

    history_path = tmp_path / "version_history.json"
    monkeypatch.setattr(update_velocity, "HISTORY_FILE", history_path)
    return history_path


# ---------------------------------------------------------------------------
# Canned triage / alert fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_triage_result() -> dict:
    """A realistic triage JSON as produced by main.py --json."""
    return {
        "extension_name": "Nx Console (SIMULATED MALICIOUS)",
        "file_path": "test.crx",
        "composite_score": 100,
        "ai_risk_score": 95,
        "risk_level": "critical",
        "mitre_techniques": ["T1176", "T1555.003", "T1071.001"],
        "iocs": ["Permission combo matches TeamPCP TTP"],
        "analyst_narrative": "This extension exhibits the TeamPCP attack profile.",
        "stage_1_checks": {
            "publisher": {"extension_id": "abcdefghijklmnopqrstuvwxyzabcdef"},
        },
        "manifest_summary": {
            "name": "Nx Console (SIMULATED MALICIOUS)",
            "version": "17.3.1",
            "manifest_version": 2,
            "permissions": ["cookies", "tabs", "storage", "webRequest"],
            "host_permissions": ["<all_urls>"],
        },
    }


@pytest.fixture
def sample_alert() -> dict:
    """A standard behavioral_monitor alert dict."""
    return {
        "alert_time": "2026-05-22T10:30:00+00:00",
        "rule": "RULE-01",
        "severity": "critical",
        "extension": {
            "id": "abcdefghijklmnopqrstuvwxyzabcdef",
            "title": "Nx Console",
            "url": "chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef/background.js",
            "type": "service_worker",
        },
        "detail": {
            "description": "Periodic POST to known exfil domain",
            "url": "https://evil.workers.dev/collect",
            "host": "evil.workers.dev",
            "interval_sec": 60.1,
            "post_count": 3,
        },
        "mitre": ["T1071.001", "T1176"],
    }
