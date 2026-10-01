# tests/test_live_apis.py - Contract tests against the REAL external services
#
# Everything else in the suite mocks HTTP. Mocks only prove the code matches
# our *assumptions* about an API - which is how the OSV hash lookup shipped
# broken (OSV never supported it) while its tests stayed green.
#
# These tests talk to the live services, so they are OFF by default:
#   EXTGUARD_LIVE_TESTS=1 pytest -m live          (PowerShell: $env:EXTGUARD_LIVE_TESTS=1)
# A weekly GitHub Actions job (.github/workflows/live-api.yml) runs them too.
# If one fails, an upstream API changed: refresh tests/fixtures/recorded/ and
# fix the parser - don't just update the assertion.

import hashlib
import os
import re

import pytest

requests = pytest.importorskip("requests")

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("EXTGUARD_LIVE_TESTS") != "1",
        reason="live API tests are opt-in: set EXTGUARD_LIVE_TESTS=1",
    ),
]

# Google Translate - a long-lived, first-party Web Store extension
KNOWN_ID = "aapbdbdomjkkjkaonfhkkikfgjllcleb"
UNKNOWN_ID = "a" * 32


def test_osv_querybatch_contract():
    from extguard.osv_lookup import _query_osv_packages_batch

    hits, error = _query_osv_packages_batch(
        [{"name": "lodash", "version": "4.17.20", "ecosystem": "npm"}]
    )
    assert error is None
    assert hits, "lodash 4.17.20 has published advisories - OSV should return them"


def test_osv_still_has_no_hash_lookup():
    """If this starts passing a hash query, OSV added the feature: revisit Stage 1d."""
    resp = requests.post(
        "https://api.osv.dev/v1/query",
        json={"hash": {"type": "sha256", "value": "0" * 64}},
        timeout=20,
    )
    assert resp.status_code == 400


def test_cws_known_and_unknown_ids():
    from extguard.publisher_checker import _query_cws

    known = _query_cws(KNOWN_ID, timeout=20)
    assert known["exists"] is True
    assert known["version"]
    assert re.fullmatch(r"[0-9a-f]{64}", known["sha256"] or "")

    assert _query_cws(UNKNOWN_ID, timeout=20)["exists"] is False


def test_real_crx_end_to_end(tmp_path):
    """Download a real .crx from the Web Store, then check that ExtensionGuard
    derives the right ID from its signing header and recognises it as the
    exact store build."""
    from extguard.crx_parser import parse_extension
    from extguard.publisher_checker import CWS_UPDATE_TEMPLATE, check_publisher

    xml = requests.get(CWS_UPDATE_TEMPLATE.format(ext_id=KNOWN_ID), timeout=20).text
    codebase = re.search(r'codebase="([^"]+)"', xml).group(1).replace("&amp;", "&")
    crx_path = tmp_path / "ext.crx"
    crx_path.write_bytes(requests.get(codebase, timeout=60).content)

    parsed = parse_extension(str(crx_path))
    result = check_publisher(
        parsed.manifest,
        crx_header_bytes=parsed.crx3_header,
        crx_sha256=hashlib.sha256(parsed.file_bytes).hexdigest(),
    )
    assert result["extension_id"] == KNOWN_ID
    assert result["id_source"] == "crx3-signed-id"
    assert result["store_build_match"] is True
    assert result["pub_score"] == 0
