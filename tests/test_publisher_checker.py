# tests/test_publisher_checker.py - Tests for publisher legitimacy checks

import base64
import hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch

from extguard.crx_parser import _build_manifest_info
from extguard.publisher_checker import (
    CWS_UPDATE_URL_PREFIX,
    _compute_extension_id,
    _decode_varint,
    _parse_length_delimited_fields,
    _query_cws,
    check_publisher,
    parse_crx3_identity,
    parse_cws_update_xml,
)

# ---------------------------------------------------------------------------
# Extension ID computation
# ---------------------------------------------------------------------------


class TestExtensionId:
    """Chrome's algorithm: SHA-256 first 16 bytes -> hex -> map each digit a-p."""

    def test_known_test_vector(self):
        """For empty bytes, the ext_id must be the digit-to-letter map of
        SHA256(b'')[:16].hex(). Compute the expectation the same way the impl does
        so a typo in the expected string can't make this test wrong."""
        result = _compute_extension_id(b"")
        empty_sha = hashlib.sha256(b"").digest()[:16].hex()
        expected = "".join(chr(ord("a") + int(c, 16)) for c in empty_sha)
        assert result == expected
        # And sanity-check the format
        assert len(result) == 32
        assert all("a" <= c <= "p" for c in result)

    def test_length_is_32_chars(self):
        """Extension IDs are always exactly 32 lowercase letters."""
        for raw in [b"key1", b"key2" * 50, b"\xff" * 100]:
            ext_id = _compute_extension_id(raw)
            assert len(ext_id) == 32
            assert ext_id.islower()
            assert all("a" <= c <= "p" for c in ext_id)

    def test_deterministic(self):
        """Same key bytes must always produce the same extension ID."""
        key = b"my fake key bytes"
        assert _compute_extension_id(key) == _compute_extension_id(key)


# ---------------------------------------------------------------------------
# update_url validation
# ---------------------------------------------------------------------------


class TestUpdateUrlValidation:
    def test_official_cws_url_passes(self, benign_manifest_raw):
        manifest = _build_manifest_info(benign_manifest_raw)
        result = check_publisher(manifest, query_cws=False)
        assert result["update_url_ok"] is True
        assert not any("Non-standard update_url" in f for f in result["flags"])

    def test_workers_dev_url_flagged(self, suspicious_update_url_manifest_raw):
        manifest = _build_manifest_info(suspicious_update_url_manifest_raw)
        result = check_publisher(manifest, query_cws=False)
        assert result["suspicious_update"] is True
        assert result["pub_score"] > 0
        assert any("workers.dev" in f.lower() for f in result["flags"])

    def test_ngrok_url_flagged(self):
        manifest = _build_manifest_info(
            {
                "manifest_version": 3,
                "name": "Test",
                "version": "1.0",
                "permissions": [],
                "update_url": "https://abc123.ngrok.io/updates",
            }
        )
        result = check_publisher(manifest, query_cws=False)
        assert result["suspicious_update"] is True
        assert any("ngrok" in f.lower() for f in result["flags"])

    def test_self_hosted_url_flagged(self):
        """Any non-CWS URL should be flagged (even if not on our pattern list)."""
        manifest = _build_manifest_info(
            {
                "manifest_version": 3,
                "name": "Test",
                "version": "1.0",
                "permissions": [],
                "update_url": "https://my-corp.example.com/chrome/updates",
            }
        )
        result = check_publisher(manifest, query_cws=False)
        assert result["update_url_ok"] is False
        assert any("Non-standard" in f for f in result["flags"])

    def test_no_update_url_does_not_flag(self):
        """Sideloaded extensions often have no update_url - shouldn't flag."""
        manifest = _build_manifest_info(
            {
                "manifest_version": 3,
                "name": "Test",
                "version": "1.0",
                "permissions": [],
            }
        )
        result = check_publisher(manifest, query_cws=False)
        # No update_url AND no key = sideloaded - should not flag for update_url
        assert result["update_url_ok"] is True


# ---------------------------------------------------------------------------
# Key extraction
# ---------------------------------------------------------------------------


class TestKeyExtraction:
    def test_extracts_key_from_manifest_key_field(self):
        """If manifest has a 'key' field, use that directly."""
        fake_key_bytes = b"fake-key-data-for-testing-12345"
        key_b64 = base64.b64encode(fake_key_bytes).decode()
        manifest = _build_manifest_info(
            {
                "manifest_version": 3,
                "name": "HasKey",
                "version": "1.0",
                "permissions": [],
                "key": key_b64,
            }
        )
        result = check_publisher(manifest, query_cws=False)
        assert result["extension_id"] == _compute_extension_id(fake_key_bytes)

    def test_no_key_flags_warning(self, benign_manifest_raw):
        """No 'key' field and no CRX header should flag as sideloaded."""
        manifest = _build_manifest_info(benign_manifest_raw)
        result = check_publisher(manifest, query_cws=False)
        assert result["extension_id"] is None
        assert any("No signing key" in f for f in result["flags"])


# ---------------------------------------------------------------------------
# Minimal protobuf parser
# ---------------------------------------------------------------------------


class TestProtobufParser:
    """The hand-rolled protobuf decoder used to extract keys from CRX3 headers."""

    def test_decode_single_byte_varint(self):
        # Varint encoding: 0x05 = value 5
        value, pos = _decode_varint(b"\x05", 0)
        assert value == 5
        assert pos == 1

    def test_decode_multi_byte_varint(self):
        # 300 in protobuf varint = 0xac 0x02 (binary: 10101100 00000010)
        value, pos = _decode_varint(b"\xac\x02", 0)
        assert value == 300
        assert pos == 2

    def test_parse_length_delimited_field(self):
        # Field 1, wire type 2 (length-delimited), length 5, value "hello"
        # Tag = (1 << 3) | 2 = 0x0a, length = 5
        data = b"\x0a\x05hello"
        fields = _parse_length_delimited_fields(data)
        assert fields == {1: [b"hello"]}

    def test_skips_varint_fields(self):
        """Varint (wire type 0) fields should be consumed but not stored."""
        # Field 2 wire 0 (varint), value 42, then field 1 wire 2 length 3 "abc"
        data = b"\x10\x2a" + b"\x0a\x03abc"
        fields = _parse_length_delimited_fields(data)
        assert fields == {1: [b"abc"]}

    def test_handles_repeated_fields(self):
        """Multiple instances of the same field number should be collected as a list."""
        # Field 1 twice with "a" and "b"
        data = b"\x0a\x01a" + b"\x0a\x01b"
        fields = _parse_length_delimited_fields(data)
        assert fields == {1: [b"a", b"b"]}


# ---------------------------------------------------------------------------
# CWS query - driven by REAL recorded responses (tests/fixtures/recorded/)
# ---------------------------------------------------------------------------

RECORDED = Path(__file__).parent / "fixtures" / "recorded"
KNOWN_ID = "aapbdbdomjkkjkaonfhkkikfgjllcleb"  # Google Translate, recorded 2026-09-29
KNOWN_VERSION = "2.0.17"
KNOWN_SHA256 = "3f752c27ae39de4bfc881ecacea4a3b4c50c676daecfd9f2fc8c50f5688c8dd1"
UNKNOWN_ID = "a" * 32


def _mock_response(text: str, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    resp.content = text.encode("utf-8")
    return resp


def _recorded(name: str) -> str:
    return (RECORDED / name).read_text(encoding="utf-8")


class TestCwsXmlParsing:
    """parse_cws_update_xml against what the Web Store really sends."""

    def test_known_extension_has_version_and_hash(self):
        result = parse_cws_update_xml(_recorded("cws_known_extension.xml"), KNOWN_ID)
        assert result == {"exists": True, "version": KNOWN_VERSION, "sha256": KNOWN_SHA256}

    def test_unknown_extension_is_not_found(self):
        """Regression: the old regex read version="1.0" from the XML declaration
        and reported an extension that doesn't exist as 'exists, v1.0'."""
        result = parse_cws_update_xml(_recorded("cws_unknown_extension.xml"), UNKNOWN_ID)
        assert result["exists"] is False
        assert result["version"] is None

    def test_other_error_status_is_unknown_not_missing(self):
        xml = (
            '<?xml version="1.0"?><gupdate xmlns="http://www.google.com/update2/response">'
            f'<app appid="{KNOWN_ID}" status="error-internal"/></gupdate>'
        )
        assert parse_cws_update_xml(xml, KNOWN_ID)["exists"] is None

    def test_garbage_is_unknown(self):
        assert parse_cws_update_xml("<not xml", KNOWN_ID)["exists"] is None

    def test_reply_for_a_different_id_is_unknown(self):
        result = parse_cws_update_xml(_recorded("cws_known_extension.xml"), UNKNOWN_ID)
        assert result["exists"] is None


class TestCwsQuery:
    """_query_cws HTTP handling - a failed lookup must be 'unknown', never 'clean'."""

    def test_cws_query_skipped_when_disabled(self, benign_manifest_raw):
        """query_cws=False must prevent any HTTP call."""
        manifest = _build_manifest_info(benign_manifest_raw)
        with patch("extguard.publisher_checker.requests.get") as mock_get:
            check_publisher(manifest, query_cws=False)
            mock_get.assert_not_called()

    def test_recorded_known_reply(self):
        resp = _mock_response(_recorded("cws_known_extension.xml"))
        with patch("extguard.publisher_checker.requests.get", return_value=resp):
            result = _query_cws(KNOWN_ID)
        assert result["exists"] is True
        assert result["version"] == KNOWN_VERSION

    def test_cws_network_error_returns_none(self):
        """Network errors must not crash - return {exists: None}."""
        with patch(
            "extguard.publisher_checker.requests.get", side_effect=Exception("network down")
        ):
            result = _query_cws("abc")
            assert result["exists"] is None

    def test_http_error_is_unknown_not_missing(self):
        """Unknown IDs come back as HTTP 200 + error-unknownApplication, so an
        HTTP error says nothing about the extension - it must be 'unknown'.
        (This used to return exists=False and add +10 risk.)"""
        with patch("extguard.publisher_checker.requests.get", return_value=_mock_response("", 404)):
            result = _query_cws("abc")
        assert result["exists"] is None
        assert "HTTP 404" in result["error"]

    def test_oversized_reply_is_unknown(self):
        big = "<x>" + "a" * 70_000 + "</x>"
        with patch("extguard.publisher_checker.requests.get", return_value=_mock_response(big)):
            assert _query_cws(KNOWN_ID)["exists"] is None


# ---------------------------------------------------------------------------
# CRX3 identity - the real Google Translate signing header plus synthetic ones
# ---------------------------------------------------------------------------


def _varint(value: int) -> bytes:
    out = b""
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out += bytes([byte | 0x80])
        else:
            return out + bytes([byte])


def _pb(field: int, payload: bytes) -> bytes:
    """Encode one length-delimited protobuf field."""
    return _varint((field << 3) | 2) + _varint(len(payload)) + payload


def _crx3_header(keys: list, crx_id: bytes | None) -> bytes:
    header = b"".join(_pb(2, _pb(1, k) + _pb(2, b"sig")) for k in keys)
    if crx_id is not None:
        header += _pb(10000, _pb(1, crx_id))
    return header


class TestCrx3Identity:
    def test_real_header_gives_real_extension_id(self):
        header = (RECORDED / "crx3_header_google_translate.bin").read_bytes()
        info = parse_crx3_identity(header)
        assert info["extension_id"] == KNOWN_ID
        assert info["developer_key"] is not None
        assert info["key_count"] == 2

    def test_signed_id_picks_matching_key_not_first_key(self):
        store_key, dev_key = b"store-publisher-key", b"developer-key"
        crx_id = hashlib.sha256(dev_key).digest()[:16]
        info = parse_crx3_identity(_crx3_header([store_key, dev_key], crx_id))
        assert info["developer_key"] == dev_key
        assert info["extension_id"] == _compute_extension_id(dev_key)

    def test_signed_id_without_matching_key_is_flagged(self, benign_manifest_raw):
        header = _crx3_header([b"some-key"], b"\x01" * 16)
        manifest = _build_manifest_info(benign_manifest_raw)
        result = check_publisher(manifest, crx_header_bytes=header, query_cws=False)
        assert result["id_source"] == "crx3-signed-id"
        assert any("does not match any public key" in f for f in result["flags"])

    def test_manifest_key_contradicting_signature_is_flagged(self, benign_manifest_raw):
        dev_key = b"developer-key"
        header = _crx3_header([dev_key], hashlib.sha256(dev_key).digest()[:16])
        raw = dict(benign_manifest_raw, key=base64.b64encode(b"someone-elses-key").decode())
        result = check_publisher(
            _build_manifest_info(raw), crx_header_bytes=header, query_cws=False
        )
        assert result["extension_id"] == _compute_extension_id(dev_key)
        assert any("repackaged extension" in f for f in result["flags"])

    def test_crx2_public_key_gives_id(self, benign_manifest_raw):
        manifest = _build_manifest_info(benign_manifest_raw)
        result = check_publisher(manifest, crx2_public_key=b"crx2-key", query_cws=False)
        assert result["extension_id"] == _compute_extension_id(b"crx2-key")
        assert result["id_source"] == "crx2-key"

    def test_corrupt_header_is_flagged_not_crash(self, benign_manifest_raw):
        header = b"\xff" * 20  # a never-ending varint
        result = check_publisher(
            _build_manifest_info(benign_manifest_raw), crx_header_bytes=header, query_cws=False
        )
        assert any("could not be parsed" in f for f in result["flags"])


# ---------------------------------------------------------------------------
# Comparing the scanned build with the Web Store build
# ---------------------------------------------------------------------------


class TestStoreComparison:
    def _run(self, version: str, crx_sha256: str | None, cws: dict) -> dict:
        key = b"developer-key"
        raw = {
            "manifest_version": 3,
            "name": "X",
            "version": version,
            "key": base64.b64encode(key).decode(),
            "update_url": CWS_UPDATE_URL_PREFIX,
        }
        with patch("extguard.publisher_checker._query_cws", return_value=cws):
            return check_publisher(_build_manifest_info(raw), crx_sha256=crx_sha256)

    def test_identical_bytes_match_store(self):
        r = self._run(
            "2.0.17", KNOWN_SHA256, {"exists": True, "version": "2.0.17", "sha256": KNOWN_SHA256}
        )
        assert r["store_build_match"] is True
        assert r["pub_score"] == 0

    def test_same_version_different_bytes_is_tampered(self):
        r = self._run(
            "2.0.17", "0" * 64, {"exists": True, "version": "2.0.17", "sha256": KNOWN_SHA256}
        )
        assert r["store_build_match"] is False
        assert r["pub_score"] >= 25
        assert any("different bytes" in f for f in r["flags"])

    def test_newer_than_store_is_flagged(self):
        r = self._run("3.0.0", None, {"exists": True, "version": "2.0.17", "sha256": None})
        assert any("NEWER than the Web Store" in f for f in r["flags"])
        assert r["pub_score"] >= 20

    def test_older_than_store_is_noted_without_score(self):
        r = self._run("1.0.0", None, {"exists": True, "version": "2.0.17", "sha256": None})
        assert any("older than" in f for f in r["flags"])
        assert r["pub_score"] == 0

    def test_failed_lookup_is_reported_as_unknown(self):
        r = self._run(
            "1.0.0", None, {"exists": None, "version": None, "sha256": None, "error": "timeout"}
        )
        assert r["cws_exists"] is None
        assert any("store status unknown" in f for f in r["flags"])
        assert r["pub_score"] == 0
