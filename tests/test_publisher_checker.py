# tests/test_publisher_checker.py - Tests for publisher legitimacy checks

import base64
import hashlib
from unittest.mock import MagicMock, patch

import pytest

from crx_parser import _build_manifest_info
from publisher_checker import (
    CWS_UPDATE_URL_PREFIX,
    _compute_extension_id,
    _decode_varint,
    _parse_length_delimited_fields,
    _query_cws,
    check_publisher,
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
        expected = "".join(chr(ord('a') + int(c, 16)) for c in empty_sha)
        assert result == expected
        # And sanity-check the format
        assert len(result) == 32
        assert all('a' <= c <= 'p' for c in result)

    def test_length_is_32_chars(self):
        """Extension IDs are always exactly 32 lowercase letters."""
        for raw in [b"key1", b"key2" * 50, b"\xff" * 100]:
            ext_id = _compute_extension_id(raw)
            assert len(ext_id) == 32
            assert ext_id.islower()
            assert all('a' <= c <= 'p' for c in ext_id)

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
        manifest = _build_manifest_info({
            "manifest_version": 3,
            "name": "Test",
            "version": "1.0",
            "permissions": [],
            "update_url": "https://abc123.ngrok.io/updates",
        })
        result = check_publisher(manifest, query_cws=False)
        assert result["suspicious_update"] is True
        assert any("ngrok" in f.lower() for f in result["flags"])

    def test_self_hosted_url_flagged(self):
        """Any non-CWS URL should be flagged (even if not on our pattern list)."""
        manifest = _build_manifest_info({
            "manifest_version": 3,
            "name": "Test",
            "version": "1.0",
            "permissions": [],
            "update_url": "https://my-corp.example.com/chrome/updates",
        })
        result = check_publisher(manifest, query_cws=False)
        assert result["update_url_ok"] is False
        assert any("Non-standard" in f for f in result["flags"])

    def test_no_update_url_does_not_flag(self):
        """Sideloaded extensions often have no update_url - shouldn't flag."""
        manifest = _build_manifest_info({
            "manifest_version": 3,
            "name": "Test",
            "version": "1.0",
            "permissions": [],
        })
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
        manifest = _build_manifest_info({
            "manifest_version": 3,
            "name": "HasKey",
            "version": "1.0",
            "permissions": [],
            "key": key_b64,
        })
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
# CWS query (mocked HTTP)
# ---------------------------------------------------------------------------

class TestCwsQuery:
    """Live CWS calls are mocked - we only test our request/response handling."""

    def test_cws_query_skipped_when_disabled(self, benign_manifest_raw):
        """query_cws=False must prevent any HTTP call."""
        manifest = _build_manifest_info(benign_manifest_raw)
        with patch("publisher_checker.requests.get") as mock_get:
            check_publisher(manifest, query_cws=False)
            mock_get.assert_not_called()

    def test_cws_returns_exists_with_version(self):
        """Parse a CWS response with a version number."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = (
            '<gupdate><app appid="abcdefg">'
            '<updatecheck status="ok" version="2.5.0" /></app></gupdate>'
        )
        with patch("publisher_checker.requests.get", return_value=mock_response):
            result = _query_cws("abcdefg")
            assert result["exists"] is True
            assert result["version"] == "2.5.0"

    def test_cws_returns_noupdate_means_exists(self):
        """'noupdate' status means the extension exists but is up-to-date."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '<gupdate><app appid="x"><updatecheck status="noupdate"/></app></gupdate>'
        with patch("publisher_checker.requests.get", return_value=mock_response):
            result = _query_cws("x")
            assert result["exists"] is True

    def test_cws_network_error_returns_none(self):
        """Network errors must not crash - return {exists: None}."""
        with patch("publisher_checker.requests.get", side_effect=Exception("network down")):
            result = _query_cws("abc")
            assert result["exists"] is None

    def test_cws_404_returns_false(self):
        mock_response = MagicMock()
        mock_response.status_code = 404
        with patch("publisher_checker.requests.get", return_value=mock_response):
            result = _query_cws("abc")
            assert result["exists"] is False
