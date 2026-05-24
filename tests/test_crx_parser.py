# tests/test_crx_parser.py - Tests for the CRX file parser

import io
import json
import struct
import zipfile

import pytest

from crx_parser import _looks_like_url_pattern, parse_crx

# ---------------------------------------------------------------------------
# Format-detection tests
# ---------------------------------------------------------------------------

class TestFormatDetection:
    """The parser must correctly identify CRX2/3/zip/json inputs."""

    def test_parses_crx3(self, tmp_path, crx3_bytes):
        path = tmp_path / "ext.crx"
        path.write_bytes(crx3_bytes)
        zip_bytes, manifest = parse_crx(str(path))
        assert manifest.name == "Dark Mode for Docs"
        assert manifest.manifest_version == 3
        assert zip_bytes is not None

    def test_parses_crx2(self, tmp_path, crx2_bytes):
        path = tmp_path / "ext.crx"
        path.write_bytes(crx2_bytes)
        _, manifest = parse_crx(str(path))
        assert manifest.name == "Dark Mode for Docs"

    def test_parses_raw_zip(self, tmp_path, benign_zip_bytes):
        """A .zip with no CRX header must also work (raw extension archive)."""
        path = tmp_path / "ext.zip"
        path.write_bytes(benign_zip_bytes)
        _, manifest = parse_crx(str(path))
        assert manifest.name == "Dark Mode for Docs"

    def test_parses_bare_manifest_json(self, tmp_path, benign_manifest_raw):
        """A bare manifest.json file should also be accepted."""
        path = tmp_path / "manifest.json"
        path.write_text(json.dumps(benign_manifest_raw))
        zip_bytes, manifest = parse_crx(str(path))
        assert zip_bytes is None   # No ZIP available for bare manifests
        assert manifest.name == "Dark Mode for Docs"

    def test_parses_any_json_file(self, tmp_path, teamccp_manifest_raw):
        """Files ending in .json (not just manifest.json) should be accepted."""
        path = tmp_path / "custom_name.json"
        path.write_text(json.dumps(teamccp_manifest_raw))
        _, manifest = parse_crx(str(path))
        assert "cookies" in manifest.permissions


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestErrors:
    """Malformed inputs must raise informative errors, not crash."""

    def test_missing_file(self):
        with pytest.raises(FileNotFoundError):
            parse_crx("/nonexistent/path/that/should/not/exist.crx")

    def test_bad_magic_bytes(self, tmp_path):
        """A file that isn't a CRX, ZIP, or .json should error clearly."""
        path = tmp_path / "garbage.crx"
        path.write_bytes(b"NOTACRX" + b"\x00" * 100)
        with pytest.raises(ValueError, match="Unrecognised file format"):
            parse_crx(str(path))

    def test_crx_with_unsupported_version(self, tmp_path):
        """CRX header with version != 2 or 3 should error."""
        path = tmp_path / "future.crx"
        path.write_bytes(b"Cr24" + struct.pack("<I", 99) + b"\x00" * 100)
        with pytest.raises(ValueError, match="Unsupported CRX version"):
            parse_crx(str(path))

    def test_zip_without_manifest_json(self, tmp_path):
        """A valid ZIP that has no manifest.json should error."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("not_a_manifest.txt", "hello")

        # Wrap in CRX3 header
        crx = b"Cr24" + struct.pack("<I", 3) + struct.pack("<I", 0) + buf.getvalue()
        path = tmp_path / "no_manifest.crx"
        path.write_bytes(crx)

        with pytest.raises(ValueError, match="manifest.json not found"):
            parse_crx(str(path))

    def test_corrupt_zip(self, tmp_path):
        """A CRX whose 'ZIP' section is garbage should error."""
        crx = b"Cr24" + struct.pack("<I", 3) + struct.pack("<I", 0) + b"NOT_A_ZIP"
        path = tmp_path / "corrupt.crx"
        path.write_bytes(crx)
        with pytest.raises(ValueError, match="Invalid ZIP archive"):
            parse_crx(str(path))

    # Regression tests for bounds-check on header_length / pubkey_len / sig_len:

    def test_crx3_with_oversized_header_length(self, tmp_path):
        """CRX3 declaring header_length larger than the file must be rejected
        with a clear error - not silently fall through to 'invalid ZIP'."""
        crx = b"Cr24" + struct.pack("<I", 3) + struct.pack("<I", 0xFFFFFFFF) + b"tail"
        path = tmp_path / "bad_header.crx"
        path.write_bytes(crx)
        with pytest.raises(ValueError, match="header_length.*exceeds"):
            parse_crx(str(path))

    def test_crx2_with_oversized_pubkey_length(self, tmp_path):
        """CRX2 declaring pubkey + sig lengths past the file must be rejected."""
        crx = (b"Cr24" + struct.pack("<I", 2)
               + struct.pack("<I", 0xFFFFFFFF)   # pubkey_len
               + struct.pack("<I", 0)            # sig_len
               + b"tail")
        path = tmp_path / "bad_crx2.crx"
        path.write_bytes(crx)
        with pytest.raises(ValueError, match="exceed"):
            parse_crx(str(path))

    def test_truncated_crx_rejected(self, tmp_path):
        """A 6-byte file claiming to be CRX must be rejected, not crash."""
        path = tmp_path / "tiny.crx"
        path.write_bytes(b"Cr24\x03\x00")   # Magic + 2 bytes of "version" then EOF
        with pytest.raises(ValueError, match="truncated"):
            parse_crx(str(path))


# ---------------------------------------------------------------------------
# MV2 vs MV3 permission flattening
# ---------------------------------------------------------------------------

class TestManifestFlattening:
    """In MV2, host patterns live inside permissions[]. The parser must split them out."""

    def test_mv2_host_patterns_split(self, tmp_path):
        """MV2 permissions with both API names and URL patterns should be separated."""
        mv2 = {
            "manifest_version": 2,
            "name": "MV2 Test",
            "version": "1.0",
            "permissions": [
                "storage",                # API permission
                "cookies",                # API permission
                "<all_urls>",             # host pattern
                "https://github.com/*",   # host pattern
            ],
        }
        path = tmp_path / "mv2.json"
        path.write_text(json.dumps(mv2))
        _, manifest = parse_crx(str(path))

        # API permissions should not contain URL patterns
        assert "storage"  in manifest.permissions
        assert "cookies"  in manifest.permissions
        assert "<all_urls>" not in manifest.permissions
        assert "https://github.com/*" not in manifest.permissions

        # URL patterns should be in host_permissions
        assert "<all_urls>" in manifest.host_permissions
        assert "https://github.com/*" in manifest.host_permissions

    def test_mv3_host_permissions_preserved(self, tmp_path, benign_manifest_raw):
        """MV3's separate host_permissions field should still work."""
        path = tmp_path / "mv3.json"
        path.write_text(json.dumps(benign_manifest_raw))
        _, manifest = parse_crx(str(path))
        assert "*://docs.google.com/*" in manifest.host_permissions


class TestUrlPatternDetection:
    """The internal _looks_like_url_pattern helper - critical for MV2 flattening."""

    def test_recognises_all_urls(self):
        assert _looks_like_url_pattern("<all_urls>")

    def test_recognises_scheme_patterns(self):
        assert _looks_like_url_pattern("http://*/*")
        assert _looks_like_url_pattern("https://example.com/*")
        assert _looks_like_url_pattern("ftp://*/*")

    def test_recognises_wildcard_patterns(self):
        assert _looks_like_url_pattern("*://*.github.com/*")

    def test_does_not_match_api_names(self):
        assert not _looks_like_url_pattern("cookies")
        assert not _looks_like_url_pattern("storage")
        assert not _looks_like_url_pattern("webRequest")
