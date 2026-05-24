# crx_parser.py — Parses Chrome Extension (.crx) files and extracts manifest.json
#
# CRX files are ZIP archives with a short binary header prepended.
# CRX3 layout (current format):
#
#   [4 bytes]  Magic string: "Cr24"
#   [4 bytes]  Version: 3 (little-endian uint32)
#   [4 bytes]  Header length H (little-endian uint32)
#   [H bytes]  Protobuf-encoded signing info (we skip this)
#   [rest]     ZIP archive — unzip normally to get extension files
#
# CRX2 layout (legacy, still seen in the wild):
#
#   [4 bytes]  Magic: "Cr24"
#   [4 bytes]  Version: 2
#   [4 bytes]  Public key length P
#   [4 bytes]  Signature length S
#   [P bytes]  RSA public key
#   [S bytes]  Signature
#   [rest]     ZIP archive

import io
import json
import struct
import zipfile
from pathlib import Path

from models import ManifestInfo

# All Chrome extensions start with these 4 bytes
CRX_MAGIC = b"Cr24"


def parse_crx(file_path: str) -> tuple:
    """
    Parse a .crx, .zip, or unpacked manifest.json and return the manifest.

    Accepts:
      - A .crx file  (binary CRX2 or CRX3)
      - A .zip file  (raw extension ZIP, no CRX header)
      - A manifest.json file directly (for unpacked/sideloaded extensions)

    Returns:
      (zip_bytes, ManifestInfo)
      zip_bytes is None when given a bare manifest.json.
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    # --- Handle bare manifest JSON (any .json file) -------------------------
    if file_path.endswith(".json"):
        raw = json.loads(path.read_bytes())
        return None, _build_manifest_info(raw)

    raw_bytes = path.read_bytes()

    # --- Detect format by magic bytes / extension ---------------------------
    # ZIP files start with "PK\x03\x04" (the local file header signature)
    if file_path.endswith(".zip") or raw_bytes[:2] == b"PK":
        zip_bytes = raw_bytes
    elif raw_bytes[:4] == CRX_MAGIC:
        zip_bytes = _strip_crx_header(raw_bytes)
    else:
        raise ValueError(
            "Unrecognised file format — expected a .crx, .zip, or manifest.json"
        )

    manifest = _extract_manifest_from_zip(zip_bytes)
    return zip_bytes, manifest


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _strip_crx_header(raw_bytes: bytes) -> bytes:
    """
    Remove the CRX header and return the raw ZIP bytes.

    Validates that every length field declared by the header points to a
    region inside the file. A malformed CRX with header_length > file size
    used to silently slip through and then surface as a misleading "Invalid
    ZIP archive" error; we now reject it at the parsing layer with a clear
    diagnostic.
    """
    total_len = len(raw_bytes)

    # Need at least 12 bytes to even read the version + header_length field
    if total_len < 12:
        raise ValueError(
            f"CRX file truncated - need at least 12 bytes for header, got {total_len}"
        )

    version = struct.unpack_from("<I", raw_bytes, 4)[0]  # bytes 4–7, little-endian

    if version == 3:
        # Fixed prefix is 12 bytes (magic + version + header_length field),
        # then skip `header_length` bytes of protobuf signing data.
        header_length = struct.unpack_from("<I", raw_bytes, 8)[0]
        zip_start = 12 + header_length
        # Sanity check: header_length must not push us past the end of the file
        if zip_start > total_len:
            raise ValueError(
                f"CRX3 header_length ({header_length}) exceeds remaining file "
                f"size ({total_len - 12}) - file is truncated or malformed"
            )

    elif version == 2:
        # Need at least 16 bytes for the two length fields
        if total_len < 16:
            raise ValueError("CRX2 file truncated - need at least 16 bytes for header")
        # Skip public key and signature blobs
        pubkey_len = struct.unpack_from("<I", raw_bytes, 8)[0]
        sig_len    = struct.unpack_from("<I", raw_bytes, 12)[0]
        zip_start  = 16 + pubkey_len + sig_len
        if zip_start > total_len:
            raise ValueError(
                f"CRX2 pubkey ({pubkey_len}) + signature ({sig_len}) lengths exceed "
                f"remaining file size ({total_len - 16}) - file is truncated or malformed"
            )

    else:
        raise ValueError(f"Unsupported CRX version: {version} (expected 2 or 3)")

    return raw_bytes[zip_start:]


def _extract_manifest_from_zip(zip_bytes: bytes) -> ManifestInfo:
    """Open ZIP in memory and parse manifest.json from its root."""
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            names = zf.namelist()
            if "manifest.json" not in names:
                raise ValueError(
                    "manifest.json not found inside extension archive. "
                    f"Archive contains: {names[:10]}"
                )
            raw = json.loads(zf.read("manifest.json"))
    except zipfile.BadZipFile as exc:
        raise ValueError(f"Invalid ZIP archive: {exc}") from exc

    return _build_manifest_info(raw)


def _build_manifest_info(raw: dict) -> ManifestInfo:
    """
    Build a ManifestInfo from raw parsed JSON.

    In MV2, host patterns (e.g. "<all_urls>") live inside the "permissions"
    array alongside API permission names. In MV3, Google split them out into
    a separate "host_permissions" array — we handle both.
    """
    # In MV2, separate out URL patterns from named API permissions
    all_perms = raw.get("permissions", [])
    api_perms   = [p for p in all_perms if not _looks_like_url_pattern(p)]
    host_perms  = [p for p in all_perms if _looks_like_url_pattern(p)]

    # MV3 puts host_permissions explicitly — merge any extras
    host_perms += raw.get("host_permissions", [])

    return ManifestInfo(
        name             = raw.get("name", "Unknown"),
        version          = raw.get("version", "Unknown"),
        manifest_version = raw.get("manifest_version", 2),
        permissions      = api_perms,
        host_permissions = list(set(host_perms)),   # deduplicate
        content_scripts  = raw.get("content_scripts", []),
        background       = raw.get("background", {}),
        raw              = raw,
    )


def _looks_like_url_pattern(perm: str) -> bool:
    """Return True if a permission string is a URL match pattern, not an API name."""
    return (
        perm.startswith("http")
        or perm.startswith("*")
        or perm.startswith("ftp")
        or perm == "<all_urls>"
    )
