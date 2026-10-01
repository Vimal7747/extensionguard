# crx_parser.py — Parses Chrome Extension (.crx) files and extracts manifest.json
#
# CRX files are ZIP archives with a short binary header prepended.
# CRX3 layout (current format):
#
#   [4 bytes]  Magic string: "Cr24"
#   [4 bytes]  Version: 3 (little-endian uint32)
#   [4 bytes]  Header length H (little-endian uint32)
#   [H bytes]  Protobuf-encoded signing info (CrxFileHeader)
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
#
# The input is UNTRUSTED - it may be a sample crafted to crash or exhaust the
# scanner. So this module:
#   - keeps the original file bytes (threat intel indexes the whole file),
#   - keeps the CRX signing header (publisher_checker derives the ID from it),
#   - caps file size, archive entry count, and decompressed sizes (zip bombs),
#   - validates manifest field types instead of assuming them.

import io
import json
import struct
import zipfile
from pathlib import Path

from extguard.models import ManifestInfo, ParsedExtension

# All Chrome extensions start with these 4 bytes
CRX_MAGIC = b"Cr24"

# ---------------------------------------------------------------------------
# Resource limits. Real extensions are far below these; a sample that goes
# over them is rejected with a clear error instead of eating all the RAM.
# ---------------------------------------------------------------------------
MAX_INPUT_BYTES = 512 * 1024 * 1024  # the file we are asked to scan
MAX_ZIP_ENTRIES = 20_000  # files inside the archive
MAX_MEMBER_BYTES = 100 * 1024 * 1024  # any single decompressed file
MAX_TOTAL_UNCOMPRESSED = 1024 * 1024 * 1024  # whole archive, decompressed
MAX_MANIFEST_BYTES = 1024 * 1024  # manifest.json itself


def parse_extension(file_path: str) -> ParsedExtension:
    """
    Parse a .crx, .zip, or unpacked manifest.json.

    Returns a ParsedExtension holding the manifest, the original file bytes,
    the ZIP payload, and (for CRX files) the signing header.

    Raises FileNotFoundError if the path doesn't exist and ValueError for
    anything malformed or over the resource limits.
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    if not path.is_file():
        raise ValueError(f"Not a regular file: {file_path}")
    size = path.stat().st_size
    if size > MAX_INPUT_BYTES:
        raise ValueError(f"File is {size:,} bytes - over the {MAX_INPUT_BYTES:,} byte limit")

    raw_bytes = path.read_bytes()
    suffix = path.suffix.lower()

    # --- Bare manifest JSON (any .json file) --------------------------------
    if suffix == ".json":
        raw = _load_json(raw_bytes, "manifest")
        return ParsedExtension(
            manifest=_build_manifest_info(raw),
            file_bytes=raw_bytes,
            zip_bytes=None,
            container="json",
        )

    # --- Detect format by magic bytes / extension ---------------------------
    crx3_header = None
    crx2_public_key = None
    # ZIP files start with "PK" (the local file header signature)
    if raw_bytes[:4] == CRX_MAGIC:
        zip_bytes, container, crx3_header, crx2_public_key = _split_crx(raw_bytes)
    elif suffix == ".zip" or raw_bytes[:2] == b"PK":
        zip_bytes, container = raw_bytes, "zip"
    else:
        raise ValueError("Unrecognised file format — expected a .crx, .zip, or manifest.json")

    manifest = _extract_manifest_from_zip(zip_bytes)
    return ParsedExtension(
        manifest=manifest,
        file_bytes=raw_bytes,
        zip_bytes=zip_bytes,
        container=container,
        crx3_header=crx3_header,
        crx2_public_key=crx2_public_key,
    )


def parse_crx(file_path: str) -> tuple:
    """
    Backwards-compatible wrapper: returns (zip_bytes, ManifestInfo).
    zip_bytes is None when given a bare manifest.json.
    New code should call parse_extension() to also get the file bytes and
    the signing header.
    """
    parsed = parse_extension(file_path)
    return parsed.zip_bytes, parsed.manifest


# ---------------------------------------------------------------------------
# Safe ZIP helpers (also used by osv_lookup when it scans the bundled files)
# ---------------------------------------------------------------------------


def check_zip_limits(zf: zipfile.ZipFile):
    """
    Reject archives that are too big once decompressed (zip bombs).
    Uses the sizes declared in the ZIP directory; read_zip_member() then
    enforces the same limit on the bytes actually produced.
    """
    infos = zf.infolist()
    if len(infos) > MAX_ZIP_ENTRIES:
        raise ValueError(f"Archive has {len(infos):,} entries - over the {MAX_ZIP_ENTRIES:,} limit")

    total = 0
    for info in infos:
        if info.file_size > MAX_MEMBER_BYTES:
            raise ValueError(
                f"Archive member {info.filename!r} decompresses to {info.file_size:,} bytes "
                f"- over the {MAX_MEMBER_BYTES:,} byte limit (possible zip bomb)"
            )
        total += info.file_size
    if total > MAX_TOTAL_UNCOMPRESSED:
        raise ValueError(
            f"Archive decompresses to {total:,} bytes - over the "
            f"{MAX_TOTAL_UNCOMPRESSED:,} byte limit (possible zip bomb)"
        )


def read_zip_member(zf: zipfile.ZipFile, name, limit: int = MAX_MEMBER_BYTES) -> bytes:
    """
    Read one archive member, refusing to produce more than `limit` bytes.
    Reads limit + 1 bytes so an over-size member is detected even if its
    directory entry lied about the size.
    """
    with zf.open(name) as member:
        data = member.read(limit + 1)
    if len(data) > limit:
        label = name.filename if isinstance(name, zipfile.ZipInfo) else name
        raise ValueError(f"Archive member {label!r} is larger than the {limit:,} byte limit")
    return data


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _split_crx(raw_bytes: bytes) -> tuple:
    """
    Split a CRX file into its parts.

    Returns (zip_bytes, container, crx3_header, crx2_public_key).

    Validates that every length field declared by the header points to a
    region inside the file, so a malformed CRX fails here with a clear
    message rather than as a misleading "Invalid ZIP archive".
    """
    total_len = len(raw_bytes)

    # Need at least 12 bytes to even read the version + header_length field
    if total_len < 12:
        raise ValueError(f"CRX file truncated - need at least 12 bytes for header, got {total_len}")

    version = struct.unpack_from("<I", raw_bytes, 4)[0]  # bytes 4–7, little-endian

    if version == 3:
        # Fixed prefix is 12 bytes (magic + version + header_length field),
        # then `header_length` bytes of protobuf signing data.
        header_length = struct.unpack_from("<I", raw_bytes, 8)[0]
        zip_start = 12 + header_length
        if zip_start > total_len:
            raise ValueError(
                f"CRX3 header_length ({header_length}) exceeds remaining file "
                f"size ({total_len - 12}) - file is truncated or malformed"
            )
        header = raw_bytes[12:zip_start]
        return raw_bytes[zip_start:], "crx3", header, None

    if version == 2:
        if total_len < 16:
            raise ValueError("CRX2 file truncated - need at least 16 bytes for header")
        pubkey_len = struct.unpack_from("<I", raw_bytes, 8)[0]
        sig_len = struct.unpack_from("<I", raw_bytes, 12)[0]
        zip_start = 16 + pubkey_len + sig_len
        if zip_start > total_len:
            raise ValueError(
                f"CRX2 pubkey ({pubkey_len}) + signature ({sig_len}) lengths exceed "
                f"remaining file size ({total_len - 16}) - file is truncated or malformed"
            )
        public_key = raw_bytes[16 : 16 + pubkey_len] or None
        return raw_bytes[zip_start:], "crx2", None, public_key

    raise ValueError(f"Unsupported CRX version: {version} (expected 2 or 3)")


def _strip_crx_header(raw_bytes: bytes) -> bytes:
    """Remove the CRX header and return only the ZIP bytes (kept for older callers)."""
    return _split_crx(raw_bytes)[0]


def _extract_manifest_from_zip(zip_bytes: bytes) -> ManifestInfo:
    """Open ZIP in memory and parse manifest.json from its root."""
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            check_zip_limits(zf)
            names = zf.namelist()
            if "manifest.json" not in names:
                raise ValueError(
                    "manifest.json not found inside extension archive. "
                    f"Archive contains: {names[:10]}"
                )
            manifest_bytes = read_zip_member(zf, "manifest.json", MAX_MANIFEST_BYTES)
            manifest = _build_manifest_info(_load_json(manifest_bytes, "manifest.json"))
            _resolve_localised_name(zf, manifest)
    except zipfile.BadZipFile as exc:
        raise ValueError(f"Invalid ZIP archive: {exc}") from exc
    except (RuntimeError, NotImplementedError) as exc:
        # zipfile raises these for encrypted members / unsupported compression
        raise ValueError(f"Cannot read ZIP archive: {exc}") from exc

    return manifest


def _resolve_localised_name(zf: zipfile.ZipFile, manifest: ManifestInfo):
    """
    Most Web Store extensions set "name": "__MSG_appName__" and keep the real
    name in _locales/<default_locale>/messages.json. Resolve it like Chrome
    does, so reports, history keys and the AI all see the real name.
    manifest.raw keeps the original placeholder. Never raises.
    """
    name = manifest.name
    if not (name.startswith("__MSG_") and name.endswith("__") and len(name) > 8):
        return
    key = name[6:-2].lower()
    locale = manifest.raw.get("default_locale")
    locales = [locale] if isinstance(locale, str) else []
    locales += ["en", "en_US"]
    for loc in locales:
        path = f"_locales/{loc}/messages.json"
        try:
            data = _load_json(read_zip_member(zf, path, MAX_MANIFEST_BYTES), path)
        except (KeyError, ValueError, zipfile.BadZipFile, RuntimeError, NotImplementedError):
            continue
        if not isinstance(data, dict):
            continue
        # Message keys are case-insensitive in Chrome
        for msg_key, entry in data.items():
            if str(msg_key).lower() == key and isinstance(entry, dict):
                message = entry.get("message")
                if isinstance(message, str) and message.strip():
                    manifest.name = message.strip()[:200]
                    return


def _load_json(data: bytes, label: str):
    """json.loads that turns every failure into a ValueError with context."""
    try:
        return json.loads(data)
    except RecursionError as exc:
        # Deeply nested JSON ("[[[[...]]]]") blows the recursion limit
        raise ValueError(f"{label} is nested too deeply to parse") from exc
    except ValueError as exc:  # JSONDecodeError and UnicodeDecodeError are ValueErrors
        raise ValueError(f"{label} is not valid JSON: {exc}") from exc


def _build_manifest_info(raw) -> ManifestInfo:
    """
    Build a ManifestInfo from raw parsed JSON, validating field types.

    In MV2, host patterns (e.g. "<all_urls>") live inside the "permissions"
    array alongside API permission names. In MV3, Google split them out into
    a separate "host_permissions" array — we handle both.

    Wrong-typed fields never crash the scan: they are coerced or ignored and
    recorded in `parse_warnings` so the analyst can see them.
    """
    if not isinstance(raw, dict):
        raise ValueError(f"manifest.json must be a JSON object, got {type(raw).__name__}")

    warnings: list = []

    name = _as_text(raw.get("name"), "name", "Unknown", warnings)
    version = _as_text(raw.get("version"), "version", "Unknown", warnings)

    manifest_version = raw.get("manifest_version", 2)
    # bool is a subclass of int in Python, so exclude it explicitly
    if not isinstance(manifest_version, int) or isinstance(manifest_version, bool):
        warnings.append(f"manifest_version has type {type(manifest_version).__name__}, not int")
        manifest_version = 2

    # MV2: separate URL patterns from named API permissions
    all_perms = _as_string_list(raw.get("permissions"), "permissions", warnings)
    api_perms = [p for p in all_perms if not _looks_like_url_pattern(p)]
    host_perms = [p for p in all_perms if _looks_like_url_pattern(p)]
    # MV3 puts host_permissions explicitly — merge any extras
    host_perms += _as_string_list(raw.get("host_permissions"), "host_permissions", warnings)

    optional_all = _as_string_list(
        raw.get("optional_permissions"), "optional_permissions", warnings
    )
    optional_api = [p for p in optional_all if not _looks_like_url_pattern(p)]
    optional_host = [p for p in optional_all if _looks_like_url_pattern(p)]
    optional_host += _as_string_list(
        raw.get("optional_host_permissions"), "optional_host_permissions", warnings
    )

    content_scripts = []
    cs_value = raw.get("content_scripts", [])
    if not isinstance(cs_value, list):
        warnings.append(f"content_scripts has type {type(cs_value).__name__}, not list")
        cs_value = []
    for i, cs in enumerate(cs_value):
        if not isinstance(cs, dict):
            warnings.append(f"content_scripts[{i}] is not an object - ignored")
            continue
        cleaned = dict(cs)
        cleaned["matches"] = _as_string_list(
            cs.get("matches"), f"content_scripts[{i}].matches", warnings
        )
        content_scripts.append(cleaned)

    background = raw.get("background", {})
    if not isinstance(background, dict):
        warnings.append(f"background has type {type(background).__name__}, not object")
        background = {}

    return ManifestInfo(
        name=name,
        version=version,
        manifest_version=manifest_version,
        permissions=api_perms,
        # dict.fromkeys de-duplicates while keeping the original order
        host_permissions=list(dict.fromkeys(host_perms)),
        content_scripts=content_scripts,
        background=background,
        raw=raw,
        optional_permissions=optional_api,
        optional_host_permissions=list(dict.fromkeys(optional_host)),
        parse_warnings=warnings,
    )


def _as_text(value, field: str, default: str, warnings: list) -> str:
    """Return `value` if it's a string, otherwise `default` plus a warning."""
    if value is None:
        return default
    if isinstance(value, str):
        return value
    warnings.append(f"{field} has type {type(value).__name__}, not string")
    return str(value) if isinstance(value, (int, float)) else default


def _as_string_list(value, field: str, warnings: list) -> list:
    """
    Normalise a manifest field that should be a list of strings.
      None            -> []
      list            -> the string items (non-strings dropped, with a warning)
      single string   -> [string] (fail closed: still gets scored), with a warning
      anything else   -> [] with a warning
    """
    if value is None:
        return []
    if isinstance(value, str):
        warnings.append(f"{field} is a single string, not a list")
        return [value]
    if not isinstance(value, list):
        warnings.append(f"{field} has type {type(value).__name__}, not list")
        return []
    strings = [item for item in value if isinstance(item, str)]
    dropped = len(value) - len(strings)
    if dropped:
        warnings.append(f"{field} contained {dropped} non-string item(s) - ignored")
    return strings


def _looks_like_url_pattern(perm: str) -> bool:
    """Return True if a permission string is a URL match pattern, not an API name."""
    return (
        perm.startswith(("http", "*", "ftp", "file:", "ws:", "wss:", "urn:"))
        or perm == "<all_urls>"
    )
