# publisher_checker.py - CRX signing identity + publisher legitimacy checks
#
# Attack indicators this module covers:
#   1. Extension identity: who signed this package, and is it the ID it claims?
#   2. Non-standard or self-hosted update_url  (supply chain red flag)
#   3. Is this byte-for-byte the build the Chrome Web Store serves?
#
# How extension IDs work in Chrome:
#   - Chrome computes the extension ID as: the first 16 bytes of
#     SHA256(developer public key), written as 32 hex digits, with each digit
#     mapped through the a-p alphabet (0=a, 1=b, ... 15=p).
#   - A CRX3 file carries that ID directly as `crx_id` inside the SIGNED part
#     of its header, plus one or more public-key proofs. The Web Store adds its
#     own publisher proof, so "the first key in the file" is NOT necessarily
#     the developer key - we use the signed crx_id and find the key matching it.
#   - For installed/unpacked extensions the manifest "key" field holds the
#     base64 DER public key instead.
#   - We do NOT verify the RSA/ECDSA signatures themselves (that needs a crypto
#     library); Chrome does that at install time.
#
# External calls:
#   - One GET to the Chrome Web Store update endpoint (optional, has timeout).
#     The response tells us whether the ID exists on the store, its current
#     version, and the SHA-256 of the exact .crx the store serves.

import base64
import hashlib
import re
import xml.etree.ElementTree as ET

try:
    import requests

    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

from extguard.models import ManifestInfo
from extguard.update_velocity import _parse_version, _tuple_gt

# Official Chrome Web Store update URL prefix - anything else is suspicious
CWS_UPDATE_URL_PREFIX = "https://clients2.google.com/service/update2/crx"

# CWS update check endpoint. These are the parameters Chrome's own updater
# sends; with fewer of them the store answers "noupdate" and leaves out the
# version and hash we need. See tests/fixtures/recorded/ for real responses.
CWS_UPDATE_TEMPLATE = (
    "https://clients2.google.com/service/update2/crx"
    "?response=updatecheck&os=win&arch=x64&os_arch=x86_64"
    "&prod=chromecrx&prodchannel=&prodversion=140.0.0.0&lang=en"
    "&acceptformat=crx3"
    "&x=id%3D{ext_id}%26installsource%3Dondemand%26uc"
)

# Refuse to parse an update response bigger than this (they are < 1 KB)
MAX_CWS_RESPONSE_BYTES = 64 * 1024

# Red-flag patterns in update_url - self-hosted or attacker-controlled feeds
SUSPICIOUS_UPDATE_URL_PATTERNS = [
    r"localhost",
    r"127\.0\.0\.1",
    r"\.ngrok\.io",
    r"\.trycloudflare\.com",
    r"\.workers\.dev",
    r"\.pages\.dev",
    r"\.netlify\.app",
    r"\.vercel\.app",
    r"raw\.githubusercontent\.com",
]

# CRX3 protobuf field numbers (from Chromium's crx3.proto)
_CRX3_RSA_PROOFS = 2  # repeated AsymmetricKeyProof sha256_with_rsa
_CRX3_ECDSA_PROOFS = 3  # repeated AsymmetricKeyProof sha256_with_ecdsa
_CRX3_SIGNED_HEADER_DATA = 10000  # bytes signed_header_data (a SignedData message)
_SIGNED_DATA_CRX_ID = 1  # bytes crx_id inside SignedData (16 bytes)


# ---------------------------------------------------------------------------
# Public entry point (returns a plain dict - keeps it CS50P-friendly)
# ---------------------------------------------------------------------------


def check_publisher(
    manifest: ManifestInfo,
    crx_header_bytes: bytes | None = None,
    query_cws: bool = True,
    crx2_public_key: bytes | None = None,
    crx_sha256: str | None = None,
) -> dict:
    """
    Check publisher legitimacy and return a risk summary dict.

    Args:
        manifest:          Parsed manifest
        crx_header_bytes:  CRX3 protobuf header (ParsedExtension.crx3_header).
        query_cws:         Whether to make a live request to the CWS update endpoint.
        crx2_public_key:   CRX2 public key (ParsedExtension.crx2_public_key).
        crx_sha256:        SHA-256 of the .crx FILE being scanned. Only pass this
                           for .crx inputs - it is compared with the hash of the
                           build the Web Store serves.

    Returns a dict with keys:
      extension_id       str or None
      id_source          "crx3-signed-id" / "crx2-key" / "manifest-key" / None
      update_url_ok      bool   (True = official CWS URL or absent)
      suspicious_update  bool
      cws_exists         True / False / None (None = not queried or lookup failed)
      cws_version        str or None
      cws_sha256         str or None  (hash of the .crx the store serves)
      store_build_match  True / False / None (None = couldn't compare)
      pub_score          int    (0-30 publisher-specific risk contribution)
      flags              list[str]
    """
    flags: list = []
    score = 0
    result = {
        "extension_id": None,
        "id_source": None,
        "update_url_ok": True,
        "suspicious_update": False,
        "cws_exists": None,
        "cws_version": None,
        "cws_sha256": None,
        "store_build_match": None,
        "pub_score": 0,
        "flags": flags,
    }

    # --- 1. Work out the extension ID --------------------------------------
    ext_id, id_source, id_flags, id_score = _resolve_extension_id(
        manifest, crx_header_bytes, crx2_public_key
    )
    result["extension_id"] = ext_id
    result["id_source"] = id_source
    flags.extend(id_flags)
    score += id_score

    # --- 2. Validate update_url field --------------------------------------
    update_url = manifest.raw.get("update_url", "")
    if update_url and not isinstance(update_url, str):
        flags.append(f"update_url has type {type(update_url).__name__}, not string")
        score += 5
        update_url = ""
    if update_url:
        if not update_url.startswith(CWS_UPDATE_URL_PREFIX):
            result["update_url_ok"] = False
            score += 15
            flags.append(
                f"Non-standard update_url: '{update_url}' - "
                "extension updates from outside Chrome Web Store"
            )

        # Check for known attacker hosting patterns
        for pattern in SUSPICIOUS_UPDATE_URL_PATTERNS:
            if re.search(pattern, update_url, re.IGNORECASE):
                result["suspicious_update"] = True
                score += 20
                flags.append(
                    f"Suspicious update_url host matches pattern '{pattern}' - "
                    "possible attacker-controlled update feed"
                )
                break
    elif manifest.raw.get("key"):
        # No update_url is fine for sideloaded extensions but unusual for
        # extensions that claim to be from the Web Store
        flags.append(
            "Has 'key' field but no update_url - may be sideloaded copy of a CWS extension"
        )

    # --- 3. Live Chrome Web Store check (optional) -------------------------
    if query_cws and ext_id and _REQUESTS_AVAILABLE:
        cws = _query_cws(ext_id)
        result["cws_exists"] = cws["exists"]
        result["cws_version"] = cws["version"]
        result["cws_sha256"] = cws["sha256"]

        if cws["exists"] is None:
            # A failed lookup is "unknown", never "clean"
            flags.append(
                f"Chrome Web Store lookup failed ({cws.get('error', 'unknown error')}) "
                "- store status unknown"
            )
        elif cws["exists"] is False:
            score += 10
            flags.append(
                f"Extension ID {ext_id} not found on Chrome Web Store - sideloaded or unpublished"
            )
        else:
            store_flags, store_score, build_match = _compare_with_store(
                manifest.version, crx_sha256, cws["version"], cws["sha256"]
            )
            result["store_build_match"] = build_match
            flags.extend(store_flags)
            score += store_score

    result["pub_score"] = min(score, 30)  # cap contribution at 30
    return result


# ---------------------------------------------------------------------------
# Identity helpers
# ---------------------------------------------------------------------------


def _resolve_extension_id(manifest, crx3_header, crx2_public_key) -> tuple:
    """
    Decide the extension ID, in priority order:
      1. the signed crx_id in a CRX3 header (what Chrome itself uses)
      2. the CRX2 public key
      3. the manifest "key" field
    Returns (ext_id, id_source, flags, score).
    """
    flags: list = []
    score = 0
    ext_id = None
    source = None

    if crx3_header:
        try:
            info = parse_crx3_identity(crx3_header)
        except ValueError as exc:
            info = None
            flags.append(f"CRX3 signing header could not be parsed ({exc})")
            score += 10
        if info and info["extension_id"]:
            ext_id = info["extension_id"]
            source = "crx3-signed-id"
            if not info["developer_key"]:
                # Chrome refuses a CRX whose signed ID has no matching key proof
                flags.append(
                    "CRX3 signed ID does not match any public key in the header - "
                    "malformed or forged package"
                )
                score += 15
    elif crx2_public_key:
        ext_id = _compute_extension_id(crx2_public_key)
        source = "crx2-key"

    # The manifest "key" field is the fallback - and a cross-check
    manifest_key = _decode_manifest_key(manifest)
    if manifest_key is not None:
        manifest_id = _compute_extension_id(manifest_key)
        if ext_id is None:
            ext_id, source = manifest_id, "manifest-key"
        elif manifest_id != ext_id:
            flags.append(
                f"manifest 'key' claims extension ID {manifest_id} but the package is "
                f"signed as {ext_id} - repackaged extension posing as another"
            )
            score += 10

    if ext_id is None:
        flags.append("No signing key found - cannot verify extension ID (sideloaded/dev mode?)")
        score += 5

    return ext_id, source, flags, score


def _decode_manifest_key(manifest: ManifestInfo) -> bytes | None:
    """Return the DER bytes from the manifest "key" field, or None."""
    key_b64 = manifest.raw.get("key")
    if not isinstance(key_b64, str) or not key_b64:
        return None
    try:
        return base64.b64decode(key_b64, validate=False)
    except (ValueError, TypeError):
        return None


def parse_crx3_identity(header_bytes: bytes) -> dict:
    """
    Read the identity information from a CRX3 CrxFileHeader.

    Returns:
      {
        "extension_id":  str or None  (from the signed crx_id),
        "developer_key": bytes or None (the proof key whose hash == crx_id),
        "key_count":     int          (all RSA + ECDSA proof keys)
      }

    Falls back to the first RSA key when the header has no signed crx_id
    (very old CRX3 files).
    """
    fields = _parse_length_delimited_fields(header_bytes)

    keys = []
    for field_num in (_CRX3_RSA_PROOFS, _CRX3_ECDSA_PROOFS):
        for proof_bytes in fields.get(field_num, []):
            inner = _parse_length_delimited_fields(proof_bytes)
            key_list = inner.get(1, [])  # field 1 = public_key
            if key_list:
                keys.append(key_list[0])

    crx_id = None
    for signed in fields.get(_CRX3_SIGNED_HEADER_DATA, []):
        signed_fields = _parse_length_delimited_fields(signed)
        ids = signed_fields.get(_SIGNED_DATA_CRX_ID, [])
        if ids and len(ids[0]) == 16:
            crx_id = ids[0]
            break

    if crx_id is not None:
        extension_id = _id_from_hash_prefix(crx_id)
        developer_key = next((k for k in keys if hashlib.sha256(k).digest()[:16] == crx_id), None)
    elif keys:
        developer_key = keys[0]
        extension_id = _compute_extension_id(developer_key)
    else:
        developer_key = None
        extension_id = None

    return {
        "extension_id": extension_id,
        "developer_key": developer_key,
        "key_count": len(keys),
    }


def _compute_extension_id(public_key_bytes: bytes) -> str:
    """
    Compute a Chrome extension ID from raw public key bytes.

    Chrome's algorithm:
      1. SHA256-hash the raw DER public key
      2. Take the first 16 bytes (128 bits)
      3. Convert each nibble (4 bits) to a letter in the range a-p
         where 0→a, 1→b, ..., 15→p
    The result is a 32-character lowercase string.
    """
    return _id_from_hash_prefix(hashlib.sha256(public_key_bytes).digest()[:16])


def _id_from_hash_prefix(prefix16: bytes) -> str:
    """Map 16 bytes (32 hex digits) onto Chrome's a-p ID alphabet."""
    return "".join(chr(ord("a") + int(c, 16)) for c in prefix16.hex())


# ---------------------------------------------------------------------------
# Web Store comparison
# ---------------------------------------------------------------------------


def _compare_with_store(local_version, crx_sha256, store_version, store_sha256) -> tuple:
    """
    Compare the scanned package with what the Web Store currently serves.
    Returns (flags, score, store_build_match).
    """
    flags: list = []
    score = 0

    # Strongest signal: are these the exact same bytes the store serves?
    if crx_sha256 and store_sha256:
        if crx_sha256.lower() == store_sha256.lower():
            return flags, 0, True
        if store_version and local_version == store_version:
            flags.append(
                f"Same version as the Web Store ({store_version}) but different bytes - "
                "repackaged or tampered build"
            )
            return flags, 25, False
        # Different version, so different bytes are expected - fall through
        # to the version comparison below.

    build_match = False if (crx_sha256 and store_sha256) else None

    if store_version and local_version != store_version:
        local = _parse_version(local_version)
        store = _parse_version(store_version)
        if local and store and _tuple_gt(local, store):
            score += 20
            flags.append(
                f"Local version {local_version} is NEWER than the Web Store's "
                f"{store_version} - this build did not come from the store"
            )
        elif local and store:
            flags.append(
                f"Local version {local_version} is older than the Web Store's "
                f"{store_version} (outdated copy)"
            )
    return flags, score, build_match


def _query_cws(ext_id: str, timeout: int = 5) -> dict:
    """
    Ask the Chrome Web Store update endpoint about `ext_id`.

    Returns {"exists": True/False/None, "version": str|None,
             "sha256": str|None, "error": str (only when exists is None)}.

    exists=False only when the store explicitly says the ID is unknown.
    Any network error, HTTP error, or unparseable reply is exists=None
    ("unknown") - never treated as clean or as missing.
    """
    unknown = {"exists": None, "version": None, "sha256": None}
    url = CWS_UPDATE_TEMPLATE.format(ext_id=ext_id)
    try:
        resp = requests.get(url, timeout=timeout)
    except Exception as exc:  # network down, timeout, DNS, TLS...
        return {**unknown, "error": f"network error: {type(exc).__name__}"}

    if resp.status_code != 200:
        return {**unknown, "error": f"HTTP {resp.status_code}"}
    if len(resp.content) > MAX_CWS_RESPONSE_BYTES:
        return {**unknown, "error": "response too large"}
    return parse_cws_update_xml(resp.text, ext_id)


def parse_cws_update_xml(text: str, ext_id: str) -> dict:
    """
    Parse an update2 XML reply. Real examples:
      unknown ID: <app appid="..." status="error-unknownApplication"/>
      known ID:   <app appid="..." status="ok">
                    <updatecheck status="ok" version="2.0.17" hash_sha256="..."/>
                  </app>
    """
    unknown = {"exists": None, "version": None, "sha256": None}
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return {**unknown, "error": "unparseable XML reply"}

    for app in root.iter():
        if _local_tag(app.tag) != "app" or app.get("appid") != ext_id:
            continue
        status = app.get("status", "")
        if status == "error-unknownApplication":
            return {"exists": False, "version": None, "sha256": None}
        if status != "ok":
            return {**unknown, "error": f"store status {status!r}"}

        version = sha256 = None
        for child in app:
            if _local_tag(child.tag) == "updatecheck":
                version = child.get("version")
                sha256 = child.get("hash_sha256")
        return {"exists": True, "version": version, "sha256": sha256}

    return {**unknown, "error": "reply did not mention this extension ID"}


def _local_tag(tag: str) -> str:
    """Strip an XML namespace: '{http://...}app' -> 'app'."""
    return tag.rsplit("}", 1)[-1]


# ---------------------------------------------------------------------------
# Minimal protobuf parser - handles only the wire types we need
# ---------------------------------------------------------------------------


def _decode_varint(data: bytes, pos: int) -> tuple:
    """
    Decode a protobuf base-128 varint starting at pos.
    Returns (value, new_pos). Raises ValueError on a varint longer than
    10 bytes (the protobuf maximum) - a sign of a corrupt header.
    """
    result = 0
    shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):  # MSB clear = last byte of varint
            break
        shift += 7
        if shift >= 70:
            raise ValueError("protobuf varint too long")
    return result, pos


def _parse_length_delimited_fields(data: bytes) -> dict:
    """
    Parse protobuf fields from `data` and return a dict of
    {field_number: [bytes_value, ...]} for length-delimited fields only.
    Varint, 32-bit, and 64-bit fields are consumed but not stored.
    """
    fields: dict = {}
    pos = 0
    while pos < len(data):
        tag, pos = _decode_varint(data, pos)

        field_num = tag >> 3
        wire_type = tag & 0x7

        if wire_type == 0:  # varint - consume and discard
            _, pos = _decode_varint(data, pos)
        elif wire_type == 1:  # 64-bit fixed - skip
            pos += 8
        elif wire_type == 2:  # length-delimited - extract
            length, pos = _decode_varint(data, pos)
            value = data[pos : pos + length]
            pos += length
            fields.setdefault(field_num, []).append(value)
        elif wire_type == 5:  # 32-bit fixed - skip
            pos += 4
        else:
            break  # Unknown wire type - bail

    return fields
