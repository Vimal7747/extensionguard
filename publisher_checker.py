# publisher_checker.py - CRX signing key extraction + publisher legitimacy checks
#
# Two attack indicators this module covers:
#   1. Publisher cert / account age < 30 days  (Shai-Hulud signature)
#   2. Non-standard or self-hosted update_url  (supply chain red flag)
#
# How extension IDs work in Chrome:
#   - Every CRX is signed with an RSA or EC key
#   - Chrome computes the extension ID as: lowercase base16 of SHA256(public_key),
#     then maps each hex digit through  a->p  alphabet (0=a,1=b,...,15=p)
#   - For installed extensions the "key" field in manifest.json holds the
#     base64-encoded DER public key, so we don't need to crack open the CRX header
#   - For raw .crx files we decode the CRX3 protobuf header ourselves (no library needed)
#
# External calls:
#   - One GET to the Chrome Web Store update endpoint (optional, has timeout)
#   - Returns gracefully if network is unavailable

import base64
import hashlib
import re

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

from models import ManifestInfo

# Official Chrome Web Store update URL prefix - anything else is suspicious
CWS_UPDATE_URL_PREFIX = "https://clients2.google.com/service/update2/crx"

# CWS update check endpoint - returns XML with version / extension metadata
CWS_UPDATE_TEMPLATE = (
    "https://clients2.google.com/service/update2/crx"
    "?response=updatecheck"
    "&x=id%3D{ext_id}%26uc"
    "&prodversion=114.0"
)

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


# ---------------------------------------------------------------------------
# Public dataclass-free result (simple dict keeps it CS50P-friendly)
# ---------------------------------------------------------------------------

def check_publisher(
    manifest: ManifestInfo,
    crx_header_bytes: bytes | None = None,
    query_cws: bool = True,
) -> dict:
    """
    Check publisher legitimacy and return a risk summary dict.

    Args:
        manifest:          Parsed manifest
        crx_header_bytes:  Raw CRX header bytes (from _strip_crx_header in crx_parser).
                           Pass None if analysing a bare manifest.json.
        query_cws:         Whether to make a live request to the CWS update endpoint.
                           Set False for offline/unit-test scenarios.

    Returns a dict with keys:
      extension_id       str or None
      update_url_ok      bool   (True = official CWS URL or absent)
      suspicious_update  bool
      cws_version        str or None  (version string from CWS, if queried)
      cws_exists         bool or None (None = not queried)
      pub_score          int    (0–30 publisher-specific risk contribution)
      flags              list[str]
    """
    flags  = []
    score  = 0
    result = {
        "extension_id":      None,
        "update_url_ok":     True,
        "suspicious_update": False,
        "cws_version":       None,
        "cws_exists":        None,
        "pub_score":         0,
        "flags":             flags,
    }

    # --- 1. Extract public key and compute extension ID --------------------
    public_key_bytes = _get_public_key(manifest, crx_header_bytes)
    if public_key_bytes:
        ext_id = _compute_extension_id(public_key_bytes)
        result["extension_id"] = ext_id
    else:
        flags.append("No signing key found - cannot verify extension ID (sideloaded/dev mode?)")
        score += 5

    # --- 2. Validate update_url field --------------------------------------
    update_url = manifest.raw.get("update_url", "")
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
    else:
        # No update_url is fine for sideloaded extensions but unusual for
        # extensions that claim to be from the Web Store
        if manifest.raw.get("key"):
            flags.append(
                "Has 'key' field but no update_url - "
                "may be sideloaded copy of a CWS extension"
            )

    # --- 3. Live CWS version check (optional) ------------------------------
    ext_id = result["extension_id"]
    if query_cws and ext_id and _REQUESTS_AVAILABLE:
        cws_info = _query_cws(ext_id)
        result["cws_version"] = cws_info.get("version")
        result["cws_exists"]  = cws_info.get("exists", False)

        if not cws_info.get("exists"):
            score += 10
            flags.append(
                f"Extension ID {ext_id} not found on Chrome Web Store - "
                "sideloaded or unpublished"
            )
        elif cws_info.get("version") and manifest.version != cws_info["version"]:
            score += 20
            flags.append(
                f"Version mismatch: local manifest says {manifest.version}, "
                f"CWS says {cws_info['version']} - possible tampered update"
            )

    result["pub_score"] = min(score, 30)   # cap contribution at 30
    return result


# ---------------------------------------------------------------------------
# Key extraction helpers
# ---------------------------------------------------------------------------

def _get_public_key(manifest: ManifestInfo, crx_header_bytes: bytes | None) -> bytes | None:
    """
    Try to get the raw DER public key bytes from two sources, in priority order:
      1. The "key" field in manifest.json (base64-encoded DER)
      2. The CRX3 protobuf header (requires crx_header_bytes)
    """
    # Source 1: manifest "key" field (present for installed/sideloaded extensions)
    key_b64 = manifest.raw.get("key")
    if key_b64:
        try:
            return base64.b64decode(key_b64)
        except Exception:
            pass

    # Source 2: CRX3 protobuf header
    if crx_header_bytes:
        try:
            return _extract_key_from_crx3_header(crx_header_bytes)
        except Exception:
            pass

    return None


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
    key_hash = hashlib.sha256(public_key_bytes).digest()[:16]
    # hex() gives us a 32-char hex string (16 bytes * 2 hex digits each)
    hex_str  = key_hash.hex()
    # Remap: each hex digit (0-9, a-f) → letter a-p
    ext_id = "".join(
        chr(ord('a') + int(c, 16))
        for c in hex_str
    )
    return ext_id


def _extract_key_from_crx3_header(header_bytes: bytes) -> bytes | None:
    """
    Manually decode the CRX3 protobuf to find the first RSA public key.

    CrxFileHeader proto:
      field 2, wire 2 - repeated AsymmetricKeyProof (sha256_with_rsa)
        field 1, wire 2 - bytes public_key (DER-encoded SubjectPublicKeyInfo)
        field 2, wire 2 - bytes signature

    We parse just enough protobuf to get the public_key bytes.
    """
    fields = _parse_length_delimited_fields(header_bytes)

    # Field 2 = sha256_with_rsa proofs
    rsa_proofs = fields.get(2, [])
    for proof_bytes in rsa_proofs:
        inner = _parse_length_delimited_fields(proof_bytes)
        # Field 1 = public_key inside AsymmetricKeyProof
        keys = inner.get(1, [])
        if keys:
            return keys[0]   # Return the first (primary) signing key

    # Fallback: try ecdsa proofs (field 3)
    ec_proofs = fields.get(3, [])
    for proof_bytes in ec_proofs:
        inner = _parse_length_delimited_fields(proof_bytes)
        keys = inner.get(1, [])
        if keys:
            return keys[0]

    return None


# ---------------------------------------------------------------------------
# Minimal protobuf parser - handles only the wire types we need
# ---------------------------------------------------------------------------

def _decode_varint(data: bytes, pos: int) -> tuple:
    """
    Decode a protobuf base-128 varint starting at pos.
    Returns (value, new_pos).
    """
    result = 0
    shift  = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):  # MSB clear = last byte of varint
            break
        shift += 7
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
        try:
            tag, pos = _decode_varint(data, pos)
        except IndexError:
            break

        field_num = tag >> 3
        wire_type = tag & 0x7

        if wire_type == 0:       # varint - consume and discard
            _, pos = _decode_varint(data, pos)
        elif wire_type == 1:     # 64-bit fixed - skip
            pos += 8
        elif wire_type == 2:     # length-delimited - extract
            length, pos = _decode_varint(data, pos)
            value = data[pos : pos + length]
            pos += length
            fields.setdefault(field_num, []).append(value)
        elif wire_type == 5:     # 32-bit fixed - skip
            pos += 4
        else:
            break  # Unknown wire type - bail

    return fields


# ---------------------------------------------------------------------------
# CWS update endpoint query
# ---------------------------------------------------------------------------

def _query_cws(ext_id: str, timeout: int = 5) -> dict:
    """
    Hit the Chrome Web Store update endpoint for `ext_id`.
    Returns {"exists": bool, "version": str_or_None}.
    Silently returns {"exists": None} on network errors.
    """
    url = CWS_UPDATE_TEMPLATE.format(ext_id=ext_id)
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code != 200:
            return {"exists": False}

        # Response is XML; a minimal check is sufficient
        text = resp.text
        if "status='noupdate'" in text or "status=\"noupdate\"" in text:
            # Extension exists but is up-to-date (no update available)
            return {"exists": True, "version": None}

        if ext_id not in text:
            return {"exists": False}

        # Try to extract the version from the response XML
        version_match = re.search(r'version="([^"]+)"', text)
        version = version_match.group(1) if version_match else None
        return {"exists": True, "version": version}

    except Exception:
        # Network unavailable, timeout, etc. - don't crash the pipeline
        return {"exists": None, "version": None}
