# remediators/forensics.py - Preserve evidence before killing a malicious extension
#
# Before we remove a suspect extension we capture an immutable evidence package
# so the IR team can:
#   - Re-analyse the malicious sample after the fact
#   - Hash-match against future incidents (deduplicate breach reports)
#   - Build court-admissible chain-of-custody records
#   - Reverse the kill if it turns out to be a false positive
#
# What we preserve:
#   1. The raw CRX / ZIP bytes (hashed, immutable filename)
#   2. The manifest.json (extracted, easy to read)
#   3. The full triage result (Claude AI narrative + IOCs + MITRE map)
#   4. Any monitoring alerts that triggered the remediation
#   5. A chain-of-custody manifest (who, what, when, hashes)
#   6. Optional: chrome.storage.local snapshot (if Chrome is still running)
#
# Quarantine layout:
#   quarantine/
#     <YYYYMMDD-HHMMSS>-<short_hash>/
#       sample.crx            (the raw bytes — read-only)
#       manifest.json
#       triage.json
#       alerts.jsonl          (if alert history was supplied)
#       storage_snapshot.json (if CDP was available)
#       chain_of_custody.json
#       chain_of_custody.json.sha256   (plain hash - detects accidental change)
#       chain_of_custody.json.hmac     (keyed signature - detects deliberate edits)
#
# Integrity model - be precise about what this proves:
#   - The artifact hashes live in chain_of_custody.json, and that file is
#     signed with HMAC-SHA256 using a key kept OUTSIDE the case folder
#     (EXTGUARD_COC_KEY env var, or ~/.extguard/coc_hmac.key, auto-created).
#   - Someone who can edit the case folder but cannot read that key cannot
#     swap a sample and fix up the hashes without verify_case() noticing.
#   - Someone who CAN read the key (same OS account, admin) can forge it.
#     For stronger guarantees, set EXTGUARD_COC_KEY from a secrets manager
#     and ship the .hmac values to your SIEM when cases are created.

import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
from datetime import datetime, timezone
from pathlib import Path

from extguard import paths

# Default quarantine root - $EXTGUARD_QUARANTINE or ~/.extguard/quarantine.
# (It used to sit next to the source files, i.e. inside site-packages once
# pip-installed - evidence must not live where a reinstall would delete it.)
DEFAULT_QUARANTINE_ROOT = paths.quarantine_root()

# Case folder names: YYYYMMDD-HHMMSS-<8 chars> with an optional collision
# suffix. The 8 chars are hex (from a hash) or a-p (from an extension ID).
# Anything taking a case ID from outside (dashboard URL, remediation queue)
# must match this before building a path - it is the path-traversal defence.
CASE_ID_PATTERN = re.compile(r"^\d{8}-\d{6}-[0-9a-p]{8}(?:-\d+|-overflow-[A-Za-z0-9_-]+)?\Z")

# Where the chain-of-custody signing key lives when EXTGUARD_COC_KEY isn't set
COC_KEY_FILE = paths.data_dir() / "coc_hmac.key"
COC_FILE = "chain_of_custody.json"
COC_SHA256_FILE = "chain_of_custody.json.sha256"
COC_HMAC_FILE = "chain_of_custody.json.hmac"


def preserve(
    extension_id: str,
    extension_name: str,
    crx_bytes: bytes | None,
    manifest: dict,
    triage_result: dict | None = None,
    alert_history: list | None = None,
    storage_snapshot: dict | None = None,
    quarantine_root: Path | None = None,
    operator: str | None = None,
    case_id: str | None = None,
    sample_name: str = "sample.crx",
) -> dict:
    """
    Build a complete forensic evidence package and store it on disk.

    Args:
        extension_id:     The 32-char Chrome ID (or "" if unknown)
        extension_name:   Display name for human-readable logs
        crx_bytes:        The ORIGINAL sample file bytes, exactly as received
                          (ParsedExtension.file_bytes), or None for bare manifests.
                          Must not be the header-stripped ZIP: the evidence hash
                          has to match the hash threat intel knows the file by.
        sample_name:      File name for the stored sample ("sample.crx" / "sample.zip")
        manifest:         Parsed manifest dict (raw form)
        triage_result:    Optional Stage 2 triage JSON
        alert_history:    Optional list of Stage 3 alert dicts
        storage_snapshot: Optional chrome.storage.local dump from CDP
        quarantine_root:  Where to store evidence (default: ./quarantine)
        operator:         Who is doing the remediation (default: current user)
        case_id:          Optional SOC ticket / incident number to tag this case

    Returns a result dict with:
      ok            bool
      case_dir      str   absolute path to the case folder
      artifacts     dict  paths to each preserved artifact
      hashes        dict  SHA-256 of each artifact
      manifest_path str   path to the chain_of_custody.json
    """
    root = Path(quarantine_root) if quarantine_root else DEFAULT_QUARANTINE_ROOT
    root.mkdir(parents=True, exist_ok=True)

    # Build a unique case folder name: timestamp + short hash
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    short_hash = _short_id(crx_bytes, extension_id, extension_name)
    case_folder_name = f"{timestamp}-{short_hash}"
    case_dir = root / case_folder_name

    try:
        case_dir.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        # Extremely unlikely (timestamp + short-hash collision), but handle
        # gracefully. Try suffixes -2, -3, ..., -99; if all are taken,
        # fall back to a random-tempdir-style guaranteed-unique name.
        case_dir = None
        for n in range(2, 100):
            candidate = root / f"{case_folder_name}-{n}"
            try:
                candidate.mkdir(parents=True, exist_ok=False)
                case_dir = candidate
                break
            except FileExistsError:
                continue
        if case_dir is None:
            # 99 collisions in the same second is so anomalous it deserves
            # a forensically-traceable random suffix from tempfile
            import tempfile

            case_dir = Path(
                tempfile.mkdtemp(
                    prefix=f"{case_folder_name}-overflow-",
                    dir=str(root),
                )
            )

    artifacts: dict = {}
    hashes: dict = {}

    # --- 1. Raw sample (CRX bytes) -----------------------------------------
    if crx_bytes:
        if not _is_plain_filename(sample_name):
            raise ValueError(f"Unsafe sample file name: {sample_name!r}")
        sample_path = case_dir / sample_name
        sample_path.write_bytes(crx_bytes)
        # Note: we deliberately do NOT chmod() the sample to read-only.
        # On Windows, chmod(0o444) is essentially a no-op (only touches the
        # user-read bit, doesn't make the file immutable). Promising
        # "read-only evidence" via file mode would be misleading.
        #
        # Tamper detection is via SHA-256 in chain_of_custody.json + the
        # standalone .sha256 sidecar - run `verify_case()` to check.
        artifacts["sample"] = str(sample_path)
        hashes[sample_name] = _sha256_file(sample_path)

    # --- 2. Manifest (always preserved, even if bare) ----------------------
    manifest_path = case_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    artifacts["manifest"] = str(manifest_path)
    hashes["manifest.json"] = _sha256_file(manifest_path)

    # --- 3. Triage result (Claude AI output) -------------------------------
    if triage_result:
        triage_path = case_dir / "triage.json"
        triage_path.write_text(json.dumps(triage_result, indent=2), encoding="utf-8")
        artifacts["triage"] = str(triage_path)
        hashes["triage.json"] = _sha256_file(triage_path)

    # --- 4. Alert history (one JSON object per line, append-only) ---------
    if alert_history:
        alerts_path = case_dir / "alerts.jsonl"
        with alerts_path.open("w", encoding="utf-8") as f:
            for alert in alert_history:
                f.write(json.dumps(alert) + "\n")
        artifacts["alerts"] = str(alerts_path)
        hashes["alerts.jsonl"] = _sha256_file(alerts_path)

    # --- 5. Storage snapshot (from CDP if Chrome was monitored live) ------
    if storage_snapshot:
        storage_path = case_dir / "storage_snapshot.json"
        storage_path.write_text(json.dumps(storage_snapshot, indent=2), encoding="utf-8")
        artifacts["storage"] = str(storage_path)
        hashes["storage_snapshot.json"] = _sha256_file(storage_path)

    # --- 6. Chain of custody manifest --------------------------------------
    coc = {
        "case_id": case_id or case_folder_name,
        "preserved_at": datetime.now(timezone.utc).isoformat(),
        "operator": operator or getpass.getuser(),
        "operator_host": socket.gethostname(),
        "extension": {
            "id": extension_id,
            "name": extension_name,
            "manifest_version": manifest.get("manifest_version"),
            "claimed_version": manifest.get("version"),
        },
        "artifacts": list(artifacts.keys()),
        "artifact_paths": artifacts,
        "sha256": hashes,
        "tool": "ExtensionGuard Stage 5 - Forensic Preservation",
        "tool_version": _tool_version(),
        # Future operations should append to this list to maintain custody chain
        "custody_log": [
            {
                "action": "preserved",
                "actor": operator or getpass.getuser(),
                "host": socket.gethostname(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "notes": "Initial preservation by ExtensionGuard Stage 5",
            }
        ],
    }

    coc_path = case_dir / COC_FILE
    coc_path.write_text(json.dumps(coc, indent=2), encoding="utf-8")
    # The CoC is hashed and signed AFTER it is written - see _seal_coc()
    coc_hash = _seal_coc(case_dir)

    return {
        "ok": True,
        "case_dir": str(case_dir.resolve()),
        "case_id": coc["case_id"],
        "artifacts": artifacts,
        "hashes": hashes,
        "manifest_path": str(coc_path.resolve()),
        "coc_hash": coc_hash,
    }


def append_custody_action(case_dir: str, action: str, actor: str, notes: str = "") -> dict:
    """
    Append an action to a case's chain_of_custody.json custody_log.
    Call this when the kill executes, the remediation playbook completes, etc.
    """
    coc_path = Path(case_dir) / "chain_of_custody.json"
    if not coc_path.exists():
        return {"ok": False, "error": f"Chain of custody not found at {coc_path}"}

    try:
        coc = json.loads(coc_path.read_text(encoding="utf-8"))
        coc.setdefault("custody_log", []).append(
            {
                "action": action,
                "actor": actor,
                "host": socket.gethostname(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "notes": notes,
            }
        )
        # Refuse to extend a chain of custody that no longer verifies -
        # re-signing it would launder the tampering.
        problem = _check_coc_seal(coc_path.parent)
        if problem:
            return {"ok": False, "error": f"Chain of custody failed verification: {problem}"}

        coc_path.write_text(json.dumps(coc, indent=2), encoding="utf-8")
        new_hash = _seal_coc(coc_path.parent)
        return {"ok": True, "new_hash": new_hash}
    except (OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "error": str(exc)}


def verify_case(case_dir: str) -> dict:
    """
    Verify a case folder:
      1. chain_of_custody.json matches its .sha256 sidecar
      2. chain_of_custody.json carries a valid HMAC signature
      3. every artifact matches the hash recorded in chain_of_custody.json

    Returns {"ok", "verified", "total", "mismatches", "signature"} where
    signature is "valid", "invalid", "missing", or "no-key" (this machine
    doesn't have the signing key, so the signature couldn't be checked).
    """
    case_path = Path(case_dir)
    coc_path = case_path / COC_FILE
    if not coc_path.exists():
        return {"ok": False, "error": "No chain_of_custody.json in case dir"}

    try:
        coc = json.loads(coc_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"ok": False, "error": f"chain_of_custody.json is unreadable: {exc}"}

    mismatches = []

    # --- 1. Plain sidecar hash --------------------------------------------
    coc_hash = _sha256_file(coc_path)
    sidecar = case_path / COC_SHA256_FILE
    if not sidecar.exists():
        mismatches.append({"file": COC_FILE, "issue": "sidecar .sha256 missing"})
    elif not sidecar.read_text(encoding="utf-8").startswith(coc_hash):
        mismatches.append({"file": COC_FILE, "issue": "does not match its .sha256 sidecar"})

    # --- 2. HMAC signature --------------------------------------------------
    signature = _signature_status(case_path, coc_path)
    if signature == "invalid":
        mismatches.append(
            {
                "file": COC_FILE,
                "issue": "HMAC signature invalid - edited outside ExtensionGuard",
            }
        )
    elif signature == "missing":
        mismatches.append({"file": COC_FILE, "issue": "unsigned (.hmac file missing)"})

    # --- 3. Artifact hashes -------------------------------------------------
    expected = coc.get("sha256", {})
    if not isinstance(expected, dict):
        expected = {}
        mismatches.append({"file": COC_FILE, "issue": "sha256 table is malformed"})

    for filename, expected_hash in expected.items():
        if not _is_plain_filename(filename):
            # A crafted CoC could otherwise make us hash files outside the case
            mismatches.append({"file": str(filename), "issue": "unsafe file name in CoC"})
            continue
        artifact_path = case_path / filename
        if not artifact_path.exists():
            mismatches.append({"file": filename, "issue": "missing"})
            continue
        actual = _sha256_file(artifact_path)
        if actual != expected_hash:
            mismatches.append(
                {
                    "file": filename,
                    "issue": "hash mismatch",
                    "expected": expected_hash,
                    "actual": actual,
                }
            )

    artifact_problems = sum(1 for m in mismatches if m["file"] != COC_FILE)
    return {
        "ok": len(mismatches) == 0,
        "verified": len(expected) - artifact_problems,
        "total": len(expected),
        "mismatches": mismatches,
        "signature": signature,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seal_coc(case_dir: Path) -> str:
    """Write the .sha256 sidecar and the .hmac signature for the CoC. Returns the hash."""
    coc_path = case_dir / COC_FILE
    coc_hash = _sha256_file(coc_path)
    (case_dir / COC_SHA256_FILE).write_text(f"{coc_hash}  {COC_FILE}\n", encoding="utf-8")
    key = _coc_key(create=True)
    signature = hmac.new(key, coc_path.read_bytes(), hashlib.sha256).hexdigest()
    (case_dir / COC_HMAC_FILE).write_text(
        f"hmac-sha256:{signature}  key-id:{_key_id(key)}\n", encoding="utf-8"
    )
    return coc_hash


def _check_coc_seal(case_dir: Path) -> str | None:
    """Return a problem description if the CoC seal is broken, else None."""
    coc_path = case_dir / COC_FILE
    sidecar = case_dir / COC_SHA256_FILE
    if sidecar.exists() and not sidecar.read_text(encoding="utf-8").startswith(
        _sha256_file(coc_path)
    ):
        return "does not match its .sha256 sidecar"
    status = _signature_status(case_dir, coc_path)
    if status in ("invalid", "missing"):
        return f"HMAC signature {status}"
    return None


def _signature_status(case_dir: Path, coc_path: Path) -> str:
    """'valid', 'invalid', 'missing', or 'no-key'."""
    hmac_file = case_dir / COC_HMAC_FILE
    if not hmac_file.exists():
        return "missing"
    key = _coc_key(create=False)
    if key is None:
        return "no-key"
    fields = hmac_file.read_text(encoding="utf-8").split()
    if not fields:
        return "invalid"
    recorded = fields[0].removeprefix("hmac-sha256:")
    actual = hmac.new(key, coc_path.read_bytes(), hashlib.sha256).hexdigest()
    return "valid" if hmac.compare_digest(recorded, actual) else "invalid"


def _coc_key(create: bool) -> bytes | None:
    """
    The chain-of-custody signing key:
      1. EXTGUARD_COC_KEY environment variable (preferred - e.g. from a vault)
      2. ~/.extguard/coc_hmac.key, created with a random key on first use
    Returns None when create=False and no key exists.
    """
    env_key = os.environ.get("EXTGUARD_COC_KEY")
    if env_key:
        return env_key.encode("utf-8")
    if COC_KEY_FILE.exists():
        return COC_KEY_FILE.read_text(encoding="utf-8").strip().encode("utf-8")
    if not create:
        return None
    COC_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_hex(32)
    COC_KEY_FILE.write_text(key, encoding="utf-8")
    try:
        os.chmod(COC_KEY_FILE, 0o600)  # owner-only on POSIX; best effort on Windows
    except OSError:
        pass
    return key.encode("utf-8")


def _key_id(key: bytes) -> str:
    """A short, non-secret fingerprint so an analyst can tell which key signed a case."""
    return hashlib.sha256(b"extguard-coc-key-id:" + key).hexdigest()[:12]


def _is_plain_filename(name) -> bool:
    """True for a bare file name - no directories, no '..', no drive letters."""
    return (
        isinstance(name, str)
        and name not in ("", ".", "..")
        and Path(name).name == name
        and "/" not in name
        and "\\" not in name
        and ":" not in name
    )


def _tool_version() -> str:
    """The installed ExtensionGuard version (recorded in evidence)."""
    try:
        from importlib.metadata import PackageNotFoundError, version

        return version("extensionguard")
    except (ImportError, PackageNotFoundError):
        return "unknown (not installed as a package)"


def _sha256_file(path: Path) -> str:
    """Compute SHA-256 of a file in chunks (handles large CRX files efficiently)."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _short_id(crx_bytes: bytes | None, extension_id: str, name: str) -> str:
    """
    Build a short stable ID for the case folder name.
    Prefer CRX hash > extension ID > name hash.
    """
    if crx_bytes:
        return hashlib.sha256(crx_bytes).hexdigest()[:8]
    if extension_id:
        return extension_id[:8]
    return hashlib.sha256(name.encode("utf-8")).hexdigest()[:8]
