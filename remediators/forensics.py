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

import getpass
import hashlib
import json
import socket
from datetime import datetime, timezone
from pathlib import Path

# Default quarantine root — sits next to the extguard install
DEFAULT_QUARANTINE_ROOT = Path(__file__).parent.parent / "quarantine"


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
) -> dict:
    """
    Build a complete forensic evidence package and store it on disk.

    Args:
        extension_id:     The 32-char Chrome ID (or "" if unknown)
        extension_name:   Display name for human-readable logs
        crx_bytes:        Raw .crx file bytes (or None for bare manifests)
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
        sample_path = case_dir / "sample.crx"
        sample_path.write_bytes(crx_bytes)
        # Note: we deliberately do NOT chmod() the sample to read-only.
        # On Windows, chmod(0o444) is essentially a no-op (only touches the
        # user-read bit, doesn't make the file immutable). Promising
        # "read-only evidence" via file mode would be misleading.
        #
        # Tamper detection is via SHA-256 in chain_of_custody.json + the
        # standalone .sha256 sidecar - run `verify_case()` to check.
        artifacts["sample"] = str(sample_path)
        hashes["sample.crx"] = _sha256_file(sample_path)

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
        "tool_version": "0.1.0",
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

    coc_path = case_dir / "chain_of_custody.json"
    coc_path.write_text(json.dumps(coc, indent=2), encoding="utf-8")
    # The CoC manifest is the only file we hash separately AFTER write —
    # so its own hash is recorded in a sibling .sha256 file for verification
    coc_hash = _sha256_file(coc_path)
    (case_dir / "chain_of_custody.json.sha256").write_text(
        f"{coc_hash}  chain_of_custody.json\n", encoding="utf-8"
    )

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
        coc_path.write_text(json.dumps(coc, indent=2), encoding="utf-8")

        # Recompute and update the side-car SHA256
        new_hash = _sha256_file(coc_path)
        (coc_path.parent / "chain_of_custody.json.sha256").write_text(
            f"{new_hash}  chain_of_custody.json\n", encoding="utf-8"
        )
        return {"ok": True, "new_hash": new_hash}
    except (OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "error": str(exc)}


def verify_case(case_dir: str) -> dict:
    """
    Re-hash every artifact in a case folder and verify against chain_of_custody.json.
    Used during incident review to confirm evidence has not been tampered with.
    """
    coc_path = Path(case_dir) / "chain_of_custody.json"
    if not coc_path.exists():
        return {"ok": False, "error": "No chain_of_custody.json in case dir"}

    coc = json.loads(coc_path.read_text(encoding="utf-8"))
    expected = coc.get("sha256", {})
    mismatches = []

    for filename, expected_hash in expected.items():
        artifact_path = Path(case_dir) / filename
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

    return {
        "ok": len(mismatches) == 0,
        "verified": len(expected) - len(mismatches),
        "total": len(expected),
        "mismatches": mismatches,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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
