# update_velocity.py - Extension version change velocity analysis
#
# Supply chain attacks often inject malicious code into a PATCH or minor update.
# Red flags we look for:
#   1. Version number jumped by more than expected (e.g., 1.0.4 → 17.3.1 overnight)
#   2. The extension has a very low version number (brand new, little history)
#   3. update_url is present but the CWS says the extension doesn't exist
#      (could mean the extension was delisted after the malicious push)
#
# For live CWS version comparison we re-use the CWS query from publisher_checker,
# so no extra network calls are needed.
#
# For persistent history, we maintain a local JSON store at:
#   ~/.extguard/version_history.json
# On first scan we record the version; on subsequent scans we compare.

import json
import re
from datetime import datetime, timezone
from pathlib import Path

# Where we persist known-good version history
HISTORY_FILE = Path.home() / ".extguard" / "version_history.json"

# Thresholds for "suspicious" version jumps
# A MAJOR bump (1.x → 2.x) in a supply chain attack is unusual — attackers
# usually hide inside minor/patch updates to avoid drawing attention.
# But a very large jump in ANY segment is suspicious.
SUSPICIOUS_MAJOR_JUMP    = 2    # e.g., 1.x → 4.x is suspicious
SUSPICIOUS_MINOR_JUMP    = 10   # e.g., x.1.y → x.15.y
SUSPICIOUS_PATCH_JUMP    = 50   # e.g., x.y.1 → x.y.55


def analyse_version(
    manifest_version: str,
    extension_id: str | None = None,
    cws_version: str | None = None,
    extension_name: str | None = None,
) -> dict:
    """
    Analyse the extension's version for supply chain injection indicators.

    Args:
        manifest_version:  The version string from manifest.json
        extension_id:      Chrome extension ID (used as history store key)
        cws_version:       Version string fetched live from CWS (may be None)
        extension_name:    Human-readable name for logging

    Returns dict with keys:
      current_version     str
      previous_version    str or None   (from local history, if any)
      cws_version         str or None
      version_jump        dict or None  (breakdown of how much it jumped)
      is_suspicious       bool
      velocity_score      int           0-15 risk contribution
      flags               list[str]
    """
    result = {
        "current_version":  manifest_version,
        "previous_version": None,
        "cws_version":      cws_version,
        "version_jump":     None,
        "is_suspicious":    False,
        "velocity_score":   0,
        "flags":            [],
    }

    current = _parse_version(manifest_version)
    if not current:
        result["flags"].append(
            f"Could not parse version string: '{manifest_version}'"
        )
        return result

    # --- Check against local history --------------------------------------
    history_key = extension_id or extension_name or manifest_version
    previous_record = _load_history(history_key)

    if previous_record:
        previous_str = previous_record.get("version", "")
        previous     = _parse_version(previous_str)
        result["previous_version"] = previous_str

        if previous and current != previous:
            jump = _compute_jump(previous, current)
            result["version_jump"] = jump

            suspicious, flag = _evaluate_jump(jump, previous_str, manifest_version)
            if suspicious:
                result["is_suspicious"]   = True
                result["velocity_score"] += 10
                result["flags"].append(flag)

    # --- Cross-check against CWS version ----------------------------------
    if cws_version and cws_version != manifest_version:
        cws = _parse_version(cws_version)
        if cws and current:
            jump = _compute_jump(cws, current)
            # If local is AHEAD of CWS that's unusual — may mean a tampered
            # update was pushed before CWS could be updated, then rolled back
            if _tuple_gt(current, cws):
                result["velocity_score"] += 8
                result["flags"].append(
                    f"Local version {manifest_version} is AHEAD of CWS version {cws_version} "
                    "— could indicate a tampered or injected update"
                )
            # If local is BEHIND CWS, less suspicious (old install)

    # --- Low version number heuristic ------------------------------------
    if current[0] == 0 and current[1] == 0:
        result["velocity_score"] += 3
        result["flags"].append(
            "Extension is at major version 0 — very early / brand-new release"
        )

    result["velocity_score"] = min(result["velocity_score"], 15)

    # Persist current version to history for future comparisons
    _save_history(history_key, manifest_version, extension_name)

    return result


# ---------------------------------------------------------------------------
# Version string parsing
# ---------------------------------------------------------------------------

def _parse_version(version_str: str) -> tuple | None:
    """
    Parse a version string like "17.3.1" into a tuple of ints (17, 3, 1).
    Returns None if the string can't be parsed.
    Handles common formats: "1.0", "1.0.0", "1.0.0.0", "1.0.0-beta1".
    """
    if not version_str:
        return None
    # Strip non-numeric suffixes like "-beta1", "+build.42"
    clean = re.split(r"[-+]", version_str)[0]
    parts = clean.split(".")
    try:
        result = tuple(int(p) for p in parts if p.isdigit())
        # An empty tuple means none of the segments were numeric - treat that
        # as an unparseable version rather than version "()"
        return result if result else None
    except ValueError:
        return None


def _compute_jump(old: tuple, new: tuple) -> dict:
    """
    Compute the delta between two version tuples.
    Pads shorter tuples with zeros to make them the same length.
    """
    length = max(len(old), len(new))
    old_p  = old + (0,) * (length - len(old))
    new_p  = new + (0,) * (length - len(new))
    return {
        "major": new_p[0] - old_p[0] if length > 0 else 0,
        "minor": new_p[1] - old_p[1] if length > 1 else 0,
        "patch": new_p[2] - old_p[2] if length > 2 else 0,
    }


def _evaluate_jump(jump: dict, old_str: str, new_str: str) -> tuple:
    """
    Given a version jump dict, decide if it's suspicious.
    Returns (is_suspicious: bool, flag_message: str).
    """
    major = abs(jump.get("major", 0))
    minor = abs(jump.get("minor", 0))
    patch = abs(jump.get("patch", 0))

    if major >= SUSPICIOUS_MAJOR_JUMP:
        return True, (
            f"Large MAJOR version jump: {old_str} -> {new_str} "
            f"(delta: +{major} major) — could indicate supply chain injection"
        )
    if minor >= SUSPICIOUS_MINOR_JUMP:
        return True, (
            f"Large MINOR version jump: {old_str} -> {new_str} "
            f"(delta: +{minor} minor)"
        )
    if patch >= SUSPICIOUS_PATCH_JUMP:
        return True, (
            f"Large PATCH version jump: {old_str} -> {new_str} "
            f"(delta: +{patch} patch)"
        )
    return False, ""


def _tuple_gt(a: tuple, b: tuple) -> bool:
    """Return True if version tuple a > tuple b."""
    length = max(len(a), len(b))
    a_p    = a + (0,) * (length - len(a))
    b_p    = b + (0,) * (length - len(b))
    return a_p > b_p


# ---------------------------------------------------------------------------
# Persistent version history (JSON file in ~/.extguard/)
# ---------------------------------------------------------------------------

def _load_history(key: str) -> dict | None:
    """Load the history record for `key` from the local store."""
    if not HISTORY_FILE.exists():
        return None
    try:
        data = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        return data.get(key)
    except (json.JSONDecodeError, OSError):
        return None


def _save_history(key: str, version: str, name: str | None):
    """
    Persist the current version to history so future runs can compare.

    Uses an atomic write pattern (write to temp file, then rename) so two
    concurrent extguard invocations can't corrupt the JSON. On POSIX the
    rename is fully atomic; on Windows os.replace() does the right thing
    too. The cost is one extra file per save, but the history file is tiny.

    This isn't a perfect cross-process lock (a true race during the
    read-modify-write window could still cause a lost update), but the
    failure mode is now "lost one update" instead of "corrupted JSON
    breaks every future read".
    """
    import os
    import tempfile

    try:
        HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        existing = {}
        if HISTORY_FILE.exists():
            try:
                existing = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass

        existing[key] = {
            "version":    version,
            "name":       name,
            "last_seen":  datetime.now(timezone.utc).isoformat(),
        }

        # Atomic write: tempfile in the same directory (so rename is atomic),
        # then os.replace() to swap it into place.
        fd, tmp_path = tempfile.mkstemp(
            prefix=".version_history-",
            suffix=".tmp",
            dir=str(HISTORY_FILE.parent),
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(existing, f, indent=2)
            os.replace(tmp_path, HISTORY_FILE)
        except Exception:
            # Best-effort cleanup of the tmp file if rename failed
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    except OSError:
        pass  # Don't crash the pipeline if we can't write history
