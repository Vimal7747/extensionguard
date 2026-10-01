# paths.py - Where ExtensionGuard keeps its configuration and data
#
# One place decides every location, so the CLI tools, the dashboard and the
# Docker image always agree. (Before this, some modules looked next to their
# own .py file - which is inside site-packages once pip-installed - and others
# looked in the current directory.)
#
# Data directory ("EXTGUARD_HOME"), default ~/.extguard:
#   quarantine/              evidence cases   (override: EXTGUARD_QUARANTINE)
#   ttp_library/             active threat intel (override: EXTGUARD_TTP_DIR)
#   ttp_library.pending/     synced intel waiting for `extguard-ttp-sync --activate`
#   webhook_deliveries.json  GitHub delivery IDs already processed (replay defence)
#   remediation_queue.jsonl  dashboard approve/reject queue
#   version_history.json     update-velocity history
#   coc_hmac.key             chain-of-custody signing key (if EXTGUARD_COC_KEY unset)
#
# Config file extguard.conf.json - first one found wins:
#   1. an explicit --config path
#   2. $EXTGUARD_CONFIG
#   3. ./extguard.conf.json             (current directory)
#   4. $EXTGUARD_HOME/extguard.conf.json

import json
import os
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
CONFIG_NAME = "extguard.conf.json"


def data_dir() -> Path:
    """The ExtensionGuard data directory ($EXTGUARD_HOME, default ~/.extguard)."""
    return Path(os.environ.get("EXTGUARD_HOME") or Path.home() / ".extguard")


def quarantine_root() -> Path:
    return Path(os.environ.get("EXTGUARD_QUARANTINE") or data_dir() / "quarantine")


def queue_file() -> Path:
    return data_dir() / "remediation_queue.jsonl"


def ttp_user_dir() -> Path:
    """Where extguard-ttp-sync writes threat intel."""
    return Path(os.environ.get("EXTGUARD_TTP_DIR") or data_dir() / "ttp_library")


def ttp_pending_dir() -> Path:
    """
    Where a sync stages new threat intel for review. It only reaches Claude's
    prompt after `extguard-ttp-sync --activate`. Kept next to ttp_user_dir()
    so activation is a rename on the same disk.
    """
    active = ttp_user_dir()
    return active.with_name(active.name + ".pending")


def webhook_deliveries_file() -> Path:
    return data_dir() / "webhook_deliveries.json"


def packaged_ttp_dir() -> Path:
    """The baseline threat intel shipped inside the package (read-only)."""
    return PACKAGE_DIR / "ttp_library"


def find_config(explicit: str | Path | None = None) -> Path | None:
    """
    Return the config file to use, or None if there isn't one.
    An explicit path is returned even if it doesn't exist, so the caller can
    report "not found" instead of silently falling back to another file.
    """
    if explicit:
        return Path(explicit)
    for candidate in (
        os.environ.get("EXTGUARD_CONFIG"),
        Path.cwd() / CONFIG_NAME,
        data_dir() / CONFIG_NAME,
    ):
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    return None


def load_config_section(section: str, explicit: str | Path | None = None) -> dict | None:
    """
    Load one section of extguard.conf.json, with "_comment"-style keys removed.
    Returns None if there is no config file, it can't be parsed, or the
    section is missing / not an object.
    """
    path = find_config(explicit)
    if path is None or not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    value = raw.get(section) if isinstance(raw, dict) else None
    if not isinstance(value, dict):
        return None
    return {k: v for k, v in value.items() if not str(k).startswith("_")}
