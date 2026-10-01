# models.py — Shared data structures for ExtensionGuard
# These dataclasses pass data between the pipeline stages so each module
# stays independent and easy to test on its own.

import re
from dataclasses import dataclass, field

# A Chrome extension ID is always exactly 32 letters from the range a-p
# (Chrome maps each hex digit 0-f of a SHA-256 prefix onto a-p). Anything
# else is either a typo or hostile input, so every place that acts on an ID
# (registry writes, policy files, API calls) checks it against this first.
EXTENSION_ID_PATTERN = re.compile(r"^[a-p]{32}$")


def is_valid_extension_id(value) -> bool:
    """Return True if `value` is a well-formed 32-char Chrome extension ID."""
    return isinstance(value, str) and bool(EXTENSION_ID_PATTERN.match(value))


@dataclass
class ManifestInfo:
    """Everything we care about from a Chrome extension's manifest.json."""

    name: str
    version: str
    manifest_version: int  # 2 (legacy) or 3 (modern)
    permissions: list  # Named API permissions, e.g. "cookies", "tabs"
    host_permissions: list  # URL patterns, e.g. "<all_urls>" (MV3 separates these)
    content_scripts: list  # Scripts injected into web pages
    background: dict  # Background service worker / persistent page config
    raw: dict  # Full raw manifest — passed to Claude for deep analysis
    # Permissions the extension can request later at runtime (the user sees a
    # prompt). Kept separate so scoring can decide how much weight they get.
    optional_permissions: list = field(default_factory=list)
    optional_host_permissions: list = field(default_factory=list)
    # Fields that had the wrong type and were ignored or coerced. Chrome would
    # refuse to load most of these, so they usually mean a broken or
    # deliberately scanner-confusing manifest - worth showing to the analyst.
    parse_warnings: list = field(default_factory=list)


@dataclass
class ParsedExtension:
    """Everything the parser learns from one input file."""

    manifest: ManifestInfo
    # The input file exactly as it was given to us. This is what VirusTotal
    # and other threat-intel feeds index, and what forensics must preserve.
    file_bytes: bytes | None
    # The ZIP payload inside the file (CRX header stripped). None for a bare
    # manifest.json. Used for scanning the extension's own files.
    zip_bytes: bytes | None
    # "crx3", "crx2", "zip", or "json"
    container: str
    # CRX3 only: the protobuf CrxFileHeader holding the signing keys and the
    # signed extension ID. publisher_checker uses it to derive the ID.
    crx3_header: bytes | None = None
    # CRX2 only: the DER public key that signs the package.
    crx2_public_key: bytes | None = None


@dataclass
class PermissionScore:
    """Result of our local (no-API) permission risk scoring pass."""

    total_score: int  # 0–100 risk score (clamped)
    risk_level: str  # "low" / "medium" / "high" / "critical"
    flagged_permissions: list  # Which permissions triggered points
    breakdown: dict  # permission_name → points_awarded
    notes: list  # Human-readable analyst flags


@dataclass
class TriageResult:
    """Full output from the Claude AI triage engine — goes to SOC alert dispatch."""

    risk_score: int  # 0–100 AI-generated score
    risk_level: str  # "low" / "medium" / "high" / "critical"
    iocs: list  # Indicators of Compromise extracted from manifest
    mitre_techniques: list  # e.g. ["T1176", "T1555.003"]
    analyst_narrative: str  # Plain-English explanation for the SOC analyst
    permission_score: PermissionScore
    manifest: ManifestInfo
    extension_name: str
    file_path: str
