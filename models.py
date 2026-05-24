# models.py — Shared data structures for ExtensionGuard
# These dataclasses pass data between the pipeline stages so each module
# stays independent and easy to test on its own.

from dataclasses import dataclass


@dataclass
class ManifestInfo:
    """Everything we care about from a Chrome extension's manifest.json."""
    name: str
    version: str
    manifest_version: int          # 2 (legacy) or 3 (modern)
    permissions: list              # Named API permissions, e.g. "cookies", "tabs"
    host_permissions: list         # URL patterns, e.g. "<all_urls>" (MV3 separates these)
    content_scripts: list          # Scripts injected into web pages
    background: dict               # Background service worker / persistent page config
    raw: dict                      # Full raw manifest — passed to Claude for deep analysis


@dataclass
class PermissionScore:
    """Result of our local (no-API) permission risk scoring pass."""
    total_score: int               # 0–100 risk score (clamped)
    risk_level: str                # "low" / "medium" / "high" / "critical"
    flagged_permissions: list      # Which permissions triggered points
    breakdown: dict                # permission_name → points_awarded
    notes: list                    # Human-readable analyst flags


@dataclass
class TriageResult:
    """Full output from the Claude AI triage engine — goes to SOC alert dispatch."""
    risk_score: int                # 0–100 AI-generated score
    risk_level: str                # "low" / "medium" / "high" / "critical"
    iocs: list                     # Indicators of Compromise extracted from manifest
    mitre_techniques: list         # e.g. ["T1176", "T1555.003"]
    analyst_narrative: str         # Plain-English explanation for the SOC analyst
    permission_score: PermissionScore
    manifest: ManifestInfo
    extension_name: str
    file_path: str
