# main.py - ExtensionGuard CLI entry point
#
# Orchestrates the full pre-install detection pipeline:
#
#   Stage 1a  CRX / ZIP / manifest parsing
#   Stage 1b  Permission risk scoring          (local, no API)
#   Stage 1c  Publisher legitimacy check       (optional CWS query)
#   Stage 1d  OSV / CVE hash lookup            (optional network)
#   Stage 1e  Update velocity analysis         (local history store)
#   Stage 2   Claude AI triage engine          (requires ANTHROPIC_API_KEY)
#
# Stage 3 (behavioral monitoring) runs as a separate long-running process:
#   python behavioral_monitor.py
#
# Usage:
#   python main.py suspicious.crx
#   python main.py extension.zip --json
#   python main.py manifest.json --no-ai --offline

import argparse
import json
import os
import sys

from claude_triage import triage_extension
from crx_parser import parse_crx
from models import TriageResult
from osv_lookup import run_osv_checks
from permission_scorer import score_permissions
from publisher_checker import check_publisher
from update_velocity import analyse_version

# ANSI colours (ASCII-safe, no Unicode box-drawing)
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

RISK_COLOURS = {
    "low": GREEN,
    "medium": YELLOW,
    "high": RED,
    "critical": RED + BOLD,
}


def main():
    # Windows ANSI quirk: prior to Windows 10 build 14931, terminals don't
    # interpret ANSI escape sequences. The `os.system("")` call spawns a
    # tiny cmd.exe child which calls SetConsoleMode internally and leaves
    # VIRTUAL_TERMINAL_PROCESSING enabled on the parent's console handle.
    # No-op on Linux/macOS, where ANSI works out of the box.
    os.system("")

    parser = argparse.ArgumentParser(
        description="ExtensionGuard - AI-powered Chrome extension supply chain threat detector",
        epilog=(
            "Examples:\n"
            "  python main.py bad_extension.crx\n"
            "  python main.py extension.zip --json\n"
            "  python main.py manifest.json --no-ai\n"
            "  python main.py manifest.json --no-ai --offline\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "extension_path",
        help="Path to the .crx, .zip, or manifest.json to analyse",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="output_json",
        help="Output results as JSON (for SIEM / webhook ingestion)",
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        dest="no_ai",
        help="Skip the Claude AI triage stage (Stages 1a-1e only)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        dest="offline",
        help="Disable all network calls (CWS queries, OSV lookup) — fully local",
    )
    args = parser.parse_args()

    network_ok = not args.offline

    if not args.output_json:
        print(f"\n{BOLD}=== ExtensionGuard ================================================{RESET}")
        print(f"{BOLD}    Browser Extension Supply Chain Threat Detector{RESET}")
        print(f"{BOLD}==================================================================={RESET}")
        print(f"\nTarget: {args.extension_path}\n")

    # -----------------------------------------------------------------------
    # Stage 1a: Parse the extension file
    # -----------------------------------------------------------------------
    _stage_header("1a", "Parsing extension file", args.output_json)

    try:
        zip_bytes, manifest = parse_crx(args.extension_path)
    except (FileNotFoundError, ValueError) as exc:
        _error_exit(f"Failed to parse extension: {exc}")
        return  # keeps type checker happy

    if not args.output_json:
        print(f"  Name:             {manifest.name}")
        print(f"  Version:          {manifest.version}")
        print(f"  Manifest version: MV{manifest.manifest_version}")
        print(
            f"  Permissions:      "
            f"{len(manifest.permissions)} API + {len(manifest.host_permissions)} host"
        )

    # -----------------------------------------------------------------------
    # Stage 1b: Local permission risk scoring
    # -----------------------------------------------------------------------
    _stage_header("1b", "Scoring permissions", args.output_json)

    perm_score = score_permissions(manifest)

    if not args.output_json:
        colour = RISK_COLOURS.get(perm_score.risk_level, RESET)
        print(
            f"  Score:    {colour}{perm_score.total_score}/100"
            f"  -  {perm_score.risk_level.upper()}{RESET}"
        )
        if perm_score.flagged_permissions:
            print(f"  Flagged:  {', '.join(perm_score.flagged_permissions)}")
        for note in perm_score.notes:
            print(f"  {YELLOW}[!] {note}{RESET}")

    # -----------------------------------------------------------------------
    # Stage 1c: Publisher legitimacy check
    # -----------------------------------------------------------------------
    _stage_header("1c", "Checking publisher legitimacy", args.output_json)

    # We pass the raw ZIP bytes so the publisher checker can extract the
    # CRX3 signing key if the manifest doesn't have a "key" field
    crx_header_bytes = None  # TODO Stage 1c+: pass parsed CRX3 header bytes
    pub_result = check_publisher(
        manifest,
        crx_header_bytes=crx_header_bytes,
        query_cws=network_ok,
    )

    if not args.output_json:
        ext_id = pub_result.get("extension_id")
        if ext_id:
            print(f"  Extension ID:  {ext_id}")
        if pub_result.get("cws_exists") is False:
            print(f"  {YELLOW}[!] Extension not found on Chrome Web Store{RESET}")
        elif pub_result.get("cws_exists"):
            cws_v = pub_result.get("cws_version")
            if cws_v:
                match = "OK" if cws_v == manifest.version else f"{RED}MISMATCH{RESET}"
                print(f"  CWS version:   {cws_v}  ({match})")
        for flag in pub_result.get("flags", []):
            print(f"  {YELLOW}[!] {flag}{RESET}")
        if pub_result.get("pub_score", 0) == 0 and not pub_result.get("flags"):
            print(f"  {GREEN}[OK] No publisher red flags{RESET}")

    # -----------------------------------------------------------------------
    # Stage 1d: OSV / CVE hash lookup
    # -----------------------------------------------------------------------
    _stage_header("1d", "OSV / CVE hash lookup", args.output_json)

    if network_ok:
        # Load VirusTotal config from extguard.conf.json if present. VT lookups
        # only fire when the section is `enabled: true` AND a key is available
        # (via env VT_API_KEY or the config). Absent config = OSV-only behaviour
        # identical to before this feature was added.
        vt_cfg = _load_vt_config()
        osv_result = run_osv_checks(zip_bytes, manifest.raw, vt_cfg=vt_cfg)
        if not args.output_json:
            print(f"  ZIP SHA-256:  {osv_result.get('zip_hash', 'N/A')[:16]}...")
            if osv_result.get("osv_zip_matches"):
                n = len(osv_result["osv_zip_matches"])
                print(f"  {RED}{BOLD}[!] {n} OSV match(es) for ZIP hash - CONFIRMED THREAT{RESET}")
            else:
                print(f"  {GREEN}[OK] No OSV hash matches{RESET}")
            # VirusTotal summary if it ran
            vt = osv_result.get("vt", {})
            if vt.get("queried"):
                if vt.get("found"):
                    mal = vt.get("malicious", 0)
                    total = vt.get("total", 0)
                    colour = RED if mal >= 3 else (YELLOW if mal >= 1 else GREEN)
                    print(f"  {colour}VirusTotal:   {mal}/{total} engines flagged{RESET}")
                elif vt.get("error"):
                    print(f"  {CYAN}VirusTotal:   skipped ({vt['error']}){RESET}")
                else:
                    print(f"  {GREEN}VirusTotal:   not in DB (no engines have seen it){RESET}")
            if osv_result.get("cdn_refs"):
                for ref in osv_result["cdn_refs"]:
                    print(f"  {YELLOW}[!] External CDN ref: {ref}{RESET}")
            for flag in osv_result.get("flags", []):
                if flag not in (osv_result.get("cdn_refs") or []):
                    print(f"  {YELLOW}[!] {flag}{RESET}")
    else:
        osv_result = {
            "zip_hash": None,
            "osv_zip_matches": [],
            "cdn_refs": [],
            "npm_packages": [],
            "osv_pkg_matches": [],
            "osv_score": 0,
            "flags": [],
        }
        if not args.output_json:
            print(f"  {CYAN}[Skipped] --offline mode{RESET}")

    # -----------------------------------------------------------------------
    # Stage 1e: Update velocity analysis
    # -----------------------------------------------------------------------
    _stage_header("1e", "Update velocity analysis", args.output_json)

    velocity_result = analyse_version(
        manifest_version=manifest.version,
        extension_id=pub_result.get("extension_id"),
        cws_version=pub_result.get("cws_version"),
        extension_name=manifest.name,
    )

    if not args.output_json:
        prev_v = velocity_result.get("previous_version")
        if prev_v:
            jump = velocity_result.get("version_jump") or {}
            delta = " / ".join(f"{k}: {'+' if v > 0 else ''}{v}" for k, v in jump.items() if v != 0)
            print(f"  Previous seen: {prev_v} -> {manifest.version}  ({delta or 'no change'})")
        else:
            print("  First time seeing this extension (version recorded for future tracking)")
        for flag in velocity_result.get("flags", []):
            print(f"  {YELLOW}[!] {flag}{RESET}")
        if not velocity_result.get("flags"):
            print(f"  {GREEN}[OK] No suspicious version jumps{RESET}")

    # -----------------------------------------------------------------------
    # Composite Stage 1 score (before AI)
    # -----------------------------------------------------------------------
    composite_score = min(
        perm_score.total_score
        + pub_result.get("pub_score", 0)
        + osv_result.get("osv_score", 0)
        + velocity_result.get("velocity_score", 0),
        100,
    )
    composite_level = _score_to_level(composite_score)

    if not args.output_json:
        colour = RISK_COLOURS.get(composite_level, RESET)
        print(
            f"\n{BOLD}Stage 1 composite: "
            f"{colour}{composite_score}/100 - {composite_level.upper()}{RESET}"
        )

    # -----------------------------------------------------------------------
    # Stage 2: Claude AI triage
    # -----------------------------------------------------------------------
    if args.no_ai:
        if not args.output_json:
            print(f"\n{CYAN}[Stage 2 skipped]{RESET} --no-ai flag set")
            _print_recommendation(composite_level, composite_score)
        else:
            _print_json_no_ai(
                manifest, perm_score, pub_result, osv_result, velocity_result, args.extension_path
            )
        return

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        if not args.output_json:
            print(
                f"\n{YELLOW}[Stage 2 skipped]{RESET} ANTHROPIC_API_KEY not set.\n"
                "  Set it with:  $env:ANTHROPIC_API_KEY = 'sk-ant-...'\n"
                "  Then re-run without --no-ai."
            )
            _print_recommendation(composite_level, composite_score)
        return

    if not args.output_json:
        print(f"\n{BOLD}[Stage 2]{RESET} Running Claude AI triage (10-20 s)...")

    try:
        result = triage_extension(manifest, perm_score, args.extension_path)
    except Exception as exc:
        _error_exit(f"Claude API triage failed: {exc}")
        return

    if args.output_json:
        _print_json_full(result, pub_result, osv_result, velocity_result, composite_score)
    else:
        _print_human_report(result, pub_result, osv_result, velocity_result)


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------


def _stage_header(num: str, title: str, output_json: bool):
    if not output_json:
        print(f"\n{BOLD}[Stage {num}]{RESET} {title}...")


def _print_human_report(result: TriageResult, pub: dict, osv: dict, vel: dict):
    colour = RISK_COLOURS.get(result.risk_level, RESET)

    print()
    print("=" * 66)
    print(
        f"  {BOLD}AI RISK SCORE: "
        f"{colour}{result.risk_score}/100 - {result.risk_level.upper()}{RESET}"
    )
    print("=" * 66)

    if result.mitre_techniques:
        print(f"\n  {BOLD}MITRE ATT&CK Techniques:{RESET}")
        for t in result.mitre_techniques:
            print(f"    - {t}")

    if result.iocs:
        print(f"\n  {BOLD}Indicators of Compromise:{RESET}")
        for ioc in result.iocs:
            print(f"    - {ioc}")

    # Summarise Stage 1 sub-checks
    print(f"\n  {BOLD}Pre-install Check Summary:{RESET}")
    pub_score = pub.get("pub_score", 0)
    osv_score = osv.get("osv_score", 0)
    vel_score = vel.get("velocity_score", 0)
    print(f"    Permission score:  {result.permission_score.total_score}/100")
    print(
        f"    Publisher risk:    +{pub_score} pts  "
        + (f"({len(pub.get('flags', []))} flags)" if pub.get("flags") else "(clean)")
    )
    print(
        f"    OSV / hash:        +{osv_score} pts  "
        + ("(matches found)" if osv.get("osv_zip_matches") else "(no matches)")
    )
    print(
        f"    Version velocity:  +{vel_score} pts  "
        + ("(suspicious jump)" if vel.get("is_suspicious") else "(normal)")
    )

    print(f"\n  {BOLD}Analyst Narrative:{RESET}")
    for line in result.analyst_narrative.strip().split("\n"):
        print(f"    {line}")

    print()
    print("-" * 66)
    _print_recommendation(result.risk_level, result.risk_score)
    print()

    # Stage 3 reminder
    print(
        f"  {CYAN}[Stage 3]{RESET} To monitor this extension at runtime:\n"
        "    1. Start Chrome: chrome.exe --remote-debugging-port=9222\n"
        "    2. Run: python behavioral_monitor.py"
        + (f" --ext-id {pub.get('extension_id')}" if pub.get("extension_id") else "")
    )
    print()


def _print_recommendation(risk_level: str, score: int):
    actions = {
        "critical": f"{RED}{BOLD}BLOCK IMMEDIATELY - initiate remediation playbook{RESET}",
        "high": f"{RED}QUARANTINE - escalate to Tier-2 analyst{RESET}",
        "medium": f"{YELLOW}REVIEW - monitor for suspicious runtime behaviour{RESET}",
        "low": f"{GREEN}LOW RISK - continue standard monitoring{RESET}",
    }
    print(
        f"  {BOLD}Recommendation ({score}/100):{RESET}  "
        + actions.get(risk_level, "Unknown risk level")
    )


def _print_json_full(result: TriageResult, pub: dict, osv: dict, vel: dict, composite: int):
    output = {
        "extension_name": result.extension_name,
        "file_path": result.file_path,
        "composite_score": composite,
        "ai_risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "mitre_techniques": result.mitre_techniques,
        "iocs": result.iocs,
        "analyst_narrative": result.analyst_narrative,
        "stage_1_checks": {
            "permission_score": {
                "total": result.permission_score.total_score,
                "level": result.permission_score.risk_level,
                "flagged": result.permission_score.flagged_permissions,
                "notes": result.permission_score.notes,
            },
            "publisher": {
                "extension_id": pub.get("extension_id"),
                "cws_exists": pub.get("cws_exists"),
                "cws_version": pub.get("cws_version"),
                "suspicious_update": pub.get("suspicious_update"),
                "risk_contribution": pub.get("pub_score"),
                "flags": pub.get("flags", []),
            },
            "osv": {
                "zip_sha256": osv.get("zip_hash"),
                "zip_matches": len(osv.get("osv_zip_matches", [])),
                "pkg_matches": len(osv.get("osv_pkg_matches", [])),
                "cdn_refs": osv.get("cdn_refs", []),
                "risk_contribution": osv.get("osv_score"),
                "flags": osv.get("flags", []),
            },
            "velocity": {
                "current_version": vel.get("current_version"),
                "previous_version": vel.get("previous_version"),
                "cws_version": vel.get("cws_version"),
                "is_suspicious": vel.get("is_suspicious"),
                "risk_contribution": vel.get("velocity_score"),
                "flags": vel.get("flags", []),
            },
        },
        "manifest_summary": {
            "name": result.manifest.name,
            "version": result.manifest.version,
            "manifest_version": result.manifest.manifest_version,
            "permissions": result.manifest.permissions,
            "host_permissions": result.manifest.host_permissions,
        },
    }
    print(json.dumps(output, indent=2))


def _print_json_no_ai(manifest, perm_score, pub, osv, vel, file_path):
    composite = min(
        perm_score.total_score
        + pub.get("pub_score", 0)
        + osv.get("osv_score", 0)
        + vel.get("velocity_score", 0),
        100,
    )
    # Aggregate Stage 1 IOCs from each sub-check's flags — gives Stage 5 something
    # to feed the credential rotation playbook even without the AI narrative
    iocs = []
    iocs += perm_score.notes or []
    iocs += pub.get("flags", []) or []
    iocs += osv.get("flags", []) or []
    iocs += vel.get("flags", []) or []

    output = {
        "extension_name": manifest.name,
        "file_path": file_path,
        "ai_triage": None,
        "composite_score": composite,
        "risk_level": _score_to_level(composite),
        "iocs": iocs,
        "mitre_techniques": [],  # Populated only by AI triage stage
        "stage_1_checks": {
            "permission_score": {
                "total": perm_score.total_score,
                "level": perm_score.risk_level,
                "flagged": perm_score.flagged_permissions,
                "notes": perm_score.notes,
            },
            "publisher": pub,
            "osv": osv,
            "velocity": vel,
        },
        # manifest_summary is consumed by remediation.py to drive the rotation playbook
        "manifest_summary": {
            "name": manifest.name,
            "version": manifest.version,
            "manifest_version": manifest.manifest_version,
            "permissions": manifest.permissions,
            "host_permissions": manifest.host_permissions,
        },
    }
    print(json.dumps(output, indent=2))


def _score_to_level(score: int) -> str:
    if score >= 70:
        return "critical"
    elif score >= 45:
        return "high"
    elif score >= 20:
        return "medium"
    else:
        return "low"


def _load_vt_config() -> dict | None:
    """
    Load the `virustotal` block from extguard.conf.json, if present.
    Returns None if the file or section is absent - which signals "skip VT".
    """
    from pathlib import Path

    config_path = Path("extguard.conf.json")
    if not config_path.exists():
        return None
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    vt = raw.get("virustotal", {})
    if not isinstance(vt, dict):
        return None
    # Strip the _comment convention
    return {k: v for k, v in vt.items() if not k.startswith("_")}


def _error_exit(message: str):
    print(f"\n{RED}[ERROR]{RESET} {message}")
    sys.exit(1)


if __name__ == "__main__":
    main()
