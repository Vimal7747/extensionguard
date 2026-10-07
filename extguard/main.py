# main.py - ExtensionGuard CLI entry point
#
# Orchestrates the full pre-install detection pipeline:
#
#   Stage 1a  CRX / ZIP / manifest parsing
#   Stage 1b  Permission risk scoring          (local, no API)
#   Stage 1c  Publisher / signing identity     (optional Chrome Web Store query)
#   Stage 1d  Known-bad lookups                (optional VirusTotal + OSV)
#   Stage 1e  Update velocity analysis         (local history store)
#   Stage 1f  Code analysis + diff vs the last accepted build
#   Stage 2   Claude AI triage engine          (requires ANTHROPIC_API_KEY)
#
# Verdict rule: the FINAL score is the higher of the Stage 1 composite score
# and Claude's score. Claude can raise a verdict but never lower it, so a
# prompt-injected manifest cannot talk its way to "LOW RISK".
#
# Exit codes:
#   0  scan completed (and the verdict is below --fail-on, if given)
#   1  scan completed and the verdict is at or above --fail-on
#   2  bad command-line arguments (argparse)
#   3  the scan could not be completed (unreadable / malformed input)
#
# Stage 3 (behavioral monitoring) runs as a separate long-running process:
#   extguard-monitor
#
# Usage:
#   extguard suspicious.crx
#   extguard extension.zip --json
#   extguard manifest.json --no-ai --offline
#   extguard suspicious.crx --json --fail-on high

import argparse
import hashlib
import json
import os
import sys

from extguard import paths, verdict
from extguard.claude_triage import triage_extension
from extguard.code_diff import analyse_code, record_profile
from extguard.crx_parser import parse_extension
from extguard.logging_setup import redact
from extguard.osv_lookup import run_osv_checks
from extguard.permission_scorer import score_permissions
from extguard.publisher_checker import check_publisher
from extguard.update_velocity import analyse_version, record_version

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

LEVELS = ["low", "medium", "high", "critical"]

EXIT_OK = 0
EXIT_VERDICT = 1
EXIT_ERROR = 3

# A file that this many VirusTotal engines call malicious is treated as
# confirmed: the composite score is raised to at least the floor below,
# whatever the permissions look like.
VT_CONFIRMED_ENGINES = 11
CONFIRMED_MALICIOUS_FLOOR = 90

# An update that starts sending data to exfil-style hosting (Discord / Telegram
# webhooks, workers.dev, ...) that its baseline never used is at least HIGH -
# the shape of the Cyberhaven hijack, which only bumped the patch version.
HIJACK_FLOOR = 60


def main(argv: list | None = None) -> int:
    """Parse arguments, run the scan, and return the process exit code."""
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
            "  extguard bad_extension.crx\n"
            "  extguard extension.zip --json\n"
            "  extguard manifest.json --no-ai --offline\n"
            "  extguard suspicious.crx --json --fail-on high\n"
            "\n"
            "Exit codes: 0 done, 1 verdict >= --fail-on, 2 bad arguments,\n"
            "            3 scan could not be completed\n"
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
        help="Output results as JSON (for SIEM / webhook ingestion). Always prints JSON, "
        "including errors and skipped AI stages.",
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        dest="no_ai",
        help="Skip the Claude AI triage stage (Stage 1 checks only)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        dest="offline",
        help="Make no network calls at all: no Web Store, VirusTotal, OSV, or Claude API",
    )
    parser.add_argument(
        "--fail-on",
        choices=["medium", "high", "critical"],
        default=None,
        help="Exit with code 1 when the final verdict is at or above this level "
        "(for CI pipelines and SOAR playbooks)",
    )
    parser.add_argument(
        "--no-record",
        action="store_true",
        dest="no_record",
        help="Don't save this build as the baseline for future version / code comparisons "
        "(baselines are only ever saved for LOW or MEDIUM verdicts)",
    )
    parser.add_argument(
        "--accept-baseline",
        action="store_true",
        help="You reviewed this build: save it as the baseline anyway (also for a HIGH "
        "verdict). Never applies when there is evidence of malicious behaviour.",
    )
    args = parser.parse_args(argv)
    return run_scan(args)


def run_scan(args) -> int:
    """Run the whole pipeline for one file. Returns the exit code."""
    json_mode = args.output_json
    network_ok = not args.offline

    if not json_mode:
        print(f"\n{BOLD}=== ExtensionGuard ================================================{RESET}")
        print(f"{BOLD}    Browser Extension Supply Chain Threat Detector{RESET}")
        print(f"{BOLD}==================================================================={RESET}")
        print(f"\nTarget: {args.extension_path}\n")

    # -----------------------------------------------------------------------
    # Stage 1a: Parse the extension file
    # -----------------------------------------------------------------------
    _stage_header("1a", "Parsing extension file", json_mode)
    try:
        parsed = parse_extension(args.extension_path)
    except (FileNotFoundError, ValueError) as exc:
        return _fail(f"Failed to parse extension: {exc}", json_mode, stage="1a")
    except Exception as exc:  # anything else is a bug - report it, don't traceback
        return _fail(
            f"Unexpected error while parsing: {type(exc).__name__}: {exc}", json_mode, stage="1a"
        )
    manifest = parsed.manifest
    file_sha256 = hashlib.sha256(parsed.file_bytes).hexdigest()

    if not json_mode:
        print(f"  Name:             {manifest.name}")
        print(f"  Version:          {manifest.version}")
        print(f"  Manifest version: MV{manifest.manifest_version}")
        print(f"  Container:        {parsed.container}")
        print(
            f"  Permissions:      "
            f"{len(manifest.permissions)} API + {len(manifest.host_permissions)} host"
            + (
                f" (+{len(manifest.optional_permissions) + len(manifest.optional_host_permissions)}"
                " optional)"
                if manifest.optional_permissions or manifest.optional_host_permissions
                else ""
            )
        )
        for warning in manifest.parse_warnings:
            print(f"  {YELLOW}[!] Malformed manifest: {warning}{RESET}")

    # -----------------------------------------------------------------------
    # Stage 1b: Local permission risk scoring (core - a failure here is fatal)
    # -----------------------------------------------------------------------
    _stage_header("1b", "Scoring permissions", json_mode)
    try:
        perm_score = score_permissions(manifest)
    except Exception as exc:
        return _fail(f"Permission scoring failed: {type(exc).__name__}: {exc}", json_mode, "1b")

    if not json_mode:
        colour = RISK_COLOURS.get(perm_score.risk_level, RESET)
        print(
            f"  Score:    {colour}{perm_score.total_score}/100"
            f"  -  {perm_score.risk_level.upper()}{RESET}"
        )
        if perm_score.flagged_permissions:
            print(f"  Flagged:  {', '.join(perm_score.flagged_permissions)}")
        for note in perm_score.notes:
            print(f"  {YELLOW}[!] {note}{RESET}")

    # Stages 1c-1f are independent: if one fails, record it and carry on.
    # A failed stage is reported as UNKNOWN - never silently as clean.
    stage_errors: dict = {}

    # -----------------------------------------------------------------------
    # Stage 1c: Publisher / signing identity
    # -----------------------------------------------------------------------
    _stage_header("1c", "Checking publisher and signing identity", json_mode)
    is_crx = parsed.container in ("crx2", "crx3")
    pub_result = _run_stage(
        "1c",
        stage_errors,
        lambda: check_publisher(
            manifest,
            crx_header_bytes=parsed.crx3_header,
            crx2_public_key=parsed.crx2_public_key,
            query_cws=network_ok,
            crx_sha256=file_sha256 if is_crx else None,
        ),
        fallback={"extension_id": None, "pub_score": 0},
    )
    if not json_mode:
        _print_stage_1c(pub_result, manifest, network_ok)

    # -----------------------------------------------------------------------
    # Stage 1d: Known-bad lookups (VirusTotal on the file hash, OSV on packages)
    # -----------------------------------------------------------------------
    _stage_header("1d", "Threat-intel lookups (VirusTotal / OSV)", json_mode)
    vt_cfg = _load_vt_config() if network_ok else None
    osv_result = _run_stage(
        "1d",
        stage_errors,
        lambda: run_osv_checks(
            parsed.zip_bytes,
            manifest.raw,
            vt_cfg=vt_cfg,
            file_bytes=parsed.file_bytes,
            network=network_ok,
        ),
        fallback={"osv_score": 0, "vt": {"queried": False}},
    )
    if not json_mode:
        _print_stage_1d(osv_result, file_sha256, network_ok, vt_cfg)

    # -----------------------------------------------------------------------
    # Stage 1e: Update velocity analysis
    # -----------------------------------------------------------------------
    _stage_header("1e", "Update velocity analysis", json_mode)
    velocity_result = _run_stage(
        "1e",
        stage_errors,
        lambda: analyse_version(
            manifest_version=manifest.version,
            extension_id=pub_result.get("extension_id"),
            cws_version=pub_result.get("cws_version"),
            extension_name=manifest.name,
            record=False,  # saved below, only if the final verdict is acceptable
        ),
        fallback={"velocity_score": 0},
    )
    if not json_mode:
        _print_stage_1e(velocity_result, manifest.version)

    # -----------------------------------------------------------------------
    # Stage 1f: Code analysis + diff against the last accepted build
    # -----------------------------------------------------------------------
    _stage_header("1f", "Code analysis (what the JavaScript actually does)", json_mode)
    code_result = _run_stage(
        "1f",
        stage_errors,
        lambda: analyse_code(
            parsed.zip_bytes,
            extension_id=pub_result.get("extension_id"),
            extension_name=manifest.name,
            version=manifest.version,
            file_sha256=file_sha256,
        ),
        fallback={"code_score": 0},
    )
    if not json_mode:
        _print_stage_1f(code_result)

    # -----------------------------------------------------------------------
    # Composite Stage 1 score (before AI)
    # -----------------------------------------------------------------------
    composite_score, floor_reason = _composite_score(
        perm_score, pub_result, osv_result, velocity_result, code_result
    )
    if not json_mode:
        level = _score_to_level(composite_score)
        colour = RISK_COLOURS.get(level, RESET)
        # No level here: the verdict (below) also weighs the evidence
        print(
            f"\n{BOLD}Stage 1 score (capability + findings): {colour}{composite_score}/100{RESET}"
        )
        if floor_reason:
            print(f"  {RED}{BOLD}[!] Score floor applied: {floor_reason}{RESET}")
        for stage, error in stage_errors.items():
            print(f"  {RED}[!] Stage {stage} failed ({error}) - its result is UNKNOWN{RESET}")

    # What do we actually KNOW? Evidence lifts the cap; without it the verdict
    # is capped (MEDIUM for a verified store build, HIGH otherwise) - see verdict.py
    assessment = verdict.assess(pub_result, osv_result, velocity_result, code_result, stage_errors)

    # -----------------------------------------------------------------------
    # Stage 2: Claude AI triage
    # -----------------------------------------------------------------------
    ai = None
    if args.no_ai:
        ai_status = {"status": "skipped", "reason": "--no-ai flag set"}
    elif args.offline:
        ai_status = {"status": "skipped", "reason": "--offline (the Claude API is a network call)"}
    elif not os.environ.get("ANTHROPIC_API_KEY"):
        ai_status = {"status": "skipped", "reason": "ANTHROPIC_API_KEY not set"}
    else:
        if not json_mode:
            print(f"\n{BOLD}[Stage 2]{RESET} Running Claude AI triage (10-20 s)...")
        findings = _stage1_findings(
            composite_score, pub_result, osv_result, velocity_result, code_result, stage_errors
        )
        findings["evidence_assessment"] = assessment
        try:
            ai = triage_extension(manifest, perm_score, args.extension_path, findings)
            ai_status = {"status": "ok"}
        except Exception as exc:
            # The AI is an extra opinion, not a dependency: fall back to Stage 1
            ai_status = {"status": "failed", "reason": redact(f"{type(exc).__name__}: {exc}")}

    uncapped_score = max(composite_score, ai.risk_score) if ai else composite_score
    final_score = verdict.apply_cap(uncapped_score, assessment)
    final_level = _score_to_level(final_score)

    # -----------------------------------------------------------------------
    # Baselines: only an ACCEPTED build becomes the reference for next time
    # -----------------------------------------------------------------------
    baseline = _record_baselines(
        args, final_level, stage_errors, manifest, pub_result, code_result, assessment
    )

    # -----------------------------------------------------------------------
    # Output
    # -----------------------------------------------------------------------
    if json_mode:
        report = _build_json_report(
            args.extension_path,
            parsed,
            file_sha256,
            perm_score,
            pub_result,
            osv_result,
            velocity_result,
            code_result,
            composite_score,
            floor_reason,
            ai,
            ai_status,
            final_score,
            final_level,
            stage_errors,
        )
        report["verdict"] = {**assessment, "uncapped_score": uncapped_score}
        report["baseline"] = baseline
        print(json.dumps(report, indent=2))
    else:
        if ai is None:
            label = "skipped" if ai_status["status"] == "skipped" else "FAILED"
            colour = CYAN if label == "skipped" else RED
            print(f"\n{colour}[Stage 2 {label}]{RESET} {ai_status['reason']}")
            if ai_status["reason"] == "ANTHROPIC_API_KEY not set":
                print("  Set it with:  $env:ANTHROPIC_API_KEY = 'sk-ant-...'")
            print("  Verdict below is based on Stage 1 only.\n")
            _print_verdict_basis(assessment, uncapped_score, final_score)
            _print_recommendation(final_level, final_score)
        else:
            _print_human_report(
                ai,
                pub_result,
                osv_result,
                velocity_result,
                code_result,
                composite_score,
                final_score,
                assessment,
                uncapped_score,
            )
        print(f"  {CYAN}Baseline:{RESET} {baseline['reason']}")

    if args.fail_on and LEVELS.index(final_level) >= LEVELS.index(args.fail_on):
        return EXIT_VERDICT
    return EXIT_OK


# ---------------------------------------------------------------------------
# Pipeline helpers
# ---------------------------------------------------------------------------


def _run_stage(label: str, stage_errors: dict, fn, fallback: dict) -> dict:
    """
    Run one Stage 1 check. If it raises, record the error and return
    `fallback` with a flag saying the result is unknown.
    """
    try:
        return fn()
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        stage_errors[label] = error
        return {**fallback, "flags": [f"Stage {label} failed ({error}) - result unknown"]}


def _composite_score(perm_score, pub: dict, osv: dict, vel: dict, code: dict) -> tuple:
    """
    Sum the Stage 1 contributions (clamped to 100) and apply the floors for
    confirmed-malicious files and hijacked updates.
    Returns (score, floor_reason_or_None).
    """
    score = min(
        perm_score.total_score
        + pub.get("pub_score", 0)
        + osv.get("osv_score", 0)
        + vel.get("velocity_score", 0)
        + code.get("code_score", 0),
        100,
    )
    floor, reason = 0, None
    if code.get("new_exfil_endpoints"):
        floor = HIJACK_FLOOR
        reason = (
            f"update started sending data to {', '.join(code['new_exfil_endpoints'][:3])} "
            f"(not used by {code.get('baseline_version') or 'the baseline'})"
        )
    vt = osv.get("vt", {})
    if vt.get("found") and vt.get("malicious", 0) >= VT_CONFIRMED_ENGINES:
        floor = CONFIRMED_MALICIOUS_FLOOR
        reason = f"VirusTotal: {vt['malicious']}/{vt.get('total', '?')} engines flag this file"
    return max(score, floor), reason


def _stage1_findings(
    composite: int, pub: dict, osv: dict, vel: dict, code: dict, errors: dict
) -> dict:
    """The Stage 1 evidence we hand to Claude alongside the manifest."""
    vt = osv.get("vt", {})
    return {
        "stage1_composite_score": composite,
        "publisher": {
            key: pub.get(key)
            for key in (
                "extension_id",
                "id_source",
                "update_url_ok",
                "suspicious_update",
                "cws_exists",
                "cws_version",
                "store_build_match",
                "flags",
            )
        },
        "threat_intel": {
            "file_sha256": osv.get("file_sha256"),
            "virustotal": {
                key: vt.get(key)
                for key in ("queried", "found", "malicious", "suspicious", "total", "error")
            },
            "npm_lookup_status": osv.get("osv_pkg_status"),
            "vulnerable_npm_packages": len(osv.get("osv_pkg_matches", [])),
            "cdn_refs": osv.get("cdn_refs", []),
            "flags": osv.get("flags", []),
        },
        "velocity": {
            "previous_version": vel.get("previous_version"),
            "flags": vel.get("flags", []),
        },
        "code": _code_summary(code),
        "stage_errors": errors,
    }


def _build_json_report(
    file_path,
    parsed,
    file_sha256,
    perm_score,
    pub,
    osv,
    vel,
    code,
    composite,
    floor_reason,
    ai,
    ai_status,
    final_score,
    final_level,
    stage_errors,
) -> dict:
    """One JSON shape for every outcome (AI ok / skipped / failed)."""
    manifest = parsed.manifest
    stage1_flags = (
        list(perm_score.notes)
        + list(pub.get("flags", []))
        + list(osv.get("flags", []))
        + list(vel.get("flags", []))
        + list(code.get("flags", []))
    )
    return {
        "extension_name": manifest.name,
        "file_path": file_path,
        "file_sha256": file_sha256,
        "container": parsed.container,
        "composite_score": composite,
        "composite_floor_reason": floor_reason,
        "ai_risk_score": ai.risk_score if ai else None,
        "final_score": final_score,
        "risk_level": final_level,
        "ai_triage": ai_status,
        "mitre_techniques": ai.mitre_techniques if ai else [],
        # Stage 5 feeds `iocs` to the credential-rotation playbook, so it must
        # never be empty just because the AI stage didn't run
        "iocs": ai.iocs if ai else stage1_flags,
        "stage_1_iocs": stage1_flags,
        "analyst_narrative": ai.analyst_narrative if ai else None,
        "stage_errors": stage_errors,
        "parse_warnings": manifest.parse_warnings,
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
            "code": _code_summary(code),
        },
        # manifest_summary is consumed by remediation.py to drive the rotation playbook
        "manifest_summary": {
            "name": manifest.name,
            "version": manifest.version,
            "manifest_version": manifest.manifest_version,
            "permissions": manifest.permissions,
            "host_permissions": manifest.host_permissions,
            "optional_permissions": manifest.optional_permissions,
            "optional_host_permissions": manifest.optional_host_permissions,
        },
    }


def _code_summary(code: dict) -> dict:
    """Stage 1f result without the per-file hash table (that stays on disk)."""
    profile = code.get("profile") or {}
    return {
        "code_score": code.get("code_score", 0),
        "baseline_version": code.get("baseline_version"),
        "changed_files": code.get("changed_files", 0),
        "new_hosts": code.get("new_hosts", []),
        "new_apis": code.get("new_apis", []),
        "new_exfil_endpoints": code.get("new_exfil_endpoints", []),
        "review_needed": code.get("review_needed", False),
        "endpoints": profile.get("hosts", []),
        "exfil_endpoints": profile.get("exfil_endpoints", []),
        "sensitive_apis": profile.get("apis", {}),
        "obfuscated_files": profile.get("obfuscated_files", []),
        "flags": code.get("flags", []),
    }


def _record_baselines(
    args, final_level, stage_errors, manifest, pub, code, assessment=None
) -> dict:
    """
    Save this build as the reference for future version / code comparisons.
    Automatically only for a LOW or MEDIUM verdict; a HIGH verdict only with
    --accept-baseline (an analyst reviewed it) and only when there is no
    evidence of malicious behaviour. Recording every scanned build (the old
    behaviour) let one scan of a malicious sample become the "known good"
    baseline that the next version was compared against.
    """
    if args.no_record:
        return {"recorded": False, "reason": "not recorded (--no-record)"}
    has_evidence = bool((assessment or {}).get("evidence"))
    accepted = getattr(args, "accept_baseline", False)
    if final_level not in ("low", "medium") and not (
        accepted and final_level == "high" and not has_evidence
    ):
        hint = (
            ""
            if has_evidence or final_level == "critical"
            else " - review it, then re-scan with --accept-baseline"
        )
        return {
            "recorded": False,
            "reason": f"not recorded - a {final_level.upper()} verdict never becomes a "
            f"baseline automatically{hint}",
        }
    if "1e" in stage_errors or "1f" in stage_errors:
        return {"recorded": False, "reason": "not recorded - a Stage 1e/1f check failed"}
    if code.get("review_needed") and not getattr(args, "accept_baseline", False):
        # A MEDIUM hijacked update must not become the reference that the
        # next malicious version is compared against
        return {
            "recorded": False,
            "reason": "not recorded - the code changed since "
            f"{code.get('baseline_version')} (new endpoints / APIs). Review the diff, "
            "then re-scan with --accept-baseline",
        }

    ext_id = pub.get("extension_id")
    saved_version = record_version(manifest.version, ext_id, manifest.name)
    saved_code = bool(code.get("profile")) and record_profile(
        ext_id, manifest.name, code["profile"]
    )
    if not (saved_version or saved_code):
        return {"recorded": False, "reason": "not recorded - no stable identity (ID or name)"}
    return {
        "recorded": True,
        "reason": f"recorded {manifest.version} as the baseline for future comparisons",
    }


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------


def _stage_header(num: str, title: str, output_json: bool):
    if not output_json:
        print(f"\n{BOLD}[Stage {num}]{RESET} {title}...")


def _print_stage_1c(pub: dict, manifest, network_ok: bool):
    ext_id = pub.get("extension_id")
    if ext_id:
        print(f"  Extension ID:  {ext_id}  (from {pub.get('id_source')})")
    if pub.get("store_build_match") is True:
        print(f"  {GREEN}[OK] Byte-for-byte identical to the Chrome Web Store build{RESET}")
    elif pub.get("cws_exists"):
        cws_v = pub.get("cws_version") or "?"
        print(f"  On Web Store:  yes, current version {cws_v} (local {manifest.version})")
    elif not network_ok:
        print(f"  {CYAN}Web Store check skipped (--offline){RESET}")
    for flag in pub.get("flags", []):
        print(f"  {YELLOW}[!] {flag}{RESET}")
    if pub.get("pub_score", 0) == 0 and not pub.get("flags"):
        print(f"  {GREEN}[OK] No publisher red flags{RESET}")


def _print_stage_1d(osv: dict, file_sha256: str, network_ok: bool, vt_cfg):
    print(f"  File SHA-256: {file_sha256[:16]}...")

    vt = osv.get("vt", {})
    if not network_ok:
        print(f"  {CYAN}VirusTotal:   skipped (--offline){RESET}")
    elif vt.get("queried"):
        if vt.get("found"):
            mal = vt.get("malicious", 0)
            total = vt.get("total", 0)
            colour = RED if mal >= 3 else (YELLOW if mal >= 1 else GREEN)
            print(f"  {colour}VirusTotal:   {mal}/{total} engines flagged{RESET}")
        elif vt.get("error"):
            print(f"  {YELLOW}VirusTotal:   UNKNOWN - {vt['error']}{RESET}")
        else:
            print(f"  {CYAN}VirusTotal:   not in database (no engine has seen this file){RESET}")
    elif vt_cfg is None or not vt_cfg.get("enabled"):
        print(f"  {CYAN}VirusTotal:   not configured (virustotal section in config){RESET}")

    status = osv.get("osv_pkg_status", "not_applicable")
    n_pkgs = len(osv.get("npm_packages", []))
    if status == "not_applicable":
        print("  npm packages: none bundled")
    elif status == "ok":
        n_vulns = len(osv.get("osv_pkg_matches", []))
        colour = RED if n_vulns else GREEN
        print(f"  {colour}npm packages: {n_pkgs} checked on OSV, {n_vulns} known vulns{RESET}")
    else:
        print(f"  {YELLOW}npm packages: {n_pkgs} found, OSV lookup {status}{RESET}")

    shown = set()
    for ref in osv.get("cdn_refs", []):
        print(f"  {YELLOW}[!] External CDN ref: {ref}{RESET}")
        shown.add(ref)
    for flag in osv.get("flags", []):
        if not any(ref in flag for ref in shown) and not flag.startswith("VirusTotal"):
            print(f"  {YELLOW}[!] {flag}{RESET}")


def _print_stage_1e(vel: dict, current_version: str):
    prev_v = vel.get("previous_version")
    if prev_v:
        jump = vel.get("version_jump") or {}
        delta = " / ".join(f"{k}: {'+' if v > 0 else ''}{v}" for k, v in jump.items() if v != 0)
        print(f"  Previous seen: {prev_v} -> {current_version}  ({delta or 'no change'})")
    else:
        print("  No earlier version on record")
    for flag in vel.get("flags", []):
        print(f"  {YELLOW}[!] {flag}{RESET}")
    if not vel.get("flags"):
        print(f"  {GREEN}[OK] No suspicious version jumps{RESET}")


def _print_stage_1f(code: dict):
    profile = code.get("profile") or {}
    if profile:
        print(
            f"  Endpoints in code: {len(profile.get('hosts', []))}  |  "
            f"sensitive APIs: {', '.join(sorted(profile.get('apis', {}))) or 'none'}"
        )
    if code.get("baseline_version"):
        print(
            f"  Compared with accepted build {code['baseline_version']}: "
            f"{code.get('changed_files', 0)} file(s) changed"
        )
    elif profile:
        print("  No accepted earlier build on record - absolute checks only")
    for flag in code.get("flags", []):
        print(f"  {YELLOW}[!] {flag}{RESET}")
    if not code.get("flags"):
        print(f"  {GREEN}[OK] No suspicious code findings{RESET}")


def _print_human_report(
    ai,
    pub: dict,
    osv: dict,
    vel: dict,
    code: dict,
    composite: int,
    final_score: int,
    assessment: dict,
    uncapped_score: int,
):
    final_level = _score_to_level(final_score)
    colour = RISK_COLOURS.get(final_level, RESET)

    print()
    print("=" * 66)
    print(f"  {BOLD}FINAL RISK SCORE: {colour}{final_score}/100 - {final_level.upper()}{RESET}")
    print(f"  (Stage 1 {composite}/100, Claude {ai.risk_score}/100 - the higher counts)")
    print("=" * 66)
    _print_verdict_basis(assessment, uncapped_score, final_score)

    if ai.mitre_techniques:
        print(f"\n  {BOLD}MITRE ATT&CK Techniques:{RESET}")
        for t in ai.mitre_techniques:
            print(f"    - {t}")

    if ai.iocs:
        print(f"\n  {BOLD}Indicators of Compromise:{RESET}")
        for ioc in ai.iocs:
            print(f"    - {ioc}")

    print(f"\n  {BOLD}Pre-install Check Summary:{RESET}")
    print(f"    Permission score:  {ai.permission_score.total_score}/100")
    print(
        f"    Publisher risk:    +{pub.get('pub_score', 0)} pts  "
        + (f"({len(pub.get('flags', []))} flags)" if pub.get("flags") else "(clean)")
    )
    vt = osv.get("vt", {})
    vt_text = (
        f"VT {vt.get('malicious', 0)}/{vt.get('total', 0)}" if vt.get("found") else "no VT hit"
    )
    print(f"    Threat intel:      +{osv.get('osv_score', 0)} pts  ({vt_text})")
    print(
        f"    Version velocity:  +{vel.get('velocity_score', 0)} pts  "
        + ("(suspicious jump)" if vel.get("is_suspicious") else "(normal)")
    )
    print(
        f"    Code analysis:     +{code.get('code_score', 0)} pts  "
        + (f"({len(code.get('flags', []))} findings)" if code.get("flags") else "(clean)")
    )

    print(f"\n  {BOLD}Analyst Narrative:{RESET}")
    for line in ai.analyst_narrative.strip().split("\n"):
        print(f"    {line}")

    print()
    print("-" * 66)
    _print_recommendation(final_level, final_score)
    print()

    # Stage 3 reminder
    print(
        f"  {CYAN}[Stage 3]{RESET} To monitor this extension at runtime:\n"
        "    1. Start Chrome with a separate profile and --remote-debugging-port=9222\n"
        "    2. Run: extguard-monitor"
        + (f" --ext-id {pub.get('extension_id')}" if pub.get("extension_id") else "")
    )
    print()


def _print_verdict_basis(assessment: dict, uncapped_score: int, final_score: int):
    """One line on what the verdict rests on - and whether it was capped."""
    if final_score < uncapped_score:
        print(
            f"  {CYAN}Verdict capped at {assessment['max_level'].upper()} "
            f"(score {uncapped_score} -> {final_score}):{RESET} {assessment['reason']}"
        )
    else:
        print(f"  {CYAN}Verdict basis:{RESET} {assessment['reason']}")


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
    Load the `virustotal` block from extguard.conf.json (see extguard/paths.py).
    Returns None if the file or section is absent - which signals "skip VT".
    """
    return paths.load_config_section("virustotal")


def _fail(message: str, output_json: bool, stage: str) -> int:
    """
    Report a scan that could not be completed. In --json mode the error is
    still valid JSON on stdout, so a pipeline never receives empty input.
    """
    print(f"\n{RED}[ERROR]{RESET} {message}", file=sys.stderr)
    if output_json:
        print(json.dumps({"error": message, "stage": stage}, indent=2))
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
