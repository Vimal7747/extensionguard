# remediation.py - Stage 5: End-to-end remediation orchestrator
#
# This is the "big red button" - given a confirmed-malicious extension, run
# the full IR sequence:
#
#   Step 1  PRESERVE   - quarantine the CRX bytes, manifest, triage, alerts
#   Step 2  KILL       - add the extension ID to Chrome's blocklist (registry/policy)
#   Step 3  PLAYBOOK   - generate a credential rotation runbook for the analyst
#   Step 4  RESOLVE    - auto-resolve the PagerDuty incident from Stage 4
#   Step 5  REPORT     - append actions to the chain of custody, print a summary
#
# Usage:
#   # Full pipeline driven by a triage JSON from Stage 2:
#   python remediation.py --from-triage triage.json
#
#   # Manual targeting (when you already know the extension ID):
#   python remediation.py --ext-id abcdefghijklmnopqrstuvwxyzabcdef --crx sample.crx
#
#   # Dry run - show what would happen but make no changes:
#   python remediation.py --from-triage triage.json --dry-run
#
#   # Skip individual steps:
#   python remediation.py --ext-id <id> --no-kill           # preserve + playbook only
#   python remediation.py --ext-id <id> --no-playbook       # preserve + kill only
#
#   # Verify an existing case folder's evidence integrity:
#   python remediation.py --verify-case quarantine/<case_dir>

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from crx_parser import parse_crx
from remediators import chrome_killer, cred_rotation, forensics

# Stage 4 integration - used to resolve the PD incident after kill
try:
    from adapters import pagerduty

    _PD_AVAILABLE = True
except ImportError:
    _PD_AVAILABLE = False


# ANSI colours
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def main():
    # Same Windows ANSI hack as main.py - spawn an empty cmd.exe to enable
    # VIRTUAL_TERMINAL_PROCESSING on the console. Harmless on POSIX.
    os.system("")

    parser = argparse.ArgumentParser(
        description="ExtensionGuard Stage 5 - Remediation orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python remediation.py --from-triage triage.json\n"
            "  python remediation.py --ext-id <32-char-id> --crx sample.crx\n"
            "  python remediation.py --from-triage triage.json --dry-run\n"
            "  python remediation.py --verify-case quarantine/20260521-103015-a1b2c3d4\n"
        ),
    )
    parser.add_argument(
        "--from-triage",
        metavar="PATH",
        help="Triage JSON file from `main.py --json` output",
    )
    parser.add_argument(
        "--ext-id",
        metavar="ID",
        help="Extension ID to remediate (manual targeting)",
    )
    parser.add_argument(
        "--crx",
        metavar="PATH",
        help="Path to the .crx file (required if --ext-id given without --from-triage)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would happen without making any changes",
    )
    parser.add_argument(
        "--no-preserve",
        action="store_true",
        help="Skip the forensic preservation step (NOT recommended)",
    )
    parser.add_argument(
        "--no-kill",
        action="store_true",
        help="Skip the Chrome blocklist update",
    )
    parser.add_argument(
        "--no-playbook",
        action="store_true",
        help="Skip credential rotation playbook generation",
    )
    parser.add_argument(
        "--no-pd-resolve",
        action="store_true",
        help="Skip PagerDuty incident auto-resolution",
    )
    parser.add_argument(
        "--rule",
        default="STAGE2-TRIAGE",
        help="Rule name (used as PD dedup key). Default: STAGE2-TRIAGE",
    )
    parser.add_argument(
        "--config",
        default="extguard.conf.json",
        help="Path to config file (for PagerDuty integration)",
    )
    parser.add_argument(
        "--case-id",
        help="Optional SOC ticket / incident number to tag this case",
    )
    parser.add_argument(
        "--verify-case",
        metavar="PATH",
        help="Verify the SHA-256 hashes of an existing case directory and exit",
    )
    args = parser.parse_args()

    # --- Verify-only mode --------------------------------------------------
    if args.verify_case:
        _run_verify(args.verify_case)
        return

    # --- Validate inputs ---------------------------------------------------
    if not args.from_triage and not args.ext_id:
        parser.error("Provide either --from-triage <path> or --ext-id <id>")

    print(f"\n{BOLD}=== ExtensionGuard Stage 5 - Remediation ===========================  {RESET}")
    print(f"{BOLD}    Mode: {'DRY-RUN' if args.dry_run else 'LIVE'}{RESET}")
    print(f"{BOLD}====================================================================={RESET}\n")

    # --- Gather inputs from --from-triage or manual flags ------------------
    inputs = _gather_inputs(args)
    if inputs is None:
        sys.exit(1)

    ext_id = inputs["ext_id"]
    ext_name = inputs["ext_name"]
    crx_bytes = inputs["crx_bytes"]
    manifest_raw = inputs["manifest_raw"]
    triage_result = inputs["triage_result"]
    host_perms = inputs["host_perms"]
    iocs = inputs["iocs"]

    print(f"Target extension:  {BOLD}{ext_name}{RESET}")
    print(f"Extension ID:      {ext_id or '(none - no signing key)'}")
    print(f"Host permissions:  {', '.join(host_perms) or '(none)'}\n")

    if not ext_id and not args.no_kill:
        print(
            f"{YELLOW}[!] No extension ID available - cannot blocklist. Kill step will be skipped.{RESET}\n"
        )

    case_dir = None

    # ===========================================================================
    # Step 1: PRESERVE
    # ===========================================================================
    if not args.no_preserve:
        print(f"{BOLD}[Step 1/5] PRESERVE - quarantining evidence...{RESET}")

        if args.dry_run:
            print(
                f"  {CYAN}[DRY-RUN] Would write CRX bytes, manifest, triage, alerts to quarantine/{RESET}\n"
            )
        else:
            preserve_result = forensics.preserve(
                extension_id=ext_id or "",
                extension_name=ext_name,
                crx_bytes=crx_bytes,
                manifest=manifest_raw,
                triage_result=triage_result,
                operator=getpass.getuser(),
                case_id=args.case_id,
            )
            if preserve_result["ok"]:
                case_dir = preserve_result["case_dir"]
                print(f"  {GREEN}OK{RESET}  Case folder:    {case_dir}")
                print(f"      Case ID:        {preserve_result['case_id']}")
                print(f"      Artifacts:      {len(preserve_result['artifacts'])}")
                for name, path in preserve_result["artifacts"].items():
                    sha = preserve_result["hashes"].get(Path(path).name, "?")[:16]
                    print(f"        - {name:8s}  {Path(path).name}  (sha256={sha}...)")
                print(f"      CoC hash:       {preserve_result['coc_hash'][:16]}...\n")
            else:
                print(f"  {RED}FAIL{RESET}  {preserve_result.get('error')}\n")
    else:
        print(f"{CYAN}[Step 1/5] PRESERVE - skipped (--no-preserve){RESET}\n")

    # ===========================================================================
    # Step 2: KILL - add extension to Chrome blocklist
    # ===========================================================================
    if not args.no_kill and ext_id:
        print(f"{BOLD}[Step 2/5] KILL - adding to Chrome ExtensionInstallBlocklist...{RESET}")

        kill_result = chrome_killer.block_extension(ext_id, dry_run=args.dry_run)

        if kill_result["ok"]:
            if args.dry_run:
                print(
                    f"  {CYAN}[DRY-RUN]{RESET} {kill_result['details'].get('note', 'Would block')}\n"
                )
            elif kill_result["details"].get("already_blocked"):
                print(
                    f"  {GREEN}OK{RESET}  Extension already in blocklist (slot {kill_result['details'].get('slot')})\n"
                )
            else:
                slot = kill_result["details"].get("slot", "?")
                print(
                    f"  {GREEN}OK{RESET}  Added to blocklist (slot {slot}). Effective on next Chrome restart.\n"
                )

            # Update CoC log
            if case_dir and not args.dry_run:
                forensics.append_custody_action(
                    case_dir=case_dir,
                    action="blocklisted",
                    actor=getpass.getuser(),
                    notes=f"Added to Chrome blocklist via {kill_result['method']}",
                )
        else:
            print(f"  {RED}FAIL{RESET}  {kill_result.get('error')}\n")
    elif args.no_kill:
        print(f"{CYAN}[Step 2/5] KILL - skipped (--no-kill){RESET}\n")
    else:
        print(f"{YELLOW}[Step 2/5] KILL - skipped (no extension ID available){RESET}\n")

    # ===========================================================================
    # Step 3: PLAYBOOK - credential rotation runbook
    # ===========================================================================
    if not args.no_playbook:
        print(f"{BOLD}[Step 3/5] PLAYBOOK - generating credential rotation runbook...{RESET}")

        playbook = cred_rotation.generate_playbook(
            host_permissions=host_perms,
            iocs=iocs,
            extension_name=ext_name,
            case_id=args.case_id or (Path(case_dir).name if case_dir else None),
            output_format="both",
        )

        if not playbook["applicable"]:
            print(
                f"  {GREEN}OK{RESET}  No tracked credential stores affected - no rotation needed.\n"
            )
        else:
            colour = RED if playbook["severity"] == "critical" else YELLOW
            print(f"  Affected stores:    {colour}{', '.join(playbook['applicable'])}{RESET}")
            print(f"  Severity:           {colour}{playbook['severity'].upper()}{RESET}")
            print(f"  Total steps:        {playbook['total_steps']}")
            print(f"  Estimated time:     ~{playbook['total_time_min']} minutes")

            if not args.dry_run and case_dir:
                paths = cred_rotation.save_playbook(playbook, case_dir, prefix="rotation")
                for fmt, path in paths.items():
                    print(f"  Saved {fmt:8s}:  {path}")

                forensics.append_custody_action(
                    case_dir=case_dir,
                    action="playbook_generated",
                    actor=getpass.getuser(),
                    notes=f"Rotation playbook for: {', '.join(playbook['applicable'])}",
                )
            elif args.dry_run:
                print(
                    f"  {CYAN}[DRY-RUN] Would write rotation_playbook.md + rotation_playbook.json{RESET}"
                )
            print()
    else:
        print(f"{CYAN}[Step 3/5] PLAYBOOK - skipped (--no-playbook){RESET}\n")

    # ===========================================================================
    # Step 4: RESOLVE - auto-close the PagerDuty incident
    # ===========================================================================
    if not args.no_pd_resolve and ext_id and _PD_AVAILABLE:
        print(f"{BOLD}[Step 4/5] RESOLVE - closing PagerDuty incident...{RESET}")

        cfg = _load_pd_config(args.config)
        if cfg and cfg.get("enabled"):
            if args.dry_run:
                dedup = f"extguard-{args.rule}-{ext_id}"
                print(
                    f"  {CYAN}[DRY-RUN]{RESET} Would resolve PD incident with dedup_key={dedup}\n"
                )
            else:
                pd_result = pagerduty.resolve(args.rule, ext_id, cfg)
                if pd_result["ok"]:
                    print(f"  {GREEN}OK{RESET}  PagerDuty incident resolved.\n")
                    if case_dir:
                        forensics.append_custody_action(
                            case_dir=case_dir,
                            action="pd_resolved",
                            actor=getpass.getuser(),
                            notes=f"PD incident dedup_key=extguard-{args.rule}-{ext_id}",
                        )
                else:
                    print(f"  {RED}FAIL{RESET}  {pd_result.get('error')}\n")
        else:
            print(f"  {CYAN}Skipped{RESET}  PagerDuty adapter disabled in config.\n")
    else:
        reason = (
            "--no-pd-resolve"
            if args.no_pd_resolve
            else "no extension ID"
            if not ext_id
            else "PD adapter missing"
        )
        print(f"{CYAN}[Step 4/5] RESOLVE - skipped ({reason}){RESET}\n")

    # ===========================================================================
    # Step 5: REPORT - final summary
    # ===========================================================================
    print(f"{BOLD}[Step 5/5] REPORT - remediation summary{RESET}")
    print(f"{'=' * 70}")
    print(f"  Extension:      {ext_name}")
    print(f"  Extension ID:   {ext_id or 'N/A'}")
    if case_dir:
        print(f"  Case folder:    {case_dir}")
        print(f"  Verify later:   python remediation.py --verify-case {case_dir}")
    if args.dry_run:
        print(f"  Mode:           {CYAN}DRY-RUN{RESET} (no changes made)")
    print(f"{'=' * 70}\n")


# ---------------------------------------------------------------------------
# Input-gathering helpers
# ---------------------------------------------------------------------------


def _gather_inputs(args) -> dict | None:
    """
    Build the standard input dict from either --from-triage or --ext-id+--crx.
    Returns a dict or None on failure.
    """
    inputs = {
        "ext_id": None,
        "ext_name": "Unknown Extension",
        "crx_bytes": None,
        "manifest_raw": {},
        "triage_result": None,
        "host_perms": [],
        "iocs": [],
    }

    if args.from_triage:
        triage_path = Path(args.from_triage)
        if not triage_path.exists():
            print(f"{RED}[ERROR]{RESET} Triage file not found: {triage_path}")
            return None
        try:
            triage = json.loads(triage_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"{RED}[ERROR]{RESET} Failed to parse triage JSON: {exc}")
            return None

        inputs["triage_result"] = triage
        inputs["ext_name"] = triage.get("extension_name", "Unknown")
        inputs["iocs"] = triage.get("iocs", [])

        stage1 = triage.get("stage_1_checks", {})
        pub = stage1.get("publisher", {})
        ms = triage.get("manifest_summary", {})

        # CLI --ext-id overrides the value extracted from the triage JSON
        # (useful when the triage was run on a bare manifest with no signing key)
        inputs["ext_id"] = args.ext_id or pub.get("extension_id")
        inputs["host_perms"] = ms.get("host_permissions", [])
        inputs["manifest_raw"] = {
            "name": ms.get("name"),
            "version": ms.get("version"),
            "manifest_version": ms.get("manifest_version"),
            "permissions": ms.get("permissions", []),
            "host_permissions": ms.get("host_permissions", []),
        }

        # If a CRX file is also provided, load it for preservation
        if args.crx:
            try:
                inputs["crx_bytes"], _ = parse_crx(args.crx)
            except Exception as exc:
                print(f"{YELLOW}[!] Could not load CRX file: {exc}{RESET}")

    elif args.ext_id:
        inputs["ext_id"] = args.ext_id
        if args.crx:
            try:
                zip_bytes, manifest = parse_crx(args.crx)
                inputs["crx_bytes"] = zip_bytes
                inputs["manifest_raw"] = manifest.raw
                inputs["ext_name"] = manifest.name
                inputs["host_perms"] = manifest.host_permissions
            except Exception as exc:
                print(f"{RED}[ERROR]{RESET} Failed to parse CRX: {exc}")
                return None
        else:
            print(
                f"{YELLOW}[!] --ext-id given without --crx - preservation will be skeleton-only{RESET}"
            )

    return inputs


def _load_pd_config(config_path: str) -> dict | None:
    """Load the pagerduty section from extguard.conf.json."""
    try:
        raw = json.loads(Path(config_path).read_text(encoding="utf-8"))
        pd = raw.get("pagerduty", {})
        return {k: v for k, v in pd.items() if not k.startswith("_")}
    except (OSError, json.JSONDecodeError):
        return None


# ---------------------------------------------------------------------------
# Verification mode
# ---------------------------------------------------------------------------


def _run_verify(case_dir: str):
    """Verify SHA-256 hashes for an existing case folder."""
    print(f"\n{BOLD}Verifying case integrity: {case_dir}{RESET}\n")

    result = forensics.verify_case(case_dir)

    if result["ok"]:
        print(
            f"  {GREEN}OK{RESET}  All {result['verified']}/{result['total']} artifacts match the recorded SHA-256 hashes.\n"
        )
    else:
        print(
            f"  {RED}FAIL{RESET}  {len(result['mismatches'])} of {result['total']} artifacts FAILED verification:\n"
        )
        for m in result["mismatches"]:
            print(f"    - {m['file']}: {m['issue']}")
            if m.get("expected"):
                print(f"        expected: {m['expected']}")
                print(f"        actual:   {m['actual']}")
        print()
        sys.exit(2)


if __name__ == "__main__":
    main()
