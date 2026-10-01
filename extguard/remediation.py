# remediation.py - Stage 5: End-to-end remediation orchestrator
#
# Given a confirmed-malicious extension, run the IR sequence:
#
#   Step 1  PRESERVE   - quarantine the ORIGINAL sample, manifest, triage,
#                        alert history and storage snapshot (signed chain of custody)
#   Step 2  KILL       - add the extension ID to Chrome's blocklist on this
#                        machine and/or a Google Workspace org unit
#   Step 3  PLAYBOOK   - generate a credential rotation runbook for the analyst
#   Step 4  PAGERDUTY  - ACKNOWLEDGE the incident (resolve only on request)
#   Step 5  REPORT     - summary; exit code 1 if any step failed
#
# Safety rules:
#   - Changing Chrome policy needs confirmation: type BLOCK at the prompt, or
#     pass --yes for automation. A non-interactive run without --yes refuses.
#   - The PagerDuty incident is ACKNOWLEDGED, not resolved: the blocklist only
#     takes effect when Chrome reloads policy, and stolen credentials still
#     have to be rotated. Use --pd-action resolve when that is done.
#
# Usage:
#   extguard-remediate --from-triage triage.json --crx sample.crx
#   extguard-remediate --ext-id <32-char-id> --crx sample.crx --yes
#   extguard-remediate --from-triage triage.json --dry-run
#   extguard-remediate --from-triage triage.json --workspace-ou /Engineering
#   extguard-remediate --process-queue            # run dashboard approvals
#   extguard-remediate --verify-case ~/.extguard/quarantine/<case_dir>

import argparse
import getpass
import hashlib
import json
import os
import sys
from pathlib import Path

from extguard import paths
from extguard.crx_parser import parse_extension
from extguard.logging_setup import redact
from extguard.models import is_valid_extension_id
from extguard.remediators import chrome_killer, cred_rotation, forensics

# Stage 4 integration - used to acknowledge / resolve the PD incident
try:
    from extguard.adapters import pagerduty

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

MAX_ALERT_LINES = 50_000  # cap on --alerts-log reading


def main(argv: list | None = None) -> int:
    # Same Windows ANSI hack as main.py - spawn an empty cmd.exe to enable
    # VIRTUAL_TERMINAL_PROCESSING on the console. Harmless on POSIX.
    os.system("")

    parser = argparse.ArgumentParser(
        description="ExtensionGuard Stage 5 - Remediation orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  extguard-remediate --from-triage triage.json --crx sample.crx\n"
            "  extguard-remediate --ext-id <32-char-id> --crx sample.crx --yes\n"
            "  extguard-remediate --from-triage triage.json --dry-run\n"
            "  extguard-remediate --process-queue\n"
            "  extguard-remediate --verify-case ~/.extguard/quarantine/20260521-103015-a1b2c3d4\n"
            "\n"
            "Exit codes: 0 all steps succeeded, 1 a step failed or was refused,\n"
            "            2 bad arguments / inputs\n"
        ),
    )
    parser.add_argument("--from-triage", metavar="PATH", help="Triage JSON from `extguard --json`")
    parser.add_argument("--ext-id", metavar="ID", help="Extension ID to remediate")
    parser.add_argument(
        "--crx",
        metavar="PATH",
        help="The sample file (.crx / .zip) to preserve as evidence",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Show what would happen without making any changes"
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Confirm policy changes without prompting (for automation / SOAR)",
    )
    parser.add_argument(
        "--no-preserve",
        action="store_true",
        help="Skip the forensic preservation step (NOT recommended)",
    )
    parser.add_argument("--no-kill", action="store_true", help="Skip the Chrome blocklist update")
    parser.add_argument(
        "--workspace-ou",
        metavar="OU_PATH",
        help="ALSO block the extension for a Google Workspace org unit (e.g. /Engineering) "
        "using the `workspace` config section",
    )
    parser.add_argument(
        "--no-playbook", action="store_true", help="Skip credential rotation playbook generation"
    )
    parser.add_argument(
        "--pd-action",
        choices=["acknowledge", "resolve", "none"],
        default="acknowledge",
        help="What to do with the PagerDuty incident (default: acknowledge - it stays "
        "open until credentials are rotated)",
    )
    parser.add_argument(
        "--no-pd-resolve",
        action="store_true",
        help="Leave PagerDuty alone (same as --pd-action none; kept for compatibility)",
    )
    parser.add_argument(
        "--rule",
        default="STAGE2-TRIAGE",
        help="Rule name used in the PagerDuty dedup key. Default: STAGE2-TRIAGE",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Config file for PagerDuty / Workspace "
        "(default: $EXTGUARD_CONFIG, ./extguard.conf.json, or ~/.extguard/extguard.conf.json)",
    )
    parser.add_argument("--case-id", help="Optional SOC ticket / incident number to tag this case")
    parser.add_argument(
        "--alerts-log",
        metavar="PATH",
        help="JSONL alert log (extguard-monitor --output-json); this extension's "
        "alerts are preserved as evidence",
    )
    parser.add_argument(
        "--storage-snapshot",
        metavar="PATH",
        help="JSON from `extguard-monitor --snapshot-storage`, preserved as evidence",
    )
    parser.add_argument(
        "--verify-case",
        metavar="PATH",
        help="Verify an existing case directory and exit",
    )
    parser.add_argument(
        "--process-queue",
        action="store_true",
        help="Execute approve / reject decisions queued from the dashboard",
    )
    parser.add_argument(
        "--queue-file",
        metavar="PATH",
        help="Queue to process (default: ~/.extguard/remediation_queue.jsonl)",
    )
    args = parser.parse_args(argv)
    if args.no_pd_resolve:
        args.pd_action = "none"

    if args.verify_case:
        return _run_verify(args.verify_case)
    if args.process_queue:
        return process_queue(args)
    if not args.from_triage and not args.ext_id:
        parser.error("Provide either --from-triage <path> or --ext-id <id>")

    print(f"\n{BOLD}=== ExtensionGuard Stage 5 - Remediation ===========================  {RESET}")
    print(f"{BOLD}    Mode: {'DRY-RUN' if args.dry_run else 'LIVE'}{RESET}")
    print(f"{BOLD}====================================================================={RESET}\n")

    inputs = _gather_inputs(args)
    if inputs is None:
        return 2

    ext_id = inputs["ext_id"]
    ext_name = inputs["ext_name"]
    host_perms = inputs["host_perms"]
    failures: list = []

    print(f"Target extension:  {BOLD}{ext_name}{RESET}")
    print(f"Extension ID:      {ext_id or '(none - no signing key)'}")
    print(f"Host permissions:  {', '.join(host_perms) or '(none)'}\n")

    case_dir = None

    # =======================================================================
    # Step 1: PRESERVE
    # =======================================================================
    if args.no_preserve:
        print(f"{CYAN}[Step 1/5] PRESERVE - skipped (--no-preserve){RESET}\n")
    else:
        print(f"{BOLD}[Step 1/5] PRESERVE - quarantining evidence...{RESET}")
        if args.dry_run:
            print(f"  {CYAN}[DRY-RUN] Would write the sample, manifest, triage and alerts{RESET}\n")
        else:
            try:
                preserved = forensics.preserve(
                    extension_id=ext_id or "",
                    extension_name=ext_name,
                    crx_bytes=inputs["crx_bytes"],
                    manifest=inputs["manifest_raw"],
                    triage_result=inputs["triage_result"],
                    alert_history=inputs["alert_history"],
                    storage_snapshot=inputs["storage_snapshot"],
                    operator=getpass.getuser(),
                    case_id=args.case_id,
                    sample_name=inputs["sample_name"],
                )
            except (OSError, ValueError) as exc:
                preserved = {"ok": False, "error": str(exc)}
            if preserved["ok"]:
                case_dir = preserved["case_dir"]
                print(f"  {GREEN}OK{RESET}  Case folder:    {case_dir}")
                print(f"      Case ID:        {preserved['case_id']}")
                for name, path in preserved["artifacts"].items():
                    sha = preserved["hashes"].get(Path(path).name, "?")[:16]
                    print(f"        - {name:8s}  {Path(path).name}  (sha256={sha}...)")
                print(f"      CoC hash:       {preserved['coc_hash'][:16]}... (HMAC-signed)\n")
            else:
                failures.append("preserve")
                print(f"  {RED}FAIL{RESET}  {preserved.get('error')}\n")

    # =======================================================================
    # Step 2: KILL
    # =======================================================================
    if args.no_kill:
        print(f"{CYAN}[Step 2/5] KILL - skipped (--no-kill){RESET}\n")
    elif not ext_id:
        failures.append("kill")
        print(f"{YELLOW}[Step 2/5] KILL - not possible (no extension ID){RESET}\n")
    else:
        print(f"{BOLD}[Step 2/5] KILL - Chrome ExtensionInstallBlocklist...{RESET}")
        if not _run_kill(args, ext_id, case_dir):
            failures.append("kill")

    # =======================================================================
    # Step 3: PLAYBOOK
    # =======================================================================
    if args.no_playbook:
        print(f"{CYAN}[Step 3/5] PLAYBOOK - skipped (--no-playbook){RESET}\n")
    else:
        print(f"{BOLD}[Step 3/5] PLAYBOOK - generating credential rotation runbook...{RESET}")
        _run_playbook(args, host_perms, inputs["iocs"], ext_name, case_dir)

    # =======================================================================
    # Step 4: PAGERDUTY
    # =======================================================================
    if args.pd_action == "none":
        print(f"{CYAN}[Step 4/5] PAGERDUTY - skipped{RESET}\n")
    elif not ext_id or not _PD_AVAILABLE:
        print(f"{CYAN}[Step 4/5] PAGERDUTY - skipped (no extension ID){RESET}\n")
    else:
        print(f"{BOLD}[Step 4/5] PAGERDUTY - {args.pd_action} incident...{RESET}")
        if not _run_pagerduty(args, args.rule, ext_id, case_dir, getpass.getuser()):
            failures.append("pagerduty")

    # =======================================================================
    # Step 5: REPORT
    # =======================================================================
    print(f"{BOLD}[Step 5/5] REPORT - remediation summary{RESET}")
    print(f"{'=' * 70}")
    print(f"  Extension:      {ext_name}")
    print(f"  Extension ID:   {ext_id or 'N/A'}")
    if case_dir:
        print(f"  Case folder:    {case_dir}")
        print(f"  Verify later:   extguard-remediate --verify-case {case_dir}")
    if args.dry_run:
        print(f"  Mode:           {CYAN}DRY-RUN{RESET} (no changes made)")
    if failures:
        print(f"  {RED}Failed steps:   {', '.join(failures)}{RESET}")
    else:
        print(f"  {GREEN}All steps completed{RESET}")
    print(f"{'=' * 70}\n")
    return 1 if failures else 0


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------


def _confirm(args, what: str) -> bool:
    """Policy changes need explicit confirmation (dry runs don't)."""
    if args.dry_run or args.yes:
        return True
    if not sys.stdin or not sys.stdin.isatty():
        print(f"  {RED}REFUSED{RESET}  {what} needs confirmation - re-run with --yes")
        return False
    answer = input(f"  Type BLOCK to {what}: ")
    if answer.strip() != "BLOCK":
        print(f"  {YELLOW}Cancelled{RESET}")
        return False
    return True


def _run_kill(args, ext_id: str, case_dir: str | None, actor: str | None = None) -> bool:
    actor = actor or getpass.getuser()
    ok = True
    if _confirm(args, f"add {ext_id} to the Chrome blocklist on this machine"):
        result = chrome_killer.block_extension(ext_id, dry_run=args.dry_run)
        ok &= _report_kill(result, args, case_dir, "this machine", actor)
    else:
        ok = False

    if args.workspace_ou:
        cfg = paths.load_config_section("workspace", args.config) or {}
        where = f"Workspace org unit {args.workspace_ou}"
        if _confirm(args, f"block {ext_id} for {where}"):
            result = chrome_killer.block_extension_workspace(
                ext_id, args.workspace_ou, cfg, dry_run=args.dry_run
            )
            ok &= _report_kill(result, args, case_dir, where, actor)
        else:
            ok = False
    print()
    return ok


def _report_kill(result: dict, args, case_dir, where: str, actor: str) -> bool:
    if not result.get("ok"):
        print(f"  {RED}FAIL{RESET}  {where}: {redact(str(result.get('error')))}")
        return False
    details = result.get("details", {})
    if args.dry_run:
        print(f"  {CYAN}[DRY-RUN]{RESET} {where}: {details.get('note', 'would block')}")
        return True
    if result.get("applied") is False:
        # e.g. macOS: a configuration profile was produced but not installed
        print(f"  {YELLOW}PARTIAL{RESET}  {where}: {details.get('note')}")
        print(f"          {details.get('profile_path', '')}")
    else:
        print(
            f"  {GREEN}OK{RESET}  {where}: blocked via {result['method']} - effective when "
            "Chrome reloads policy (restart, or chrome://policy > Reload policies)"
        )
    if case_dir:
        forensics.append_custody_action(
            case_dir=case_dir,
            action="blocklisted" if result.get("applied") is not False else "blocklist_prepared",
            actor=actor,
            notes=f"{where} via {result['method']}",
        )
    return True


def _run_playbook(args, host_perms, iocs, ext_name, case_dir):
    playbook = cred_rotation.generate_playbook(
        host_permissions=host_perms,
        iocs=iocs,
        extension_name=ext_name,
        case_id=args.case_id or (Path(case_dir).name if case_dir else None),
        output_format="both",
    )
    if not playbook["applicable"]:
        print(f"  {GREEN}OK{RESET}  No tracked credential stores affected - no rotation needed.\n")
        return
    colour = RED if playbook["severity"] == "critical" else YELLOW
    print(f"  Affected stores:    {colour}{', '.join(playbook['applicable'])}{RESET}")
    print(f"  Severity:           {colour}{playbook['severity'].upper()}{RESET}")
    print(f"  Total steps:        {playbook['total_steps']}")
    print(f"  Estimated time:     ~{playbook['total_time_min']} minutes")
    if args.dry_run:
        print(f"  {CYAN}[DRY-RUN] Would write rotation_playbook.md + rotation_playbook.json{RESET}")
    elif case_dir:
        for fmt, path in cred_rotation.save_playbook(playbook, case_dir, prefix="rotation").items():
            print(f"  Saved {fmt:8s}:  {path}")
        forensics.append_custody_action(
            case_dir=case_dir,
            action="playbook_generated",
            actor=getpass.getuser(),
            notes=f"Rotation playbook for: {', '.join(playbook['applicable'])}",
        )
    print()


def _run_pagerduty(args, rule: str, ext_id: str, case_dir, actor: str, action=None) -> bool:
    action = action or args.pd_action  # "acknowledge" or "resolve"
    cfg = _load_pd_config(args.config)
    if not cfg or not cfg.get("enabled"):
        print(f"  {CYAN}Skipped{RESET}  PagerDuty adapter disabled in config.\n")
        return True
    dedup = f"extguard-{rule}-{ext_id}"
    if args.dry_run:
        print(f"  {CYAN}[DRY-RUN]{RESET} Would {action} PD incident {dedup}\n")
        return True
    call = pagerduty.resolve if action == "resolve" else pagerduty.acknowledge
    result = call(rule, ext_id, cfg)
    if not result["ok"]:
        print(f"  {RED}FAIL{RESET}  {result.get('error')}\n")
        return False
    note = (
        "resolved"
        if action == "resolve"
        else "acknowledged (still OPEN - resolve after credentials are rotated)"
    )
    print(f"  {GREEN}OK{RESET}  PagerDuty incident {note}.\n")
    if case_dir:
        forensics.append_custody_action(
            case_dir=case_dir,
            action=f"pd_{action}",
            actor=actor,
            notes=f"PD incident dedup_key={dedup}",
        )
    return True


# ---------------------------------------------------------------------------
# Dashboard queue consumer
# ---------------------------------------------------------------------------


def process_queue(args) -> int:
    """
    Execute the approve / reject decisions analysts queued in the dashboard.

    Each entry is processed once: its fingerprint is appended to
    <queue>.done after success. Failed entries stay pending and are retried
    next run. A case that fails integrity verification is never acted on.
    """
    queue = Path(args.queue_file) if args.queue_file else paths.queue_file()
    done_file = queue.with_name(queue.name + ".done")
    if not queue.exists():
        print(f"No remediation queue at {queue} - nothing to do.")
        return 0

    done = set(done_file.read_text(encoding="utf-8").split()) if done_file.exists() else set()
    failures = 0
    processed = 0

    for line in queue.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        fingerprint = hashlib.sha256(line.strip().encode("utf-8")).hexdigest()
        if fingerprint in done:
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            print(f"{YELLOW}[!] Skipping malformed queue line{RESET}")
            continue

        ok = _process_entry(args, entry)
        if ok and not args.dry_run:
            with done_file.open("a", encoding="utf-8") as f:
                f.write(fingerprint + "\n")
            processed += 1
        elif not ok:
            failures += 1

    print(f"\nQueue: {processed} processed, {failures} failed (will retry next run).")
    return 1 if failures else 0


def _process_entry(args, entry: dict) -> bool:
    case_id = str(entry.get("case_id", ""))
    decision = entry.get("decision")
    action = entry.get("action")
    actor = f"{entry.get('actor', 'unknown')} (approved in dashboard)"
    print(
        f"\n{BOLD}Queue entry:{RESET} case {case_id} - {decision} / {action} by {entry.get('actor')}"
    )

    if not forensics.CASE_ID_PATTERN.match(case_id):
        print(f"  {RED}FAIL{RESET}  invalid case id")
        return False
    case_dir = forensics.DEFAULT_QUARANTINE_ROOT / case_id
    if not case_dir.is_dir():
        print(
            f"  {RED}FAIL{RESET}  case folder not found under {forensics.DEFAULT_QUARANTINE_ROOT}"
        )
        return False

    # Only act on a case this machine can prove is intact. "no-key" (signing
    # key missing) is not good enough: anyone who can write to the quarantine
    # folder could otherwise plant a case that blocks a legitimate extension.
    verification = forensics.verify_case(str(case_dir))
    if not verification.get("ok") or verification.get("signature") != "valid":
        print(
            f"  {RED}REFUSED{RESET}  case failed integrity verification "
            f"(signature: {verification.get('signature')}) - not acting on it"
        )
        return False

    coc = json.loads((case_dir / "chain_of_custody.json").read_text(encoding="utf-8"))
    ext_id = (coc.get("extension") or {}).get("id")

    if decision == "reject":
        if not args.dry_run:
            forensics.append_custody_action(
                str(case_dir), "false_positive_confirmed", actor, entry.get("notes", "")
            )
        print(f"  {GREEN}OK{RESET}  recorded as false positive - no action taken")
        return True
    if decision != "approve":
        print(f"  {RED}FAIL{RESET}  unknown decision {decision!r}")
        return False

    if action == "kill":
        if not is_valid_extension_id(ext_id):
            print(f"  {RED}FAIL{RESET}  case has no valid extension ID ({ext_id!r})")
            return False
        return _run_kill(args, ext_id, None if args.dry_run else str(case_dir), actor)

    if action == "playbook":
        triage = _load_json_file(case_dir / "triage.json") or {}
        manifest = _load_json_file(case_dir / "manifest.json") or {}
        host_perms = (triage.get("manifest_summary") or {}).get("host_permissions") or manifest.get(
            "host_permissions", []
        )
        _run_playbook(
            args,
            host_perms if isinstance(host_perms, list) else [],
            triage.get("iocs", []),
            (coc.get("extension") or {}).get("name", "Unknown"),
            None if args.dry_run else str(case_dir),
        )
        return True

    if action == "resolve":
        if not is_valid_extension_id(ext_id):
            print(f"  {RED}FAIL{RESET}  case has no valid extension ID ({ext_id!r})")
            return False
        if not _PD_AVAILABLE:
            print(f"  {RED}FAIL{RESET}  PagerDuty adapter not available")
            return False
        case = None if args.dry_run else str(case_dir)
        return _run_pagerduty(args, args.rule, ext_id, case, actor, action="resolve")

    print(f"  {RED}FAIL{RESET}  unknown action {action!r}")
    return False


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
        "sample_name": "sample.crx",
        "alert_history": None,
        "storage_snapshot": None,
    }

    if args.from_triage:
        triage_path = Path(args.from_triage)
        if not triage_path.exists():
            print(f"{RED}[ERROR]{RESET} Triage file not found: {triage_path}")
            return None
        try:
            triage = json.loads(triage_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"{RED}[ERROR]{RESET} Failed to parse triage JSON: {exc}")
            return None
        if not isinstance(triage, dict) or "error" in triage and "risk_level" not in triage:
            print(f"{RED}[ERROR]{RESET} Triage file is a failed scan, not a result")
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

        if args.crx:
            try:
                parsed = parse_extension(args.crx)
                inputs["crx_bytes"], inputs["sample_name"] = _evidence_bytes(parsed)
            except Exception as exc:
                print(f"{YELLOW}[!] Could not load CRX file: {exc}{RESET}")

    elif args.ext_id:
        inputs["ext_id"] = args.ext_id
        if args.crx:
            try:
                parsed = parse_extension(args.crx)
                inputs["crx_bytes"], inputs["sample_name"] = _evidence_bytes(parsed)
                inputs["manifest_raw"] = parsed.manifest.raw
                inputs["ext_name"] = parsed.manifest.name
                inputs["host_perms"] = parsed.manifest.host_permissions
            except Exception as exc:
                print(f"{RED}[ERROR]{RESET} Failed to parse CRX: {exc}")
                return None
        else:
            print(
                f"{YELLOW}[!] --ext-id given without --crx - preservation will be skeleton-only{RESET}"
            )

    # Every ID that could reach the registry / policy files is checked here.
    # "*" in ExtensionInstallBlocklist would block EVERY extension, and the ID
    # may come from a triage JSON file that someone could have edited.
    if inputs["ext_id"] is not None and not is_valid_extension_id(inputs["ext_id"]):
        print(
            f"{RED}[ERROR]{RESET} Invalid extension ID {inputs['ext_id']!r} - "
            "expected 32 letters a-p"
        )
        return None

    if args.alerts_log:
        inputs["alert_history"] = _load_alert_history(args.alerts_log, inputs["ext_id"])
        print(
            f"Alert history:     {len(inputs['alert_history'] or [])} alert(s) for this extension"
        )
    if args.storage_snapshot:
        inputs["storage_snapshot"] = _load_json_file(Path(args.storage_snapshot))
        if inputs["storage_snapshot"] is None:
            print(f"{YELLOW}[!] Could not read storage snapshot {args.storage_snapshot}{RESET}")

    return inputs


def _load_alert_history(path: str, ext_id: str | None) -> list:
    """This extension's alerts from a JSONL alert log (all alerts if no ID)."""
    alerts = []
    try:
        with open(path, encoding="utf-8") as f:
            for i, line in enumerate(f):
                if i >= MAX_ALERT_LINES:
                    break
                try:
                    alert = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(alert, dict):
                    continue
                if ext_id is None or (alert.get("extension") or {}).get("id") == ext_id:
                    alerts.append(alert)
    except OSError as exc:
        print(f"{YELLOW}[!] Could not read alert log {path}: {exc}{RESET}")
    return alerts


def _load_json_file(path: Path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _evidence_bytes(parsed) -> tuple:
    """
    The sample to preserve is the ORIGINAL file, exactly as received - its
    hash must match the one VirusTotal / the Web Store know it by. (The old
    code stored the header-stripped ZIP under the name sample.crx.)
    Returns (bytes_or_None, sample_file_name).
    """
    if parsed.container == "json":
        return None, "sample.json"  # the manifest itself is preserved separately
    suffix = "zip" if parsed.container == "zip" else "crx"
    return parsed.file_bytes, f"sample.{suffix}"


def _load_pd_config(config_path: str | None) -> dict | None:
    """Load the pagerduty section from extguard.conf.json (see extguard/paths.py)."""
    return paths.load_config_section("pagerduty", explicit=config_path)


# ---------------------------------------------------------------------------
# Verification mode
# ---------------------------------------------------------------------------


def _run_verify(case_dir: str) -> int:
    """Verify SHA-256 hashes and the signature of an existing case folder."""
    print(f"\n{BOLD}Verifying case integrity: {case_dir}{RESET}\n")

    result = forensics.verify_case(case_dir)
    if "error" in result:
        print(f"  {RED}FAIL{RESET}  {result['error']}\n")
        return 1

    signature = result.get("signature")
    sig_text = {
        "valid": f"{GREEN}signature valid{RESET}",
        "no-key": f"{YELLOW}signature NOT checked (signing key not on this machine){RESET}",
    }.get(signature, f"{RED}signature {signature}{RESET}")

    if result["ok"]:
        print(
            f"  {GREEN}OK{RESET}  All {result['verified']}/{result['total']} artifacts match "
            f"the recorded SHA-256 hashes; {sig_text}.\n"
        )
        return 0
    print(f"  {RED}FAIL{RESET}  {len(result['mismatches'])} problem(s); {sig_text}:\n")
    for m in result["mismatches"]:
        print(f"    - {m['file']}: {m['issue']}")
        if m.get("expected"):
            print(f"        expected: {m['expected']}")
            print(f"        actual:   {m['actual']}")
    print()
    return 1


if __name__ == "__main__":
    sys.exit(main())
