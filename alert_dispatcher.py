# alert_dispatcher.py - Stage 4: SOC alert enrichment and multi-channel dispatch
#
# Reads JSON alert lines from stdin (piped from behavioral_monitor.py) and/or
# from the Stage 2 triage output, then:
#   1. Deduplicates — suppresses re-sends of the same alert within a TTL window
#   2. Escalates — promotes severity when the same rule fires repeatedly
#   3. Enriches — adds host context, recommendation, and analyst notes
#   4. Dispatches — sends to all enabled channels in parallel
#
# Usage:
#   # Real-time runtime monitoring pipeline (Stage 3 -> 4):
#   python behavioral_monitor.py --output-json | python alert_dispatcher.py
#
#   # Dispatch a pre-install triage result (Stage 2 -> 4):
#   python main.py suspicious.crx --json | python alert_dispatcher.py --source triage
#
#   # Test with a sample alert file:
#   python alert_dispatcher.py --test
#
#   # Dry run (show what would be sent, don't actually send):
#   python alert_dispatcher.py --dry-run

import argparse
import json
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

# Import all four destination adapters
from adapters import pagerduty, sentinel, slack, splunk
from config_schema import format_errors as format_config_errors
from config_schema import validate as validate_config

# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

DEFAULT_CONFIG_PATH = Path(__file__).parent / "extguard.conf.json"


def load_config(path=None, validate: bool = True) -> dict:
    """
    Load extguard.conf.json.
    Strips keys starting with '_' (our comment convention).
    Falls back to sensible defaults if a section is missing.

    If validate=True, runs the config_schema.validate check and prints any
    errors to stderr (but still returns the config so partially-valid configs
    can still be used in dry-run / debugging modes).
    """
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH

    if not config_path.exists():
        print(f"[Config] No config file found at {config_path}. Using defaults (all adapters disabled).",
              file=sys.stderr)
        return _default_config()

    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[Config] Failed to parse config: {exc}", file=sys.stderr)
        return _default_config()

    # Strip _comment keys recursively
    config = _strip_comments(raw)

    # Validate the structure - any errors get printed but we still return
    # the config so dry-run testing still works with a partially-valid file
    if validate:
        errors = validate_config(config)
        if errors:
            print(format_config_errors(errors), file=sys.stderr)
            print(
                f"[Config] {len(errors)} validation error(s) above. "
                "Adapters with invalid config will fail at dispatch time.",
                file=sys.stderr,
            )

    return config


def _strip_comments(obj):
    if isinstance(obj, dict):
        return {k: _strip_comments(v) for k, v in obj.items() if not k.startswith("_")}
    return obj


def _default_config() -> dict:
    return {
        "sentinel":  {"enabled": False},
        "splunk":    {"enabled": False},
        "pagerduty": {"enabled": False},
        "slack":     {"enabled": False},
        "dispatch": {
            "dedup_ttl_seconds":    300,
            "escalation_threshold": 3,
            "min_severity":         "low",
            "also_dispatch_triage": True,
            "triage_min_score":     45,
        },
    }


# ---------------------------------------------------------------------------
# Deduplication and escalation state
# ---------------------------------------------------------------------------

class AlertState:
    """
    Tracks alert history to drive deduplication and escalation.

    Dedup:
      An alert fingerprint = rule + extension_id.
      If we already sent this fingerprint within dedup_ttl_seconds, suppress it.

    Escalation:
      If the same rule fires `escalation_threshold` times for the same extension,
      promote the severity to "critical" and send a special escalation alert.
    """

    def __init__(self, dedup_ttl: int, escalation_threshold: int):
        self.dedup_ttl            = dedup_ttl
        self.escalation_threshold = escalation_threshold

        # fingerprint -> timestamp of last dispatch
        self._last_sent: dict = {}

        # extension_id -> rule -> count
        self._rule_counts: dict = {}

        # Lock for thread safety (parallel dispatches can update state concurrently)
        self._lock = threading.Lock()

    def should_send(self, alert: dict) -> tuple:
        """
        Decide whether to send this alert.

        Returns (should_send: bool, escalated: bool, reason: str).
        escalated = True means we should promote severity to "critical".
        """
        fingerprint = _fingerprint(alert)
        ext_id      = alert.get("extension", {}).get("id") or "unknown"
        rule        = alert.get("rule", "?")

        with self._lock:
            now = time.time()

            # --- Deduplication check ---
            last = self._last_sent.get(fingerprint, 0)
            if now - last < self.dedup_ttl:
                remaining = int(self.dedup_ttl - (now - last))
                return False, False, f"Duplicate suppressed (next in {remaining}s)"

            # --- Escalation tracking ---
            counts = self._rule_counts.setdefault(ext_id, {})
            counts[rule] = counts.get(rule, 0) + 1
            count = counts[rule]

            escalated = (count == self.escalation_threshold)

            # Record that we're about to send
            self._last_sent[fingerprint] = now

        if escalated:
            reason = f"ESCALATED: rule {rule} has now fired {count}x for this extension"
        else:
            reason = f"New alert (rule count: {count})"

        return True, escalated, reason


# ---------------------------------------------------------------------------
# Alert normaliser — converts different input formats to the standard alert
# ---------------------------------------------------------------------------

def normalise_alert(raw: dict, source: str) -> dict | None:
    """
    Convert either a behavioral monitor alert or a triage JSON result to the
    standard alert format consumed by the adapters.

    Returns None if the input should be skipped (e.g. low-score triage).
    """
    if source == "triage":
        return _normalise_triage(raw)
    else:
        # Already in standard format from behavioral_monitor.py
        # Just validate the required keys are present
        if not raw.get("rule") or not raw.get("severity"):
            return None
        return raw


def _normalise_triage(triage: dict) -> dict | None:
    """
    Convert a Stage 2 triage JSON result (from main.py --json) into a
    standard alert dict for dispatch.
    """
    score     = triage.get("ai_risk_score") or triage.get("composite_score", 0)
    risk_lvl  = triage.get("risk_level", "low")
    name      = triage.get("extension_name", "Unknown")
    narrative = triage.get("analyst_narrative", "")
    mitre     = triage.get("mitre_techniques", [])
    iocs      = triage.get("iocs", [])

    if risk_lvl == "low":
        return None   # Don't page on low-risk pre-install results

    return {
        "alert_time":  _now_iso(),
        "rule":        "STAGE2-TRIAGE",
        "severity":    risk_lvl,
        "source":      "pre-install-scan",
        "extension": {
            "id":    triage.get("stage_1_checks", {}).get("publisher", {}).get("extension_id"),
            "title": name,
            "url":   None,
            "type":  "pre-install",
        },
        "detail": {
            "description": (
                f"Pre-install AI triage: {score}/100 {risk_lvl.upper()}. "
                f"IOCs: {'; '.join(iocs[:3])}"
            ),
            "score":           score,
            "analyst_narrative": narrative,
            "iocs":            iocs,
        },
        "mitre": mitre,
    }


# ---------------------------------------------------------------------------
# Alert enrichment — adds context fields before dispatch
# ---------------------------------------------------------------------------

def enrich(alert: dict, escalated: bool) -> dict:
    """
    Add enrichment fields to the alert before sending.
    Modifies a copy — does not change the original.
    """
    enriched = dict(alert)

    # Add hostname of the sensor machine (useful in distributed SOC deployments)
    enriched["sensor_host"] = socket.gethostname()

    # Promote severity if escalated
    if escalated:
        enriched["severity"]    = "critical"
        enriched["escalated"]   = True
        enriched["escalation_note"] = (
            "Auto-escalated: same rule has fired multiple times for this extension."
        )

    # Add a plain-English recommendation
    enriched["recommendation"] = {
        "critical": "BLOCK IMMEDIATELY - initiate Stage 5 remediation playbook",
        "high":     "QUARANTINE extension - escalate to Tier-2 analyst",
        "medium":   "REVIEW - monitor for additional suspicious behaviour",
        "low":      "LOW RISK - continue standard monitoring",
    }.get(enriched.get("severity", "low"), "Review and triage")

    return enriched


# ---------------------------------------------------------------------------
# Parallel dispatch to all enabled destinations
# ---------------------------------------------------------------------------

ADAPTERS = {
    "sentinel":  sentinel.send,
    "splunk":    splunk.send,
    "pagerduty": pagerduty.send,
    "slack":     slack.send,
}


def dispatch(alert: dict, config: dict, dry_run: bool = False) -> dict:
    """
    Send the alert to every enabled adapter, in parallel.
    Returns a dict of {adapter_name: result_dict}.

    If dry_run is True, prints what would be sent but does nothing.
    """
    results = {}
    tasks   = {}

    with ThreadPoolExecutor(max_workers=4) as pool:
        for name, send_fn in ADAPTERS.items():
            adapter_cfg = config.get(name, {})
            if not adapter_cfg.get("enabled", False):
                results[name] = {"ok": True, "skipped": True, "reason": "adapter disabled"}
                continue

            if dry_run:
                results[name] = {"ok": True, "skipped": True, "reason": "dry-run mode"}
                _print_dry_run(name, alert)
                continue

            # Submit dispatch to thread pool so all adapters run in parallel
            tasks[pool.submit(send_fn, alert, adapter_cfg)] = name

        # Collect results as they complete
        for future in as_completed(tasks):
            adapter_name = tasks[future]
            try:
                results[adapter_name] = future.result()
            except Exception as exc:
                results[adapter_name] = {"ok": False, "error": str(exc)}

    return results


def _print_dry_run(name: str, alert: dict):
    ext  = alert.get("extension", {}).get("title", "?")
    rule = alert.get("rule", "?")
    sev  = alert.get("severity", "?")
    print(f"  [DRY RUN] Would send to {name}: [{sev.upper()}] {rule} for {ext}")


# ---------------------------------------------------------------------------
# Dispatch result logging
# ---------------------------------------------------------------------------

def log_dispatch_results(alert: dict, results: dict, verbose: bool = True):
    """Print a summary of which adapters succeeded or failed."""
    if not verbose:
        return

    ext  = alert.get("extension", {}).get("title", "?")
    rule = alert.get("rule", "?")
    sev  = alert.get("severity", "?").upper()
    ts   = alert.get("alert_time", "?")[:19]

    colour = {
        "CRITICAL": "\033[91m\033[1m",
        "HIGH":     "\033[91m",
        "MEDIUM":   "\033[93m",
        "LOW":      "\033[92m",
    }.get(sev, "")
    reset = "\033[0m"

    print(f"\n{colour}[DISPATCH] [{sev}] {rule} - {ext} @ {ts}{reset}")

    for name, result in results.items():
        if result.get("skipped"):
            reason = result.get("reason", "")
            print(f"  {name:12s}  --  {reason}")
        elif result.get("ok"):
            extra = ""
            if result.get("incident_key"):
                extra = f"  (PD key: {result['incident_key']})"
            print(f"  {name:12s}  OK{extra}")
        else:
            print(f"  {name:12s}  FAILED: {result.get('error', '?')}")


# ---------------------------------------------------------------------------
# Main pipeline loop
# ---------------------------------------------------------------------------

def run_pipeline(source: str, config: dict, dry_run: bool, verbose: bool):
    """
    Read JSON from stdin, normalise, deduplicate, enrich, and dispatch.

    Two reading modes:
      "triage"  - reads all of stdin at once and parses as one JSON object
                  (main.py --json outputs pretty-printed, multi-line JSON)
      "monitor" - reads one JSON line at a time
                  (behavioral_monitor.py --output-json emits one object per line)
    """
    dispatch_cfg = config.get("dispatch", {})
    state = AlertState(
        dedup_ttl            = dispatch_cfg.get("dedup_ttl_seconds",    300),
        escalation_threshold = dispatch_cfg.get("escalation_threshold", 3),
    )
    min_severity = dispatch_cfg.get("min_severity", "low")

    if verbose:
        if source == "triage":
            print("[Dispatcher] Reading triage result from stdin...")
        else:
            print("[Dispatcher] Listening for alerts on stdin... (Ctrl+C to stop)")
        print(f"[Dispatcher] Source: {source} | Dry-run: {dry_run}\n")

    # Build an iterator of raw dicts depending on source type
    raw_items = (
        _read_triage_stdin(verbose)
        if source == "triage"
        else _read_monitor_stdin(verbose)
    )

    for raw in raw_items:
        # Normalise to standard alert format
        alert = normalise_alert(raw, source)
        if alert is None:
            continue   # e.g. low-score triage result — skip silently

        # Apply global minimum severity filter
        if not _severity_meets_minimum(alert.get("severity", "low"), min_severity):
            if verbose:
                print(f"[Dispatcher] Skipped (below min_severity): {alert.get('rule')}")
            continue

        # Dedup + escalation check
        should, escalated, reason = state.should_send(alert)
        if not should:
            if verbose:
                print(f"[Dispatcher] Suppressed: {alert.get('rule')} - {reason}")
            continue

        # Enrich before dispatch
        enriched = enrich(alert, escalated)

        if escalated and verbose:
            print(f"\033[91m\033[1m[ESCALATED] {reason}\033[0m")

        # Dispatch to all enabled adapters
        results = dispatch(enriched, config, dry_run=dry_run)

        # Log results
        log_dispatch_results(enriched, results, verbose=verbose)


def _read_triage_stdin(verbose: bool):
    """
    Read stdin and yield parsed dict(s).

    Auto-detects two formats so users don't have to remember which --source to use:
      - JSONL (line-mode): one complete JSON object per line. The format emitted
        by `behavioral_monitor.py --output-json`. Parsed lazily.
      - Pretty JSON (document-mode): one large pretty-printed object spanning
        many lines. The format emitted by `main.py --json`. Parsed all-at-once.

    Heuristic: peek at the first non-whitespace line. If it's `{` (or `[`) on
    its OWN (with no content after), we're in document mode and need to buffer
    the whole thing. Otherwise, we're in line mode.

    The previous implementation read all of stdin into memory unconditionally,
    which would OOM on a long-running behavioral_monitor stream.
    """
    first_line = sys.stdin.readline()
    if not first_line:
        return

    stripped = first_line.strip()
    if not stripped:
        # Skip blank leading lines and re-try
        yield from _read_triage_stdin(verbose)
        return

    # Document mode marker: a line that is JUST "{" or "[" (a pretty-printed
    # JSON object always starts this way; a JSONL line is always a complete
    # object on its own).
    if stripped in ("{", "["):
        # Buffer the rest of stdin and parse the whole thing
        rest = sys.stdin.read()
        try:
            yield json.loads(first_line + rest)
        except json.JSONDecodeError as exc:
            if verbose:
                print(f"[Dispatcher] Failed to parse triage JSON: {exc}")
        return

    # Line mode: first line itself is a complete JSON object. Parse it,
    # then continue reading line-by-line via the standard monitor path.
    try:
        yield json.loads(stripped)
    except json.JSONDecodeError:
        if verbose:
            print(f"[Dispatcher] Skipping non-JSON line: {stripped[:60]}")

    # Stream the remaining lines
    yield from _read_monitor_stdin(verbose)


def _read_monitor_stdin(verbose: bool):
    """
    Read stdin one line at a time and yield parsed dicts.
    Used for the behavioral monitor which emits one JSON object per line.
    """
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            if verbose:
                print(f"[Dispatcher] Skipping non-JSON line: {line[:60]}")


# ---------------------------------------------------------------------------
# Test alert generator
# ---------------------------------------------------------------------------

SAMPLE_ALERT = {
    "alert_time": "2026-05-21T10:30:00+00:00",
    "rule":       "RULE-01",
    "severity":   "critical",
    "extension": {
        "id":    "abcdefghijklmnopqrstuvwxyzabcdef",
        "title": "Nx Console (SIMULATED MALICIOUS)",
        "url":   "chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef/background.js",
        "type":  "service_worker",
    },
    "detail": {
        "description": "Periodic POST to known exfil domain - C2 beacon pattern",
        "url":         "https://malicious-tenant.workers.dev/collect",
        "host":        "malicious-tenant.workers.dev",
        "interval_sec": 61.2,
        "post_count":  4,
        "mitre_note":  "Matches TeamPCP 60-second beacon to *.workers.dev",
    },
    "mitre": ["T1071.001", "T1176"],
}


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="ExtensionGuard Stage 4 - Alert enrichment and dispatch",
        epilog=(
            "Pipe examples:\n"
            "  python behavioral_monitor.py --output-json | python alert_dispatcher.py\n"
            "  python main.py suspicious.crx --json | python alert_dispatcher.py --source triage\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--source",
        choices=["monitor", "triage"],
        default="monitor",
        help="Input format: 'monitor' (behavioral alerts) or 'triage' (main.py --json output)",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        default=None,
        help="Path to config file (default: extguard.conf.json)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="Print what would be dispatched without actually sending",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress human-readable output (useful when output is being parsed)",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Inject a sample alert and dispatch it (for testing adapter config)",
    )
    args = parser.parse_args()

    config  = load_config(args.config)
    verbose = not args.quiet

    if verbose:
        print("\n\033[1m=== ExtensionGuard Stage 4 - Alert Dispatcher ===\033[0m")
        enabled = [k for k in ("sentinel", "splunk", "pagerduty", "slack")
                   if config.get(k, {}).get("enabled")]
        if enabled:
            print(f"Active adapters: {', '.join(enabled)}")
        else:
            print("No adapters enabled. Edit extguard.conf.json to enable destinations.")
            if not args.dry_run and not args.test:
                print("Tip: use --dry-run to test the pipeline without real credentials.")
        print()

    # --- Test mode: inject sample alert ------------------------------------
    if args.test:
        if verbose:
            print("[Test] Injecting sample CRITICAL alert...\n")
        results = dispatch(enrich(SAMPLE_ALERT, False), config, dry_run=args.dry_run)
        log_dispatch_results(SAMPLE_ALERT, results, verbose=True)
        return

    # --- Normal pipeline mode: read from stdin ----------------------------
    try:
        run_pipeline(
            source   = args.source,
            config   = config,
            dry_run  = args.dry_run,
            verbose  = verbose,
        )
    except KeyboardInterrupt:
        if verbose:
            print("\n[Dispatcher] Stopped.")


def _severity_meets_minimum(severity: str, minimum: str) -> bool:
    order = ["low", "medium", "high", "critical"]
    try:
        return order.index(severity) >= order.index(minimum)
    except ValueError:
        return True


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fingerprint(alert: dict) -> str:
    """Compute a deduplication fingerprint from rule + extension_id."""
    rule   = alert.get("rule", "?")
    ext_id = alert.get("extension", {}).get("id") or alert.get("extension", {}).get("title") or "?"
    return f"{rule}:{ext_id}"


if __name__ == "__main__":
    main()
