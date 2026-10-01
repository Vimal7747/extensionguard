# sigma_generator.py - Generate Sigma-format detection rules
#
# Sigma (https://github.com/SigmaHQ/sigma) is the generic SIEM rule format.
# A single Sigma YAML can be converted to:
#   - Splunk SPL (via sigma-cli or pysigma)
#   - Microsoft Sentinel KQL
#   - Elastic / OpenSearch DSL
#   - Chronicle YARA-L
#   - Wazuh, ArcSight, QRadar, ...
#
# Two kinds of rule, depending on which logs actually exist:
#
#   1. PROXY rules - run on ordinary web-proxy logs, no sensor needed.
#      Only one monitor detection is specific enough for proxy logs: POSTs to
#      the exfil / C2 hosting used by extension malware (RULE-01's hosts plus
#      Discord / Telegram webhook URLs). A proxy log can't tell an extension
#      from a browser tab, so it is a MEDIUM-level hunting rule.
#
#      Not translated on purpose: "POST with a long cookie to github.com"
#      (old RULE-02) and "JSON API call to a high-value domain" (old RULE-03)
#      match every logged-in user action in proxy logs - an alert firehose.
#
#   2. SENSOR rules - one per behavioral_monitor rule (RULE-01 ... RULE-07),
#      over the alert events ExtensionGuard itself forwards to the SIEM
#      (extguard-dispatch -> Splunk HEC sourcetype extguard:alert, Sentinel
#      table ExtensionGuard_CL, or any webhook). Storage staging, the
#      management API, dynamic code and cookie reads are only visible inside
#      the browser, so there is no generic log source for them - the old rules
#      pointed at `product: browser` sources that no SIEM receives.
#
# Output is deterministic: stable rule IDs (UUIDv5) and fixed dates, so
# regenerating never churns a rules repo.

import argparse
import sys
import uuid
from pathlib import Path

from extguard.logging_setup import get_logger

log = get_logger(__name__)


# Stable UUIDv5 namespace so the same rule always gets the same ID across
# regenerations. Sigma rule consumers use this ID to track updates.
# Generated once with uuid.uuid4() and hardcoded so re-runs are deterministic.
SIGMA_NAMESPACE = uuid.UUID("d8e6f3a1-7c4f-4b9e-9abc-7e6d5c4b3a21")

AUTHOR = "ExtensionGuard (https://github.com/Vimal7747/extensionguard)"

# Bump RULES_MODIFIED when a rule definition changes (not on every run)
RULES_CREATED = "2026-05-22"
RULES_MODIFIED = "2026-09-29"

# Log source for events forwarded by extguard-dispatch
SENSOR_LOGSOURCE = {"product": "extensionguard", "service": "behavioral_monitor"}


# ---------------------------------------------------------------------------
# Rule definitions - keep these in sync with behavioral_monitor.py
#
# Each rule is a Python dict that becomes one Sigma YAML document. We hand-
# write YAML (small, fixed schema) rather than pulling in PyYAML as a dep.
# ---------------------------------------------------------------------------

# Hosts matched by behavioral_monitor.C2_HOST_PATTERNS
C2_HOST_SUFFIXES = [
    ".workers.dev",
    ".pages.dev",
    ".netlify.app",
    ".vercel.app",
    ".trycloudflare.com",
    ".ngrok.io",
    ".ngrok-free.app",
    ".loca.lt",
    ".glitch.me",
    ".repl.co",
]

PROXY_RULES = [
    {
        "rule_key": "PROXY-EXFIL-HOSTING",
        "source_rule": "RULE-01",
        "title": "POST to Exfiltration-Style Hosting or Chat Webhook",
        "description": (
            "Detects HTTP POSTs to free edge / tunnel hosting (Cloudflare Workers\n"
            "and Pages, ngrok, Netlify, Vercel, ...) and to Discord / Telegram bot\n"
            "webhooks - the exfiltration endpoints used by malicious browser\n"
            "extensions (e.g. the TeamPCP and Cyberhaven-style campaigns).\n"
            "Proxy logs don't show which extension or tab sent the request, so\n"
            "treat hits as leads and confirm with the ExtensionGuard sensor."
        ),
        "references": [
            "https://attack.mitre.org/techniques/T1071/001/",
            "https://attack.mitre.org/techniques/T1567/004/",
            "https://attack.mitre.org/techniques/T1176/",
        ],
        "tags": [
            "attack.command-and-control",
            "attack.t1071.001",
            "attack.exfiltration",
            "attack.t1567.004",
        ],
        "logsource": {"category": "proxy"},
        "detection": {
            "selection_method": {"cs-method": "POST"},
            "selection_hosting": {"cs-host|endswith": C2_HOST_SUFFIXES},
            "selection_webhook": {
                "c-uri|contains": [
                    "discord.com/api/webhooks/",
                    "discordapp.com/api/webhooks/",
                    "api.telegram.org/bot",
                ]
            },
            "condition": "selection_method and (selection_hosting or selection_webhook)",
        },
        "falsepositives": [
            "Developers testing their own Workers / Pages / tunnel deployments",
            "Chat-ops integrations that post to Discord or Telegram",
        ],
        "level": "medium",
    },
]

# One sensor rule per behavioral_monitor rule. `level` is the LOWEST
# severity the monitor emits for that rule; the event's own `severity`
# field carries the escalation (see selection_escalated where it matters).
SENSOR_RULES = [
    {
        "rule_key": "RULE-01",
        "title": "ExtensionGuard: Browser Extension Beaconing to C2 Hosting",
        "description": (
            "The ExtensionGuard sensor saw a browser extension POST to exfil-style\n"
            "hosting (critical when it repeats at a regular interval)."
        ),
        "references": ["https://attack.mitre.org/techniques/T1071/001/"],
        "tags": ["attack.command-and-control", "attack.t1071.001", "attack.t1176"],
        "level": "high",
    },
    {
        "rule_key": "RULE-02",
        "title": "ExtensionGuard: Credential Material Sent by a Browser Extension",
        "description": (
            "A browser extension sent a token, password or cookie dump to a host\n"
            "other than the one it belongs to."
        ),
        "references": ["https://attack.mitre.org/techniques/T1555/003/"],
        "tags": ["attack.credential-access", "attack.t1555.003", "attack.exfiltration"],
        "level": "high",
    },
    {
        "rule_key": "RULE-03",
        "title": "ExtensionGuard: Browser Extension Calling a High-Value API",
        "description": (
            "A browser extension called GitHub / npm / cloud / SSO APIs (high when\n"
            "the request rode the user's session to change something)."
        ),
        "references": ["https://attack.mitre.org/techniques/T1185/"],
        "tags": ["attack.collection", "attack.t1185", "attack.t1530"],
        "level": "medium",
    },
    {
        "rule_key": "RULE-04",
        "title": "ExtensionGuard: Data Staged in Extension Storage",
        "description": (
            "A browser extension wrote a large encoded blob or credential-like\n"
            "data into chrome.storage / localStorage (critical with credentials)."
        ),
        "references": ["https://attack.mitre.org/techniques/T1074/"],
        "tags": ["attack.collection", "attack.t1074", "attack.t1555.003"],
        "level": "high",
    },
    {
        "rule_key": "RULE-05",
        "title": "ExtensionGuard: Extension Disabled or Uninstalled Another Extension",
        "description": (
            "A browser extension used chrome.management to disable or uninstall\n"
            "another extension - typically to silence a security extension."
        ),
        "references": ["https://attack.mitre.org/techniques/T1562/001/"],
        "tags": ["attack.defense-evasion", "attack.t1562.001", "attack.t1176"],
        "level": "critical",
    },
    {
        "rule_key": "RULE-06",
        "title": "ExtensionGuard: Dynamic or Obfuscated Code in a Browser Extension",
        "description": (
            "A browser extension ran code from eval / new Function / remote script\n"
            "injection (high when the code is obfuscated)."
        ),
        "references": ["https://attack.mitre.org/techniques/T1059/007/"],
        "tags": ["attack.execution", "attack.t1059.007", "attack.t1027"],
        "level": "medium",
    },
    {
        "rule_key": "RULE-07",
        "title": "ExtensionGuard: Browser Extension Reading Session Cookies",
        "description": (
            "A browser extension bulk-read cookies (chrome.cookies.getAll) or read\n"
            "document.cookie on a high-value site."
        ),
        "references": ["https://attack.mitre.org/techniques/T1539/"],
        "tags": ["attack.credential-access", "attack.t1539"],
        "level": "medium",
    },
]


def _sensor_rule_to_sigma(rule: dict) -> dict:
    """Fill in the fields every sensor rule shares."""
    return {
        **rule,
        "source_rule": rule["rule_key"],
        "logsource": SENSOR_LOGSOURCE,
        "detection": {
            "selection": {"rule": rule["rule_key"]},
            "condition": "selection",
        },
        "falsepositives": [
            "See the rule description in the ExtensionGuard README; tune with "
            "extension.id allow-lists for extensions you have reviewed",
        ],
    }


RULES = PROXY_RULES + [_sensor_rule_to_sigma(r) for r in SENSOR_RULES]


# ---------------------------------------------------------------------------
# YAML emission
# ---------------------------------------------------------------------------


def _rule_uuid(rule_key: str) -> str:
    """Stable UUIDv5 so repeated runs produce the same id field."""
    return str(uuid.uuid5(SIGMA_NAMESPACE, rule_key))


def _emit_yaml(rule: dict) -> str:
    """
    Emit one Sigma rule as YAML. Hand-rolled emitter (no PyYAML dep) - the
    schema is small and deterministic, so we control the formatting exactly
    the way Sigma consumers expect.
    """
    lines = []
    lines.append(f"title: {_yaml_value(rule['title'])}")
    lines.append(f"id: {_rule_uuid(rule['rule_key'])}")
    lines.append("status: experimental")
    lines.append("description: |")
    for desc_line in rule["description"].split("\n"):
        lines.append(f"  {desc_line}")
    lines.append("references:")
    for ref in rule["references"]:
        lines.append(f"  - {ref}")
    lines.append(f"author: {_yaml_value(AUTHOR)}")
    lines.append(f"date: {RULES_CREATED}")
    lines.append(f"modified: {RULES_MODIFIED}")
    lines.append("tags:")
    for tag in rule["tags"]:
        lines.append(f"  - {tag}")
    lines.append("logsource:")
    for k, v in rule["logsource"].items():
        lines.append(f"  {k}: {v}")
    lines.append("detection:")
    for sel_name, sel_body in rule["detection"].items():
        if sel_name == "condition":
            lines.append(f"  condition: {sel_body}")
            continue
        lines.append(f"  {sel_name}:")
        for field, value in sel_body.items():
            if isinstance(value, list):
                lines.append(f"    {field}:")
                for item in value:
                    lines.append(f"      - {_yaml_value(item)}")
            else:
                lines.append(f"    {field}: {_yaml_value(value)}")
    lines.append("falsepositives:")
    for fp in rule["falsepositives"]:
        lines.append(f"  - {_yaml_value(fp)}")
    lines.append(f"level: {rule['level']}")
    lines.append(f"# Source: ExtensionGuard behavioral_monitor.py {rule['source_rule']}")
    lines.append("")
    return "\n".join(lines)


def _yaml_value(value) -> str:
    """
    Quote a YAML scalar safely. We always quote strings to avoid YAML's
    type-coercion quirks (e.g. "yes" being parsed as True).
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if value is None:
        return "~"
    # Escape backslashes and double-quotes for JSON-style string escaping
    s = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{s}"'


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_all_rules() -> dict:
    """Return a dict mapping rule_key -> Sigma YAML string."""
    return {r["rule_key"]: _emit_yaml(r) for r in RULES}


def write_rules_to(output_dir: Path | str) -> dict:
    """
    Write one .yml file per rule into output_dir.
    Returns a dict mapping rule_key -> output Path.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    written = {}
    for rule in RULES:
        yaml_text = _emit_yaml(rule)
        out_path = output_dir / f"{rule['rule_key'].lower()}.yml"
        out_path.write_text(yaml_text, encoding="utf-8")
        written[rule["rule_key"]] = out_path
        log.info("Wrote Sigma rule %s -> %s", rule["rule_key"], out_path)

    # Also generate a README documenting what's here and how to import
    readme = _README_TEMPLATE.format(
        n=len(RULES), n_proxy=len(PROXY_RULES), n_sensor=len(SENSOR_RULES), modified=RULES_MODIFIED
    )
    readme_path = output_dir / "README.md"
    readme_path.write_text(readme, encoding="utf-8")
    written["README"] = readme_path
    return written


_README_TEMPLATE = """# ExtensionGuard Sigma Rules

Generated by `extguard-sigma` (rule set last modified {modified}). {n} rules:

- {n_proxy} **proxy** rule for standard web-proxy logs - no sensor needed.
- {n_sensor} **sensor** rules over the alert events ExtensionGuard forwards to
  your SIEM with `extguard-dispatch` - one per `extguard-monitor` rule.

## Log sources

| Rules | logsource | What feeds it |
| --- | --- | --- |
| `proxy-exfil-hosting` | `category: proxy` | Corporate web gateway logs (Zscaler, Cloudflare Zero Trust, Squid, ...) |
| `rule-01` ... `rule-07` | `product: extensionguard`, `service: behavioral_monitor` | `extguard-monitor --output-json` piped to `extguard-dispatch` (Splunk HEC / Sentinel / webhook) |

The sensor rules match on the event's `rule` field. Map the log source in
your conversion pipeline:

- **Splunk:** `sourcetype="extguard:alert"`; fields `rule`, `severity`, `extension.id`
- **Sentinel:** table `ExtensionGuard_CL`; fields `rule_s`, `severity_s`, `extension_id_s`

Storage staging, management-API abuse, dynamic code and cookie reads happen
inside the browser. No proxy or endpoint log shows them, which is why those
detections exist only as sensor rules.

## What is deliberately NOT here

Proxy versions of "POST with a session cookie to github.com" and "JSON API
call to a high-value domain". In proxy logs they match every logged-in user,
and a proxy can't tell an extension from a browser tab.

## How to import

### Splunk

```
pip install sigma-cli pysigma-backend-splunk
sigma convert -t splunk -p splunk_windows ./proxy-exfil-hosting.yml
```

### Microsoft Sentinel

```
pip install sigma-cli pysigma-backend-kusto
sigma convert -t kusto -p sentinel ./*.yml > sentinel_rules.kql
```

### Elastic / OpenSearch

```
pip install sigma-cli pysigma-backend-elasticsearch
sigma convert -t elasticsearch -f dsl_lucene ./*.yml
```

## Regenerating

```
extguard-sigma --output sigma/
```

Rule IDs (UUIDv5) and dates are fixed, so regenerating gives byte-identical
files unless a rule changed - SIEM-side tuning survives.
"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate Sigma detection rules from ExtensionGuard's behavioral_monitor rules",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  extguard-sigma --output sigma/\n"
            "  extguard-sigma --output - --rule RULE-05    # print one rule to stdout\n"
        ),
    )
    parser.add_argument(
        "--output",
        default="sigma/",
        help="Directory to write .yml files into, or '-' for stdout (default: ./sigma/)",
    )
    parser.add_argument(
        "--rule",
        default=None,
        help="Emit only one specific rule (e.g. RULE-05 or PROXY-EXFIL-HOSTING). "
        "Default: all rules.",
    )
    args = parser.parse_args(argv)

    by_key = {r["rule_key"]: r for r in RULES}
    keys = [args.rule.upper()] if args.rule else list(by_key)
    unknown = [key for key in keys if key not in by_key]
    if unknown:
        print(f"Unknown rule: {unknown[0]} (known: {', '.join(by_key)})", file=sys.stderr)
        return 2

    if args.output == "-":
        print("---\n".join(_emit_yaml(by_key[key]) for key in keys))
        return 0

    written = write_rules_to(args.output)
    print(f"Wrote {len(written)} files to {args.output}")
    for key, path in sorted(written.items()):
        print(f"  {key:20s}  {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
