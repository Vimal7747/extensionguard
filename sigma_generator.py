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
# We translate our 6 behavioral_monitor rules (RULE-01 ... RULE-06) into
# Sigma so a SOC team that already has SIEM logs from extensions / proxies
# can run the same detections natively, without needing to run
# behavioral_monitor.py as a sensor.
#
# Each rule we emit targets the `category: proxy` log source (which most
# SIEMs already feed from their corporate web gateway) and the
# `category: webserver` source where it fits.
#
# Caveat: not every behavioral_monitor rule has a direct Sigma equivalent.
# RULE-04 (storage staging) requires browser-side telemetry that a SIEM
# usually doesn't have - we still emit the rule but the SOC team has to
# wire up a custom log source.

import argparse
import sys
import uuid
from datetime import date
from pathlib import Path

from logging_setup import get_logger

log = get_logger(__name__)


# Stable UUIDv5 namespace so the same rule always gets the same ID across
# regenerations. Sigma rule consumers use this ID to track updates.
# Generated once with uuid.uuid4() and hardcoded so re-runs are deterministic.
SIGMA_NAMESPACE = uuid.UUID("d8e6f3a1-7c4f-4b9e-9abc-7e6d5c4b3a21")


# ---------------------------------------------------------------------------
# Rule definitions - keep these in sync with behavioral_monitor.py
#
# Each rule is a Python dict that becomes one Sigma YAML document. We hand-
# write YAML (small, fixed schema) rather than pulling in PyYAML as a dep.
# ---------------------------------------------------------------------------

RULES = [
    {
        "rule_key":    "RULE-01",
        "title":       "Browser Extension C2 Beacon to Workers/Pages Edge",
        "description": (
            "Detects browser-extension-initiated POST requests to "
            "Cloudflare Workers / Pages / ngrok / netlify domains, the "
            "exfil-hosting pattern used by the TeamPCP supply-chain attack."
        ),
        "references": [
            "https://attack.mitre.org/techniques/T1071/001/",
            "https://attack.mitre.org/techniques/T1176/",
        ],
        "tags": ["attack.command_and_control", "attack.t1071.001", "attack.t1176"],
        "logsource": {"category": "proxy"},
        "detection": {
            "selection": {
                "cs-method": "POST",
                "c-uri-host|endswith": [
                    ".workers.dev", ".pages.dev", ".netlify.app",
                    ".vercel.app", ".trycloudflare.com", ".ngrok.io",
                ],
                "c-uri-extension": "",   # No file extension - API call shape
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Legitimate developer tools that intentionally use Cloudflare edge hosting",
            "Cloud-native staging environments before formal DNS",
        ],
        "level": "high",
    },

    {
        "rule_key":    "RULE-02",
        "title":       "Session Cookie POSTed to High-Value Auth Domain",
        "description": (
            "Detects POST requests carrying a long session-token cookie to "
            "github.com, npmjs.com, *.atlassian.net, slack.com, or "
            "aws.amazon.com. Compatible with the TeamPCP credential-harvest TTP."
        ),
        "references": [
            "https://attack.mitre.org/techniques/T1555/003/",
            "https://attack.mitre.org/techniques/T1176/",
        ],
        "tags": ["attack.credential_access", "attack.t1555.003", "attack.t1176"],
        "logsource": {"category": "proxy"},
        "detection": {
            "selection": {
                "cs-method": "POST",
                "c-uri-host|contains": [
                    "github.com", "npmjs.com", "atlassian.net",
                    "slack.com", "aws.amazon.com",
                ],
                "cs(Cookie)|re": ".{40,}",   # 40+ chars of cookie data
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Legitimate API integrations that re-use the user's session cookie",
            "CI/CD agents using PAT-based auth (no session cookie)",
        ],
        "level": "high",
    },

    {
        "rule_key":    "RULE-03",
        "title":       "Browser Extension API Call to High-Value Domain",
        "description": (
            "Detects GET-with-JSON-Accept or POST requests from a browser "
            "extension context to GitHub/npm/AWS/Slack/Atlassian/Google APIs. "
            "Lower-severity signal complementing RULE-01 and RULE-02."
        ),
        "references": [
            "https://attack.mitre.org/techniques/T1530/",
            "https://attack.mitre.org/techniques/T1555/003/",
        ],
        "tags": ["attack.collection", "attack.t1530", "attack.t1555.003"],
        "logsource": {"category": "proxy"},
        "detection": {
            "selection_api": {
                "c-uri-host|contains": [
                    "github.com", "npmjs.com", "gitlab.com",
                    "atlassian.net", "slack.com", "aws.amazon.com",
                    "accounts.google.com", "login.microsoftonline.com",
                ],
                "cs(Accept)|contains": "json",
            },
            "selection_post": {
                "cs-method": "POST",
                "c-uri-host|contains": [
                    "github.com", "npmjs.com", "atlassian.net",
                    "slack.com", "aws.amazon.com",
                ],
            },
            "condition": "selection_api or selection_post",
        },
        "falsepositives": [
            "Browser-based IDEs and dashboards that call high-value APIs",
            "Single-page apps with the same auth-domain pattern",
        ],
        "level": "medium",
    },

    {
        "rule_key":    "RULE-04",
        "title":       "Large Base64 Blob Staged to Browser Storage",
        "description": (
            "Detects browser localStorage / IndexedDB writes containing a "
            "100+ char base64 payload, the TeamPCP credential-staging pattern "
            "(harvested cookies are JSON-encoded and base64-wrapped under "
            "chrome.storage.local key 's_cache' before exfil)."
        ),
        "references": [
            "https://attack.mitre.org/techniques/T1074/",
            "https://attack.mitre.org/techniques/T1555/003/",
        ],
        "tags": ["attack.collection", "attack.t1074", "attack.t1555.003"],
        "logsource": {"product": "browser", "category": "storage"},
        "detection": {
            "selection": {
                "storage_value|re": "[A-Za-z0-9+/]{100,}={0,2}",
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Web apps caching base64-encoded images / fonts in IndexedDB",
            "PWA service workers persisting binary blobs",
        ],
        "level": "medium",
    },

    {
        "rule_key":    "RULE-05",
        "title":       "Browser Extension Disabling Other Extensions",
        "description": (
            "Detects use of chrome.management.setEnabled() to disable another "
            "extension - common lateral-movement technique to silence "
            "competing AV / security extensions."
        ),
        "references": [
            "https://attack.mitre.org/techniques/T1176/",
        ],
        "tags": ["attack.persistence", "attack.t1176"],
        "logsource": {"product": "browser", "category": "extension_api"},
        "detection": {
            "selection": {
                "api_call": "chrome.management.setEnabled",
                "args|contains": "false",
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Extension manager utilities that legitimately toggle others",
            "Browser sync tools",
        ],
        "level": "high",
    },

    {
        "rule_key":    "RULE-06",
        "title":       "Obfuscated eval() Chain in Browser Extension",
        "description": (
            "Detects eval(atob(...)), eval(String.fromCharCode(...)), or "
            "eval(unescape(...)) patterns in extension JS console output. "
            "Signature of the Shai-Hulud extension malware family."
        ),
        "references": [
            "https://attack.mitre.org/techniques/T1059/007/",
        ],
        "tags": ["attack.execution", "attack.t1059.007"],
        "logsource": {"product": "browser", "category": "console"},
        "detection": {
            "selection": {
                "message|re": r"eval\s*\(\s*(atob|String\.fromCharCode|unescape)",
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Legitimate JS minifiers / packers that wrap output in eval(atob(...))",
            "Browser DevTools console exploration by developers",
        ],
        "level": "high",
    },
]


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
    lines.append(f"title: {rule['title']}")
    lines.append(f"id: {_rule_uuid(rule['rule_key'])}")
    lines.append("status: experimental")
    lines.append("description: |")
    for desc_line in rule["description"].split("\n"):
        lines.append(f"  {desc_line}")
    lines.append("references:")
    for ref in rule["references"]:
        lines.append(f"  - {ref}")
    lines.append("author: ExtensionGuard <https://github.com/example/extensionguard>")
    lines.append(f"date: {date.today().isoformat()}")
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
        lines.append(f"  - {fp}")
    lines.append(f"level: {rule['level']}")
    lines.append(f"# Source: ExtensionGuard behavioral_monitor.py {rule['rule_key']}")
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
    readme = _README_TEMPLATE.format(n=len(RULES), date=date.today().isoformat())
    readme_path = output_dir / "README.md"
    readme_path.write_text(readme, encoding="utf-8")
    written["README"] = readme_path
    return written


_README_TEMPLATE = """# ExtensionGuard Sigma Rules

Auto-generated by `extguard-sigma` on {date}. Contains {n} detection rules
translated from `behavioral_monitor.py` for use in any SIEM that supports
Sigma.

## How to import

### Splunk

```
pip install sigma-cli pysigma-backend-splunk
sigma convert -t splunk -p splunk_windows ./rule-01.yml
```

Drop the resulting SPL into a Splunk saved search.

### Microsoft Sentinel

```
pip install sigma-cli pysigma-backend-kusto
sigma convert -t kusto -p sentinel ./*.yml > sentinel_rules.kql
```

Then import the KQL through Sentinel > Analytics > Create > Scheduled query rule.

### Elastic / OpenSearch

```
pip install sigma-cli pysigma-backend-elasticsearch
sigma convert -t elasticsearch -f dsl_lucene ./*.yml
```

### Chronicle / Google SecOps

```
pip install sigma-cli pysigma-backend-chronicle
sigma convert -t chronicle ./*.yml
```

## Log sources

The rules target three log-source categories - make sure your SIEM is
ingesting at least one:

| Category | Source | Used by |
| --- | --- | --- |
| `proxy` | Corporate web gateway logs (Zscaler, Cloudflare Zero Trust, etc.) | RULE-01, RULE-02, RULE-03 |
| `browser/storage` | Browser-side storage telemetry (custom; rare) | RULE-04 |
| `browser/extension_api` | Chrome management-API telemetry (custom) | RULE-05 |
| `browser/console` | Browser console messages (custom; e.g. devtools log shipper) | RULE-06 |

RULE-01 through RULE-03 are the most broadly deployable - they work off
standard proxy logs that most SOC teams already have.

## Regenerating

```
extguard-sigma --output sigma/
```

The rule IDs are stable across regenerations (UUIDv5), so updating a rule
won't break upstream tracking.

## Differences from behavioral_monitor.py

- The Python sensor runs against live Chrome DevTools Protocol events,
  giving it access to per-extension context that proxy logs lack. The Sigma
  rules can't tell WHICH extension issued a request, only that one did.
- Sigma rules are stateless. The Python sensor tracks beacon frequency
  (n POSTs in 60s); the Sigma version fires on every individual POST and
  relies on SIEM-side throttling / grouping.
- Sigma rule IDs are stable across runs (UUIDv5) so SIEM-side tuning
  survives regeneration.
"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate Sigma detection rules from ExtensionGuard's behavioral_monitor rules",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  extguard-sigma --output sigma/\n"
            "  extguard-sigma --output - --rule RULE-01    # print one rule to stdout\n"
        ),
    )
    parser.add_argument(
        "--output", default="sigma/",
        help="Directory to write .yml files into, or '-' for stdout (default: ./sigma/)",
    )
    parser.add_argument(
        "--rule", default=None,
        help="Emit only one specific rule (e.g. RULE-01). Default: all rules.",
    )
    args = parser.parse_args()

    keys = [args.rule] if args.rule else [r["rule_key"] for r in RULES]
    for key in keys:
        rule = next((r for r in RULES if r["rule_key"] == key), None)
        if not rule:
            print(f"Unknown rule: {key}", file=sys.stderr)
            sys.exit(2)

    if args.output == "-":
        for key in keys:
            rule = next(r for r in RULES if r["rule_key"] == key)
            print(_emit_yaml(rule))
            print("---")
        return

    written = write_rules_to(args.output)
    print(f"Wrote {len(written)} files to {args.output}")
    for key, path in sorted(written.items()):
        print(f"  {key:8s}  {path}")


if __name__ == "__main__":
    main()
