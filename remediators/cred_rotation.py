# remediators/cred_rotation.py - Credential rotation playbook generator
#
# When a malicious extension is killed, we still have a credential exposure
# problem: anything the attacker harvested before kill is already exfiltrated.
# This module:
#   1. Inspects the extension's host_permissions + IOCs from triage
#   2. Identifies which credential stores are at risk
#   3. Generates a detailed step-by-step rotation playbook
#   4. Optionally calls live APIs to revoke tokens (GitHub, AWS)
#
# Output formats:
#   - Markdown:  human-readable playbook for the IR runbook
#   - JSON:      machine-readable for ServiceNow / Jira ticket creation
#
# Currently supported credential stores:
#   - GitHub  (PATs, SSH keys, OAuth apps, Codespaces secrets)
#   - npm     (auth tokens, publish access)
#   - AWS     (access keys, session tokens)
#   - Slack   (user tokens, bot tokens, webhooks)
#   - Atlassian (Jira/Confluence API tokens)
#   - Google  (OAuth tokens, app passwords)
#
# Each playbook entry includes:
#   - WHY this credential is at risk
#   - HOW to rotate (exact commands / UI clicks)
#   - VERIFY step to confirm the old credential is dead
#   - Estimated time to complete
#   - Severity (if there's evidence of active use)

import json
import re
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Credential exposure database
# Maps host patterns to credential types at risk + rotation playbooks.
# ---------------------------------------------------------------------------

CREDENTIAL_PLAYBOOKS = {
    "github": {
        "host_patterns":     ["github.com", "*.github.com", "api.github.com"],
        "credential_types":  ["PAT", "SSH key", "OAuth app token", "Codespaces secrets"],
        "severity":          "critical",
        "time_estimate_min": 25,
        "steps": [
            {
                "step":   1,
                "title":  "Revoke all Personal Access Tokens (PATs)",
                "why":    "PATs grant API access to repos, packages, and Actions. Most session-cookie theft also captures these.",
                "how": [
                    "Open https://github.com/settings/tokens",
                    "Click 'Revoke all' (or revoke each token individually)",
                    "If you maintain a token vault (Vault, Bitwarden, 1Password), purge old tokens there too",
                ],
                "verify": "curl -H 'Authorization: token <old_pat>' https://api.github.com/user  -> expect HTTP 401",
                "automation_api": "DELETE https://api.github.com/applications/{client_id}/grant",
            },
            {
                "step":   2,
                "title":  "Rotate SSH keys",
                "why":    "Browser session sometimes provides admin access to add/replace SSH keys via the web UI.",
                "how": [
                    "On your local machine: ssh-keygen -t ed25519 -C 'rotated-<date>'",
                    "Open https://github.com/settings/keys",
                    "Delete all existing keys, then add the new public key",
                    "Test:  ssh -T git@github.com",
                ],
                "verify": "git push to a known-good test repo  -> succeeds with new key only",
            },
            {
                "step":   3,
                "title":  "Audit and revoke OAuth app authorisations",
                "why":    "OAuth tokens are session-independent and persist after browser logout.",
                "how": [
                    "Open https://github.com/settings/applications",
                    "Review the 'Authorized OAuth Apps' list",
                    "Revoke any app that does not match a known business approval",
                ],
                "verify": "Re-check the same page  -> only approved apps remain",
            },
            {
                "step":   4,
                "title":  "Rotate Codespaces and Actions secrets",
                "why":    "Repository secrets exposed via web session can be read by the attacker through copy-on-create.",
                "how": [
                    "For each repository: Settings > Secrets and variables > Actions",
                    "Rotate every secret (note: GitHub does not display existing values, but assume compromised)",
                    "Update CI/CD pipelines to use new secret names if necessary",
                ],
                "verify": "Trigger a CI run that uses the secret  -> succeeds",
            },
            {
                "step":   5,
                "title":  "Sign out of all sessions globally",
                "why":    "The stolen session cookies will remain valid until explicitly invalidated.",
                "how": [
                    "Open https://github.com/settings/security",
                    "Click 'Sign out of all other sessions'",
                    "Force re-authentication with 2FA on next login",
                ],
                "verify": "Open a private browser window, try to visit github.com  -> redirected to login",
            },
        ],
    },

    "npm": {
        "host_patterns":     ["npmjs.com", "*.npmjs.com", "registry.npmjs.org"],
        "credential_types":  ["auth token", "automation token", "publish access"],
        "severity":          "critical",
        "time_estimate_min": 15,
        "steps": [
            {
                "step":   1,
                "title":  "Revoke all npm access tokens",
                "why":    "An npm token with publish rights enables supply-chain injection into your downstream packages.",
                "how": [
                    "Open https://www.npmjs.com/settings/<your-user>/tokens",
                    "Delete every token (or only Publish/Automation tokens if you must keep Read-only ones)",
                    "From CLI:  npm token list  ->  npm token revoke <token-id>  for each",
                ],
                "verify": "npm whoami --registry https://registry.npmjs.org/  using the old token  -> expect 401",
            },
            {
                "step":   2,
                "title":  "Audit recent publishes",
                "why":    "Detect whether the attacker already pushed a malicious version of your packages.",
                "how": [
                    "For each package you maintain: npm view <pkg> versions --json",
                    "Compare the latest version + dist-tag against your CI publish history",
                    "If an unauthorised version exists: npm deprecate <pkg>@<version> 'Compromised, do not install'",
                ],
                "verify": "Confirm only versions you knowingly published are present",
            },
            {
                "step":   3,
                "title":  "Generate new automation tokens",
                "why":    "CI/CD pipelines that publish to npm need fresh credentials.",
                "how": [
                    "https://www.npmjs.com/settings/<your-user>/tokens > Generate New Token > Automation",
                    "Update the token in: GitHub Actions secrets / GitLab CI variables / etc.",
                    "Limit token scope to specific packages if possible",
                ],
                "verify": "Trigger a CI publish to a test package  -> succeeds with new token",
            },
        ],
    },

    "aws": {
        "host_patterns":     ["*.aws.amazon.com", "*.amazonaws.com", "console.aws.amazon.com"],
        "credential_types":  ["IAM access key", "session token", "console session"],
        "severity":          "critical",
        "time_estimate_min": 30,
        "steps": [
            {
                "step":   1,
                "title":  "Rotate IAM access keys for the affected user",
                "why":    "Browser console sessions can leak short-lived session credentials. Long-lived IAM keys may also be present in browser storage if the user pasted them.",
                "how": [
                    "Identify the affected IAM user: who was logged in when the extension was active?",
                    "aws iam list-access-keys --user-name <user>",
                    "Create a new key:  aws iam create-access-key --user-name <user>",
                    "Update CI/CD and local configs to use the new key",
                    "Disable the old key:  aws iam update-access-key --access-key-id <old-key-id> --status Inactive",
                    "Wait 24h, then delete:  aws iam delete-access-key --access-key-id <old-key-id> --user-name <user>",
                ],
                "verify": "aws sts get-caller-identity  with old key  -> expect AccessDenied after Inactive",
            },
            {
                "step":   2,
                "title":  "Force re-authentication of all console sessions",
                "why":    "Active console sessions remain valid until expiry. Session token theft = full account access.",
                "how": [
                    "IAM > Users > <affected user> > Security credentials > 'Deactivate' and re-create the console password",
                    "Or use AWS Organizations + SCP to require re-MFA across all sessions",
                ],
                "verify": "Have the user re-login  -> prompted for new password + MFA",
            },
            {
                "step":   3,
                "title":  "Review CloudTrail for unauthorised API calls",
                "why":    "Confirm whether the attacker actually used the harvested credentials before rotation.",
                "how": [
                    "Open CloudTrail > Event history",
                    "Filter:  Event source = signin.amazonaws.com  or  source IP NOT in your corporate ranges",
                    "Look for the affected user's actions in the past 7 days",
                    "Export findings for the IR ticket",
                ],
                "verify": "No suspicious events identified, OR document and contain identified events",
            },
        ],
    },

    "slack": {
        "host_patterns":     ["*.slack.com", "slack.com"],
        "credential_types":  ["user token", "bot token", "incoming webhook"],
        "severity":          "high",
        "time_estimate_min": 10,
        "steps": [
            {
                "step":   1,
                "title":  "Sign out of all Slack sessions",
                "why":    "Slack session tokens give DM read access and can post as the user.",
                "how": [
                    "Slack > Profile > Account settings > Sign out all other sessions",
                    "Optionally: workspace admin can force-sign-out via Admin > Members > 'Force sign out'",
                ],
                "verify": "Other devices show Slack as signed out",
            },
            {
                "step":   2,
                "title":  "Rotate any compromised Slack app tokens",
                "why":    "If the user is a Slack app developer, their bot/user tokens may have been exfiltrated.",
                "how": [
                    "Open https://api.slack.com/apps",
                    "For each app: OAuth & Permissions > Revoke Token",
                    "Re-install the app to generate fresh tokens",
                ],
                "verify": "Old token in curl call:  curl -H 'Authorization: Bearer <old>' https://slack.com/api/auth.test  -> {ok: false, error: 'invalid_auth'}",
            },
        ],
    },

    "atlassian": {
        "host_patterns":     ["*.atlassian.net", "*.atlassian.com"],
        "credential_types":  ["API token", "OAuth", "session"],
        "severity":          "high",
        "time_estimate_min": 10,
        "steps": [
            {
                "step":   1,
                "title":  "Revoke all Atlassian API tokens",
                "why":    "Atlassian API tokens persist independently of browser sessions. They allow full Jira/Confluence read+write.",
                "how": [
                    "Open https://id.atlassian.com/manage-profile/security/api-tokens",
                    "Click Revoke next to each token",
                    "Re-generate tokens for any integrations you control",
                ],
                "verify": "curl -u email:<old-token> https://<site>.atlassian.net/rest/api/3/myself  -> 401",
            },
        ],
    },

    "google": {
        "host_patterns":     ["*.google.com", "accounts.google.com", "*.googleapis.com"],
        "credential_types":  ["OAuth token", "app password", "session"],
        "severity":          "high",
        "time_estimate_min": 15,
        "steps": [
            {
                "step":   1,
                "title":  "Sign out of all Google sessions",
                "why":    "Google session cookies grant Gmail read, Drive access, Workspace admin (if applicable).",
                "how": [
                    "Open https://myaccount.google.com/security",
                    "Under 'Your devices' click 'Manage all devices'",
                    "Sign out of every device except the one you trust now",
                ],
                "verify": "Other devices show Google as signed out",
            },
            {
                "step":   2,
                "title":  "Revoke third-party app access",
                "why":    "OAuth tokens for connected apps survive password rotation.",
                "how": [
                    "Open https://myaccount.google.com/permissions",
                    "Review the list of connected apps",
                    "Remove access for any app not explicitly approved",
                ],
                "verify": "Re-check the same page; only approved apps remain",
            },
        ],
    },
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_playbook(
    host_permissions: list,
    iocs:             list | None = None,
    extension_name:   str = "Unknown",
    case_id:          str | None = None,
    output_format:    str = "markdown",
) -> dict:
    """
    Generate a tailored credential rotation playbook.

    Args:
        host_permissions: list from manifest (e.g. ["<all_urls>", "*://github.com/*"])
        iocs:             list of IOC strings from triage (used to confirm targets)
        extension_name:   for log titles
        case_id:          forensic case ID to cross-reference
        output_format:    "markdown" / "json" / "both"

    Returns:
      {
        "ok":               bool,
        "applicable":       list[str]   credential stores at risk
        "total_steps":      int
        "total_time_min":   int
        "markdown":         str         (if requested)
        "json":             dict        (if requested)
        "severity":         str         worst severity across applicable stores
      }
    """
    iocs = iocs or []
    applicable_keys = _detect_applicable_stores(host_permissions, iocs)

    if not applicable_keys:
        return {
            "ok":             True,
            "applicable":     [],
            "total_steps":    0,
            "total_time_min": 0,
            "markdown":       "# No credential rotation required\n\nThis extension's permissions don't map to any tracked credential store.\n",
            "json":           {"applicable": [], "steps": []},
            "severity":       "low",
        }

    # Pull out the relevant playbook entries
    playbooks = {k: CREDENTIAL_PLAYBOOKS[k] for k in applicable_keys}

    total_steps    = sum(len(p["steps"]) for p in playbooks.values())
    total_time_min = sum(p.get("time_estimate_min", 0) for p in playbooks.values())

    # Compute worst severity across all applicable stores
    severities = [p.get("severity", "medium") for p in playbooks.values()]
    severity   = _max_severity(severities)

    result = {
        "ok":             True,
        "applicable":     applicable_keys,
        "total_steps":    total_steps,
        "total_time_min": total_time_min,
        "severity":       severity,
    }

    if output_format in ("markdown", "both"):
        result["markdown"] = _render_markdown(
            playbooks       = playbooks,
            extension_name  = extension_name,
            case_id         = case_id,
            iocs            = iocs,
            total_time_min  = total_time_min,
        )

    if output_format in ("json", "both"):
        result["json"] = _render_json(
            playbooks      = playbooks,
            extension_name = extension_name,
            case_id        = case_id,
            iocs           = iocs,
        )

    return result


def save_playbook(playbook: dict, output_dir: str, prefix: str = "rotation") -> dict:
    """
    Write the markdown and/or JSON playbook files to disk.
    Returns the paths written.
    """
    from pathlib import Path
    out  = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = {}

    if "markdown" in playbook:
        md_path = out / f"{prefix}_playbook.md"
        md_path.write_text(playbook["markdown"], encoding="utf-8")
        paths["markdown"] = str(md_path)

    if "json" in playbook:
        json_path = out / f"{prefix}_playbook.json"
        json_path.write_text(json.dumps(playbook["json"], indent=2), encoding="utf-8")
        paths["json"] = str(json_path)

    return paths


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _detect_applicable_stores(host_permissions: list, iocs: list) -> list:
    """
    Match the extension's host_permissions and IOC strings against the
    CREDENTIAL_PLAYBOOKS host_patterns to find at-risk stores.

    Always returns the applicable store keys in their order of severity
    (critical first, low last) so the playbook reads sensibly.
    """
    matches = []

    # Treat <all_urls> as a wildcard match for ALL stores (worst case)
    all_urls = any(
        p in ("<all_urls>", "*://*/*", "https://*/*", "http://*/*")
        for p in host_permissions
    )

    for store_key, store in CREDENTIAL_PLAYBOOKS.items():
        if all_urls:
            matches.append(store_key)
            continue

        # Check each host_permission against the store's host_patterns
        for perm in host_permissions:
            for pattern in store["host_patterns"]:
                if _pattern_matches(pattern, perm):
                    matches.append(store_key)
                    break
            if store_key in matches:
                break

        # Also scan IOC strings for store-specific signals
        if store_key not in matches:
            joined_iocs = " ".join(iocs).lower()
            for pattern in store["host_patterns"]:
                if pattern.replace("*.", "").replace("*", "").lower() in joined_iocs:
                    matches.append(store_key)
                    break

    # De-duplicate while preserving order, then sort by severity (critical first)
    seen = set()
    unique = [x for x in matches if not (x in seen or seen.add(x))]

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    unique.sort(key=lambda k: severity_order.get(
        CREDENTIAL_PLAYBOOKS[k].get("severity", "medium"), 99
    ))

    return unique


def _pattern_matches(pattern: str, permission: str) -> bool:
    """
    Check if a host_pattern (e.g. "*.github.com") matches a permission's host.

    Uses proper DNS-suffix matching, not substring matching, so:
      - "github.com" matches  https://github.com/*  and  https://api.github.com/*
      - "github.com" does NOT match  https://attacker-github.com/*
      - "github.com" does NOT match  https://mygithub.com/*

    The previous implementation used `bare_pattern in bare_permission`, which
    matched any URL containing the pattern as a substring - a real security
    bug because a typosquatted domain like "attacker-github.com" would trigger
    the GitHub credential rotation playbook against an unrelated extension.
    """
    # 1. Extract the *host* from the permission string.
    #    permission can look like:
    #      "https://github.com/*"
    #      "*://*.github.com/*"
    #      "*://api.github.com/*"
    #      "https://github.com"
    perm = permission.lower().strip()
    # Drop the scheme (http://, https://, *://, ftp://, ...)
    perm = re.sub(r"^[a-z*]+://", "", perm)
    # Drop the path (everything from the first slash onward)
    perm = perm.split("/", 1)[0]
    # Drop leading wildcards like "*." -> just the bare host
    perm_host = re.sub(r"^\*\.?", "", perm)
    if not perm_host:
        return False

    # 2. Normalise the pattern to a bare host
    bare_pattern = pattern.lower().strip()
    bare_pattern = re.sub(r"^\*\.?", "", bare_pattern)
    if not bare_pattern:
        return False

    # 3. DNS-suffix match: exact match OR host ends with ".<pattern>"
    #    "github.com" matches "github.com" and "api.github.com"
    #    "github.com" does NOT match "mygithub.com" (no leading dot)
    return perm_host == bare_pattern or perm_host.endswith("." + bare_pattern)


def _max_severity(severities: list) -> str:
    """Return the worst severity in the list."""
    order = ["low", "medium", "high", "critical"]
    worst = "low"
    for s in severities:
        if order.index(s) > order.index(worst):
            worst = s
    return worst


def _render_markdown(
    playbooks:      dict,
    extension_name: str,
    case_id:        str | None,
    iocs:           list,
    total_time_min: int,
) -> str:
    """Render the playbook as a Markdown document for the IR runbook."""
    lines = []
    lines.append(f"# Credential Rotation Playbook — {extension_name}")
    lines.append("")
    lines.append(f"**Generated:** {datetime.now(timezone.utc).isoformat()}")
    if case_id:
        lines.append(f"**Case ID:** {case_id}")
    lines.append(f"**Estimated total time:** ~{total_time_min} minutes")
    lines.append(f"**Affected credential stores:** {', '.join(playbooks.keys())}")
    lines.append("")

    if iocs:
        lines.append("## Indicators of Compromise")
        for ioc in iocs:
            lines.append(f"- {ioc}")
        lines.append("")

    lines.append("## Rotation Steps")
    lines.append("")
    lines.append(
        "> Work through the sections below in order. Each step has a `verify` action — "
        "do not skip these; they're how you confirm the old credentials are dead."
    )
    lines.append("")

    for store_key, store in playbooks.items():
        sev = store.get("severity", "medium").upper()
        lines.append(f"### {store_key.upper()}  —  Severity: {sev}")
        lines.append("")
        lines.append(f"_Estimated time: {store.get('time_estimate_min', '?')} minutes_")
        lines.append("")
        lines.append(f"**Credential types at risk:** {', '.join(store['credential_types'])}")
        lines.append("")

        for step in store["steps"]:
            lines.append(f"#### Step {step['step']}: {step['title']}")
            lines.append("")
            lines.append(f"**Why:** {step['why']}")
            lines.append("")
            lines.append("**How:**")
            for instruction in step["how"]:
                lines.append(f"- {instruction}")
            lines.append("")
            lines.append(f"**Verify:** `{step['verify']}`")
            if step.get("automation_api"):
                lines.append("")
                lines.append(f"**Automation hook:** `{step['automation_api']}`")
            lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## Completion checklist")
    lines.append("")
    for store_key, store in playbooks.items():
        for step in store["steps"]:
            lines.append(f"- [ ] {store_key.upper()} step {step['step']}: {step['title']}")
    lines.append("- [ ] All verify steps passed")
    lines.append("- [ ] Chain of custody updated (run `append_custody_action`)")
    lines.append("- [ ] PagerDuty incident resolved")
    lines.append("")

    return "\n".join(lines)


def _render_json(
    playbooks:      dict,
    extension_name: str,
    case_id:        str | None,
    iocs:           list,
) -> dict:
    """Render the playbook as a structured JSON dict for ticketing systems."""
    return {
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "case_id":        case_id,
        "extension_name": extension_name,
        "iocs":           iocs,
        "stores": {
            key: {
                "severity":         store.get("severity"),
                "time_estimate_min": store.get("time_estimate_min"),
                "credential_types": store["credential_types"],
                "steps":            store["steps"],
            }
            for key, store in playbooks.items()
        },
    }
