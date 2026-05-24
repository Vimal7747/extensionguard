# ExtensionGuard

> Defensive SOC tooling for detecting, alerting on, and remediating malicious browser-extension supply-chain attacks.

ExtensionGuard is a Python pipeline that catches malicious Chrome extensions
before they exfiltrate credentials. It's built for blue-team / SOC use,
inspired by the May 2026 TeamPCP supply-chain breach — a compromised npm
publisher account that pushed a malicious update to the legitimate Nx Console
extension and harvested GitHub / npm session tokens from every install.

What's in the box:

- **Pre-install scan** — CRX parser, TTP-calibrated permission scorer,
  publisher legitimacy check, OSV + VirusTotal hash lookup, version-velocity
  detection.
- **AI triage** — Claude Sonnet 4.6 with cached threat-intel library and
  forced structured output.
- **Runtime monitor** — Chrome DevTools Protocol sensor with 6 detection
  rules covering C2 beacons, cookie exfil, debugger abuse, etc.
- **SOC alert dispatch** — parallel fan-out to Sentinel, Splunk, PagerDuty,
  and Slack with deduplication, escalation, and retry/backoff.
- **Remediation** — forensic preservation with hash-based chain of custody,
  cross-platform extension blocklist (registry / policy / Workspace SDK),
  credential-rotation playbook generator.
- **Analyst dashboard** — Flask web UI to browse quarantine cases, verify
  evidence integrity, and approve / reject remediation actions.
- **Live threat-intel updates** — GitHub webhook ingestor with HMAC-SHA256
  signature verification, keeps the TTP library in sync from a central repo.
- **SIEM portability** — Sigma rule generator translates the runtime
  detections into format consumable by Splunk, Sentinel, Elastic, and
  Chronicle.

## Status

| Property | Value |
| --- | --- |
| Version | **0.2.0** |
| Tests | **503 passing** (`pytest`) |
| Benchmarks | **13** in `tests/benchmarks/` (see [PERFORMANCE.md](PERFORMANCE.md)) |
| Lint | **0 findings** (`ruff check`) |
| Python | 3.10 – 3.13 |
| Runtime deps | `anthropic`, `requests`, `websockets`, `flask` |
| Optional deps | `[dev]`, `[workspace]` |
| Console scripts | 7 (see below) |

Companion docs:

- [CHANGELOG.md](CHANGELOG.md) — what changed between releases
- [THREAT_MODEL.md](THREAT_MODEL.md) — trust boundaries + 10 catalogued threats
- [PERFORMANCE.md](PERFORMANCE.md) — measured baselines for every hot path
- [RELEASING.md](RELEASING.md) — release checklist for maintainers

---

## Quickstart

### From source

```powershell
git clone https://github.com/example/extensionguard.git
cd extensionguard
pip install -e ".[dev]"
```

### From PyPI (once published)

```powershell
pip install extensionguard
```

### From Docker

```powershell
docker compose up -d                  # full SOC deployment
# OR
docker run -p 5000:5000 extensionguard:0.2.0 extguard-dashboard --host 0.0.0.0
```

### Run a scan

```powershell
# Scan a sample malicious manifest (no API key needed)
extguard test_fixtures/teamccp_sim_manifest.json --no-ai --offline

# With Claude AI triage
$env:ANTHROPIC_API_KEY = "sk-ant-..."
extguard test_fixtures/teamccp_sim_manifest.json

# Machine-readable for SIEM / webhook ingestion
extguard test_fixtures/teamccp_sim_manifest.json --json

# Full incident-response pipeline against a triage result
extguard test_fixtures/teamccp_sim_manifest.json --no-ai --offline --json > triage.json
extguard-remediate --from-triage triage.json --dry-run --no-pd-resolve

# Browse quarantine cases, verify integrity, approve remediations
extguard-dashboard            # http://127.0.0.1:5000

# Pull latest threat intel from a GitHub repo
extguard-ttp-sync --owner myorg --repo extguard-ttp

# Export detections as Sigma rules for Splunk / Sentinel / Elastic
extguard-sigma --output sigma/
```

Expected output for the malicious test fixture:

```
Stage 1 composite: 100/100 - CRITICAL
  Flagged: webRequestBlocking, cookies, webRequest, tabs, history, storage, <all_urls>
  [!] Session token harvesting combo - matches TeamPCP TTP (T1555.003)
  [!] Traffic intercept + cookie theft pipeline (T1071 + T1555)
  [!] Persistent background page - always-on monitoring
  Recommendation: BLOCK IMMEDIATELY - initiate remediation playbook
```

---

## Architecture

Five loosely-coupled stages plus the dashboard. Each stage can run
standalone — you don't need a SOC platform to use just the pre-install
scanner.

```
+----------------------------------------------------------------+
| Stage 1: Pre-install detection           (CLI: extguard)       |
|   crx_parser           - parses CRX2/CRX3/zip/manifest.json    |
|   permission_scorer    - TTP-calibrated weight + combo rules   |
|   publisher_checker    - extension ID + Web Store cross-check  |
|   osv_lookup           - SHA-256 hash + npm dep vuln scan      |
|   virustotal_lookup    - multi-engine consensus (optional)     |
|   update_velocity      - semver jump detection vs history      |
+----------------------------------------------------------------+
                              v  (composite score + manifest)
+----------------------------------------------------------------+
| Stage 2: AI triage                       (claude_triage.py)    |
|   - Loads threat-intel from ttp_library/ on disk               |
|   - Prompt caching: TTP library reused per 5-min cache window  |
|   - Forced tool_use: Claude returns structured JSON, not prose |
|   - Prompt-injection mitigation on every manifest field        |
+----------------------------------------------------------------+
                              v  (triage JSON)
+----------------------------------------------------------------+
| Stage 3: Runtime behavioral monitor (CLI: extguard-monitor)    |
|   - Connects to Chrome's CDP (--remote-debugging-port=9222)    |
|   - Six detection rules:                                       |
|     RULE-01  C2 beacon: periodic POST to *.workers.dev         |
|     RULE-02  Session-cookie exfil to non-first-party host      |
|     RULE-03  Extension API call to high-value auth domain      |
|     RULE-04  Large base64 blob staged to localStorage          |
|     RULE-05  Extension disables another via management API     |
|     RULE-06  Obfuscated eval(atob(...)) chains                 |
|   - Emits JSON alert lines on stdout                           |
+----------------------------------------------------------------+
                              v  (alert JSON lines)
+----------------------------------------------------------------+
| Stage 4: SOC alert dispatch       (CLI: extguard-dispatch)     |
|   - Dedup (300s TTL by fingerprint = rule + extension_id)      |
|   - Escalation (severity auto-promoted on Nth re-fire)         |
|   - Enrichment (sensor host, recommendation, MITRE)            |
|   - Parallel fan-out:                                          |
|       Microsoft Sentinel (HMAC-SHA256 LAW API)                 |
|       Splunk HTTP Event Collector                              |
|       PagerDuty Events API v2                                  |
|       Slack Incoming Webhook                                   |
|   - Retry/backoff (3 attempts, 1s/2s/4s + jitter) on 5xx/429   |
+----------------------------------------------------------------+
                              v  (paged analyst confirms threat)
+----------------------------------------------------------------+
| Stage 5: Remediation               (CLI: extguard-remediate)   |
|   1. PRESERVE  -  quarantine CRX + chain of custody + SHA-256  |
|   2. KILL      -  add extension ID to Chrome ExtensionInstall- |
|                   Blocklist: HKLM registry (Windows),          |
|                   /etc/opt/chrome/policies (Linux),            |
|                   plist (macOS), Chrome Policy API (Workspace) |
|   3. PLAYBOOK  -  generate credential-rotation runbook for     |
|                   each at-risk store (GitHub, npm, AWS, Slack, |
|                   Atlassian, Google)                           |
|   4. RESOLVE   -  auto-close the PagerDuty incident            |
|   5. REPORT    -  console summary + verify command             |
+----------------------------------------------------------------+

  Sitting alongside all of the above:
+----------------------------------------------------------------+
| Analyst dashboard           (CLI: extguard-dashboard)          |
|   - Browses quarantine cases + verifies SHA-256 integrity      |
|   - Tails recent alerts                                        |
|   - Approve/reject queue (writes to a file the remediator      |
|     CLI watches; never directly modifies system state)         |
|   - /webhook/github receives TTP pushes (HMAC-SHA256 verified) |
+----------------------------------------------------------------+
```

---

## Console scripts

After `pip install`, seven CLIs are available:

| Command | Purpose |
| --- | --- |
| `extguard` | Stage 1 pre-install scanner |
| `extguard-monitor` | Stage 3 runtime behavioural monitor (CDP client) |
| `extguard-dispatch` | Stage 4 alert dispatcher (reads JSONL from stdin) |
| `extguard-remediate` | Stage 5 incident-response orchestrator |
| `extguard-dashboard` | Flask analyst UI on 127.0.0.1:5000 |
| `extguard-ttp-sync` | Manual TTP-library pull from a GitHub repo |
| `extguard-sigma` | Export detection rules as Sigma YAML for SIEM import |

---

## Configuration

A single config file controls all destinations and tunables. Copy the
template and edit:

```powershell
copy extguard.conf.json my-config.json
extguard-dispatch --config my-config.json --source triage
```

Top-level sections:

| Section | What it controls |
| --- | --- |
| `sentinel` | Workspace ID + base64 shared key for Log Analytics ingestion |
| `splunk` | HEC URL + token + index/sourcetype |
| `pagerduty` | Events v2 integration key, min severity for paging |
| `slack` | Incoming webhook URL, channel, min severity |
| `virustotal` | API key for Stage 1d multi-engine hash lookup |
| `webhook` | GitHub TTP-library webhook secret + repo coordinates |
| `workspace` | Service account + customer ID for Chrome Browser Cloud Management |
| `dispatch` | Dedup TTL, escalation threshold, global min severity |

Environment variables override credential defaults — preferred for production
because keys never end up in `extguard.conf.json` on disk:

| Variable | Purpose | Default |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | Required for Stage 2 AI triage | unset |
| `EXTGUARD_CLAUDE_MODEL` | Pin a specific Claude snapshot | `claude-sonnet-4-6` |
| `VT_API_KEY` | Enable VirusTotal hash lookup in Stage 1d | unset |
| `VT_DISABLED` | If `"1"`, globally disable VT (privacy opt-out) | unset |
| `GITHUB_TOKEN` | PAT for private TTP repos or higher rate limit | unset |
| `EXTGUARD_LOG_LEVEL` | `DEBUG`/`INFO`/`WARNING`/`ERROR` | `INFO` |
| `EXTGUARD_LOG_FILE` | Path to also write JSON log lines | unset |
| `EXTGUARD_LOG_JSON` | If `"1"`, stderr is JSON too | unset |

The config file itself is validated on load — missing required fields,
placeholder values, type mismatches, and bad severity strings produce a
clear error rather than a silent dispatch failure.

---

## Detection coverage

### Known campaigns

| Campaign | Year | Pattern | What ExtensionGuard catches |
| --- | --- | --- | --- |
| **TeamPCP / Nx Console** | 2026 | Compromised npm publisher pushes malicious .crx | Permission combo (cookies+tabs+storage+`<all_urls>`), beacon to `*.workers.dev` |
| **Shai-Hulud family** | 2025-26 | Typosquatted extensions abuse `debugger` + `nativeMessaging` | Critical permission weights + Runtime obfuscated-eval detection |

### MITRE ATT&CK techniques

T1176 (Browser Extensions), T1555.003 (Credentials from Web Browsers),
T1071.001 (Web Protocols / C2), T1059.007 (JavaScript), T1530 (Data from
Cloud Storage), T1074 (Data Staged), T1185 (Browser Session Hijacking).

### Detection layers (pre-install)

1. **Permission weights** — `debugger` and `nativeMessaging` are 35 points
   each; `cookies`, `webRequestBlocking`, `browsingData`, `management`,
   `proxy` are 20 each.
2. **Combo bonuses** — five known attack-chain combos (e.g.
   `cookies+tabs+storage` = TeamPCP session-token harvester).
3. **Broad host access** — `<all_urls>` and `*://*/*` patterns.
4. **Publisher legitimacy** — extension ID computed from CRX3 signing key,
   cross-checked against Chrome Web Store.
5. **OSV hash lookup** — SHA-256 of the ZIP against `api.osv.dev`.
6. **VirusTotal hash lookup** (optional) — same hash against VT's
   multi-engine database. Free tier: 4 req/min, 500/day. Set
   `VT_DISABLED=1` for privacy-sensitive teams who can't send hashes to a
   third party.
7. **Version velocity** — semver jumps (e.g. 1.0.4 → 17.3.1) flagged from
   local history.

---

## What it doesn't do

Honest list of out-of-scope items so you know when to reach for another
tool:

- **No machine learning / behavioural model training.** Detection is rules
  + LLM-assisted triage, not anomaly detection over your fleet.
- **No browser-process memory inspection.** We see what CDP exposes; we
  don't attach a kernel probe.
- **No Firefox / Safari / Edge support yet.** Extensions on other browsers
  use different formats and APIs.
- **No automatic credential rotation.** The playbook generates step-by-step
  instructions; an analyst still has to click the buttons (deliberate —
  auto-rotating prod credentials is too risky).
- **No persistent SOC backend.** The dashboard is a thin Flask app reading
  from disk; there's no database, multi-tenancy, or RBAC. Pair with your
  existing SIEM for query history.
- **Single-host state.** Dedup / version-history / quarantine all live on
  the local filesystem. For a multi-host fleet, run one sensor per host
  and rely on destination-side dedup (PagerDuty's `dedup_key`, Sentinel
  log-table queries).

---

## Project layout

```
extguard/
  # Console-script entry points
  main.py                       - Stage 1 CLI (extguard)
  behavioral_monitor.py         - Stage 3 CDP monitor (extguard-monitor)
  alert_dispatcher.py           - Stage 4 dispatcher (extguard-dispatch)
  remediation.py                - Stage 5 orchestrator (extguard-remediate)
  dashboard.py                  - Flask web UI (extguard-dashboard)
  ttp_ingestor.py               - GitHub sync (extguard-ttp-sync)
  sigma_generator.py            - SIEM export (extguard-sigma)

  # Supporting modules
  models.py                     - Shared dataclasses
  crx_parser.py                 - CRX2/CRX3/ZIP/manifest.json parser
  permission_scorer.py          - Local permission risk scoring
  publisher_checker.py          - CRX signing key + Web Store check
  osv_lookup.py                 - OSV hash + npm dep vuln scan
  virustotal_lookup.py          - VirusTotal v3 multi-engine consensus
  update_velocity.py            - Semver jump detection
  claude_triage.py              - Claude API integration (cache + tool_use)
  ttp_loader.py                 - Disk-backed TTP library with mtime cache
  config_schema.py              - extguard.conf.json validator
  logging_setup.py              - Logger + SecretRedactionFilter

  adapters/
    sentinel.py                 - Microsoft Sentinel (HMAC-signed)
    splunk.py                   - Splunk HEC
    pagerduty.py                - PagerDuty Events v2 + resolve()
    slack.py                    - Slack Incoming Webhook (Block Kit)
    http_retry.py               - Exponential-backoff POST helper

  remediators/
    chrome_killer.py            - Cross-platform blocklist (incl. Workspace)
    forensics.py                - Quarantine + chain-of-custody + verify
    cred_rotation.py            - Credential rotation playbook generator

  ttp_library/                  - Markdown TTP intel (synced from GitHub)
    campaigns/
    patterns/
    mitre_reference.md

  dashboard_templates/          - Jinja2 templates for the Flask UI
  dashboard_static/             - CSS for the Flask UI

  tests/                        - 503 pytest tests
    benchmarks/                 - 13 pytest-benchmark performance baselines
  test_fixtures/                - Simulated malicious + benign manifests
  quarantine/                   - Stage 5 case folders land here

  extguard.conf.json            - Configuration template
  pyproject.toml                - Package + ruff + pytest config
  Dockerfile                    - Multi-stage container image
  docker-compose.yml            - SOC deployment (dashboard + dispatcher + sync)
```

---

## Development

```powershell
# Editable install with dev tools (pytest, ruff, build, pytest-benchmark)
pip install -e ".[dev]"

# Run the full test suite (~10 seconds, excludes benchmarks)
pytest

# Run the performance benchmark suite
pytest tests/benchmarks/

# Snapshot a baseline, then compare after changes
pytest tests/benchmarks/ --benchmark-save=baseline
pytest tests/benchmarks/ --benchmark-compare=baseline

# Lint + format check
ruff check .
ruff format --check .

# Build a distributable wheel
python -m build
```

The CI workflow (`.github/workflows/ci.yml`) runs pytest across Python
3.10/3.11/3.12/3.13 on Ubuntu plus ruff + wheel build on every push.

### Adding a new detection rule

The pre-install scoring lives in `permission_scorer.py`. Add an entry to
`PERMISSION_WEIGHTS`, `COMBO_BONUSES`, or write a new check function, then
add a test in `tests/test_permission_scorer.py`. The scoring is
deliberately calibrated so a "TeamPCP-shape" manifest hits 100/100 — keep
that test green when tuning weights.

The runtime detection rules live in `behavioral_monitor.py`. Each rule is
a branch in `_handle_network_request` or `_handle_console_call`. Update
the `_rule_to_mitre` mapping when adding new rules, and add a matching
entry to `sigma_generator.RULES` so the SIEM export stays in sync.

### Adding a new alert destination

Drop a new module in `adapters/`. The contract is a single
`send(alert: dict, cfg: dict) -> dict` function that returns
`{"ok": bool, "error": str?}`. Register it in `alert_dispatcher.ADAPTERS`
and add the credential schema to `config_schema.ADAPTER_REQUIRED_KEYS`.
Wire HTTP through `adapters.http_retry.post_with_retry` to get the
retry/backoff for free.

---

## Workspace setup (optional)

For organisations running cloud-managed Chrome via Google Workspace, the
remediation step can push the extension blocklist policy to every browser
in an org unit instead of relying on per-host registry writes. One-time
setup:

1. **Enable the Chrome Policy API** in your Workspace admin console
   (Account > Account settings > Legal and compliance — confirm the API is
   on for your domain).
2. **Create a service account** in Google Cloud IAM under the project
   tied to your Workspace.
3. **Grant scope `https://www.googleapis.com/auth/chrome.management.policy`** in
   Workspace Admin > Security > API controls > Domain-wide delegation.
4. **Download the service account JSON key** and set its path in
   `extguard.conf.json` under `workspace.service_account_json`.
5. **Find your customer ID** at admin.google.com > Account settings >
   Profile and put it in `workspace.customer_id`.
6. Install the optional Google libraries:

   ```powershell
   pip install -e ".[workspace]"
   ```

Without this setup, `extguard-remediate` falls back to the local
registry/policy-file method for the current host only.

---

## TTP library sync

The Stage 2 Claude triage reads its threat intelligence from
`ttp_library/`. Two ways to keep it fresh:

```powershell
# Manual pull from a configured GitHub repo
extguard-ttp-sync --owner myorg --repo extguard-ttp

# Or set up a GitHub webhook pointing at https://<dashboard>/webhook/github
# with content-type=application/json and the shared secret from
# extguard.conf.json#webhook.secret. Every push to the configured branch
# triggers an automatic sync.
```

The dashboard verifies the `X-Hub-Signature-256` HMAC on every webhook
delivery — requests without a valid signature are rejected with 401.

---

## Sigma rule export

```powershell
extguard-sigma --output sigma/
```

Generates one Sigma `.yml` per behavioural detection rule plus a README
with import instructions for Splunk SPL, Sentinel KQL, Elastic DSL, and
Chronicle YARA-L. Rule UUIDs are stable across regenerations (UUIDv5) so
SIEM-side tuning survives updates.

---

## Performance

Measured baselines for every hot path are in [PERFORMANCE.md](PERFORMANCE.md).
A single dispatcher handles **20,000+ alerts per second** at the Python
layer before adapter HTTP calls become the bottleneck. A full
incident-response sequence (preserve → kill → playbook → PD-resolve)
completes in under **100 ms of local CPU** plus the PagerDuty resolve
HTTP call.

Re-measure after any change to a hot path:

```powershell
pytest tests/benchmarks/ --benchmark-compare=baseline
```

---

## License

[MIT](LICENSE).

## Acknowledgments

- The MITRE ATT&CK framework's Browser Extensions (T1176) technique and
  supporting research.
- The OSV.dev open-source vulnerability database.
- VirusTotal for the multi-engine consensus API.
- The [SigmaHQ](https://github.com/SigmaHQ/sigma) project for the generic
  SIEM detection format.
- Microsoft Sentinel, Splunk, PagerDuty, and Slack for documenting their
  ingestion APIs well enough that the adapters are ~150 lines each.
