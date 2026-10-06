# ExtensionGuard

> Defensive SOC tooling for detecting, alerting on, and remediating malicious browser-extension supply-chain attacks.

ExtensionGuard is a Python pipeline that catches malicious Chrome extensions
before they exfiltrate credentials. It's built for blue-team / SOC use,
inspired by the May 2026 TeamPCP supply-chain breach — a compromised npm
publisher account that pushed a malicious update to the legitimate Nx Console
extension and harvested GitHub / npm session tokens from every install.

What's in the box:

- **Pre-install scan** — hardened CRX parser (zip-bomb limits, malformed
  manifests can't crash it), TTP-calibrated permission scorer, signing
  identity + Chrome Web Store build verification (byte-for-byte hash match),
  VirusTotal file-hash lookup, OSV check of bundled npm packages,
  version-velocity detection, and a code diff against the last accepted
  build that catches hijacked updates shipped as an ordinary patch bump.
- **AI triage** — Claude with a cached threat-intel library, forced
  structured output, and an injection-resistant prompt. Claude can raise a
  verdict but never lower it: the final score is the higher of Claude's and
  the deterministic Stage 1 score.
- **Runtime monitor** — Chrome DevTools Protocol sensor that instruments
  extension service workers, extension pages and content scripts. Seven
  rules (see [Running the runtime monitor](#running-the-runtime-monitor)).
  Tested end to end against a real headless Chrome.
- **SOC alert dispatch** — parallel fan-out to Sentinel, Splunk, PagerDuty,
  and Slack with deduplication, escalation, and retry/backoff.
- **Remediation** — forensic preservation of the original sample with an
  HMAC-signed chain of custody. Blocks the extension through the Windows
  registry, the Linux policy file, a macOS configuration profile, or the
  Google Workspace Chrome Policy API. Also generates a credential-rotation
  playbook. Policy changes need explicit confirmation.
- **Analyst dashboard** — Flask web UI to browse quarantine cases, verify
  evidence integrity, and approve / reject remediation actions (executed by
  `extguard-remediate --process-queue`).
- **Live threat-intel updates** — a separate webhook receiver
  (`extguard-webhook`, HMAC-verified, replay-protected) keeps the TTP library
  in sync from a central repo. Updates are staged and only go live after an
  analyst activates them.
- **SIEM portability** — Sigma rules for proxy logs and for the alerts
  ExtensionGuard forwards to Splunk, Sentinel, Elastic, or Chronicle.

## Status

| Property | Value |
| --- | --- |
| Version | **0.3.0** |
| Tests | **859** (`pytest`; 4 run on Windows only) + 5 opt-in live tests (real APIs, headless Chrome) |
| Benchmarks | **13** in `tests/benchmarks/` (see [PERFORMANCE.md](PERFORMANCE.md)) |
| Lint | **0 findings** (`ruff check`) |
| Python | 3.10 – 3.13 |
| Runtime deps | `anthropic`, `requests`, `websockets`, `flask` |
| Optional deps | `[dev]`, `[workspace]` |
| Console scripts | 8 (see below) |

Companion docs:

- [CHANGELOG.md](CHANGELOG.md) — what changed between releases
- [THREAT_MODEL.md](THREAT_MODEL.md) — trust boundaries + 13 catalogued threats
- [PERFORMANCE.md](PERFORMANCE.md) — measured baselines for every hot path
- [RELEASING.md](RELEASING.md) — release checklist for maintainers

---

## Quickstart

### From source

```powershell
git clone https://github.com/Vimal7747/extensionguard.git
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
docker run -p 127.0.0.1:5000:5000 extensionguard:0.3.0   # dashboard, localhost only
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
extguard-remediate --from-triage triage.json --dry-run --pd-action none

# Browse quarantine cases, verify integrity, approve remediations
extguard-dashboard            # http://127.0.0.1:5000
extguard-remediate --process-queue    # execute what analysts approved

# Pull latest threat intel from a GitHub repo, review it, make it live
extguard-ttp-sync --owner myorg --repo extguard-ttp
extguard-ttp-sync --activate

# Export detections as Sigma rules for Splunk / Sentinel / Elastic
extguard-sigma --output sigma/
```

### Verdicts, exit codes and automation

- **Final score** = the higher of the Stage 1 composite score and Claude's
  score. A file that 11+ VirusTotal engines flag is raised to at least 90.
  An update that starts sending data to exfil-style hosting (Discord /
  Telegram webhooks, `*.workers.dev`, tunnels) that the previous accepted
  build never used is raised to at least 60 (HIGH).
- **Baselines.** Each LOW / MEDIUM scan is saved as the reference for
  comparing the next version: its version for velocity, its code profile for
  the code diff. HIGH / CRITICAL builds never become the baseline. Nor does a
  build whose code changed (new endpoints, sensitive APIs, obfuscation) until
  you review it and re-scan with `--accept-baseline`. `--no-record` saves
  nothing.
- `--json` always prints one JSON document, including when the AI stage is
  skipped or fails (`ai_triage.status`) and when the scan can't complete
  (`{"error": ..., "stage": ...}`).
- `--offline` makes no network calls at all: no Web Store, VirusTotal, OSV,
  or Claude API.
- Exit codes: `0` done · `1` verdict at or above `--fail-on` · `2` bad
  arguments · `3` the scan could not be completed.

```powershell
extguard suspicious.crx --json --fail-on high   # exit 1 if HIGH or CRITICAL
```

### Where ExtensionGuard keeps data

Everything lives under `EXTGUARD_HOME` (default `~/.extguard`): `quarantine/`,
the active `ttp_library/` and the staged `ttp_library.pending/`,
`remediation_queue.jsonl` (+ `.done`), `version_history.json`,
`code_profiles/`, `webhook_deliveries.json`, and the evidence signing key
`coc_hmac.key`. `EXTGUARD_QUARANTINE` and `EXTGUARD_TTP_DIR` override the
quarantine and TTP locations.

`extguard.conf.json` is found in this order: `--config`, `$EXTGUARD_CONFIG`,
`./extguard.conf.json`, `$EXTGUARD_HOME/extguard.conf.json`.

### Evidence integrity

Stage 5 preserves the **original** sample file, so its SHA-256 matches what
VirusTotal and the Web Store know it by. `chain_of_custody.json` is signed
with HMAC-SHA256 using a key kept outside the case folder: set
`EXTGUARD_COC_KEY` (for example from a secrets manager), or let ExtensionGuard
create `~/.extguard/coc_hmac.key`. `extguard-remediate --verify-case <dir>`
fails if an artifact or the chain of custody was edited, or the signature is
missing. Anyone who can read the key can still forge a signature, so keep it
away from the analyst workstation account where you can.

Expected output for the malicious test fixture:

```
Stage 1 composite: 100/100 - CRITICAL
  Flagged: webRequestBlocking, cookies, webRequest, tabs, history, storage, <all_urls>
  [!] Session token harvesting combo - matches TeamPCP TTP (T1555.003)
  [!] Traffic intercept + cookie theft pipeline (T1071 + T1555)
  [!] Persistent background page - always-on monitoring
  Recommendation: BLOCK IMMEDIATELY - initiate remediation playbook
```

### Running the runtime monitor

The monitor drives Chrome through the DevTools Protocol. **Anything that can
reach the debugging port has full control of that browser** - cookies,
sessions, every tab. So run it against a separate sandbox Chrome with its own
profile, never your everyday one (Chrome 136+ refuses remote debugging on the
default profile anyway):

```powershell
& "C:\Program Files\Google\Chrome\Application\chrome.exe" `
    --user-data-dir=C:\extguard-sandbox --remote-debugging-port=9222
extguard-monitor --list-targets                      # find extension IDs
extguard-monitor --output-json | extguard-dispatch   # all extensions -> SOC
extguard-monitor --ext-id <id> --snapshot-storage <id> --out storage.json
```

It attaches to extension service workers, extension pages and web pages (for
content scripts; `--no-pages` skips them). It hooks the storage, management
and cookie APIs before the extension's own code runs, and reconnects if
Chrome restarts (`--once` to exit instead).

| Rule | Detects | Severity |
| --- | --- | --- |
| RULE-01 | POST to exfil-style hosting (`*.workers.dev`, tunnels...); regular beaconing | high / critical |
| RULE-02 | Tokens, passwords or cookie dumps sent to a host they don't belong to | high / critical |
| RULE-03 | Calls to GitHub / npm / cloud / SSO APIs; authenticated state-changing requests | medium / high |
| RULE-04 | Large encoded blobs or credentials staged in extension storage | high / critical |
| RULE-05 | `chrome.management` used to disable or uninstall another extension | critical |
| RULE-06 | `eval` / `new Function` / injected remote scripts; obfuscated eval chains | medium / high |
| RULE-07 | `chrome.cookies.getAll` bulk reads; `document.cookie` reads on high-value sites | medium / high |

### Remediation

```powershell
extguard-remediate --from-triage triage.json --crx sample.crx   # asks you to type BLOCK
extguard-remediate --ext-id <id> --crx sample.crx --yes          # automation / SOAR
extguard-remediate --from-triage triage.json --workspace-ou /Engineering
extguard-remediate --from-triage triage.json --alerts-log alerts.jsonl `
    --storage-snapshot storage.json                             # more evidence
```

- **Windows / Linux** write Chrome's `ExtensionInstallBlocklist` policy (run
  as administrator / root). It applies when Chrome reloads policy.
- **macOS**: Chrome only honours *managed* preferences, so ExtensionGuard
  writes `extguard-block-<id>.mobileconfig`. Install it through your MDM or
  System Settings > Privacy & Security > Profiles. The step is reported as
  PARTIAL until then.
- **Google Workspace**: `--workspace-ou` blocks the extension for an org unit
  via the Chrome Policy API. The request follows Google's documented format;
  it has not been run against a live tenant from this project.
- **PagerDuty** is *acknowledged* by default, not resolved. Blocking doesn't
  undo stolen credentials, so resolve it with `--pd-action resolve` after the
  rotation playbook is done.
- Exit code `1` means a step failed or was refused.

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
|   code_diff            - code changes vs last accepted build   |
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
|   - Connects to a sandbox Chrome over CDP (remote debugging)   |
|   - Instruments service workers, extension pages, content      |
|     scripts; hooks storage / management / cookie APIs          |
|   - Seven detection rules:                                     |
|     RULE-01  POST / beacon to exfil-style hosting              |
|     RULE-02  Credentials sent to a host they don't belong to   |
|     RULE-03  High-value API access / session riding            |
|     RULE-04  Data staged in extension storage                  |
|     RULE-05  Extension disables / uninstalls another           |
|     RULE-06  Dynamic or obfuscated code execution              |
|     RULE-07  Bulk cookie reads                                 |
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
|                   .mobileconfig profile (macOS),               |
|                   Chrome Policy API (Workspace)                |
|   3. PLAYBOOK  -  generate credential-rotation runbook for     |
|                   each at-risk store (GitHub, npm, AWS, Slack, |
|                   Atlassian, Google)                           |
|   4. PAGERDUTY -  acknowledge (resolve on request)             |
|   5. REPORT    -  console summary + verify command             |
+----------------------------------------------------------------+

  Sitting alongside all of the above:
+----------------------------------------------------------------+
| Analyst dashboard   (CLI: extguard-dashboard, localhost only)  |
|   - Browses quarantine cases + verifies SHA-256 integrity      |
|   - Tails recent alerts                                        |
|   - Approve/reject queue (a file that                          |
|     `extguard-remediate --process-queue` executes; the         |
|     dashboard never modifies system state itself)              |
+----------------------------------------------------------------+
| TTP webhook         (CLI: extguard-webhook, internet-facing)   |
|   - GitHub pushes, HMAC-SHA256 verified, replay-protected      |
|   - Stages the new library for `extguard-ttp-sync --activate`  |
+----------------------------------------------------------------+
```

---

## Console scripts

After `pip install`, eight CLIs are available:

| Command | Purpose |
| --- | --- |
| `extguard` | Stage 1 pre-install scanner |
| `extguard-monitor` | Stage 3 runtime behavioural monitor (CDP client) |
| `extguard-dispatch` | Stage 4 alert dispatcher (reads JSONL from stdin) |
| `extguard-remediate` | Stage 5 incident-response orchestrator |
| `extguard-dashboard` | Flask analyst UI on 127.0.0.1:5000 |
| `extguard-ttp-sync` | Pull the TTP library from GitHub (staged); `--status`, `--activate` |
| `extguard-webhook` | GitHub push receiver for TTP updates (separate from the dashboard) |
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
| `webhook` | TTP repo coordinates, webhook secret, `auto_activate`, `require_verified_commit` |
| `workspace` | Service account, customer ID and admin email for the Chrome Policy API |
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
   each; `userScripts` 25; `cookies`, `scripting`, `webRequestBlocking`,
   `webRequestAuthProvider`, tab / desktop capture, `management`, `proxy`
   20 each. Optional permissions count at half weight - an extension can
   request them at any time.
2. **Combo bonuses** — known attack-chain combos (e.g.
   `cookies+tabs+storage` = TeamPCP session-token harvester; `scripting` on
   all sites; `cookies` on high-value domains).
3. **Host access** — every spelling of "all sites" (`<all_urls>`,
   `*://*/*`, `https://*/*`, `*://*.com/*`...), high-value domains (code
   hosting, package registries, cloud consoles, SSO), content scripts in the
   page's MAIN world, `externally_connectable` to every site, and weak CSP.
4. **Signing identity** — the extension ID is taken from the signed `crx_id`
   in the CRX3 header (the value Chrome itself uses), with the manifest `key`
   as a cross-check. A manifest key that contradicts the signature is flagged.
5. **Chrome Web Store build check** — the store's update service reports the
   current version and the SHA-256 of the exact `.crx` it serves. A matching
   hash means "this is the genuine store build". The same version with a
   different hash means a repackaged or tampered build.
6. **VirusTotal file-hash lookup** (optional) — the SHA-256 of the whole
   input file. Free tier: 4 req/min, 500/day. Set `VT_DISABLED=1` for teams
   that can't send hashes to a third party.
7. **OSV package check** — npm packages bundled in the extension (from
   `package.json` / `package-lock.json`) checked against `api.osv.dev`.
   (OSV has no file-hash lookup; an earlier version sent one anyway and it
   always came back empty.)
8. **Version velocity** — large semver jumps (e.g. 1.0.4 → 17.3.1) and
   versions that go backwards, from local history.
9. **Code diff (Stage 1f)** — endpoints, sensitive APIs (cookies, debugger,
   `eval`, remote script loading...) and obfuscation, compared with the last
   accepted build of the same extension. A hijacked update that ships as an
   ordinary patch bump shows up as new endpoints / capabilities; one that
   starts talking to exfil-style hosting is at least HIGH.

A lookup that fails (network error, rate limit) is reported as **unknown**,
never as clean.

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
extguard/                         (repository root)
  extguard/                       - the Python package (everything pip installs)
    __main__.py                   - `python -m extguard` = `extguard`
    paths.py                      - where config + data live (EXTGUARD_HOME)

    # Console-script entry points
    main.py                       - Stage 1 CLI (extguard)
    behavioral_monitor.py         - Stage 3 CDP monitor (extguard-monitor)
    alert_dispatcher.py           - Stage 4 dispatcher (extguard-dispatch)
    remediation.py                - Stage 5 orchestrator (extguard-remediate)
    dashboard.py                  - Flask web UI (extguard-dashboard)
    ttp_ingestor.py               - GitHub sync + activation (extguard-ttp-sync)
    webhook_server.py             - GitHub push receiver (extguard-webhook)
    sigma_generator.py            - SIEM export (extguard-sigma)

    # Supporting modules
    models.py                     - Shared dataclasses + extension-ID validation
    crx_parser.py                 - CRX2/CRX3/ZIP/manifest.json parser + limits
    permission_scorer.py          - Local permission risk scoring
    publisher_checker.py          - CRX3 signed ID + Web Store build check
    osv_lookup.py                 - VirusTotal hash, npm/OSV check, CDN refs
    virustotal_lookup.py          - VirusTotal v3 multi-engine consensus
    update_velocity.py            - Semver jump / rollback detection
    code_diff.py                  - Stage 1f code profile + diff vs baseline
    claude_triage.py              - Claude API integration (cache + tool_use)
    ttp_loader.py                 - Disk-backed TTP library with mtime cache
    config_schema.py              - extguard.conf.json validator
    logging_setup.py              - Logger + SecretRedactionFilter

    adapters/                     - Sentinel, Splunk, PagerDuty, Slack, retry
    remediators/                  - chrome_killer, forensics, cred_rotation
    ttp_library/                  - Baseline TTP intel (synced copy: EXTGUARD_HOME)
    dashboard_templates/          - Jinja2 templates for the Flask UI
    dashboard_static/             - CSS for the Flask UI

  tests/                          - 859 pytest tests
    benchmarks/                   - 13 pytest-benchmark performance baselines
    fixtures/recorded/            - Real API responses the tests replay
    test_live_apis.py             - Opt-in contract tests against real APIs
    test_live_monitor.py          - Opt-in monitor test on a headless Chrome
  tools/                          - Release checks + wheel smoke test (not shipped)
  test_fixtures/                  - Simulated malicious + benign manifests

  extguard.conf.json              - Configuration template
  pyproject.toml                  - Package + ruff config (pytest: pytest.ini)
  Dockerfile                      - Multi-stage container image
  docker-compose.yml              - SOC deployment (dashboard, dispatcher, sync, webhook)
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

# Contract tests against the REAL Web Store / OSV APIs, plus the runtime
# monitor on a headless Chrome with a throwaway profile (opt-in, needs
# network and Chrome)
$env:EXTGUARD_LIVE_TESTS = "1"; pytest -m live

# Lint + format check
ruff check .
ruff format --check .

# Build a distributable wheel
python -m build
```

The CI workflow (`.github/workflows/ci.yml`) runs on every push to `main`
and every pull request:

- pytest on Python 3.10 / 3.11 / 3.12 / 3.13 (Ubuntu) and on Windows, where
  the blocklist code does a real registry round trip (a scratch key under
  HKCU - never Chrome's policy);
- ruff, and a wheel + sdist build whose wheel is installed in a fresh
  virtualenv and smoke-tested (`tools/smoke_test.py`);
- a Docker job that builds the image and checks every CLI, a scan, the
  dashboard health endpoint, the non-root user and the writable data volumes,
  and validates `docker-compose.yml`;
- the benchmark suite (timings uploaded as an artifact).

`.github/workflows/live-api.yml` runs the live contract tests and the
real-Chrome monitor test weekly, and on any PR that changes them, so a
change in an upstream API shows up as a failing job instead of a check that
quietly stops working.

`.github/workflows/release.yml` publishes a release when a `v*` tag is
pushed - see [RELEASING.md](RELEASING.md).

### Adding a new detection rule

The pre-install scoring lives in `extguard/permission_scorer.py`. Add an entry to
`PERMISSION_WEIGHTS`, `COMBO_BONUSES`, or write a new check function, then
add a test in `tests/test_permission_scorer.py`. The scoring is
deliberately calibrated so a "TeamPCP-shape" manifest hits 100/100 — keep
that test green when tuning weights.

The runtime detection rules live in `extguard/behavioral_monitor.py`. Each rule is
a branch in one of the `_handle_*` functions (network requests, console
calls, dynamic scripts, API hook events). Update the `_rule_to_mitre`
mapping when adding new rules, and add a matching entry to
`sigma_generator.SENSOR_RULES` - a test fails until you do.

### Adding a new alert destination

Drop a new module in `extguard/adapters/`. The contract is a single
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
3. **Grant the scopes** `https://www.googleapis.com/auth/chrome.management.policy`
   and `https://www.googleapis.com/auth/admin.directory.orgunit.readonly` in
   Workspace Admin > Security > API controls > Domain-wide delegation.
4. **Download the service account JSON key** and set its path in
   `extguard.conf.json` under `workspace.service_account_json`. Keep the
   key out of git (`service-account*.json` is in `.gitignore`).
5. **Find your customer ID** at admin.google.com > Account settings >
   Profile and put it in `workspace.customer_id`. Set `workspace.admin_email`
   to an admin the service account acts as (Google requires one).
6. Install the optional Google libraries:

   ```powershell
   pip install -e ".[workspace]"
   ```

Then `extguard-remediate ... --workspace-ou /Engineering` blocks the
extension (policy `chrome.users.apps.InstallType` = BLOCKED) for that org
unit, in addition to the local machine. Use `--dry-run` to see the exact
request first. The request follows Google's published format but has not
been exercised against a live tenant from this project.

---

## TTP library sync

The Stage 2 Claude triage reads its threat intelligence from
`ttp_library/`, and that text goes into Claude's system prompt. Whoever can
push to the TTP repo can therefore influence every verdict, so updates are
**staged**:

```powershell
extguard-ttp-sync --owner myorg --repo extguard-ttp   # download to ttp_library.pending/
extguard-ttp-sync --status                            # added / changed / removed files
extguard-ttp-sync --activate                          # make it live (old copy kept as .previous)
```

To sync on every push, run the webhook receiver. It is a separate process
because it has to be reachable from GitHub, and the dashboard must not be:

```powershell
extguard-webhook --port 8765    # serve it through a TLS reverse proxy or tunnel
```

Point a GitHub push webhook at `https://<host>/webhook/github` with content
type `application/json` and the secret from `extguard.conf.json#webhook.secret`.
The receiver checks the `X-Hub-Signature-256` HMAC (401 if wrong) and
rejects replayed `X-GitHub-Delivery` IDs (409). It returns 202 at once and
syncs in the background, one sync at a time.

Safety options in the `webhook` section: `auto_activate` (skip the review
step - only for a repo you fully trust), `require_verified_commit` (refuse
unless the branch head commit is signature-verified), `delete_orphans`
(refuses to delete more than half the library or to run after errors). The
GitHub token is only ever sent to GitHub hosts, files are size-limited, and
the library is framed as reference data in Claude's prompt.

---

## Sigma rule export

```powershell
extguard-sigma --output sigma/
```

Two kinds of rule, depending on which logs you actually have:

- **Proxy rule** (`proxy-exfil-hosting.yml`, `category: proxy`) - POSTs to
  exfil-style hosting and Discord / Telegram webhooks in ordinary web-proxy
  logs. Proxy logs can't tell an extension from a tab, so it is a MEDIUM
  hunting rule.
- **Sensor rules** (`rule-01.yml` ... `rule-07.yml`, `product: extensionguard`)
  - one per monitor rule, over the alerts `extguard-dispatch` forwards to
  Splunk (`sourcetype=extguard:alert`) or Sentinel (`ExtensionGuard_CL`).
  Storage, management-API and cookie activity happen inside the browser;
  no generic log source shows them.

The generated README has import instructions for Splunk, Sentinel and
Elastic. Rule IDs and dates are fixed, so regenerating produces identical
files unless a rule changed.

---

## Performance

Measured baselines for every hot path are in [PERFORMANCE.md](PERFORMANCE.md).
A single dispatcher handles **20,000+ alerts per second** at the Python
layer before adapter HTTP calls become the bottleneck. A full
incident-response sequence (preserve → kill → playbook → PagerDuty)
completes in under **100 ms of local CPU** plus the PagerDuty HTTP call.

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
