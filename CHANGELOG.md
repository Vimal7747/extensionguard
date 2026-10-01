# Changelog

All notable changes to ExtensionGuard. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [SemVer](https://semver.org/).

## [Unreleased]

## [0.3.0] — 2026-10-01

Fixes the correctness and safety bugs a full review (2026-09-29) found in 0.2.0. Several
0.2.0 checks reported "clean" while never actually working. All 14 bugs the
review reproduced are fixed, along with the other High / Medium findings:
scorer evasion, patch-bump hijacks, a runtime monitor that missed service
workers, a remediation queue that nothing executed, a public webhook on an
unauthenticated dashboard, and Sigma rules for log sources that don't exist.
Contains breaking changes - see below. (While the version is 0.x, breaking
changes bump the MINOR number, as SemVer allows.)

### Breaking

- **Evidence from 0.2.0 is unsigned.** Case folders preserved by 0.2.0 have
  no `chain_of_custody.json.hmac`, so `extguard-remediate --verify-case`
  reports them as unsigned (exit 1). The dashboard and `--process-queue`
  refuse to act on them, and new custody entries can't be appended. Their
  artifact hashes can still be compared by hand against the old
  `chain_of_custody.json`, but nothing proves that file itself wasn't edited
  - the 0.2.0 weakness this release fixes. They are deliberately not re-signed
  automatically, since that would vouch for evidence nobody checked.

- **The GitHub webhook moved to its own server**, `extguard-webhook`. The
  dashboard no longer serves `/webhook/github`: GitHub needs to reach the
  webhook from the internet, and the dashboard (no authentication) must stay
  on localhost. Point the GitHub webhook at the new server.
- **TTP syncs are staged.** `extguard-ttp-sync` and the webhook write to
  `ttp_library.pending/`; the intel reaches Claude's prompt only after
  `extguard-ttp-sync --activate` (or `"auto_activate": true`). `--status`
  shows what would change. Download URLs must be on GitHub, and files are
  size-limited.
- **`extguard-remediate`** asks you to type `BLOCK` before changing Chrome
  policy (`--yes` for automation; a non-interactive run without it refuses),
  **acknowledges** the PagerDuty incident instead of resolving it (use
  `--pd-action resolve` once credentials are rotated), and exits 1 when any
  step fails.
- **Dashboard approve / reject** require the analyst's name, which is recorded
  as the actor in the queue and chain of custody. `/api/health` no longer
  returns file paths.
- **macOS blocking** writes a configuration profile
  (`extguard-block-<id>.mobileconfig`) to install through MDM or System
  Settings. Chrome ignores the `defaults write` policies 0.2.0 wrote.
- **Sigma output** is a new rule set: one proxy rule plus one rule per monitor
  rule over forwarded ExtensionGuard alerts (see Fixed). Rule IDs changed.
- **Docker**: one `ttp` volume (`EXTGUARD_TTP_DIR=/var/lib/extguard/ttp/library`)
  replaces `ttp_library`, so the pending copy lives in the volume too.

- **Package layout.** All code moved into an `extguard/` package. Imports are
  now `from extguard.crx_parser import ...`. Console-script names are
  unchanged; `python -m extguard <file>` is new. 0.2.0 installed 18 top-level
  modules (`main`, `models`, `dashboard`...) into site-packages.
- **Data location.** Quarantine, remediation queue, version history, synced
  TTP intel and the evidence signing key now live under `EXTGUARD_HOME`
  (default `~/.extguard`). 0.2.0 used the source directory - inside
  site-packages when pip-installed. Set `EXTGUARD_QUARANTINE=./quarantine` to
  keep using an old repo-local quarantine.
- **Config lookup** is the same everywhere: `--config`, `$EXTGUARD_CONFIG`,
  `./extguard.conf.json`, `$EXTGUARD_HOME/extguard.conf.json`.
- **`main.py --json` output**: new `final_score`, `file_sha256`, `container`,
  `ai_triage` (status object), `stage_errors`, `parse_warnings`,
  `stage_1_iocs`, `composite_floor_reason`; `risk_level` is now the FINAL
  level. `stage_1_checks.osv.osv_zip_matches` and `zip_matches` are removed.
- **Version history** is keyed by extension ID, or `name:<name>` when there is
  no ID. Old name-keyed entries are not reused. Extensions with only an i18n
  placeholder name (`__MSG_...__`) are no longer tracked.
- **Chrome extension IDs are validated** (`^[a-p]{32}$`) before any blocklist
  write. Invalid IDs (including `*`) are refused.

### Fixed

- **OSV hash lookup removed.** OSV has no file-hash query (it returns HTTP 400
  "invalid query"), so the check never matched anything while printing
  "[OK] No OSV hash matches". OSV is now used only for bundled npm packages.
- **VirusTotal and forensics used the wrong bytes.** They hashed/preserved the
  ZIP with the CRX header stripped, which never matches the hash VirusTotal
  and the Web Store index. Both now use the original file.
- **Extension ID for Web Store `.crx` files.** The CRX header was never passed
  on (a `TODO`), so store CRXs got a false "sideloaded?" flag, no store check,
  and could not be blocklisted. The ID now comes from the signed `crx_id`.
- **Chrome Web Store check** read `version="1.0"` from the XML declaration, so
  extensions that don't exist were reported as "exists, v1.0". The reply is
  now parsed as XML, and the request uses the parameters the store needs to
  return the version and the served build's SHA-256.
- **AI could lower the verdict.** The final score is now max(Stage 1, AI);
  Claude also receives the Stage 1 findings (VirusTotal, store build match,
  update URL...). 11+ VirusTotal engines raise the score to at least 90.
- **Prompt boundary.** A manifest value or key containing
  `</UNTRUSTED_MANIFEST>`, or a name with a newline, could escape the untrusted
  block. All manifest text is now escaped and serialised as JSON inside a
  nonce-tagged block. Claude's tool output is validated and clamped.
- **Scanner crashes on hostile input**: non-string permissions, a list-shaped
  manifest, deeply nested JSON, a v1 `package-lock.json`, version `"0"`. No
  zip-bomb limits existed; there are now caps on file size, entry count and
  decompressed size. Stages 1c-1e now degrade to "unknown" instead of
  crashing the scan.
- **CLI contract**: `--offline` still called the Claude API; `--json` printed
  nothing when no API key was set; a CRITICAL verdict exited 0. New
  `--fail-on` flag and documented exit codes.
- **C2 beacon rule** needed two POSTs < 55 s apart, so the 60 s TeamPCP beacon
  it was named after never went critical. It now detects timing regularity.
- **Dispatcher** swallowed a CRITICAL that followed a HIGH of the same rule as
  a "duplicate", and escalated alerts dropped back to their old severity.
  More severe alerts now bypass dedup, suppressed repeats count toward
  escalation, and escalation holds within `escalation_window_seconds`.
- **Evidence verification** never checked the chain-of-custody sidecar, so
  swapping the sample and rewriting its hash passed. The chain of custody is
  now HMAC-signed (`EXTGUARD_COC_KEY` or `~/.extguard/coc_hmac.key`) and
  verification fails closed; a tampered case can no longer be re-signed by
  appending to it. The evidence `tool_version` was hardcoded to 0.1.0.
- **Slack alerts** put attacker-controlled extension names into mrkdwn
  unescaped (`<!channel>`, disguised links); long fields could make Slack
  reject, i.e. lose, the alert.
- **Wheel** shipped without the dashboard templates, CSS and TTP library.
- **Docker**: the dispatcher never read the mounted config, and triage never
  read the synced TTP volume. `EXTGUARD_HOME=/var/lib/extguard` fixes both.

Second round (the rest of the review):

- **Permission scorer evasion.** Optional permissions were ignored, and
  host patterns like `https://*/*`, `*://*.com/*` or `*.npmjs.com` were not
  treated as broad / high-value. `scripting`, `userScripts`,
  `webRequestAuthProvider`, tab / desktop capture, `declarativeNetRequest`
  and others had no weight. Optional permissions now count at half weight,
  and MAIN-world content scripts, `externally_connectable` to every site and
  weak CSP are scored.
- **Patch-bump hijacks were invisible** (a Cyberhaven-style 24.10.3 -> 24.10.4
  release with unchanged permissions scored low). New Stage 1f compares each
  update's code with the last accepted build. An update that starts sending
  data to exfil-style hosting is at least HIGH.
- **Baselines could be poisoned.** A MEDIUM hijacked update became the
  "known good" reference for the next version. A build whose code changed
  (new endpoints, sensitive APIs, obfuscation) is now only recorded after
  review (`--accept-baseline`), and HIGH / CRITICAL builds never are.
- **Update velocity**: a version going backwards wasn't flagged, and a
  2.0.0 -> 2.0.5 jump was scored as a minor bump. `__MSG_*__` names are
  resolved from `_locales` for display.
- **Runtime monitor** (verified against a real Chrome):
  - Extension service workers were never instrumented; the monitor now
    auto-attaches to every extension target.
  - Content scripts are attributed to their extension.
  - Alerts carried the CDP target ID instead of the extension ID, which
    broke dedup, PagerDuty keys and remediation.
  - Host regexes weren't anchored, so `github.com.evil.example` counted as
    GitHub.
  - RULE-02 fired when a cookie went to its own site (normal) instead of when
    credentials left for another host.
  - RULE-04 and RULE-05 were never emitted; they are implemented now, along
    with new RULE-07 (cookie harvesting). Hook reports can't be forged by the
    page.
  - The monitor reconnects when Chrome restarts.
- **Remediation queue**: dashboard approvals were written to a queue nothing
  read. `extguard-remediate --process-queue` executes them once each, only
  for cases whose signed chain of custody verifies.
- **Windows blocklist** stopped reading at the first gap in the numbered
  values, so an ID listed after a gap was added again and `unblock` couldn't
  find it. **Linux** replaced a corrupt policy file instead of refusing. The
  **Workspace** request didn't match the Chrome Policy API. It now calls
  `orgunits:batchModify` with `chrome.users.apps.InstallType` BLOCKED, org
  unit lookup and domain-wide delegation.
- **TTP library as a prompt-injection path**: synced intel went straight into
  Claude's system prompt. Beyond the staging gate, it is now framed as
  reference data and size-capped. Optional `require_verified_commit` refuses
  unsigned head commits. `delete_orphans` refuses to wipe most of the library
  or run after errors.
- **Webhook**: the sync ran inside the request (GitHub times out at 10 s),
  concurrent pushes raced, and a captured delivery could be replayed. It now
  returns 202, runs one sync at a time, and rejects repeated
  `X-GitHub-Delivery` IDs.
- **Dashboard** read the whole alert log on every page load; it now reads the
  end of the file.
- **Sigma rules**:
  - RULE-04/05/06 targeted `product: browser` log sources no SIEM receives.
  - RULE-01 required `c-uri-extension: ""`, so it could never match.
  - RULE-02/03 matched every logged-in user in proxy logs.
  - Every run wrote today's date, and the author URL was a placeholder.
- **Dispatcher / adapters**: Stage 2 triage results can be dispatched
  (`also_dispatch_triage`, `triage_min_score`), and a failed scan is itself
  an alert. PagerDuty gained `acknowledge`. The VirusTotal engine total left
  out suspicious / harmless verdicts. Log redaction missed `x-apikey` headers
  and labelled secrets.

### Changed

- Store comparison moved from `update_velocity` to `publisher_checker`
  (scoring it in both double-counted).

### Added

- `tests/fixtures/recorded/` - real API responses the tests replay, instead of
  hand-written mocks shaped like the author's assumptions.
- `tests/test_live_apis.py` (opt-in, `EXTGUARD_LIVE_TESTS=1`) and a weekly
  `live-api` workflow: contract tests against the real Web Store and OSV,
  including an end-to-end check on a real `.crx`.
- `tests/test_main.py`, `tests/test_paths.py`.
- `extguard-webhook`; `extguard-ttp-sync --status / --activate /
  --auto-activate / --require-verified`; `extguard-remediate --yes /
  --pd-action / --alerts-log / --storage-snapshot / --workspace-ou /
  --process-queue`; `extguard --accept-baseline`; `extguard-monitor
  --list-targets / --no-pages / --once / --host / --port / --snapshot-storage`.
- `tests/test_live_monitor.py` (opt-in): drives a headless Chrome with a
  throwaway profile and checks that worker hooks fire and RULE-02/04/06 alert.
- `tests/test_code_diff.py`, `tests/test_remediation.py`,
  `tests/test_webhook_server.py`; 503 -> 829 tests.

## [0.2.0] — 2026-05-23

### Added

- **Flask analyst dashboard** (`extguard-dashboard`) — browse quarantine cases,
  view AI triage narratives + chain of custody + artifact hashes, run live
  integrity verification, and approve/reject remediation actions via an
  out-of-band queue file. Binds 127.0.0.1 by default, requires CSRF tokens
  on every state-changing POST.
- **VirusTotal threat-intel adapter** (`virustotal_lookup.py`) — augments
  Stage 1d's OSV hash lookup with VirusTotal v3 multi-engine consensus.
  `VT_API_KEY` env var preferred over config. `VT_DISABLED=1` for privacy
  opt-out.
- **Live TTP library updates via GitHub webhook** — the threat-intel
  library moved from a hardcoded Python string to a tree of markdown files
  under `ttp_library/`. The new `extguard-ttp-sync` CLI pulls from a
  configured GitHub repo, and the dashboard's `/webhook/github` route
  receives push events with HMAC-SHA256 signature verification.
- **Sigma rule generator** (`extguard-sigma`) — translates the 6
  behavioral_monitor detection rules into SIEM-agnostic Sigma YAML so they
  can run natively in Splunk, Sentinel, Elastic, Chronicle, etc.
- **Google Workspace Admin SDK integration** in `chrome_killer.py` — pushes
  Chrome Browser Cloud Management policy via the Chrome Policy API for
  organisations running cloud-managed Chrome fleets. Optional dependency
  group `[workspace]`.
- **Performance benchmarks** under `tests/benchmarks/` with documented
  baselines in `PERFORMANCE.md`. Run with `pytest tests/benchmarks/`.
- **`THREAT_MODEL.md`** documenting 10 catalogued threats with mitigations,
  test references, and residual risks.

### Changed

- `osv_lookup.run_osv_checks` now accepts an optional `vt_cfg` parameter
  and merges VirusTotal's 0–30 score into the OSV total. Score ceiling
  raised 20 → 30.
- `claude_triage.CLAUDE_MODEL` is now overridable via
  `EXTGUARD_CLAUDE_MODEL` env var.
- `update_velocity._save_history` uses an atomic `tempfile` + `os.replace`
  pattern so concurrent invocations can't corrupt the JSON history file.
- `alert_dispatcher._read_triage_stdin` auto-detects between line-mode
  (JSONL) and document-mode (pretty-printed) input instead of buffering
  all of stdin unconditionally.
- `crx_parser._strip_crx_header` validates every length field against the
  file size — malformed CRXs now give a clear `CRX3 header_length exceeds
  file size` error instead of a misleading `Invalid ZIP archive`.
- `cred_rotation._pattern_matches` rewritten to use DNS-suffix matching
  instead of naive substring matching. **This was a real bug** —
  `attacker-github.com` could trigger the GitHub credential rotation
  playbook against an unrelated extension.

### Security

- **Prompt injection mitigation** in `claude_triage.py`. Manifest fields
  are now sanitised (control chars stripped, markdown fences neutralised,
  fields truncated at 4 KB) and wrapped in a `<UNTRUSTED_MANIFEST>` block
  with an explicit data-only instruction to Claude.
- **Secret redaction in logs** — `logging_setup.SecretRedactionFilter`
  scrubs Anthropic / Slack webhook / Bearer / Splunk HEC / PagerDuty /
  Sentinel / AWS / GitHub PAT / npm token shapes from every log line
  before it reaches a handler.
- **Forensics chmod removal** — dropped the misleading `chmod(0o444)` on
  the preserved sample (a no-op on Windows). Tamper detection is now
  exclusively hash-based and clearly documented.
- **Path-traversal defence in the dashboard** — `CASE_ID_PATTERN`
  validates every URL segment before any path operation. `[0-9a-p]{8}`
  covers both hex SHA short-IDs AND Chrome's `a-p` extension-ID alphabet.

### Fixed

- `_parse_version("not.a.version")` previously returned `()` instead of
  `None`. Now returns `None` consistently for any string with no parseable
  numeric segments.
- `behavioral_monitor.monitor_target` and `_handle_network_request`
  narrowed `except Exception` to specific expected exception types so
  programming bugs (TypeError, NameError) and KeyboardInterrupt surface
  to the operator instead of being swallowed.
- `behavioral_monitor._handle_network_request` now catches `TypeError`
  from `urllib.parse.urlparse(None)` in addition to `AttributeError`
  (Python-version-dependent behaviour).
- `sentinel._flatten_alert` now bounded to depth 10 to prevent
  `RecursionError` on hostile input.
- `forensics.preserve` collision fallback now tries `-2 … -99` and then
  `tempfile.mkdtemp` instead of giving up at one collision.

### Test coverage

- **503 passing unit tests** (up from 0 at the start of v0.1.0)
- **13 performance benchmarks**
- **0 ruff findings**
- New test modules: `test_behavioral_monitor.py` (40),
  `test_claude_triage.py` (15), `test_dashboard.py` (40),
  `test_virustotal_lookup.py` (28), `test_ttp_loader.py` (16),
  `test_ttp_ingestor.py` (21), `test_sigma_generator.py` (47)

## [0.1.0] — 2026-05-22

Initial release.

### Pipeline

- **Stage 1a** — CRX parser (`crx_parser.py`) handling CRX2, CRX3, raw ZIP, and bare manifest.json.
- **Stage 1b** — Permission scorer with TTP-calibrated weights and combo bonuses.
- **Stage 1c** — Publisher checker (manual CRX3 protobuf decode, Chrome Web Store update endpoint cross-check).
- **Stage 1d** — OSV / CVE hash lookup against `api.osv.dev`.
- **Stage 1e** — Update velocity analysis with persistent history.
- **Stage 2** — Claude AI triage (`claude-sonnet-4-6`, prompt caching, forced `tool_use`).
- **Stage 3** — Real-time behavioural monitor over Chrome DevTools Protocol (6 detection rules).
- **Stage 4** — SOC alert dispatch to Microsoft Sentinel, Splunk HEC, PagerDuty Events v2, and Slack with deduplication + escalation + retry/backoff.
- **Stage 5** — Remediation orchestrator: preserve → kill → playbook → resolve → report.

### Tooling

- `extguard`, `extguard-monitor`, `extguard-dispatch`, `extguard-remediate` console scripts.
- Comprehensive `pyproject.toml` with ruff + pytest config.
- GitHub Actions workflow for test matrix + lint + wheel build.
- Initial `README.md` with quickstart, architecture diagram, and detection coverage table.
