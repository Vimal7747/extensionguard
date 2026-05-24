# Changelog

All notable changes to ExtensionGuard. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [SemVer](https://semver.org/).

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
