# ExtensionGuard Performance

Throughput and latency baselines for every hot path in the pipeline.
These numbers are how SOC teams capacity-plan: how many extensions can
one ExtensionGuard sensor handle, and where will it bottleneck first?

## Running the benchmarks

```powershell
pip install -e ".[dev]"
pytest tests/benchmarks/
```

To snapshot a baseline for comparison after future changes:

```powershell
pytest tests/benchmarks/ --benchmark-save=baseline
# ... make changes ...
pytest tests/benchmarks/ --benchmark-compare=baseline
```

`pytest-benchmark` auto-calibrates iteration count and reports
min/mean/median/max/stddev/ops. The `Outliers` line in the summary
flags samples >1 standard deviation from the mean (usually GC pauses
or OS scheduling jitter — generally safe to ignore).

## Baseline (Python 3.13.6, Windows 11, single-core wall-clock)

Measured 2026-05-23 on a developer laptop. Your numbers will vary
±2–5× depending on CPU, disk speed, and Python build. **The relative
ordering is what matters — that's stable across hardware.**

| Hot path | Median latency | Throughput (ops/s) | What it represents |
| --- | ---: | ---: | --- |
| `AlertState.should_send` | 1.2 µs | 675,000 | Stage 4 dedup decision per alert |
| `score_permissions` | 5.3 µs | 174,000 | Stage 1b TTP-calibrated scoring |
| `check_publisher` (offline) | 6.6 µs | 147,000 | Stage 1c local validation |
| `enrich` | 18 µs | 52,000 | Stage 4 enrichment per alert |
| `cred_rotation.generate_playbook` (worst case) | 48 µs | 20,000 | Stage 5 playbook synthesis |
| `sigma_generator.generate_all_rules` | 80 µs | 12,000 | SIEM export, all 6 rules |
| `parse_crx` (50 KB CRX) | 213 µs | 4,160 | Stage 1a parsing |
| `osv._scan_zip_contents` (50 KB ZIP) | 233 µs | 4,100 | Stage 1d local content scan |
| `ttp_loader.load_ttp_library` (warm cache) | 382 µs | 2,440 | Stage 2 pre-API per-call cost |
| `forensics.verify_case` | 391 µs | 2,315 | Re-hash every artifact in a case |
| `ttp_loader.load_ttp_library` (cold) | 1.9 ms | 485 | First call after sync |
| `analyse_version` (first run) | 8.2 ms | 120 | Includes atomic JSON-write to history |
| `forensics.preserve` (50 KB CRX) | 14.7 ms | 67 | Full case folder: bytes + manifest + CoC + sidecar SHA |

## What this means in practice

### Pre-install scan (Stage 1 only, no Claude API)

```
parse_crx + score + publisher + osv + velocity ≈ 9 ms per CRX
```

Of which **8 ms is `analyse_version`'s history-file write**. If you're
batch-scanning thousands of extensions and don't need persistent jump
detection, skip `analyse_version` and the per-CRX cost drops to ~250 µs
(**~4,000 CRX/second** on this laptop).

### Stage 2 (Claude AI triage)

Per-extension cost is dominated by the network round-trip to the
Anthropic API, typically **5–15 seconds**. The local overhead from
`ttp_loader.load_ttp_library` (382 µs warm) is negligible. Prompt
caching means the TTP library only re-tokenises when it changes — see
the `claude_triage` cache hit logs.

### Stage 3 (behavioral monitor)

The CDP event loop is bounded by **event arrival rate**, not handler
speed. The handlers themselves are sub-microsecond; the limiting
factor is Chrome's websocket event rate (~hundreds per second per
extension under heavy use).

### Stage 4 (dispatch)

Per-alert cost: **~20 µs** (dedup + enrich) **+ network** (the
adapters' HTTP calls take 50–500 ms each, depending on the SIEM).
With four adapters firing in parallel via the thread pool the
end-to-end critical path is bounded by the slowest adapter.

A single dispatcher process can comfortably handle **20,000+ alerts
per second** at the Python layer before the adapter HTTP calls
become the bottleneck.

### Stage 5 (remediation)

Per-incident: **15 ms** for `forensics.preserve` (proportional to CRX
size — 90 % is hashing). The Chrome blocklist write itself is ~1 ms
(registry edit). Credential rotation playbook generation: 50 µs.

A full incident-response sequence (preserve → kill → playbook →
PD-resolve) completes in well under **100 ms of local CPU**, plus the
PagerDuty resolve HTTP call (~200 ms).

## Bottleneck ranking

If you want to make the pipeline faster, here's where to look first.
The slowest operations are at the top:

1. **`forensics.preserve` (15 ms)** — 90 % is SHA-256 hashing the CRX
   bytes and the manifest JSON. To halve this: switch from
   `hashlib.sha256` (pure Python) to `hashlib.blake2b` (C extension,
   ~2× faster) — but the SHA-256 output is what we promise in the
   chain of custody, so any change is a schema migration.
2. **`analyse_version` (8 ms)** — almost entirely the atomic
   tempfile + `os.replace`. Switching to a SQLite-backed history
   store would amortise the write across many extensions.
3. **`ttp_loader` cold load (1.9 ms)** — `Path.read_text` on each .md
   file. If the TTP library ever grows to thousands of files,
   pre-concatenate into a single `ttp_library.full.md` artifact at
   sync time.
4. **`parse_crx` (213 µs)** — bounded by `zipfile.ZipFile` open +
   `manifest.json` read. Probably not worth optimising further.

## CI behaviour

The benchmark suite is **not** part of `pytest` runs by default —
`pytest.ini` declares `norecursedirs = tests/benchmarks` so unit-test
CI stays fast. Run them explicitly:

```powershell
pytest tests/benchmarks/
```

This separation means a regression in a benchmark won't block a merge,
but it also means **benchmarks aren't run automatically.** For a
larger team, consider adding a separate workflow that runs benchmarks
weekly and posts results to a tracking dashboard.

## When to update this document

Re-run the benchmarks and update the numbers whenever:

- You change anything inside one of the measured functions.
- You change a Python dependency that affects a hot path (e.g.
  upgrading `cryptography` would touch HMAC signing).
- You target a new Python version in CI.
- The pipeline picks up a new performance-sensitive stage.

The `--benchmark-compare` flag is your friend — diff the new numbers
against the saved baseline and only ship the change if the regression
is acceptable.
