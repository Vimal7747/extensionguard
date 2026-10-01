# Recorded API responses

Real responses captured from the live services on 2026-09-29. Tests replay
them instead of hand-written mocks, so the parsers are checked against what the
services actually send.

| File | Source | Used by |
|---|---|---|
| `cws_known_extension.xml` | Chrome Web Store update endpoint, Google Translate (`aapbdbdomjkkjkaonfhkkikfgjllcleb`) | `test_publisher_checker.py` |
| `cws_unknown_extension.xml` | Same endpoint, an ID that doesn't exist (`a` × 32) | `test_publisher_checker.py` |
| `crx3_header_google_translate.bin` | The CRX3 signing header (public keys + signatures only, no extension code) cut from the Google Translate `.crx` | `test_publisher_checker.py` |
| `osv_querybatch_lodash_isnumber.json` | `POST https://api.osv.dev/v1/querybatch` for lodash 4.17.20 and is-number 7.0.0 | `test_osv_lookup.py` |
| `osv_hash_query_rejected.json` | `POST https://api.osv.dev/v1/query` with a `{"hash": ...}` body. OSV answers HTTP 400, which is why ExtensionGuard no longer sends it | `test_osv_lookup.py` |

The CWS requests use the same parameters as `publisher_checker.CWS_UPDATE_TEMPLATE`.
With fewer parameters the store answers `noupdate` and omits `version` and
`hash_sha256`.

## Refreshing

When a live test (`tests/test_live_apis.py`) fails, an upstream API changed.
Re-capture the affected file, fix the parser to match, and note the new
capture date here. Don't edit a recording by hand to make a test pass.
