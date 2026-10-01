# High-Risk Permission Combination Signatures

These are generic attack-chain patterns — when an extension requests this
specific set of permissions, treat the extension as suspicious even if no
named campaign matches.

## COMBO-01: Session Token Harvester

**Required:** `cookies` + `tabs` + `storage` + `<all_urls>`

**Risk:** Can enumerate all open tabs to find authenticated sessions, read
their cookies, and stage harvested tokens in `chrome.storage.local` before
batch exfil. This was the TeamPCP profile exactly.

**Seen in:** TeamPCP, CredStealer-2024.

## COMBO-02: Traffic MITM

**Required:** `webRequest` + `webRequestBlocking` + `cookies`

**Risk:** Can read and rewrite any HTTP/S request/response, extract auth
headers, inject malicious JS into served pages.

## COMBO-03: Debugger Credential Extraction

**Required:** `debugger` + `tabs`

**Risk:** Attach debugger to any tab, pause execution, walk the heap to
extract passwords, tokens, PII from JS memory — bypasses CSP entirely.

**Seen in:** Shai-Hulud family.

## COMBO-04: Silent Extension Persistence

**Required:** `management` + `storage`  (+ optional: `background.persistent=true`)

**Risk:** Can disable AV/EDR browser extensions, store self-reinstall config,
survive manual removal attempts by re-enabling via the management API.

## Publisher Red Flags

- Cert / account age < 30 days before first publish.
- Version bump > 10x within 7 days (supply-chain injection pattern).
- Publisher email on a free provider (gmail, outlook) for an enterprise-targeting tool.
- No privacy-policy URL in manifest despite requesting sensitive permissions.
