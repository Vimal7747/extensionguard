# TeamPCP — Nx Console Supply Chain Attack (May 2026)

## Attack vector

Compromised npm publisher account → malicious .crx pushed via Chrome Web Store
auto-update to all installs of the Nx Console extension.

## Permission profile (exact match)

```json
{
  "permissions": ["cookies", "tabs", "storage", "webRequest", "webRequestBlocking"],
  "host_permissions": ["<all_urls>"]
}
```

## Behavioural IOCs

- Background service worker makes POST requests every 60 seconds.
- Exfil endpoints follow pattern: `https://<random>.workers.dev/collect`
  (Cloudflare Workers used to evade domain-reputation blocking).
- Targeted session cookies for: `github.com`, `npmjs.com`, `*.atlassian.net`,
  `*.slack.com`, `*.aws.amazon.com`.
- Cookie harvest staged in `chrome.storage.local` under key `s_cache` before
  exfiltration batch.
- Publisher cert issued < 14 days before malicious update pushed.

## MITRE ATT&CK mapping

- **T1176** — Browser Extensions (persistence / initial access)
- **T1555.003** — Credentials from Web Browsers
- **T1071.001** — Application Layer Protocol: Web Protocols (C2)
- **T1530** — Data from Cloud Storage Object (token exfil)
