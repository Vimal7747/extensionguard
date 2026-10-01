# Shai-Hulud Extension Malware Family (2025–2026)

## Attack vector

Typosquatted extension IDs submitted to Chrome Web Store. Known impersonations:

- React DevTools
- Redux DevTools
- JSON Viewer Pro

## Permission profile (characteristic)

```json
{
  "permissions": ["debugger", "nativeMessaging", "tabs", "storage"],
  "background": { "persistent": true }
}
```

## Behavioural IOCs

- Uses `chrome.debugger.attach()` then `Runtime.evaluate` to extract in-memory
  credentials from React / Angular component state.
- `chrome.runtime.connectNative("com.shai.loader")` spawns native helper.
- `background.js` contains multi-layer eval() obfuscation:

  ```javascript
  eval(atob(String.fromCharCode(...)))
  ```

- Publisher account age < 30 days at first submission.
- Extension update interval set to 1 hour (unusually aggressive).

## MITRE ATT&CK mapping

- **T1176** — Browser Extensions
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1555** — Credentials from Password Stores
- **T1071** — Application Layer Protocol
