# MITRE ATT&CK Quick Reference (Browser-Extension Relevant)

| ID | Name | Stage |
| --- | --- | --- |
| T1176 | Browser Extensions | Initial access / Persistence |
| T1555 | Credentials from Password Stores | Credential Access |
| T1555.003 | Credentials from Web Browsers (cookies, saved passwords) | Credential Access |
| T1071 | Application Layer Protocol (C2) | Command & Control |
| T1071.001 | Web Protocols | Command & Control |
| T1059 | Command and Scripting Interpreter | Execution |
| T1059.007 | JavaScript | Execution |
| T1530 | Data from Cloud Storage Object | Collection / Exfiltration |
| T1113 | Screen Capture (via `tabs.captureVisibleTab`) | Collection |
| T1185 | Browser Session Hijacking | Collection |
| T1074 | Data Staged | Collection |

When generating the analyst narrative, cite the most specific applicable sub-technique
(e.g. `T1555.003` is more useful than the parent `T1555`).
