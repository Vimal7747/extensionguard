# ExtensionGuard TTP Library

This directory holds the threat-intelligence library that Claude consults
during Stage 2 AI triage. Every `.md` file under this tree is concatenated
into the system prompt (with prompt caching, so it's only tokenised once
per cache window).

## Layout

- `campaigns/` — One file per named adversary campaign (TeamPCP, Shai-Hulud, ...)
- `patterns/`  — Generic attack-chain patterns mapped to MITRE techniques
- `mitre_reference.md` — Quick-reference for the technique IDs we cite

## Format

Plain markdown. Claude reads the prose, so write for an analyst audience.
Each campaign file should include:

1. **Attack vector** — How the adversary got their code into a user's browser
2. **Permission profile** — Exact `permissions` / `host_permissions` they request
3. **Behavioural IOCs** — Network patterns, storage usage, console signatures
4. **MITRE mapping** — Bullet list of relevant technique IDs

## Updating

Files in this directory are typically synced from a central GitHub repo via
the webhook ingestor (see `ttp_ingestor.py`). Manual edits here will be
overwritten on the next sync — make changes in the source repo instead.

To pull manually:

```powershell
extguard-ttp-sync
```

To set up the GitHub webhook, see the `webhook` section of `extguard.conf.json`.
