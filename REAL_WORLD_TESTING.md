# Real-world testing

The unit tests check ExtensionGuard against synthetic samples. This page
records how it behaves on **real, genuine Chrome Web Store extensions**, and
how anyone can repeat the test with one command.

**In short**, from the run on 2026-10-14:

- **7 of 7 genuine extensions** are rated MEDIUM ("review / allowlist") with
  no evidence of malice, and the runtime monitor raised **0 alerts** about
  them in a real browser.
- **5 of 5 attack samples** are still rated HIGH or CRITICAL.
- The monitor caught the test-only canary extension's fake token **both
  ways**: saved to storage the moment it started, and sent over the network
  (7 requests out of 7). So "0 alerts" means the monitor was watching and saw
  nothing, not that it was asleep.

The same test runs **every week** on GitHub against the then-current store
versions ([`real-extensions.yml`](https://github.com/Vimal7747/extensionguard/actions/workflows/real-extensions.yml)).
Each run's summary page shows its results table.

## Why these extensions

They are hard cases on purpose. All seven are legitimate and widely used, but
their permissions look like what malware asks for. A scanner that counts
permissions flags them all, and a SOC that blocks on that would break the
company's password manager.

| Extension | What a permission scan sees |
| --- | --- |
| uBlock Origin Lite | `userScripts`, `scripting` and network-rule control on every site; can strip security headers |
| Bitwarden Password Manager | Code injection into every site, `webRequest`, clipboard read, native messaging (optional) |
| Grammarly | `cookies` + `identity` + all sites: the TeamPCP session-token-harvesting combination |
| Dark Reader | `scripting` on every site, content script in the page's MAIN world |
| React Developer Tools | `scripting` + `tabs` on `<all_urls>` |
| JSON Formatter | Content script on every page, in the MAIN world |
| Google Translate | Content script on every page (Google's own extension) |

## Method

Everything is done by [`tools/real_extension_check.py`](https://github.com/Vimal7747/extensionguard/blob/main/tools/real_extension_check.py).

1. **Genuine builds only.** For each extension the tool asks the Chrome Web
   Store update service for the current build. This is the same request
   Chrome itself makes, and the reply includes the version, download URL,
   size and SHA-256. The tool downloads the file from Google and **refuses
   to test it unless its SHA-256 matches the store's**. Nothing is committed
   to this repository or redistributed.
2. **Static scan.** It runs the real `extguard` CLI on each file
   (`--json --no-ai`), with the Web Store and OSV checks online and
   VirusTotal and AI triage off, so anyone can reproduce the run without API
   keys. A genuine extension **passes** when it is:
   - not rated HIGH or CRITICAL;
   - reported with no evidence of malice;
   - recognised as the verified store build (signed ID, byte-identical);
   - scanned with every stage completed.
3. **Attack samples (positive controls).** Five synthetic packages modelled
   on public reports of real campaigns are scanned offline:
   - TeamPCP permissions, manifest only;
   - TeamPCP permissions plus cookie-stealing code;
   - Shai-Hulud permissions, manifest only;
   - Shai-Hulud permissions plus an obfuscated `eval` loader;
   - a Cyberhaven-style hijacked patch update, scanned after its clean
     predecessor.

   Each one must reach at least its expected level. Without this step, "no
   false positives" could also come from a detector that never fires.
4. **Runtime (`--runtime`).** **Chrome for Testing** starts empty:
   headless, with a throwaway profile and nothing from a real browser.
   - `extguard-monitor` attaches over the DevTools protocol first. **Then**
     the seven extensions are installed into the running browser, so the
     monitor sees each one's first-install activity on every machine, fast
     or slow.
   - Each one is unpacked with its store signing key, so it keeps its real
     Web Store ID.
   - The browser visits six ordinary sites for 15 seconds each:
     example.com, Wikipedia, GitHub, BBC News, MDN and a GitHub API JSON
     page.
   - Chrome's own `chrome://extensions` list confirms each extension is
     installed and enabled.
   - A small **canary** extension (test-only, not on the store) misuses a
     fake GitHub token in the two ways the monitor watches. On its very
     first line it saves the token to `chrome.storage`; this RULE-04 alert
     only fires if the monitor's hooks were in place before the extension's
     code ran. Every time a tab loads, it also posts the token to a local
     server (RULE-02). Both **must** be reported.

   This part **passes** when every genuine extension loaded, none of them
   caused an alert, the canary was caught both ways, and the monitor didn't
   crash.

## Latest results

Run on 2026-10-14 with ExtensionGuard 0.4.1, Python 3.13.6, Windows 11 and
Chrome for Testing 155.0.8059.39. **Result: PASS.**

### Genuine Web Store extensions (static scan)

The **capability score** is what the permissions alone would give, out of
100. The verdict is capped at MEDIUM (44, the top of the MEDIUM band)
because each file is a verified store build with no evidence of malicious
behaviour. See [verdicts](https://github.com/Vimal7747/extensionguard/blob/main/README.md#verdicts-exit-codes-and-automation).

| Extension | Version | Capability score | Verdict | Evidence | Result |
| --- | --- | --- | --- | --- | --- |
| uBlock Origin Lite | 2026.1012.1545 | 100 | MEDIUM (44) | none | PASS |
| Bitwarden Password Manager | 2026.9.3 | 100 | MEDIUM (44) | none | PASS |
| Grammarly | 14.1338.0 | 100 | MEDIUM (44) | none | PASS |
| Dark Reader | 4.9.133 | 79 | MEDIUM (44) | none | PASS |
| React Developer Tools | 8.0.0 | 84 | MEDIUM (44) | none | PASS |
| JSON Formatter | 0.10.2 | 68 | MEDIUM (44) | none | PASS |
| Google Translate | 2.0.17 | 44 | MEDIUM (44) | none | PASS |

### Attack samples (must be rated HIGH or CRITICAL)

| Sample | Verdict | Evidence | Result |
| --- | --- | --- | --- |
| TeamPCP permissions, manifest only | HIGH (69) | none (capped: can't be verified) | PASS |
| Shai-Hulud permissions, manifest only | HIGH (69) | none (capped: can't be verified) | PASS |
| TeamPCP package with cookie-exfil code | CRITICAL (100) | sends data to exfil-style hosting: `nx-sync.workers.dev` | PASS |
| Shai-Hulud package with obfuscated eval loader | CRITICAL (100) | obfuscated code: `bg.js` | PASS |
| Cyberhaven-style hijacked patch update | HIGH (60) | an update started sending data to `cyberhavenext.workers.dev` | PASS |

### Runtime: Chrome for Testing + extguard-monitor, 6 sites, 134 seconds

| Extension | Loaded | Alerts | Result |
| --- | --- | --- | --- |
| uBlock Origin Lite | yes | 0 | PASS |
| Bitwarden Password Manager | yes | 0 | PASS |
| Grammarly | yes | 0 | PASS |
| Dark Reader | yes | 0 | PASS |
| React Developer Tools | yes | 0 | PASS |
| JSON Formatter | yes | 0 | PASS |
| Google Translate | yes | 0 | PASS |
| ExtensionGuard canary (fake token, must be caught) | yes | 7 RULE-02 (network), 1 RULE-04 (storage, at start-up) | PASS |

### Exact builds tested

Anyone can check these against the store. For example, Chrome's update
reply for an extension includes `hash_sha256`.

| Extension | Web Store ID | Version | Size (bytes) | SHA-256 |
| --- | --- | --- | --- | --- |
| uBlock Origin Lite | `ddkjiahejlhfcafbddmgiahcphecmpfh` | 2026.1012.1545 | 9,125,970 | `de67c08f8f7a337bc82c2cc86423eea0243e02be3fd3bd9e289c20c82eadb24a` |
| Bitwarden Password Manager | `nngceckbapebfimnlniiiahkandclblb` | 2026.9.3 | 24,051,044 | `9964f660a11023cb19a730b7f908353ec1dae77a027c8192315d0a7f3d8ef921` |
| Grammarly | `kbfnbcaeplbcioakkpcpgfkobkghlhen` | 14.1338.0 | 18,433,190 | `bd5236bf128a4c24976b04fe42bd1a9930396cad31264061d359a8d47cd06e46` |
| Dark Reader | `eimadpbcbfnmbkopoojfekhnkhdbieeh` | 4.9.133 | 851,022 | `ee38f20d1d50789f4b482c9a1a5dadab599b8682fd2a7dfb7de21fae8561b918` |
| React Developer Tools | `fmkadmapgofadopljbjfkapdkoienihi` | 8.0.0 | 670,658 | `d92e1122a16362cc5510927068a5b1a8d50b43e1f3be25c3117f7c005807b302` |
| JSON Formatter | `bcjindcccaagfpapjjmafapmmgkkhgoa` | 0.10.2 | 20,840 | `5e0ebde71ee60f997a9f5fc0850e6ae4a9f67006dbf662f00507f99e957c2b21` |
| Google Translate | `aapbdbdomjkkjkaonfhkkikfgjllcleb` | 2.0.17 | 1,145,560 | `3f752c27ae39de4bfc881ecacea4a3b4c50c676daecfd9f2fc8c50f5688c8dd1` |

## What the test has found

The test is only useful because it can fail. It has failed twice, and both
times it found real problems.

### First run, by hand (2026-10-07, ExtensionGuard 0.3.0)

- **Static:** five of the seven genuine extensions were rated CRITICAL, one
  HIGH and one MEDIUM, all on permissions alone.
- **Runtime:** the monitor raised six false alarms. Grammarly sending its own
  login token to its own servers, Grammarly's sign-in token in its storage,
  and Dark Reader's image cache were all reported as credential theft or
  data staging.
- **Bugs:** it also exposed seven detector bugs, such as uBlock Origin Lite's
  CSS filter rules read as "exfil endpoints" and minified code called
  "obfuscated", plus a way for a malicious extension to slip past one
  monitor rule.

All of it was fixed in 0.4.0. The fixes are listed under "Fixed" in the
[CHANGELOG](https://github.com/Vimal7747/extensionguard/blob/main/CHANGELOG.md),
and unit tests now cover the shapes these extensions exposed. Verdicts now
need evidence, not just permissions.

### First run on GitHub (2026-10-14, ExtensionGuard 0.4.0)

The first run on a GitHub Linux runner failed. uBlock Origin Lite raised
two RULE-04 alerts: 565 KB and 455 KB written to storage "in one write".
The same test had passed on a faster Windows PC. Working out why found
three problems:

- **The test depended on machine speed.** Extensions were loaded when
  Chrome started, before the monitor attached. On a fast machine uBlock
  finished copying its filter data into storage before the monitor was
  watching, and on a slow one it didn't. Now Chrome starts empty, the
  monitor attaches, and only then are the extensions installed, so every
  machine sees the same thing.
- **A real monitor bug, a regression in 0.4.0.** The canary was extended
  to save its fake token to storage on its very first line, and the monitor
  missed it. For a newly started extension worker, the in-extension hooks
  (RULE-04, RULE-05, RULE-07) went in only after the worker's start-up code
  had run. The extension-name lookup added in 0.4.0 used up the "pause
  before the first script" the hooks rely on. Network rules weren't
  affected. Fixed, with a unit test, and the canary now proves the hook
  timing on every run.
- **A false positive.** RULE-04 alerted on any storage write of 50,000
  bytes or more, whatever it contained. uBlock's writes were its own
  packaged cosmetic-filter CSS (`css.specific.easylist`,
  `css.specific.ublock-filters`), on every install and filter update. Size
  alone no longer alerts; credentials, cookie dumps and large encoded blobs
  still do. That size check was never part of RULE-04's documented
  behaviour.

## How to reproduce

You need Python 3.10 or newer, a checkout of this repository and an internet
connection. The seven downloads total about 55 MB.

```bash
pip install -e .
python tools/real_extension_check.py                     # static scan + attack samples
python tools/real_extension_check.py --runtime --chrome PATH/TO/chrome
```

- **Chrome for Testing** is needed for `--runtime`, because branded Chrome
  ignores `--load-extension`. Download the zip for your platform from the
  [official Chrome for Testing page](https://googlechromelabs.github.io/chrome-for-testing/)
  and pass the path of the `chrome` (or `chrome.exe`) inside it.
  The tool never touches your normal browser or its profile.
- **Reports:** `--json-report report.json --markdown report.md` write the
  full report and the tables above.
- **Downloads:** `--cache-dir DIR` keeps the downloaded files and reuses any
  that still match the store's current build.
- **One extension:** `--only SLUG` (for example `--only grammarly`) tests
  just that one.
- **Exit codes:** `0` every check passed, `1` a check failed (each problem is
  listed), `2` the test couldn't run (network, Chrome).

Results will differ from the tables above when an extension has released a
new version since; that is the point of the weekly run.

## Limitations

Read these before citing the results.

- **Seven extensions is not a statistical sample.** They were chosen as hard
  cases, not at random, so they don't measure a false-positive *rate*.
- **No real malware.** The attack samples are synthetic reconstructions
  based on public reports of TeamPCP, Shai-Hulud and Cyberhaven. Real
  malware may look different. ExtensionGuard has not been tested against
  live samples of those campaigns.
- **The runtime session is short.** It lasts about two minutes, on six public
  sites, with nobody signed in. Behaviour behind a login (a Bitwarden vault,
  a Grammarly account), on other sites, or after days of use is not covered.
  Zero alerts means no false alarms *in this session*, not that these
  extensions can never trigger one.
- **Every extension is a fresh install.** The monitor sees first-install
  behaviour and normal browsing. It doesn't see what happens to an
  extension installed long ago, for example a data migration when it
  updates.
- **The MEDIUM results rely on the 0.4.0 verdict model.** A verified store
  build with no evidence is capped at MEDIUM; the same extension sideloaded,
  so not verifiable, would be capped at HIGH. A *malicious* extension whose
  code looks clean is also MEDIUM at first scan. It is then the runtime
  monitor and the update diff that catch it (risk R14 in
  [THREAT_MODEL.md](https://github.com/Vimal7747/extensionguard/blob/main/THREAT_MODEL.md)).
- **AI triage and VirusTotal were off,** so the run needs no API keys and
  gives the same result for everyone. With AI on, the same verdict cap
  applies to Claude's score.
- **The browser is headless Chrome for Testing, not branded Chrome.** On the
  Linux CI runner it also runs without Chrome's sandbox; the runner is a
  throwaway virtual machine.
