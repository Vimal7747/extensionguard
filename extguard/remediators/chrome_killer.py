# remediators/chrome_killer.py - Block a Chrome extension via enterprise policy
#
# Chrome obeys the ExtensionInstallBlocklist policy from:
#   Windows  HKLM\Software\Policies\Google\Chrome\ExtensionInstallBlocklist  (registry)
#   Linux    /etc/opt/chrome/policies/managed/<file>.json                     (JSON file)
#   macOS    a configuration profile (MDM or user-approved) - NOT `defaults write`
#   Fleet    Google Workspace / Chrome Browser Cloud Management (Chrome Policy API)
#
# Blocking by exact extension ID also disables and removes an extension that
# is already installed, once Chrome reloads policy (at restart, or within
# ~3 hours; chrome://policy -> "Reload policies" applies it immediately).
#
# Scope: the Windows / Linux / macOS methods change THIS machine only. To
# block across a fleet, use block_extension_workspace() or push the policy
# through your GPO / Intune / MDM.
#
# Every function validates the extension ID first ("*" would block every
# extension) and supports dry-run. Admin / root rights are needed to write the
# Windows and Linux locations; the error says so rather than crashing.

import json
import os
import platform
import plistlib
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from extguard import paths
from extguard.models import is_valid_extension_id

# Chrome enterprise policy locations (per platform)
WINDOWS_POLICY_KEY = r"Software\Policies\Google\Chrome\ExtensionInstallBlocklist"
# Registry hive, by winreg constant name. Machine-wide policy lives in HKLM;
# the tests point this at HKEY_CURRENT_USER and a scratch key so they can
# exercise the real registry without touching Chrome's policy.
WINDOWS_POLICY_ROOT = "HKEY_LOCAL_MACHINE"
LINUX_POLICY_DIR = Path("/etc/opt/chrome/policies/managed")
LINUX_POLICY_FILE = LINUX_POLICY_DIR / "extguard_blocklist.json"
MACOS_POLICY_DOMAIN = "com.google.Chrome"


def _reject_bad_id(extension_id, platform_name: str, method: str) -> dict | None:
    """
    Every blocking function calls this first. Policy values are powerful:
    "*" in ExtensionInstallBlocklist blocks EVERY extension, and a stray string
    could corrupt the policy list. Only a real 32-letter a-p ID is accepted.
    """
    if is_valid_extension_id(extension_id):
        return None
    return {
        "ok": False,
        "platform": platform_name,
        "method": method,
        "error": f"Invalid extension ID {extension_id!r} - expected 32 letters a-p",
    }


def block_extension(extension_id: str, dry_run: bool = False) -> dict:
    """
    Cross-platform dispatcher that picks the right method for the current OS.

    Returns a result dict:
      {
        "ok":       bool,
        "applied":  bool,    # True = Chrome will enforce it; False = an artefact
                             #        was produced but still needs deploying (macOS)
        "platform": str,
        "method":   str,     # "registry", "policy-file", "configuration-profile"
        "details":  dict,
        "error":    str,     # only when ok=False
      }
    """
    system = platform.system().lower()

    if system == "windows":
        return block_extension_windows(extension_id, dry_run)
    elif system == "darwin":
        return block_extension_macos(extension_id, dry_run)
    elif system == "linux":
        return block_extension_linux(extension_id, dry_run)
    else:
        return {
            "ok": False,
            "platform": system,
            "error": f"Unsupported platform: {system}",
        }


# ---------------------------------------------------------------------------
# Windows: HKLM registry via winreg
# ---------------------------------------------------------------------------


def block_extension_windows(extension_id: str, dry_run: bool = False) -> dict:
    """
    Add an extension ID to the Chrome ExtensionInstallBlocklist policy in HKLM.

    Each blocklist entry is a REG_SZ value at a numbered slot:
      HKLM\\Software\\Policies\\Google\\Chrome\\ExtensionInstallBlocklist
        1  =  "abcdefghijklmnopabcdefghijklmnop"
        2  =  "some-other-extension-id"

    Requires the script to be running as Administrator.
    """
    bad = _reject_bad_id(extension_id, "windows", "registry")
    if bad:
        return bad
    result = {
        "ok": False,
        "applied": False,
        "platform": "windows",
        "method": "registry",
        "details": {
            "registry_path": f"HKLM\\{WINDOWS_POLICY_KEY}",
            "extension_id": extension_id,
        },
    }

    if dry_run:
        result["ok"] = True
        result["details"]["dry_run"] = True
        result["details"]["note"] = (
            f"Would write extension ID '{extension_id}' to HKLM\\{WINDOWS_POLICY_KEY}"
        )
        return result

    # winreg is only available on Windows — import inside the function so the
    # module still loads on Linux/macOS for the cross-platform dispatcher
    try:
        import winreg
    except ImportError:
        result["error"] = "winreg module not available (not running on Windows)"
        return result

    try:
        # Open or create the policy key (CreateKey is idempotent — opens if exists)
        key = winreg.CreateKey(getattr(winreg, WINDOWS_POLICY_ROOT), WINDOWS_POLICY_KEY)
        try:
            existing_slot = _find_existing_slot(key, extension_id)
            if existing_slot is not None:
                result["ok"] = result["applied"] = True
                result["details"]["already_blocked"] = True
                result["details"]["slot"] = existing_slot
                return result

            next_slot = _find_next_free_slot(key)
            winreg.SetValueEx(key, str(next_slot), 0, winreg.REG_SZ, extension_id)
        finally:
            winreg.CloseKey(key)

        result["ok"] = result["applied"] = True
        result["details"]["slot"] = next_slot

    except PermissionError:
        result["error"] = (
            "Access denied writing to HKLM. Re-run the remediation tool as Administrator."
        )
    except OSError as exc:
        result["error"] = f"Registry write failed: {exc}"

    return result


def _find_next_free_slot(key) -> int:
    """Find the smallest unused numbered slot in the blocklist key."""
    import winreg

    slot = 1
    while True:
        try:
            winreg.QueryValueEx(key, str(slot))
            slot += 1
        except FileNotFoundError:
            return slot


def _find_existing_slot(key, extension_id: str):
    """
    Return the slot (value name) holding extension_id, else None.

    Enumerates EVERY value. The old version probed 1, 2, 3... and stopped at
    the first missing number, so an ID stored after a gap (slots 1, 2, 4)
    was never found and got added a second time.
    """
    import winreg

    index = 0
    while True:
        try:
            name, value, _value_type = winreg.EnumValue(key, index)
        except OSError:  # no more values
            return None
        if value == extension_id:
            return int(name) if str(name).isdigit() else name
        index += 1


def unblock_extension_windows(extension_id: str, dry_run: bool = False) -> dict:
    """
    Reverse operation: remove an extension ID from the blocklist.
    Useful for false positive recovery.
    """
    bad = _reject_bad_id(extension_id, "windows", "registry")
    if bad:
        return bad
    result = {
        "ok": False,
        "platform": "windows",
        "method": "registry",
        "details": {"extension_id": extension_id},
    }

    if dry_run:
        result["ok"] = True
        result["details"]["dry_run"] = True
        return result

    try:
        import winreg
    except ImportError:
        result["error"] = "winreg not available"
        return result

    try:
        key = winreg.OpenKey(
            getattr(winreg, WINDOWS_POLICY_ROOT), WINDOWS_POLICY_KEY, 0, winreg.KEY_ALL_ACCESS
        )
        try:
            slot = _find_existing_slot(key, extension_id)
            if slot is None:
                result["ok"] = True
                result["details"]["note"] = "Extension was not in the blocklist"
                return result
            winreg.DeleteValue(key, str(slot))
        finally:
            winreg.CloseKey(key)
        result["ok"] = True
        result["details"]["removed_slot"] = slot
    except PermissionError:
        result["error"] = "Access denied — requires Administrator"
    except OSError as exc:
        result["error"] = f"Registry delete failed: {exc}"

    return result


# ---------------------------------------------------------------------------
# Linux: JSON file in /etc/opt/chrome/policies/managed/
# ---------------------------------------------------------------------------


def block_extension_linux(extension_id: str, dry_run: bool = False) -> dict:
    """
    Add an extension ID to a JSON policy file Chrome reads at startup.
    Multiple files in the managed/ directory are merged by Chrome.
    The file is written atomically, and a file that isn't valid JSON is left
    alone (overwriting it would silently drop whatever else it contained).
    """
    bad = _reject_bad_id(extension_id, "linux", "policy-file")
    if bad:
        return bad
    result = {
        "ok": False,
        "applied": False,
        "platform": "linux",
        "method": "policy-file",
        "details": {
            "policy_file": str(LINUX_POLICY_FILE),
            "extension_id": extension_id,
        },
    }

    if dry_run:
        result["ok"] = True
        result["details"]["dry_run"] = True
        result["details"]["note"] = (
            f"Would write to {LINUX_POLICY_FILE} with extension ID '{extension_id}' "
            "in ExtensionInstallBlocklist array"
        )
        return result

    try:
        existing = {"ExtensionInstallBlocklist": []}
        if LINUX_POLICY_FILE.exists():
            try:
                existing = json.loads(LINUX_POLICY_FILE.read_text(encoding="utf-8"))
            except ValueError:
                result["error"] = (
                    f"{LINUX_POLICY_FILE} is not valid JSON - fix or remove it first "
                    "(not overwriting a policy file we can't read)"
                )
                return result
            if not isinstance(existing, dict):
                result["error"] = f"{LINUX_POLICY_FILE} is not a JSON object - not overwriting"
                return result

        blocklist = existing.setdefault("ExtensionInstallBlocklist", [])
        if not isinstance(blocklist, list):
            result["error"] = "ExtensionInstallBlocklist in the policy file is not a list"
            return result
        if extension_id in blocklist:
            result["details"]["already_blocked"] = True
        else:
            blocklist.append(extension_id)

        LINUX_POLICY_DIR.mkdir(parents=True, exist_ok=True)
        _atomic_write_text(LINUX_POLICY_FILE, json.dumps(existing, indent=2))

        result["ok"] = result["applied"] = True
        result["details"]["blocklist_size"] = len(blocklist)

    except PermissionError:
        result["error"] = f"Access denied writing {LINUX_POLICY_FILE}. Re-run with sudo."
    except OSError as exc:
        result["error"] = f"Policy file write failed: {exc}"

    return result


def _atomic_write_text(path: Path, text: str):
    """Write via a temp file + rename, so Chrome never reads half a file."""
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".extguard-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, 0o644)  # Chrome (running as the user) must be able to read it
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# macOS: configuration profile
# ---------------------------------------------------------------------------


def block_extension_macos(
    extension_id: str, dry_run: bool = False, output_dir: Path | str | None = None
) -> dict:
    """
    Produce a configuration profile (.mobileconfig) that blocklists the
    extension in Chrome.

    Why not `defaults write com.google.Chrome ...`: Chrome on macOS only
    enforces policies delivered as MANAGED preferences (a configuration
    profile from MDM, or one the user installs and approves). Plain
    `defaults write` values are ignored - the old code reported success
    while nothing was blocked.

    The profile is NOT applied by this function (macOS won't let a script
    silently install one). Deploy it through your MDM (Jamf, Kandji, Intune)
    or double-click it and approve it in System Settings > Profiles. If your
    MDM already manages Chrome's ExtensionInstallBlocklist, add the ID there
    instead - two profiles setting the same key conflict.
    """
    bad = _reject_bad_id(extension_id, "darwin", "configuration-profile")
    if bad:
        return bad
    out_dir = Path(output_dir) if output_dir else paths.data_dir() / "profiles"
    profile_path = out_dir / f"extguard-block-{extension_id}.mobileconfig"
    result = {
        "ok": False,
        "applied": False,
        "platform": "darwin",
        "method": "configuration-profile",
        "details": {
            "domain": MACOS_POLICY_DOMAIN,
            "extension_id": extension_id,
            "profile_path": str(profile_path),
            "note": (
                "Profile created but NOT applied - deploy it via MDM, or open it and "
                "approve it in System Settings > Profiles"
            ),
        },
    }

    if dry_run:
        result["ok"] = True
        result["details"]["dry_run"] = True
        result["details"]["note"] = f"Would write configuration profile {profile_path}"
        return result

    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        profile_path.write_bytes(build_mobileconfig(extension_id))
        result["ok"] = True
    except OSError as exc:
        result["error"] = f"Could not write configuration profile: {exc}"
    return result


def build_mobileconfig(extension_id: str) -> bytes:
    """A minimal configuration profile setting Chrome's ExtensionInstallBlocklist."""
    payload_uuid = str(uuid.uuid4()).upper()
    profile_uuid = str(uuid.uuid4()).upper()
    profile = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"com.extensionguard.block.{extension_id}",
        "PayloadUUID": profile_uuid,
        "PayloadDisplayName": f"ExtensionGuard - block Chrome extension {extension_id}",
        "PayloadDescription": (
            "Adds a malicious Chrome extension to Chrome's ExtensionInstallBlocklist. "
            f"Generated {datetime.now(timezone.utc).isoformat()}."
        ),
        "PayloadScope": "System",
        "PayloadContent": [
            {
                "PayloadType": MACOS_POLICY_DOMAIN,
                "PayloadVersion": 1,
                "PayloadIdentifier": f"com.extensionguard.block.{extension_id}.chrome",
                "PayloadUUID": payload_uuid,
                "PayloadDisplayName": "Google Chrome extension blocklist",
                "ExtensionInstallBlocklist": [extension_id],
            }
        ],
    }
    return plistlib.dumps(profile)


# ---------------------------------------------------------------------------
# Google Workspace / Chrome Browser Cloud Management (fleet-wide)
# ---------------------------------------------------------------------------

# Chrome Policy API: per-app install policy. Request shape taken from Google's
# documentation ("Code samples for app policies", Chrome Policy API).
CBCM_APP_POLICY_SCHEMA = "chrome.users.apps.InstallType"
CBCM_SCOPE = "https://www.googleapis.com/auth/chrome.management.policy"
# Needed to turn an org-unit PATH ("/Engineering") into the org-unit ID the
# Chrome Policy API requires ("orgunits/03ph8a2z...")
ORGUNIT_SCOPE = "https://www.googleapis.com/auth/admin.directory.orgunit.readonly"


def build_workspace_request(extension_id: str, org_unit_id: str) -> dict:
    """The batchModify body that sets the extension to BLOCKED for an org unit."""
    return {
        "requests": [
            {
                "policyTargetKey": {
                    "targetResource": f"orgunits/{org_unit_id}",
                    "additionalTargetKeys": {"app_id": f"chrome:{extension_id}"},
                },
                "policyValue": {
                    "policySchema": CBCM_APP_POLICY_SCHEMA,
                    "value": {"appInstallType": "BLOCKED"},
                },
                "updateMask": {"paths": "appInstallType"},
            }
        ]
    }


def block_extension_workspace(
    extension_id: str,
    org_unit: str,
    cfg: dict,
    dry_run: bool = False,
) -> dict:
    """
    Block an extension for every browser in a Google Workspace org unit via
    the Chrome Policy API (customers.policies.orgunits.batchModify).

    Args:
        extension_id: 32-char Chrome extension ID to block.
        org_unit:     Org unit PATH, e.g. "/Engineering" ("/" = whole domain).
        cfg:          The "workspace" section of extguard.conf.json:
                        service_account_json  path to the service account key
                        customer_id           e.g. "C01abc123" (or "my_customer")
                        admin_email           a Workspace admin the service
                                              account impersonates (domain-wide
                                              delegation) - required by Google
                        org_unit_id           optional: skip the path lookup
        dry_run:      Show the exact request without calling Google.

    Setup (one-time): enable the Chrome Policy API and Admin SDK API, create a
    service account, grant it domain-wide delegation for the two scopes
    above (Admin console > Security > API controls), download its key.
    """
    bad = _reject_bad_id(extension_id, "google-workspace", "chrome-policy-api")
    if bad:
        return bad
    result = {
        "ok": False,
        "applied": False,
        "platform": "google-workspace",
        "method": "chrome-policy-api",
        "details": {
            "extension_id": extension_id,
            "org_unit": org_unit,
            "customer_id": cfg.get("customer_id"),
        },
    }

    # --- 1. Validate config -----------------------------------------------
    sa_path = cfg.get("service_account_json")
    customer_id = cfg.get("customer_id")
    admin_email = cfg.get("admin_email")
    missing = [
        name
        for name, value in (
            ("service_account_json", sa_path),
            ("customer_id", customer_id),
            ("admin_email", admin_email),
        )
        if not value
    ]
    if missing:
        result["error"] = (
            f"workspace.{missing[0]} not configured (needed: service_account_json, customer_id, "
            "admin_email). See the Workspace section of README.md."
        )
        return result

    # --- 2. Dry-run: show exactly what would be sent -----------------------
    if dry_run:
        ou_id = cfg.get("org_unit_id") or f"<id of {org_unit}, looked up at run time>"
        result["ok"] = True
        result["details"]["dry_run"] = True
        result["details"]["request"] = build_workspace_request(extension_id, ou_id)
        result["details"]["note"] = (
            f"Would call chromepolicy.googleapis.com batchModify for customers/{customer_id}: "
            f"app chrome:{extension_id} -> BLOCKED in org unit {org_unit}"
        )
        return result

    # --- 3. Lazy import - google libs are an optional dep ------------------
    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build
        from googleapiclient.errors import HttpError
    except ImportError:
        result["error"] = (
            'Google API libraries not installed. Run:  pip install "extensionguard[workspace]"'
        )
        return result

    if not Path(sa_path).exists():
        result["error"] = f"Service account JSON file not found at {sa_path}"
        return result

    try:
        creds = service_account.Credentials.from_service_account_file(
            sa_path, scopes=[CBCM_SCOPE, ORGUNIT_SCOPE]
        ).with_subject(admin_email)
    except (ValueError, FileNotFoundError) as exc:
        result["error"] = f"Failed to load service account credentials: {exc}"
        return result

    try:
        # --- 4. Org-unit path -> org-unit ID ------------------------------
        ou_id = cfg.get("org_unit_id")
        if not ou_id:
            directory = build("admin", "directory_v1", credentials=creds, cache_discovery=False)
            path = org_unit.strip("/")
            if path:
                ou = directory.orgunits().get(customerId=customer_id, orgUnitPath=path).execute()
                ou_id = ou["orgUnitId"]
            else:
                # The root OU: its ID is the parent of any top-level OU
                listing = (
                    directory.orgunits().list(customerId=customer_id, type="children").execute()
                )
                children = listing.get("organizationUnits", [])
                if not children:
                    result["error"] = (
                        "Could not determine the root org unit ID - set workspace.org_unit_id"
                    )
                    return result
                ou_id = children[0]["parentOrgUnitId"]
        ou_id = str(ou_id).removeprefix("id:")
        result["details"]["org_unit_id"] = ou_id

        # --- 5. Chrome Policy API ------------------------------------------
        service = build("chromepolicy", "v1", credentials=creds, cache_discovery=False)
        response = (
            service.customers()
            .policies()
            .orgunits()
            .batchModify(
                customer=f"customers/{customer_id}",
                body=build_workspace_request(extension_id, ou_id),
            )
            .execute()
        )
        result["ok"] = result["applied"] = True
        result["details"]["api_response"] = response
        return result

    except HttpError as exc:
        result["error"] = f"Google API HTTP {exc.resp.status}: {exc._get_reason()}"
        return result
    except Exception as exc:
        result["error"] = f"Google API call failed: {type(exc).__name__}: {exc}"
        return result
