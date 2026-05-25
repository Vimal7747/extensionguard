# remediators/chrome_killer.py - Kill / block a Chrome extension across platforms
#
# Chrome obeys enterprise policies set via:
#   Windows  HKLM:\Software\Policies\Google\Chrome\ExtensionInstallBlocklist  (registry)
#   macOS    /Library/Managed Preferences/com.google.Chrome.plist             (plist)
#   Linux    /etc/opt/chrome/policies/managed/<file>.json                     (JSON file)
#
# We use the ExtensionInstallBlocklist policy:
#   - Block by exact extension ID
#   - Special value "*" blocks ALL extensions (overkill, rarely used)
#   - Takes effect on next Chrome launch (kills the running extension too)
#
# This module has THREE methods so a single command works on any host:
#   1. block_extension_windows   - writes HKLM registry values via winreg
#   2. block_extension_macos     - writes a plist via defaults / managed prefs
#   3. block_extension_linux     - writes a JSON file under /etc/opt/chrome/...
#
# All three return a uniform result dict, and all three support dry-run mode.
#
# Admin / sudo / SYSTEM privileges are required to write these locations.
# The module surfaces a friendly error rather than crashing if privileges are missing.

import json
import platform
import subprocess
from pathlib import Path

# Chrome enterprise policy paths (per platform)
WINDOWS_POLICY_KEY = r"Software\Policies\Google\Chrome\ExtensionInstallBlocklist"
LINUX_POLICY_DIR = Path("/etc/opt/chrome/policies/managed")
LINUX_POLICY_FILE = LINUX_POLICY_DIR / "extguard_blocklist.json"
MACOS_POLICY_DOMAIN = "com.google.Chrome"


def block_extension(extension_id: str, dry_run: bool = False) -> dict:
    """
    Cross-platform dispatcher that picks the right method for the current OS.

    Args:
        extension_id: The 32-char Chrome extension ID to block
        dry_run:      If True, show what would be changed but make no changes

    Returns a result dict:
      {
        "ok":       bool,
        "platform": str,
        "method":   str,     # e.g. "registry", "policy-file", "plist"
        "details":  ...,     # platform-specific details
        "error":    str,     # only present when ok=False
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
        1  =  "abcdefghijklmnopqrstuvwxyzabcdef"
        2  =  "some-other-extension-id"
        ...

    Requires the script to be running as Administrator.
    """
    result = {
        "ok": False,
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
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, WINDOWS_POLICY_KEY)

        # Check if this extension ID is already blocked (avoid duplicates)
        existing_slot = _find_existing_slot(key, extension_id)
        if existing_slot is not None:
            winreg.CloseKey(key)
            result["ok"] = True
            result["details"]["already_blocked"] = True
            result["details"]["slot"] = existing_slot
            return result

        # Find next available numbered slot (Chrome expects 1, 2, 3, ...)
        next_slot = _find_next_free_slot(key)

        # Write the extension ID as a REG_SZ string at that slot
        winreg.SetValueEx(key, str(next_slot), 0, winreg.REG_SZ, extension_id)
        winreg.CloseKey(key)

        result["ok"] = True
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
    """Return the slot number if extension_id is already in the blocklist, else None."""
    import winreg

    slot = 1
    while True:
        try:
            value, _ = winreg.QueryValueEx(key, str(slot))
            if value == extension_id:
                return slot
            slot += 1
        except FileNotFoundError:
            return None


def unblock_extension_windows(extension_id: str, dry_run: bool = False) -> dict:
    """
    Reverse operation: remove an extension ID from the blocklist.
    Useful for false positive recovery.
    """
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
            winreg.HKEY_LOCAL_MACHINE, WINDOWS_POLICY_KEY, 0, winreg.KEY_ALL_ACCESS
        )
        slot = _find_existing_slot(key, extension_id)
        if slot is None:
            winreg.CloseKey(key)
            result["ok"] = True
            result["details"]["note"] = "Extension was not in the blocklist"
            return result

        winreg.DeleteValue(key, str(slot))
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
    """
    result = {
        "ok": False,
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
        # Load existing policy (or start fresh)
        existing = {"ExtensionInstallBlocklist": []}
        if LINUX_POLICY_FILE.exists():
            try:
                existing = json.loads(LINUX_POLICY_FILE.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass

        blocklist = existing.setdefault("ExtensionInstallBlocklist", [])
        if extension_id not in blocklist:
            blocklist.append(extension_id)

        # Ensure directory exists with strict perms (root-owned, 0755)
        LINUX_POLICY_DIR.mkdir(parents=True, exist_ok=True)
        LINUX_POLICY_FILE.write_text(json.dumps(existing, indent=2), encoding="utf-8")

        result["ok"] = True
        result["details"]["blocklist_size"] = len(blocklist)

    except PermissionError:
        result["error"] = f"Access denied writing {LINUX_POLICY_FILE}. Re-run with sudo."
    except OSError as exc:
        result["error"] = f"Policy file write failed: {exc}"

    return result


# ---------------------------------------------------------------------------
# macOS: defaults write to managed plist
# ---------------------------------------------------------------------------


def block_extension_macos(extension_id: str, dry_run: bool = False) -> dict:
    """
    On macOS, Chrome reads policy from a managed preferences plist.
    We shell out to `defaults write` since the plist format is non-trivial.

    Note: For proper MDM-managed deployments, this should be pushed via
    your MDM (Jamf, Kandji, Intune). This implementation is for the
    standalone / lab case.
    """
    result = {
        "ok": False,
        "platform": "darwin",
        "method": "plist",
        "details": {
            "domain": MACOS_POLICY_DOMAIN,
            "extension_id": extension_id,
        },
    }

    if dry_run:
        result["ok"] = True
        result["details"]["dry_run"] = True
        result["details"]["command"] = (
            f"sudo defaults write {MACOS_POLICY_DOMAIN} ExtensionInstallBlocklist "
            f"-array-add '{extension_id}'"
        )
        return result

    try:
        # Use `defaults` to append to the array — sudo required
        cmd = [
            "sudo",
            "defaults",
            "write",
            MACOS_POLICY_DOMAIN,
            "ExtensionInstallBlocklist",
            "-array-add",
            extension_id,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

        if proc.returncode == 0:
            result["ok"] = True
        else:
            result["error"] = f"defaults command failed: {proc.stderr.strip() or 'unknown error'}"
    except subprocess.TimeoutExpired:
        result["error"] = "defaults command timed out"
    except FileNotFoundError:
        result["error"] = "'defaults' command not found (is this really macOS?)"

    return result


# ---------------------------------------------------------------------------
# Google Workspace Admin SDK stub (for cloud-managed Chrome fleets)
# ---------------------------------------------------------------------------

# Chrome Browser Cloud Management policy schema name for the install blocklist.
# This is the schema identifier the Chrome Policy API expects.
CBCM_POLICY_SCHEMA = "chrome.users.apps.InstallType"
CBCM_BLOCKLIST_SCHEMA = "chrome.users.apps.ManagedInstall"

# Required OAuth scope for managing Chrome policies in Workspace
CBCM_SCOPE = "https://www.googleapis.com/auth/chrome.management.policy"


def block_extension_workspace(
    extension_id: str,
    org_unit: str,
    cfg: dict,
    dry_run: bool = False,
) -> dict:
    """
    Block an extension across a Google Workspace organisational unit by pushing
    a Chrome Browser Cloud Management policy via the Chrome Policy API.

    Args:
        extension_id: 32-char Chrome extension ID to block.
        org_unit:     Org unit path (e.g. "/Engineering/Senior") to apply the
                      policy to. Use "/" for the root OU.
        cfg:          Configuration dict (the "workspace" section of
                      extguard.conf.json). Must include:
                        service_account_json: path to the service account
                                              credentials JSON file
                        customer_id:          your Workspace customer ID
                                              (find in admin.google.com)
        dry_run:      If True, show what would be pushed without making the
                      API call. Returns the same shape as a real call.

    Setup prerequisites (one-time):
      1. In Google Workspace Admin, enable the Chrome Policy API.
      2. Create a service account in Google Cloud IAM.
      3. Grant the service account "Chrome Policy Admin" or finer-grained
         policy scopes in Workspace Admin > Security > API controls >
         Domain-wide delegation.
      4. Download the service account JSON key and reference it in
         workspace.service_account_json.
      5. Get your customer ID from admin.google.com > Account settings.

    Returns the standard result dict shape used by the cross-platform
    dispatcher.
    """
    result = {
        "ok": False,
        "platform": "google-workspace",
        "method": "admin-sdk",
        "details": {
            "extension_id": extension_id,
            "org_unit": org_unit,
            "customer_id": cfg.get("customer_id"),
        },
    }

    # --- 1. Validate config -----------------------------------------------
    sa_path = cfg.get("service_account_json")
    customer_id = cfg.get("customer_id")
    if not sa_path:
        result["error"] = (
            "workspace.service_account_json not configured. "
            "See the [workspace] section of README.md for setup steps."
        )
        return result
    if not customer_id:
        result["error"] = (
            "workspace.customer_id not configured. "
            "Find it at admin.google.com > Account settings > Profile."
        )
        return result

    # --- 2. Dry-run short-circuit ------------------------------------------
    if dry_run:
        result["ok"] = True
        result["details"]["dry_run"] = True
        result["details"]["note"] = (
            f"Would call chromemanagement.googleapis.com to set "
            f"ExtensionInstallBlocklist += ['{extension_id}'] "
            f"on org_unit='{org_unit}' for customer='{customer_id}'"
        )
        return result

    # --- 3. Lazy import - google libs are an optional dep ------------------
    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build
        from googleapiclient.errors import HttpError
    except ImportError:
        result["error"] = 'Google API libraries not installed. Run:  pip install -e ".[workspace]"'
        return result

    # --- 4. Authenticate ---------------------------------------------------
    if not Path(sa_path).exists():
        result["error"] = f"Service account JSON file not found at {sa_path}"
        return result

    try:
        creds = service_account.Credentials.from_service_account_file(
            sa_path,
            scopes=[CBCM_SCOPE],
        )
    except (ValueError, FileNotFoundError) as exc:
        result["error"] = f"Failed to load service account credentials: {exc}"
        return result

    # --- 5. Call the Chrome Policy API ------------------------------------
    try:
        service = build("chromepolicy", "v1", credentials=creds, cache_discovery=False)
        policies = service.customers().policies()

        # The Chrome Policy API uses "modify" semantics: we send the new
        # blocklist value and Workspace applies it. The full schema is
        # documented at:
        # https://developers.google.com/chrome/policy/guides/policy-schemas
        modify_request = {
            "requests": [
                {
                    "policyTargetKey": {
                        "targetResource": f"orgunits/{org_unit.lstrip('/')}",
                    },
                    "policyValue": {
                        "policySchema": CBCM_BLOCKLIST_SCHEMA,
                        "value": {
                            "appInstallType": "BLOCKED",
                            "appId": extension_id,
                        },
                    },
                    "updateMask": "appInstallType,appId",
                },
            ],
        }

        response = (
            policies.orgunits()
            .batchModify(
                customer=f"customers/{customer_id}",
                body=modify_request,
            )
            .execute()
        )

        result["ok"] = True
        result["details"]["api_response"] = response
        return result

    except HttpError as exc:
        # Surface the underlying error message - usually the most useful for
        # debugging permissions / scope / customer-ID problems.
        result["error"] = f"Chrome Policy API HTTP {exc.resp.status}: {exc._get_reason()}"
        return result
    except Exception as exc:
        result["error"] = f"Chrome Policy API call failed: {exc}"
        return result
