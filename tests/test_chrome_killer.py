# tests/test_chrome_killer.py - Chrome extension kill tests (dry-run only)
#
# These tests stick strictly to dry-run mode and the cross-platform dispatcher
# logic. We do NOT touch the real HKLM registry, /etc/opt/chrome/, or macOS
# managed prefs - that requires admin privileges and would mutate the host.

import json
import platform
from pathlib import Path
from unittest.mock import patch

import pytest

from extguard.remediators import chrome_killer

# Valid-format IDs (32 letters a-p). The old fixture 'abcdefghijklmnopqrstuvwxyzabcdef'
# was not a legal Chrome ID - it contains q-z.
EXT_ID = "ngcnfhbdhbbhajagjfmnfgbbfgkfljhf"
EXT_ID_2 = "a" * 32
EXT_ID_3 = "p" * 32

# ---------------------------------------------------------------------------
# Cross-platform dispatcher
# ---------------------------------------------------------------------------


class TestDispatcher:
    def test_dispatcher_picks_windows(self):
        """On Windows, block_extension should route to block_extension_windows."""
        with patch("extguard.remediators.chrome_killer.platform.system", return_value="Windows"):
            with patch("extguard.remediators.chrome_killer.block_extension_windows") as mock_win:
                mock_win.return_value = {"ok": True}
                chrome_killer.block_extension(EXT_ID, dry_run=True)
                mock_win.assert_called_once()

    def test_dispatcher_picks_linux(self):
        with patch("extguard.remediators.chrome_killer.platform.system", return_value="Linux"):
            with patch("extguard.remediators.chrome_killer.block_extension_linux") as mock_linux:
                mock_linux.return_value = {"ok": True}
                chrome_killer.block_extension(EXT_ID, dry_run=True)
                mock_linux.assert_called_once()

    def test_dispatcher_picks_macos(self):
        with patch("extguard.remediators.chrome_killer.platform.system", return_value="Darwin"):
            with patch("extguard.remediators.chrome_killer.block_extension_macos") as mock_mac:
                mock_mac.return_value = {"ok": True}
                chrome_killer.block_extension(EXT_ID, dry_run=True)
                mock_mac.assert_called_once()

    def test_unsupported_platform_returns_error(self):
        with patch("extguard.remediators.chrome_killer.platform.system", return_value="Plan9"):
            result = chrome_killer.block_extension(EXT_ID, dry_run=True)
            assert result["ok"] is False
            assert "Unsupported platform" in result["error"]


# ---------------------------------------------------------------------------
# Dry-run mode - safe to run on any host
# ---------------------------------------------------------------------------


class TestDryRun:
    """Dry-run must NEVER touch real state. These tests are safe on every OS."""

    def test_windows_dry_run_does_not_import_winreg(self):
        """Dry-run path returns before importing winreg, so it works on Linux too."""
        result = chrome_killer.block_extension_windows(EXT_ID, dry_run=True)
        assert result["ok"] is True
        assert result["details"]["dry_run"] is True
        assert "would write" in result["details"]["note"].lower()

    def test_linux_dry_run_does_not_write_file(self, tmp_path, monkeypatch):
        """Dry-run path must not create /etc/opt/chrome/policies/managed/ files."""
        # Redirect the policy file to a path that doesn't exist, to confirm we
        # never even try to write
        fake_policy = tmp_path / "nonexistent" / "policy.json"
        monkeypatch.setattr(chrome_killer, "LINUX_POLICY_FILE", fake_policy)
        result = chrome_killer.block_extension_linux(EXT_ID, dry_run=True)
        assert result["ok"] is True
        assert result["details"]["dry_run"] is True
        # File must NOT have been created
        assert not fake_policy.exists()

    def test_macos_dry_run_writes_nothing(self, tmp_path):
        result = chrome_killer.block_extension_macos(EXT_ID, dry_run=True, output_dir=tmp_path)
        assert result["ok"] is True
        assert list(tmp_path.iterdir()) == []

    def test_workspace_missing_config_returns_error(self):
        """Without service_account_json or customer_id, surface a clear error."""
        result = chrome_killer.block_extension_workspace(EXT_ID, "/", cfg={})
        assert result["ok"] is False
        assert "service_account_json" in result["error"]

    def test_workspace_missing_customer_id_returns_error(self):
        result = chrome_killer.block_extension_workspace(
            EXT_ID, "/", cfg={"service_account_json": "/tmp/sa.json"}
        )
        assert result["ok"] is False
        assert "customer_id" in result["error"]


# ---------------------------------------------------------------------------
# Workspace Admin SDK integration (real implementation tests with mocks)
# ---------------------------------------------------------------------------


class TestWorkspaceImpl:
    """Tests the real CBCM Chrome Policy API code path with mocks - we never
    actually contact Google's APIs in tests."""

    def test_dry_run_skips_google_imports(self, tmp_path):
        """Dry-run must work even when google-api-python-client isn't installed."""
        # Create a fake SA JSON file so the path check passes
        sa = tmp_path / "sa.json"
        sa.write_text("{}")
        result = chrome_killer.block_extension_workspace(
            EXT_ID,
            "/Engineering",
            cfg={
                "service_account_json": str(sa),
                "customer_id": "C01abc123",
                "admin_email": "admin@example.com",
            },
            dry_run=True,
        )
        assert result["ok"] is True
        assert result["details"]["dry_run"] is True
        assert EXT_ID in result["details"]["note"]
        assert "C01abc123" in result["details"]["note"]

    def test_request_matches_googles_documented_shape(self):
        """Per Google's 'Code samples for app policies' (Chrome Policy API).
        The old request used schema chrome.users.apps.ManagedInstall, an org-unit
        PATH as targetResource, and put appId in the value - none of which the
        API accepts."""
        body = chrome_killer.build_workspace_request(EXT_ID, "03ph8a2z1xyz")
        req = body["requests"][0]
        assert req["policyTargetKey"] == {
            "targetResource": "orgunits/03ph8a2z1xyz",
            "additionalTargetKeys": {"app_id": f"chrome:{EXT_ID}"},
        }
        assert req["policyValue"] == {
            "policySchema": "chrome.users.apps.InstallType",
            "value": {"appInstallType": "BLOCKED"},
        }
        assert req["updateMask"] == {"paths": "appInstallType"}

    def test_admin_email_is_required(self, tmp_path):
        """A service account needs an admin to impersonate (domain-wide delegation)."""
        cfg = {"service_account_json": "sa.json", "customer_id": "C01"}
        result = chrome_killer.block_extension_workspace(EXT_ID, "/", cfg, dry_run=True)
        assert "admin_email" in result["error"]

    def test_missing_service_account_file_returns_clear_error(self, tmp_path):
        """If the SA path is set but the file doesn't exist, say so."""
        # We need to skip the dry-run path AND get past the early config checks
        # Pass a nonexistent path so the real code does the file check
        result = chrome_killer.block_extension_workspace(
            EXT_ID,
            "/",
            cfg={
                "service_account_json": str(tmp_path / "missing.json"),
                "customer_id": "C01",
                "admin_email": "admin@example.com",
            },
        )
        assert result["ok"] is False
        # Either the import fails (no google libs in test env) OR the file
        # check fails. Both are acceptable outcomes - we just need the user
        # to see SOMETHING actionable rather than a stack trace.
        assert (
            "not found" in result["error"].lower()
            or "google api libraries" in result["error"].lower()
        )


# ---------------------------------------------------------------------------
# Linux policy file actual write (uses tmp_path - safe)
# ---------------------------------------------------------------------------


class TestLinuxPolicyFile:
    """Test real (non-dry-run) Linux policy file write, but in tmp_path."""

    def test_creates_new_policy_file(self, tmp_path, monkeypatch):
        policy_file = tmp_path / "test_policy.json"
        monkeypatch.setattr(chrome_killer, "LINUX_POLICY_FILE", policy_file)
        monkeypatch.setattr(chrome_killer, "LINUX_POLICY_DIR", tmp_path)

        result = chrome_killer.block_extension_linux(EXT_ID, dry_run=False)
        assert result["ok"] is True
        assert policy_file.exists()

        data = json.loads(policy_file.read_text())
        assert EXT_ID in data["ExtensionInstallBlocklist"]

    def test_appends_to_existing_policy_file(self, tmp_path, monkeypatch):
        policy_file = tmp_path / "test_policy.json"
        policy_file.write_text(json.dumps({"ExtensionInstallBlocklist": [EXT_ID_3]}))
        monkeypatch.setattr(chrome_killer, "LINUX_POLICY_FILE", policy_file)
        monkeypatch.setattr(chrome_killer, "LINUX_POLICY_DIR", tmp_path)

        chrome_killer.block_extension_linux(EXT_ID_2, dry_run=False)

        data = json.loads(policy_file.read_text())
        assert EXT_ID_3 in data["ExtensionInstallBlocklist"]
        assert EXT_ID_2 in data["ExtensionInstallBlocklist"]

    def test_does_not_duplicate_ids(self, tmp_path, monkeypatch):
        """Adding the same ID twice should not create duplicate entries."""
        policy_file = tmp_path / "test_policy.json"
        monkeypatch.setattr(chrome_killer, "LINUX_POLICY_FILE", policy_file)
        monkeypatch.setattr(chrome_killer, "LINUX_POLICY_DIR", tmp_path)

        chrome_killer.block_extension_linux(EXT_ID, dry_run=False)
        chrome_killer.block_extension_linux(EXT_ID, dry_run=False)

        data = json.loads(policy_file.read_text())
        assert data["ExtensionInstallBlocklist"].count(EXT_ID) == 1

    def test_corrupt_policy_file_is_not_overwritten(self, tmp_path, monkeypatch):
        """The old code replaced an unreadable file, silently dropping its entries."""
        policy_file = tmp_path / "test_policy.json"
        policy_file.write_text("{ this is not json, but has other admins' entries")
        monkeypatch.setattr(chrome_killer, "LINUX_POLICY_FILE", policy_file)
        monkeypatch.setattr(chrome_killer, "LINUX_POLICY_DIR", tmp_path)
        result = chrome_killer.block_extension_linux(EXT_ID)
        assert result["ok"] is False
        assert "not valid JSON" in result["error"]
        assert "other admins' entries" in policy_file.read_text()

    def test_write_leaves_no_temp_files(self, tmp_path, monkeypatch):
        policy_file = tmp_path / "test_policy.json"
        monkeypatch.setattr(chrome_killer, "LINUX_POLICY_FILE", policy_file)
        monkeypatch.setattr(chrome_killer, "LINUX_POLICY_DIR", tmp_path)
        chrome_killer.block_extension_linux(EXT_ID)
        assert [p.name for p in tmp_path.iterdir()] == ["test_policy.json"]


class TestMacosProfile:
    def test_profile_contains_the_blocklist(self, tmp_path):
        import plistlib

        result = chrome_killer.block_extension_macos(EXT_ID, output_dir=tmp_path)
        assert result["ok"] is True
        # Honest result: the profile still has to be deployed
        assert result["applied"] is False
        profile = plistlib.loads(Path(result["details"]["profile_path"]).read_bytes())
        payload = profile["PayloadContent"][0]
        assert payload["PayloadType"] == "com.google.Chrome"
        assert payload["ExtensionInstallBlocklist"] == [EXT_ID]


# ---------------------------------------------------------------------------
# Extension-ID validation - nothing malformed may reach a policy store
# ---------------------------------------------------------------------------

BAD_IDS = ["*", "abc", "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP", "q" * 32, "a" * 31, "", None]


class TestIdValidation:
    @pytest.mark.parametrize("bad_id", BAD_IDS)
    @pytest.mark.parametrize(
        "block",
        [
            chrome_killer.block_extension_windows,
            chrome_killer.block_extension_linux,
            chrome_killer.block_extension_macos,
            chrome_killer.unblock_extension_windows,
        ],
    )
    def test_invalid_ids_are_refused(self, block, bad_id):
        result = block(bad_id, dry_run=True)
        assert result["ok"] is False
        assert "Invalid extension ID" in result["error"]

    def test_wildcard_never_reaches_the_linux_policy_file(self, tmp_path, monkeypatch):
        """'*' in ExtensionInstallBlocklist would block every extension."""
        policy_file = tmp_path / "policy.json"
        monkeypatch.setattr(chrome_killer, "LINUX_POLICY_FILE", policy_file)
        monkeypatch.setattr(chrome_killer, "LINUX_POLICY_DIR", tmp_path)
        assert chrome_killer.block_extension_linux("*", dry_run=False)["ok"] is False
        assert not policy_file.exists()

    def test_workspace_refuses_invalid_id(self):
        result = chrome_killer.block_extension_workspace("*", "/", cfg={}, dry_run=True)
        assert "Invalid extension ID" in result["error"]


# ---------------------------------------------------------------------------
# Windows registry helpers - test only via mock since winreg is OS-locked
# ---------------------------------------------------------------------------


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only registry test")
class TestWindowsHelpers:
    """These tests only run on Windows since winreg isn't importable elsewhere."""

    def test_find_next_free_slot_starts_at_one(self):
        """An empty registry key should return slot 1 as the next free."""
        import winreg

        # We can't easily create a temp HKLM key, so just test the function
        # signature/behavior with a mock
        from unittest.mock import MagicMock

        fake_key = MagicMock()
        # First QueryValueEx call should raise FileNotFoundError (slot 1 free)
        fake_key.__class__ = type(fake_key)

        with patch("winreg.QueryValueEx", side_effect=FileNotFoundError()):
            slot = chrome_killer._find_next_free_slot(fake_key)
            assert slot == 1

    def test_existing_id_found_after_a_gap(self):
        """Slots 1, 2, 4 (3 deleted): the old probe stopped at 3 and missed 4."""
        values = [("1", "a" * 32, 1), ("2", "b" * 32, 1), ("4", EXT_ID, 1)]

        def enum(_key, index):
            if index >= len(values):
                raise OSError("no more data")
            return values[index]

        with patch("winreg.EnumValue", side_effect=enum):
            assert chrome_killer._find_existing_slot(object(), EXT_ID) == 4
            assert chrome_killer._find_existing_slot(object(), "p" * 32) is None
