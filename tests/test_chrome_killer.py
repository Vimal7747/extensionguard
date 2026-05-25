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

from remediators import chrome_killer

# ---------------------------------------------------------------------------
# Cross-platform dispatcher
# ---------------------------------------------------------------------------


class TestDispatcher:
    def test_dispatcher_picks_windows(self):
        """On Windows, block_extension should route to block_extension_windows."""
        with patch("remediators.chrome_killer.platform.system", return_value="Windows"):
            with patch("remediators.chrome_killer.block_extension_windows") as mock_win:
                mock_win.return_value = {"ok": True}
                chrome_killer.block_extension("abc", dry_run=True)
                mock_win.assert_called_once()

    def test_dispatcher_picks_linux(self):
        with patch("remediators.chrome_killer.platform.system", return_value="Linux"):
            with patch("remediators.chrome_killer.block_extension_linux") as mock_linux:
                mock_linux.return_value = {"ok": True}
                chrome_killer.block_extension("abc", dry_run=True)
                mock_linux.assert_called_once()

    def test_dispatcher_picks_macos(self):
        with patch("remediators.chrome_killer.platform.system", return_value="Darwin"):
            with patch("remediators.chrome_killer.block_extension_macos") as mock_mac:
                mock_mac.return_value = {"ok": True}
                chrome_killer.block_extension("abc", dry_run=True)
                mock_mac.assert_called_once()

    def test_unsupported_platform_returns_error(self):
        with patch("remediators.chrome_killer.platform.system", return_value="Plan9"):
            result = chrome_killer.block_extension("abc", dry_run=True)
            assert result["ok"] is False
            assert "Unsupported platform" in result["error"]


# ---------------------------------------------------------------------------
# Dry-run mode - safe to run on any host
# ---------------------------------------------------------------------------


class TestDryRun:
    """Dry-run must NEVER touch real state. These tests are safe on every OS."""

    def test_windows_dry_run_does_not_import_winreg(self):
        """Dry-run path returns before importing winreg, so it works on Linux too."""
        result = chrome_killer.block_extension_windows("abc", dry_run=True)
        assert result["ok"] is True
        assert result["details"]["dry_run"] is True
        assert "would write" in result["details"]["note"].lower()

    def test_linux_dry_run_does_not_write_file(self, tmp_path, monkeypatch):
        """Dry-run path must not create /etc/opt/chrome/policies/managed/ files."""
        # Redirect the policy file to a path that doesn't exist, to confirm we
        # never even try to write
        fake_policy = tmp_path / "nonexistent" / "policy.json"
        monkeypatch.setattr(chrome_killer, "LINUX_POLICY_FILE", fake_policy)
        result = chrome_killer.block_extension_linux("abc", dry_run=True)
        assert result["ok"] is True
        assert result["details"]["dry_run"] is True
        # File must NOT have been created
        assert not fake_policy.exists()

    def test_macos_dry_run_does_not_shell_out(self):
        """Dry-run path must not invoke subprocess."""
        with patch("remediators.chrome_killer.subprocess.run") as mock_run:
            result = chrome_killer.block_extension_macos("abc", dry_run=True)
            assert result["ok"] is True
            mock_run.assert_not_called()

    def test_workspace_missing_config_returns_error(self):
        """Without service_account_json or customer_id, surface a clear error."""
        result = chrome_killer.block_extension_workspace("abc", "/", cfg={})
        assert result["ok"] is False
        assert "service_account_json" in result["error"]

    def test_workspace_missing_customer_id_returns_error(self):
        result = chrome_killer.block_extension_workspace(
            "abc", "/", cfg={"service_account_json": "/tmp/sa.json"}
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
            "abcdefghijklmnopqrstuvwxyzabcdef",
            "/Engineering",
            cfg={
                "service_account_json": str(sa),
                "customer_id": "C01abc123",
            },
            dry_run=True,
        )
        assert result["ok"] is True
        assert result["details"]["dry_run"] is True
        assert "abcdefghijklmnopqrstuvwxyzabcdef" in result["details"]["note"]
        assert "C01abc123" in result["details"]["note"]

    def test_missing_service_account_file_returns_clear_error(self, tmp_path):
        """If the SA path is set but the file doesn't exist, say so."""
        # We need to skip the dry-run path AND get past the early config checks
        # Pass a nonexistent path so the real code does the file check
        result = chrome_killer.block_extension_workspace(
            "abc",
            "/",
            cfg={
                "service_account_json": str(tmp_path / "missing.json"),
                "customer_id": "C01",
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

        result = chrome_killer.block_extension_linux("abcd-ext-id", dry_run=False)
        assert result["ok"] is True
        assert policy_file.exists()

        data = json.loads(policy_file.read_text())
        assert "abcd-ext-id" in data["ExtensionInstallBlocklist"]

    def test_appends_to_existing_policy_file(self, tmp_path, monkeypatch):
        policy_file = tmp_path / "test_policy.json"
        policy_file.write_text(json.dumps({"ExtensionInstallBlocklist": ["pre-existing-id"]}))
        monkeypatch.setattr(chrome_killer, "LINUX_POLICY_FILE", policy_file)
        monkeypatch.setattr(chrome_killer, "LINUX_POLICY_DIR", tmp_path)

        chrome_killer.block_extension_linux("new-id", dry_run=False)

        data = json.loads(policy_file.read_text())
        assert "pre-existing-id" in data["ExtensionInstallBlocklist"]
        assert "new-id" in data["ExtensionInstallBlocklist"]

    def test_does_not_duplicate_ids(self, tmp_path, monkeypatch):
        """Adding the same ID twice should not create duplicate entries."""
        policy_file = tmp_path / "test_policy.json"
        monkeypatch.setattr(chrome_killer, "LINUX_POLICY_FILE", policy_file)
        monkeypatch.setattr(chrome_killer, "LINUX_POLICY_DIR", tmp_path)

        chrome_killer.block_extension_linux("dup-id", dry_run=False)
        chrome_killer.block_extension_linux("dup-id", dry_run=False)

        data = json.loads(policy_file.read_text())
        assert data["ExtensionInstallBlocklist"].count("dup-id") == 1


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
