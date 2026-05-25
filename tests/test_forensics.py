# tests/test_forensics.py - Forensic preservation and chain-of-custody tests

import hashlib
import json
from pathlib import Path

import pytest

from remediators import forensics

# ---------------------------------------------------------------------------
# Preserve - core happy path
# ---------------------------------------------------------------------------


class TestPreserve:
    def test_creates_case_folder_with_expected_files(self, temp_quarantine, teamccp_manifest_raw):
        result = forensics.preserve(
            extension_id="abcdefghijklmnopqrstuvwxyzabcdef",
            extension_name="Test Ext",
            crx_bytes=b"fake-crx-bytes",
            manifest=teamccp_manifest_raw,
            quarantine_root=temp_quarantine,
        )
        assert result["ok"] is True
        case_dir = Path(result["case_dir"])
        assert case_dir.exists()
        assert (case_dir / "sample.crx").exists()
        assert (case_dir / "manifest.json").exists()
        assert (case_dir / "chain_of_custody.json").exists()
        assert (case_dir / "chain_of_custody.json.sha256").exists()

    def test_records_hashes(self, temp_quarantine, benign_manifest_raw):
        result = forensics.preserve(
            extension_id="x",
            extension_name="X",
            crx_bytes=b"some-content",
            manifest=benign_manifest_raw,
            quarantine_root=temp_quarantine,
        )
        # Hashes recorded should match actual file hashes
        case_dir = Path(result["case_dir"])
        for filename, expected_hash in result["hashes"].items():
            actual = hashlib.sha256((case_dir / filename).read_bytes()).hexdigest()
            assert actual == expected_hash

    def test_bare_manifest_omits_sample_file(self, temp_quarantine, benign_manifest_raw):
        """When no crx_bytes are given, sample.crx should not exist."""
        result = forensics.preserve(
            extension_id="x",
            extension_name="X",
            crx_bytes=None,
            manifest=benign_manifest_raw,
            quarantine_root=temp_quarantine,
        )
        case_dir = Path(result["case_dir"])
        assert not (case_dir / "sample.crx").exists()
        assert (case_dir / "manifest.json").exists()

    def test_includes_optional_artifacts(self, temp_quarantine, benign_manifest_raw, sample_alert):
        result = forensics.preserve(
            extension_id="x",
            extension_name="X",
            crx_bytes=b"a",
            manifest=benign_manifest_raw,
            triage_result={"risk_score": 95},
            alert_history=[sample_alert, sample_alert],
            storage_snapshot={"s_cache": "base64-blob"},
            quarantine_root=temp_quarantine,
        )
        case_dir = Path(result["case_dir"])
        assert (case_dir / "triage.json").exists()
        assert (case_dir / "alerts.jsonl").exists()
        assert (case_dir / "storage_snapshot.json").exists()

        # alerts.jsonl should have one JSON object per line
        alerts_text = (case_dir / "alerts.jsonl").read_text()
        assert len(alerts_text.strip().splitlines()) == 2

    def test_chain_of_custody_has_required_fields(self, temp_quarantine, benign_manifest_raw):
        result = forensics.preserve(
            extension_id="x",
            extension_name="Test",
            crx_bytes=b"a",
            manifest=benign_manifest_raw,
            quarantine_root=temp_quarantine,
            case_id="SOC-2026-001",
        )
        coc = json.loads(Path(result["manifest_path"]).read_text())
        assert coc["case_id"] == "SOC-2026-001"
        assert coc["preserved_at"]
        assert coc["operator"]
        assert coc["operator_host"]
        assert "sha256" in coc
        assert "custody_log" in coc
        assert len(coc["custody_log"]) == 1  # initial "preserved" action
        assert coc["custody_log"][0]["action"] == "preserved"


# ---------------------------------------------------------------------------
# Chain of custody append
# ---------------------------------------------------------------------------


class TestAppendCustody:
    def test_appends_action(self, temp_quarantine, benign_manifest_raw):
        result = forensics.preserve(
            extension_id="x",
            extension_name="X",
            crx_bytes=b"a",
            manifest=benign_manifest_raw,
            quarantine_root=temp_quarantine,
        )
        case_dir = result["case_dir"]

        append_result = forensics.append_custody_action(
            case_dir=case_dir,
            action="blocklisted",
            actor="test-operator",
            notes="added to ExtensionInstallBlocklist",
        )
        assert append_result["ok"] is True

        coc = json.loads((Path(case_dir) / "chain_of_custody.json").read_text())
        actions = [e["action"] for e in coc["custody_log"]]
        assert actions == ["preserved", "blocklisted"]

    def test_updates_sidecar_hash(self, temp_quarantine, benign_manifest_raw):
        """After appending, the .sha256 sidecar should reflect the new CoC hash."""
        result = forensics.preserve(
            extension_id="x",
            extension_name="X",
            crx_bytes=b"a",
            manifest=benign_manifest_raw,
            quarantine_root=temp_quarantine,
        )
        case_dir = Path(result["case_dir"])
        original_hash = result["coc_hash"]

        forensics.append_custody_action(str(case_dir), "blocklisted", "op", "")

        new_sidecar = (case_dir / "chain_of_custody.json.sha256").read_text()
        assert original_hash not in new_sidecar
        # New hash should match actual file
        new_actual = hashlib.sha256((case_dir / "chain_of_custody.json").read_bytes()).hexdigest()
        assert new_actual in new_sidecar

    def test_missing_case_dir_returns_error(self, tmp_path):
        result = forensics.append_custody_action(
            case_dir=str(tmp_path / "nonexistent"),
            action="x",
            actor="y",
        )
        assert result["ok"] is False


# ---------------------------------------------------------------------------
# Verify - the critical integrity check
# ---------------------------------------------------------------------------


class TestVerifyCase:
    def test_clean_case_verifies(self, temp_quarantine, benign_manifest_raw):
        """A freshly preserved case should pass verification."""
        result = forensics.preserve(
            extension_id="x",
            extension_name="X",
            crx_bytes=b"some-bytes",
            manifest=benign_manifest_raw,
            quarantine_root=temp_quarantine,
        )
        verify = forensics.verify_case(result["case_dir"])
        assert verify["ok"] is True
        assert verify["verified"] == verify["total"]
        assert verify["mismatches"] == []

    def test_tampered_manifest_detected(self, temp_quarantine, benign_manifest_raw):
        """Modifying a preserved file must trigger a hash mismatch."""
        result = forensics.preserve(
            extension_id="x",
            extension_name="X",
            crx_bytes=b"a",
            manifest=benign_manifest_raw,
            quarantine_root=temp_quarantine,
        )
        case_dir = Path(result["case_dir"])

        # Tamper with manifest.json
        manifest_path = case_dir / "manifest.json"
        tampered = json.loads(manifest_path.read_text())
        tampered["evil_field"] = "attacker_was_here"
        manifest_path.write_text(json.dumps(tampered))

        verify = forensics.verify_case(str(case_dir))
        assert verify["ok"] is False
        assert any(m["file"] == "manifest.json" for m in verify["mismatches"])

    def test_deleted_file_detected(self, temp_quarantine, benign_manifest_raw):
        """Removing a preserved artifact must show up as a verification failure."""
        result = forensics.preserve(
            extension_id="x",
            extension_name="X",
            crx_bytes=b"a",
            manifest=benign_manifest_raw,
            quarantine_root=temp_quarantine,
        )
        case_dir = Path(result["case_dir"])

        # The chmod(0o444) call in preserve() makes sample.crx read-only on POSIX,
        # but on Windows we need to clear that to delete - try both
        sample = case_dir / "sample.crx"
        try:
            sample.chmod(0o666)
        except (OSError, NotImplementedError):
            pass
        sample.unlink()

        verify = forensics.verify_case(str(case_dir))
        assert verify["ok"] is False
        missing = [m for m in verify["mismatches"] if m["issue"] == "missing"]
        assert len(missing) == 1
        assert missing[0]["file"] == "sample.crx"

    def test_missing_coc_returns_error(self, tmp_path):
        verify = forensics.verify_case(str(tmp_path))
        assert verify["ok"] is False
        assert "chain_of_custody" in verify["error"]
