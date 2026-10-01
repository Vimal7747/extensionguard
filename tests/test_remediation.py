# tests/test_remediation.py - extguard-remediate CLI and dashboard queue consumer
#
# chrome_killer and the PagerDuty adapter are mocked - these tests check the
# orchestration: confirmation, exit codes, evidence, and that queued dashboard
# decisions are executed once, and only for cases that verify.

import json
from unittest.mock import patch

import pytest

from extguard import remediation
from extguard.remediators import forensics

EXT_ID = "abcdefghijklmnopabcdefghijklmnop"
OTHER_ID = "ponmlkjihgfedcbaponmlkjihgfedcba"
BLOCK_OK = {"ok": True, "method": "registry", "applied": True, "details": {}}


@pytest.fixture
def sample(tmp_path, crx3_bytes):
    path = tmp_path / "sample.crx"
    path.write_bytes(crx3_bytes)
    return path


@pytest.fixture
def killer():
    with patch("extguard.remediation.chrome_killer.block_extension", return_value=BLOCK_OK) as m:
        yield m


def _run(*argv):
    return remediation.main(list(argv))


def _only_case_dir():
    cases = [p for p in forensics.DEFAULT_QUARANTINE_ROOT.iterdir() if p.is_dir()]
    assert len(cases) == 1
    return cases[0]


def _custody_actions(case_dir):
    coc = json.loads((case_dir / "chain_of_custody.json").read_text())
    return [entry["action"] for entry in coc["custody_log"]]


BASE = ["--no-playbook", "--pd-action", "none"]


# ---------------------------------------------------------------------------
# Direct CLI runs
# ---------------------------------------------------------------------------


class TestConfirmation:
    def test_live_kill_without_yes_is_refused_when_not_interactive(self, sample, killer):
        # pytest's stdin is not a TTY, like a cron job or SOAR runner
        code = _run("--ext-id", EXT_ID, "--crx", str(sample), *BASE)
        assert code == 1
        killer.assert_not_called()

    def test_yes_confirms(self, sample, killer):
        code = _run("--ext-id", EXT_ID, "--crx", str(sample), "--yes", *BASE)
        assert code == 0
        killer.assert_called_once_with(EXT_ID, dry_run=False)
        assert "blocklisted" in _custody_actions(_only_case_dir())

    def test_interactive_prompt_needs_the_word_block(self, sample, killer, monkeypatch):
        monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
        with patch("builtins.input", return_value="yes"):
            assert _run("--ext-id", EXT_ID, "--crx", str(sample), *BASE) == 1
        killer.assert_not_called()
        with patch("builtins.input", return_value="BLOCK"):
            assert _run("--ext-id", EXT_ID, "--crx", str(sample), *BASE) == 0
        killer.assert_called_once()

    def test_dry_run_needs_no_confirmation_and_writes_nothing(self, sample, killer):
        code = _run("--ext-id", EXT_ID, "--crx", str(sample), "--dry-run", *BASE)
        assert code == 0
        killer.assert_called_once_with(EXT_ID, dry_run=True)
        root = forensics.DEFAULT_QUARANTINE_ROOT
        assert not root.exists() or not any(root.iterdir())


class TestExitCodes:
    def test_failed_kill_exits_1(self, sample):
        failed = {"ok": False, "method": "registry", "error": "access denied"}
        with patch("extguard.remediation.chrome_killer.block_extension", return_value=failed):
            assert _run("--ext-id", EXT_ID, "--crx", str(sample), "--yes", *BASE) == 1

    def test_invalid_extension_id_exits_2(self, sample, killer):
        assert _run("--ext-id", "*", "--crx", str(sample), "--yes", *BASE) == 2
        killer.assert_not_called()

    def test_missing_triage_file_exits_2(self, tmp_path):
        assert _run("--from-triage", str(tmp_path / "nope.json"), *BASE) == 2

    def test_macos_profile_is_partial_success(self, sample):
        prepared = {
            "ok": True,
            "method": "mobileconfig",
            "applied": False,
            "details": {"note": "install the profile", "profile_path": "x.mobileconfig"},
        }
        with patch("extguard.remediation.chrome_killer.block_extension", return_value=prepared):
            assert _run("--ext-id", EXT_ID, "--crx", str(sample), "--yes", *BASE) == 0
        assert "blocklist_prepared" in _custody_actions(_only_case_dir())


class TestPagerDuty:
    CFG = {"enabled": True, "routing_key": "x"}

    def test_default_is_acknowledge_not_resolve(self, sample, killer):
        ok = {"ok": True}
        with (
            patch("extguard.remediation._load_pd_config", return_value=self.CFG),
            patch("extguard.remediation.pagerduty.acknowledge", return_value=ok) as ack,
            patch("extguard.remediation.pagerduty.resolve", return_value=ok) as res,
        ):
            code = _run("--ext-id", EXT_ID, "--crx", str(sample), "--yes", "--no-playbook")
        assert code == 0
        ack.assert_called_once()
        res.assert_not_called()
        assert "pd_acknowledge" in _custody_actions(_only_case_dir())

    def test_resolve_on_request(self, sample, killer):
        ok = {"ok": True}
        with (
            patch("extguard.remediation._load_pd_config", return_value=self.CFG),
            patch("extguard.remediation.pagerduty.resolve", return_value=ok) as res,
        ):
            _run("--ext-id", EXT_ID, "--crx", str(sample), "--yes", "--no-playbook",
                 "--pd-action", "resolve")  # fmt: skip
        res.assert_called_once()

    def test_no_pd_resolve_alias_skips_pagerduty(self, sample, killer):
        with patch("extguard.remediation.pagerduty.acknowledge") as ack:
            _run("--ext-id", EXT_ID, "--crx", str(sample), "--yes", "--no-playbook",
                 "--no-pd-resolve")  # fmt: skip
        ack.assert_not_called()

    def test_pd_failure_exits_1(self, sample, killer):
        with (
            patch("extguard.remediation._load_pd_config", return_value=self.CFG),
            patch("extguard.remediation.pagerduty.acknowledge", return_value={"ok": False}),
        ):
            code = _run("--ext-id", EXT_ID, "--crx", str(sample), "--yes", "--no-playbook")
        assert code == 1


class TestEvidence:
    def test_alert_log_filtered_to_this_extension(self, sample, killer, tmp_path):
        log = tmp_path / "alerts.jsonl"
        log.write_text(
            json.dumps({"rule": "RULE-01", "extension": {"id": EXT_ID}})
            + "\nnot json\n"
            + json.dumps({"rule": "RULE-02", "extension": {"id": OTHER_ID}})
            + "\n"
        )
        _run("--ext-id", EXT_ID, "--crx", str(sample), "--yes", "--alerts-log", str(log), *BASE)
        lines = (_only_case_dir() / "alerts.jsonl").read_text().splitlines()
        assert [json.loads(line)["rule"] for line in lines] == ["RULE-01"]

    def test_storage_snapshot_preserved(self, sample, killer, tmp_path):
        snap = tmp_path / "storage.json"
        snap.write_text(json.dumps({"local": {"token": "stolen"}}))
        _run("--ext-id", EXT_ID, "--crx", str(sample), "--yes", "--storage-snapshot",
             str(snap), *BASE)  # fmt: skip
        case = _only_case_dir()
        assert json.loads((case / "storage_snapshot.json").read_text())["local"]["token"]
        assert forensics.verify_case(str(case))["ok"] is True

    def test_original_sample_bytes_preserved(self, sample, killer):
        _run("--ext-id", EXT_ID, "--crx", str(sample), "--yes", *BASE)
        assert (_only_case_dir() / "sample.crx").read_bytes() == sample.read_bytes()


class TestWorkspace:
    def test_workspace_ou_uses_config_section(self, sample, killer, tmp_path):
        cfg_file = tmp_path / "extguard.conf.json"
        ws = {"service_account_json": "sa.json", "customer_id": "C1", "admin_email": "a@b.c"}
        cfg_file.write_text(json.dumps({"workspace": ws}))
        with patch(
            "extguard.remediation.chrome_killer.block_extension_workspace",
            return_value={"ok": True, "method": "chrome-policy-api", "details": {}},
        ) as ws_block:
            code = _run("--ext-id", EXT_ID, "--crx", str(sample), "--yes", "--config",
                        str(cfg_file), "--workspace-ou", "/Engineering", *BASE)  # fmt: skip
        assert code == 0
        ws_block.assert_called_once_with(EXT_ID, "/Engineering", ws, dry_run=False)


class TestVerifyCase:
    def test_clean_case_exits_0_tampered_exits_1(self, sample, killer):
        _run("--ext-id", EXT_ID, "--crx", str(sample), "--yes", *BASE)
        case = _only_case_dir()
        assert _run("--verify-case", str(case)) == 0
        (case / "manifest.json").write_text("{}")
        assert _run("--verify-case", str(case)) == 1


# ---------------------------------------------------------------------------
# Dashboard queue consumer
# ---------------------------------------------------------------------------


@pytest.fixture
def case_dir(benign_manifest_raw):
    result = forensics.preserve(
        extension_id=EXT_ID,
        extension_name="Queued Extension",
        crx_bytes=b"sample",
        manifest=benign_manifest_raw,
        triage_result={"risk_level": "high", "iocs": []},
    )
    return forensics.DEFAULT_QUARANTINE_ROOT / result["case_id"]


@pytest.fixture
def queue(tmp_path):
    return tmp_path / "queue.jsonl"


def _enqueue(queue, case_id, decision="approve", action="kill", actor="Priya"):
    entry = {"case_id": case_id, "decision": decision, "action": action, "actor": actor}
    with queue.open("a") as f:
        f.write(json.dumps(entry) + "\n")


class TestQueue:
    def test_approved_kill_is_executed_once(self, case_dir, queue, killer):
        _enqueue(queue, case_dir.name)
        assert _run("--process-queue", "--queue-file", str(queue), "--yes") == 0
        killer.assert_called_once_with(EXT_ID, dry_run=False)
        coc = json.loads((case_dir / "chain_of_custody.json").read_text())
        assert coc["custody_log"][-1]["action"] == "blocklisted"
        assert "Priya" in coc["custody_log"][-1]["actor"]

        # Second run: already processed
        assert _run("--process-queue", "--queue-file", str(queue), "--yes") == 0
        killer.assert_called_once()

    def test_queue_kill_still_needs_confirmation(self, case_dir, queue, killer):
        _enqueue(queue, case_dir.name)
        assert _run("--process-queue", "--queue-file", str(queue)) == 1
        killer.assert_not_called()
        # Not marked done - it runs once someone confirms
        assert _run("--process-queue", "--queue-file", str(queue), "--yes") == 0
        killer.assert_called_once()

    def test_tampered_case_is_refused(self, case_dir, queue, killer):
        coc_path = case_dir / "chain_of_custody.json"
        coc = json.loads(coc_path.read_text())
        coc["extension"]["id"] = OTHER_ID  # try to get a different extension blocked
        coc_path.write_text(json.dumps(coc))
        _enqueue(queue, case_dir.name)
        assert _run("--process-queue", "--queue-file", str(queue), "--yes") == 1
        killer.assert_not_called()

    def test_unsigned_case_is_refused(self, case_dir, queue, killer, monkeypatch):
        # Without the signing key the signature can't be checked -> no action
        monkeypatch.delenv("EXTGUARD_COC_KEY")
        _enqueue(queue, case_dir.name)
        assert _run("--process-queue", "--queue-file", str(queue), "--yes") == 1
        killer.assert_not_called()

    @pytest.mark.parametrize("bad", ["../../etc", "20260101-000000-deadbeef/..", ""])
    def test_bad_case_id_is_refused(self, queue, killer, bad):
        _enqueue(queue, bad)
        assert _run("--process-queue", "--queue-file", str(queue), "--yes") == 1
        killer.assert_not_called()

    def test_reject_records_false_positive(self, case_dir, queue, killer):
        _enqueue(queue, case_dir.name, decision="reject", action="none")
        assert _run("--process-queue", "--queue-file", str(queue)) == 0
        killer.assert_not_called()
        assert "false_positive_confirmed" in _custody_actions(case_dir)

    def test_dry_run_does_not_mark_processed(self, case_dir, queue, killer):
        _enqueue(queue, case_dir.name)
        assert _run("--process-queue", "--queue-file", str(queue), "--dry-run") == 0
        killer.assert_called_once_with(EXT_ID, dry_run=True)
        assert not queue.with_name(queue.name + ".done").exists()

    def test_resolve_action_resolves_pagerduty(self, case_dir, queue, killer):
        _enqueue(queue, case_dir.name, action="resolve")
        with (
            patch("extguard.remediation._load_pd_config", return_value={"enabled": True}),
            patch("extguard.remediation.pagerduty.resolve", return_value={"ok": True}) as res,
        ):
            assert _run("--process-queue", "--queue-file", str(queue)) == 0
        res.assert_called_once()
        assert "pd_resolve" in _custody_actions(case_dir)

    def test_playbook_action_writes_playbook(self, case_dir, queue):
        _enqueue(queue, case_dir.name, action="playbook")
        assert _run("--process-queue", "--queue-file", str(queue)) == 0

    def test_missing_queue_is_fine(self, tmp_path):
        assert _run("--process-queue", "--queue-file", str(tmp_path / "none.jsonl")) == 0
