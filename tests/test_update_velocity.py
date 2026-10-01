# tests/test_update_velocity.py - Version change velocity analysis tests

import json

import pytest

from extguard.update_velocity import (
    SUSPICIOUS_MAJOR_JUMP,
    SUSPICIOUS_MINOR_JUMP,
    SUSPICIOUS_PATCH_JUMP,
    _compute_jump,
    _evaluate_jump,
    _parse_version,
    _tuple_gt,
    analyse_version,
)

# ---------------------------------------------------------------------------
# Version-string parsing
# ---------------------------------------------------------------------------


class TestParseVersion:
    @pytest.mark.parametrize(
        "input_str,expected",
        [
            ("1.0.0", (1, 0, 0)),
            ("17.3.1", (17, 3, 1)),
            ("1.0", (1, 0)),
            ("1", (1,)),
            ("1.0.0.0", (1, 0, 0, 0)),
            ("1.0.0-beta1", (1, 0, 0)),  # Strip pre-release tags
            ("2.0+build42", (2, 0)),  # Strip build metadata
        ],
    )
    def test_parses_common_formats(self, input_str, expected):
        assert _parse_version(input_str) == expected

    def test_unparseable_returns_none(self):
        assert _parse_version("") is None
        assert _parse_version(None) is None
        assert _parse_version("not.a.version") is None

    def test_handles_letters_in_segments(self):
        """'1.0a' isn't a clean numeric segment - should return only what parses."""
        result = _parse_version("1.0a")
        # The "0a" segment fails int() so it gets filtered out
        assert result is None or result == (1,)


# ---------------------------------------------------------------------------
# Jump computation
# ---------------------------------------------------------------------------


class TestComputeJump:
    def test_simple_patch_bump(self):
        jump = _compute_jump((1, 0, 0), (1, 0, 5))
        assert jump == {"major": 0, "minor": 0, "patch": 5}

    def test_major_jump(self):
        jump = _compute_jump((1, 0, 0), (17, 0, 0))
        assert jump["major"] == 16

    def test_pads_short_tuples(self):
        """1.0 -> 1.0.0.1 should pad and compute correctly."""
        jump = _compute_jump((1, 0), (1, 0, 0, 1))
        assert jump["major"] == 0
        assert jump["minor"] == 0
        assert jump["patch"] == 0

    def test_negative_jump_for_downgrade(self):
        """A downgrade should produce negative deltas."""
        jump = _compute_jump((17, 3, 1), (1, 0, 0))
        assert jump["major"] == -16


# ---------------------------------------------------------------------------
# Suspicion thresholds
# ---------------------------------------------------------------------------


class TestEvaluateJump:
    def test_teamccp_major_jump_flagged(self):
        """The actual TeamPCP attack: 1.0.4 -> 17.3.1."""
        jump = _compute_jump((1, 0, 4), (17, 3, 1))
        suspicious, msg = _evaluate_jump(jump, "1.0.4", "17.3.1")
        assert suspicious
        assert "MAJOR" in msg

    def test_small_minor_bump_not_flagged(self):
        """1.0.0 -> 1.1.0 is a normal minor update."""
        jump = _compute_jump((1, 0, 0), (1, 1, 0))
        suspicious, _ = _evaluate_jump(jump, "1.0.0", "1.1.0")
        assert not suspicious

    def test_at_threshold_flagged(self):
        """The threshold value itself should be flagged."""
        jump = _compute_jump((1, 0, 0), (1 + SUSPICIOUS_MAJOR_JUMP, 0, 0))
        suspicious, _ = _evaluate_jump(jump, "1.0.0", "irrelevant")
        assert suspicious


# ---------------------------------------------------------------------------
# Tuple comparison
# ---------------------------------------------------------------------------


class TestTupleGt:
    def test_basic_comparison(self):
        assert _tuple_gt((2, 0, 0), (1, 9, 9))
        assert not _tuple_gt((1, 0, 0), (1, 0, 0))
        assert not _tuple_gt((1, 0, 0), (1, 0, 1))

    def test_different_lengths(self):
        """Padding should be handled correctly."""
        assert _tuple_gt((1, 0, 0, 1), (1, 0, 0))
        assert not _tuple_gt((1, 0, 0), (1, 0, 0, 0))


# ---------------------------------------------------------------------------
# End-to-end: history persistence
# ---------------------------------------------------------------------------


class TestHistoryPersistence:
    """Tests that exercise the JSON history file (using temp_history_file fixture)."""

    def test_first_run_records_version(self, temp_history_file):
        """First analysis of an extension records the version with no comparison."""
        result = analyse_version(
            manifest_version="1.0.0",
            extension_id="abc123",
            extension_name="Test",
        )
        assert result["previous_version"] is None
        assert result["velocity_score"] == 0

        # History file should now exist with this extension
        assert temp_history_file.exists()
        data = json.loads(temp_history_file.read_text())
        assert data["abc123"]["version"] == "1.0.0"

    def test_second_run_detects_jump(self, temp_history_file):
        """The 2nd analysis with a major-jumped version should flag it."""
        # First call records 1.0.4
        analyse_version("1.0.4", extension_id="abc", extension_name="X")
        # Second call with 17.3.1 should detect the jump
        result = analyse_version("17.3.1", extension_id="abc", extension_name="X")
        assert result["previous_version"] == "1.0.4"
        assert result["is_suspicious"] is True
        assert result["velocity_score"] > 0

    def test_same_version_no_jump(self, temp_history_file):
        """Re-analysing the same version shouldn't flag anything."""
        analyse_version("1.0.0", extension_id="abc")
        result = analyse_version("1.0.0", extension_id="abc")
        assert result["is_suspicious"] is False
        assert result["velocity_score"] == 0


class TestCwsVersion:
    """The store comparison moved to publisher_checker (which also compares the
    build hash). Velocity must not score it too - that double-counted."""

    def test_cws_version_is_reported_but_not_scored(self, temp_history_file):
        result = analyse_version(manifest_version="2.0.0", cws_version="1.0.0", extension_id="abc")
        assert result["cws_version"] == "1.0.0"
        assert result["velocity_score"] == 0

    def test_low_version_flagged_softly(self, temp_history_file):
        """Major version 0 is a soft signal - brand new extension."""
        result = analyse_version("0.0.5", extension_id="abc")
        assert result["velocity_score"] >= 3

    def test_single_segment_zero_does_not_crash(self, temp_history_file):
        """Regression (review harness #5): version "0" raised IndexError."""
        result = analyse_version("0", extension_id="abc")
        assert result["velocity_score"] >= 3


class TestRecording:
    def test_record_false_leaves_baseline_untouched(self, temp_history_file):
        """Scanning a (possibly malicious) sample must not become the baseline."""
        analyse_version("1.0.0", extension_id="abc")
        analyse_version("1.0.1", extension_id="abc", record=False)
        result = analyse_version("1.0.2", extension_id="abc", record=False)
        assert result["previous_version"] == "1.0.0"

    def test_record_version_sets_baseline(self, temp_history_file):
        from extguard.update_velocity import record_version

        assert record_version("2.0.0", "abc", "X") is True
        assert (
            analyse_version("2.0.1", extension_id="abc", record=False)["previous_version"]
            == "2.0.0"
        )

    def test_record_version_without_identity(self, temp_history_file):
        from extguard.update_velocity import record_version

        assert record_version("1.0.0", None, "__MSG_appName__") is False

    def test_rollback_is_flagged(self, temp_history_file):
        analyse_version("5.0.0", extension_id="abc")
        result = analyse_version("1.0.0", extension_id="abc")
        assert result["is_suspicious"] is True
        assert any("BACKWARDS" in f for f in result["flags"])

    def test_major_bump_resetting_minor_is_not_a_minor_jump(self, temp_history_file):
        """1.19.0 -> 2.0.0 has minor delta -19; that's a normal release."""
        analyse_version("1.19.0", extension_id="abc")
        result = analyse_version("2.0.0", extension_id="abc")
        assert result["is_suspicious"] is False


class TestStableIdentity:
    def test_i18n_placeholder_names_do_not_share_history(self, temp_history_file):
        """Regression (review harness #4): two unrelated extensions both named
        __MSG_appName__ shared one history and produced a fake major jump."""
        analyse_version("1.0.0", extension_name="__MSG_appName__")
        result = analyse_version("5.2.0", extension_name="__MSG_appName__")
        assert result["previous_version"] is None
        assert result["is_suspicious"] is False
        assert any("history skipped" in f for f in result["flags"])
        assert not temp_history_file.exists()

    def test_plain_name_is_still_tracked(self, temp_history_file):
        analyse_version("1.0.0", extension_name="My Tool")
        result = analyse_version("9.0.0", extension_name="My Tool")
        assert result["previous_version"] == "1.0.0"


class TestAtomicWrite:
    """Regression: history writes must be atomic - never leave a half-written
    file that the next read would choke on."""

    def test_history_file_remains_valid_json_after_write(self, temp_history_file):
        import json as _json

        from extguard.update_velocity import analyse_version

        analyse_version("1.0.0", extension_id="abc", extension_name="X")
        # File should exist and be parseable
        assert temp_history_file.exists()
        data = _json.loads(temp_history_file.read_text())
        assert "abc" in data

    def test_no_temp_files_left_behind(self, temp_history_file):
        """The tempfile used for atomic write must be cleaned up after success."""
        from extguard.update_velocity import analyse_version

        analyse_version("1.0.0", extension_id="abc")
        # Look for any leftover .version_history-*.tmp files
        leftovers = list(temp_history_file.parent.glob(".version_history-*.tmp"))
        assert leftovers == []
