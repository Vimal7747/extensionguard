# tests/test_release_tools.py - tools/release_check.py (release workflow gate)
#
# The release workflow refuses to publish unless the tag, pyproject.toml and
# CHANGELOG.md agree. These tests pin that behaviour, including against the
# repository's real CHANGELOG, so a formatting change there can't silently
# break the next release.

from pathlib import Path

import pytest

from tools import release_check
from tools.release_check import (
    ReleaseError,
    build_notes,
    changelog_section,
    check_release,
    is_prerelease,
    read_project_version,
    version_from_tag,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

CHANGELOG = """# Changelog

## [Unreleased]

### Added
- something not released yet

## [0.4.0] — 2026-11-02

### Fixed
- a bug

## [0.3.0] - 2026-10-01

Older notes.
"""


def _project(tmp_path, version="0.4.0", changelog=CHANGELOG):
    (tmp_path / "pyproject.toml").write_text(
        f'[project]\nname = "extensionguard"\nversion         = "{version}"\n', encoding="utf-8"
    )
    (tmp_path / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
    return tmp_path


class TestTags:
    @pytest.mark.parametrize(
        "tag, version",
        [
            ("v0.4.0", "0.4.0"),
            ("v1.10.3", "1.10.3"),
            ("v0.4.0rc1", "0.4.0rc1"),
            ("v2.0.0b2", "2.0.0b2"),
        ],
    )
    def test_valid_tags(self, tag, version):
        assert version_from_tag(tag) == version

    @pytest.mark.parametrize(
        "tag", ["0.4.0", "v0.4", "v0.4.0-beta", "release-0.4.0", "v0.4.0 ", ""]
    )
    def test_invalid_tags(self, tag):
        with pytest.raises(ReleaseError):
            version_from_tag(tag)

    def test_prerelease_detection(self):
        assert is_prerelease("0.4.0rc1") and is_prerelease("0.4.0a3") and is_prerelease("1.0.0b1")
        assert not is_prerelease("0.4.0")


class TestChangelog:
    def test_section_body_stops_at_next_heading(self):
        date, body = changelog_section(CHANGELOG, "0.4.0")
        assert date == "2026-11-02"
        assert body == "### Fixed\n- a bug"

    def test_plain_dash_date_separator(self):
        assert changelog_section(CHANGELOG, "0.3.0") == ("2026-10-01", "Older notes.")

    def test_missing_section(self):
        with pytest.raises(ReleaseError, match="no section for 0.5.0"):
            changelog_section(CHANGELOG, "0.5.0")

    def test_undated_section_is_refused(self):
        with pytest.raises(ReleaseError, match="no date"):
            changelog_section("## [0.5.0]\n\n- stuff\n", "0.5.0")

    def test_empty_section_is_refused(self):
        with pytest.raises(ReleaseError, match="empty"):
            changelog_section("## [0.5.0] - 2026-12-01\n\n## [0.4.0] - 2026-11-02\nx\n", "0.5.0")

    def test_unreleased_is_never_a_release(self):
        with pytest.raises(ReleaseError):
            changelog_section(CHANGELOG, "Unreleased")


class TestCheckRelease:
    def test_consistent_release(self, tmp_path):
        result = check_release("v0.4.0", _project(tmp_path))
        assert result["version"] == "0.4.0" and result["prerelease"] is False

    def test_tag_must_match_pyproject(self, tmp_path):
        with pytest.raises(ReleaseError, match="does not match pyproject.toml version 0.3.0"):
            check_release("v0.4.0", _project(tmp_path, version="0.3.0"))

    def test_pyproject_without_version(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[project]\nname = 'x'\n", encoding="utf-8")
        with pytest.raises(ReleaseError):
            read_project_version((tmp_path / "pyproject.toml").read_text(encoding="utf-8"))

    def test_the_real_repository_is_consistent(self):
        """The current version in pyproject.toml has a dated CHANGELOG entry."""
        version = read_project_version((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        result = check_release(f"v{version}", REPO_ROOT)
        assert result["date"]
        assert "### " in result["body"]


class TestNotes:
    def test_notes_with_pypi(self):
        notes = build_notes("### Fixed\n- a bug", "0.4.0", "v0.4.0", "o/r", on_pypi=True)
        assert notes.startswith("### Fixed")
        assert "pip install extensionguard==0.4.0" in notes
        assert "https://github.com/o/r/blob/v0.4.0/CHANGELOG.md" in notes

    def test_notes_without_pypi_point_at_the_wheel(self):
        notes = build_notes("x", "0.4.0", "v0.4.0", "o/r", on_pypi=False)
        assert "pip install extensionguard-0.4.0-py3-none-any.whl" in notes
        assert "extensionguard==" not in notes


class TestCli:
    def test_writes_notes_and_github_outputs(self, tmp_path, monkeypatch, capsys):
        project = _project(tmp_path, version="0.4.0rc1",
                           changelog="## [0.4.0rc1] - 2026-11-01\n\n- rc\n")  # fmt: skip
        outputs = tmp_path / "github_output"
        monkeypatch.chdir(project)
        monkeypatch.setenv("GITHUB_OUTPUT", str(outputs))
        monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")

        assert release_check.main(["--tag", "v0.4.0rc1", "--notes", "notes.md"]) == 0
        assert "- rc" in (project / "notes.md").read_text(encoding="utf-8")
        assert outputs.read_text().splitlines() == ["version=0.4.0rc1", "prerelease=true"]
        assert "pre-release" in capsys.readouterr().out

    def test_failure_is_a_github_error_annotation(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(_project(tmp_path, version="0.3.0"))
        assert release_check.main(["--tag", "v0.4.0"]) == 1
        assert capsys.readouterr().out.startswith("::error::")

    def test_print_version(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(_project(tmp_path, version="1.2.3"))
        assert release_check.main(["--print-version"]) == 0
        assert capsys.readouterr().out.strip() == "1.2.3"


# ---------------------------------------------------------------------------
# tools/junit_annotations.py (failure reasons readable without a sign-in)
# ---------------------------------------------------------------------------

JUNIT = """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest" tests="3" failures="1" errors="1">
  <testcase classname="tests.test_live_apis" name="test_ok" time="0.1"/>
  <testcase classname="tests.test_live_apis" name="test_osv" time="0.2">
    <failure message="AssertionError: assert 200 == 400">resp = ...
E   assert 200 == 400
E    +  where 200 = &lt;Response [200]&gt;.status_code</failure>
  </testcase>
  <testcase classname="tests.test_live_monitor" name="test_chrome" time="1">
    <error message="failed on setup with &quot;RuntimeError: Chrome did not start&quot;">trace</error>
  </testcase>
</testsuite></testsuites>"""


class TestJunitAnnotations:
    def test_one_error_line_per_failed_test(self):
        from tools.junit_annotations import annotations

        lines = annotations(JUNIT)
        assert len(lines) == 2
        assert lines[0].startswith("::error title=FAILURE tests.test_live_apis.test_osv::")
        assert "assert 200 == 400" in lines[0]
        assert "%0A" in lines[0] and "\n" not in lines[0]  # one physical line
        assert lines[1].startswith("::error title=ERROR tests.test_live_monitor.test_chrome::")

    def test_long_tracebacks_keep_the_end(self):
        from tools.junit_annotations import MAX_MESSAGE_CHARS, annotations

        xml = JUNIT.replace("resp = ...", "x" * 10_000)
        assert "assert 200 == 400" in annotations(xml)[0]
        assert len(annotations(xml)[0]) < MAX_MESSAGE_CHARS + 500

    def test_missing_report_is_a_warning_not_a_crash(self, tmp_path, capsys):
        from tools.junit_annotations import main

        assert main([str(tmp_path / "nope.xml")]) == 0
        assert capsys.readouterr().out.startswith("::warning::")
