# tests/test_ttp_loader.py - Disk-backed TTP library loader tests

import time

import pytest

from extguard.ttp_loader import (
    _FALLBACK_LIBRARY,
    clear_cache,
    library_stats,
    load_ttp_library,
)


@pytest.fixture(autouse=True)
def reset_cache():
    """The loader's mtime cache is module-level - reset between tests."""
    clear_cache()
    yield
    clear_cache()


@pytest.fixture
def ttp_root(tmp_path):
    """A clean TTP library directory for each test."""
    d = tmp_path / "ttp_library"
    d.mkdir()
    return d


class TestFallback:
    """Behaviour when the library isn't on disk yet."""

    def test_missing_directory_returns_fallback(self, tmp_path):
        result = load_ttp_library(tmp_path / "does-not-exist")
        assert result == _FALLBACK_LIBRARY.strip()

    def test_empty_directory_returns_fallback(self, ttp_root):
        # ttp_root exists but has no .md files
        assert load_ttp_library(ttp_root) == _FALLBACK_LIBRARY.strip()

    def test_non_md_files_ignored(self, ttp_root):
        (ttp_root / "notes.txt").write_text("not markdown")
        (ttp_root / "data.json").write_text('{"x": 1}')
        # Only .md files count - directory is "empty" for our purposes
        assert load_ttp_library(ttp_root) == _FALLBACK_LIBRARY.strip()


class TestConcat:
    """Verify the concat behaviour across multiple files."""

    def test_single_file_loaded(self, ttp_root):
        (ttp_root / "campaign.md").write_text("# Campaign X\n\nDetails here.")
        result = load_ttp_library(ttp_root)
        assert "Campaign X" in result
        assert "Details here." in result

    def test_multiple_files_concatenated(self, ttp_root):
        (ttp_root / "a.md").write_text("# A\nAlpha content")
        (ttp_root / "b.md").write_text("# B\nBravo content")
        result = load_ttp_library(ttp_root)
        assert "Alpha content" in result
        assert "Bravo content" in result

    def test_subdirectories_recursed(self, ttp_root):
        (ttp_root / "campaigns").mkdir()
        (ttp_root / "campaigns" / "teamccp.md").write_text("TeamPCP info")
        (ttp_root / "patterns").mkdir()
        (ttp_root / "patterns" / "combo.md").write_text("Combo info")
        result = load_ttp_library(ttp_root)
        assert "TeamPCP info" in result
        assert "Combo info" in result

    def test_source_comment_added(self, ttp_root):
        """Each file gets a `<!-- source: path -->` marker so Claude can tell
        where each document starts."""
        (ttp_root / "campaigns").mkdir()
        (ttp_root / "campaigns" / "teamccp.md").write_text("content")
        result = load_ttp_library(ttp_root)
        assert "<!-- source: campaigns/teamccp.md -->" in result

    def test_file_order_is_stable(self, ttp_root):
        """Same input must always produce the same output - critical for
        Claude's prompt cache to hit."""
        (ttp_root / "b.md").write_text("B")
        (ttp_root / "a.md").write_text("A")
        (ttp_root / "c.md").write_text("C")
        result1 = load_ttp_library(ttp_root)
        clear_cache()
        result2 = load_ttp_library(ttp_root)
        assert result1 == result2


class TestCache:
    def test_repeat_calls_return_same_content(self, ttp_root):
        (ttp_root / "x.md").write_text("original")
        r1 = load_ttp_library(ttp_root)
        r2 = load_ttp_library(ttp_root)
        assert r1 == r2

    def test_file_change_invalidates_cache(self, ttp_root):
        (ttp_root / "x.md").write_text("v1 content")
        first = load_ttp_library(ttp_root)
        assert "v1 content" in first

        # Sleep enough that mtime resolution actually changes (Windows: 1s)
        time.sleep(1.1)
        (ttp_root / "x.md").write_text("v2 content")

        second = load_ttp_library(ttp_root)
        assert "v2 content" in second
        assert "v1 content" not in second

    def test_new_file_invalidates_cache(self, ttp_root):
        (ttp_root / "a.md").write_text("alpha")
        load_ttp_library(ttp_root)  # populate cache

        time.sleep(1.1)
        (ttp_root / "b.md").write_text("bravo")

        result = load_ttp_library(ttp_root)
        assert "alpha" in result
        assert "bravo" in result

    def test_clear_cache_forces_reload(self, ttp_root):
        (ttp_root / "x.md").write_text("v1")
        load_ttp_library(ttp_root)
        clear_cache()
        # Even without an mtime change, clear_cache forces a fresh read
        (ttp_root / "x.md").write_text("v2")
        result = load_ttp_library(ttp_root)
        assert "v2" in result


class TestLibraryStats:
    def test_stats_for_missing_dir(self, tmp_path):
        stats = library_stats(tmp_path / "nope")
        assert stats["exists"] is False
        assert stats["files"] == 0

    def test_stats_for_populated_dir(self, ttp_root):
        (ttp_root / "a.md").write_text("aaa")
        (ttp_root / "b.md").write_text("bbbb")
        stats = library_stats(ttp_root)
        assert stats["exists"] is True
        assert stats["files"] == 2
        assert stats["bytes"] == 7  # 3 + 4
        assert stats["latest_mtime"] > 0
