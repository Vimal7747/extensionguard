# tests/test_ttp_ingestor.py - GitHub webhook + Contents API sync tests
#
# All HTTP is mocked. The HMAC tests use real signatures so we catch any
# regression that breaks the verification math.

import hashlib
import hmac
import json
from unittest.mock import MagicMock, patch

import pytest

from extguard import paths, ttp_ingestor
from extguard.ttp_ingestor import (
    _git_blob_sha1,
    sync_from_github,
    verify_github_signature,
)

# ---------------------------------------------------------------------------
# HMAC signature verification - the security-critical bit
# ---------------------------------------------------------------------------


class TestSignatureVerification:
    SECRET = "shhh-its-a-secret"

    def _sign(self, body: bytes) -> str:
        """Mimic exactly what GitHub does to build X-Hub-Signature-256."""
        digest = hmac.new(
            self.SECRET.encode("utf-8"),
            body,
            hashlib.sha256,
        ).hexdigest()
        return f"sha256={digest}"

    def test_valid_signature_accepted(self):
        body = b'{"event": "push"}'
        sig = self._sign(body)
        assert verify_github_signature(body, sig, self.SECRET) is True

    def test_wrong_secret_rejected(self):
        body = b'{"event": "push"}'
        sig = self._sign(body)
        # Reject when the secret doesn't match
        assert verify_github_signature(body, sig, "wrong-secret") is False

    def test_modified_body_rejected(self):
        """Even a single-byte tamper must produce a mismatch."""
        body = b'{"event": "push"}'
        sig = self._sign(body)
        assert verify_github_signature(b'{"event": "PUSH"}', sig, self.SECRET) is False

    def test_missing_sha256_prefix_rejected(self):
        body = b"x"
        # Raw hex with no "sha256=" prefix - must reject
        digest = hmac.new(self.SECRET.encode(), body, hashlib.sha256).hexdigest()
        assert verify_github_signature(body, digest, self.SECRET) is False

    def test_empty_signature_rejected(self):
        assert verify_github_signature(b"x", "", self.SECRET) is False

    def test_empty_secret_rejected(self):
        """Defensive: an empty configured secret must NOT accept any signature."""
        assert verify_github_signature(b"x", "sha256=abc", "") is False

    def test_timing_safe_comparison(self):
        """We use hmac.compare_digest - same-length wrong strings should
        still reject. Just verify the function returns False, the actual
        timing properties are tested in cpython upstream."""
        body = b"x"
        good = self._sign(body)
        # Substitute one hex character - still 64 chars but no longer valid
        bad = good[:-1] + ("0" if good[-1] != "0" else "1")
        assert verify_github_signature(body, bad, self.SECRET) is False


# ---------------------------------------------------------------------------
# Git blob SHA reproduction (for change detection)
# ---------------------------------------------------------------------------


class TestGitBlobSha:
    def test_known_vector(self):
        """Git's blob SHA for empty content is e69de29..."""
        assert _git_blob_sha1(b"") == "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"

    def test_deterministic(self):
        assert _git_blob_sha1(b"hello") == _git_blob_sha1(b"hello")

    def test_different_content_different_sha(self):
        assert _git_blob_sha1(b"hello") != _git_blob_sha1(b"world")


# ---------------------------------------------------------------------------
# sync_from_github happy path
# ---------------------------------------------------------------------------


class TestSyncSuccess:
    def test_writes_remote_files_to_target(self, tmp_path):
        """A flat directory listing with two .md files should download both."""
        target = tmp_path / "ttp"
        # First call: the directory listing
        listing = [
            {
                "type": "file",
                "name": "a.md",
                "path": "a.md",
                "sha": _git_blob_sha1(b"alpha content"),
                "download_url": "https://raw.githubusercontent.com/o/r/main/a",
            },
            {
                "type": "file",
                "name": "b.md",
                "path": "b.md",
                "sha": _git_blob_sha1(b"bravo content"),
                "download_url": "https://raw.githubusercontent.com/o/r/main/b",
            },
            # README should be skipped because it's not .md... wait it IS .md
            # Use a non-md file for the negative case
            {
                "type": "file",
                "name": "ignored.txt",
                "path": "ignored.txt",
                "download_url": "https://raw.githubusercontent.com/o/r/main/ignored",
            },
        ]
        listing_resp = MagicMock(status_code=200)
        listing_resp.json.return_value = listing
        # Subsequent calls: the individual file downloads
        a_resp = MagicMock(status_code=200, content=b"alpha content")
        b_resp = MagicMock(status_code=200, content=b"bravo content")

        def _route(url, **kwargs):
            if "contents" in url:
                return listing_resp
            if url.endswith("/a"):
                return a_resp
            if url.endswith("/b"):
                return b_resp
            raise AssertionError(f"unexpected URL: {url}")

        with patch("extguard.ttp_ingestor.requests.get", side_effect=_route):
            result = sync_from_github(
                owner="o",
                repo="r",
                target_root=target,
            )

        assert result["ok"] is True
        assert result["fetched"] == 2
        assert (target / "a.md").read_bytes() == b"alpha content"
        assert (target / "b.md").read_bytes() == b"bravo content"
        # The .txt file must NOT be downloaded
        assert not (target / "ignored.txt").exists()

    def test_unchanged_file_skipped(self, tmp_path):
        """A file already on disk with matching git-blob SHA should not be re-downloaded."""
        target = tmp_path / "ttp"
        target.mkdir()
        existing_content = b"already up to date"
        (target / "x.md").write_bytes(existing_content)
        existing_sha = _git_blob_sha1(existing_content)

        listing_resp = MagicMock(status_code=200)
        listing_resp.json.return_value = [
            {
                "type": "file",
                "name": "x.md",
                "path": "x.md",
                "sha": existing_sha,
                "download_url": "https://raw.githubusercontent.com/o/r/main/x",
            }
        ]

        with patch("extguard.ttp_ingestor.requests.get", return_value=listing_resp) as mock_get:
            result = sync_from_github(owner="o", repo="r", target_root=target)

        assert result["skipped"] == 1
        assert result["fetched"] == 0
        # Only the listing call - no download call
        assert mock_get.call_count == 1

    def test_recursive_directory_walk(self, tmp_path):
        """Nested directories should be recursed into."""
        target = tmp_path / "ttp"

        root_listing = MagicMock(status_code=200)
        root_listing.json.return_value = [
            {"type": "dir", "name": "campaigns", "path": "campaigns"},
            {
                "type": "file",
                "name": "README.md",
                "path": "README.md",
                "sha": _git_blob_sha1(b"readme"),
                "download_url": "https://raw.githubusercontent.com/o/r/main/readme",
            },
        ]
        sub_listing = MagicMock(status_code=200)
        sub_listing.json.return_value = [
            {
                "type": "file",
                "name": "campaign.md",
                "path": "campaigns/campaign.md",
                "sha": _git_blob_sha1(b"camp"),
                "download_url": "https://raw.githubusercontent.com/o/r/main/camp",
            },
        ]
        readme_resp = MagicMock(status_code=200, content=b"readme")
        camp_resp = MagicMock(status_code=200, content=b"camp")

        def _route(url, **kwargs):
            if url.endswith("/contents/"):
                return root_listing
            if url.endswith("/contents/campaigns"):
                return sub_listing
            if "readme" in url:
                return readme_resp
            if "camp" in url:
                return camp_resp
            raise AssertionError(f"unexpected URL: {url}")

        with patch("extguard.ttp_ingestor.requests.get", side_effect=_route):
            result = sync_from_github(owner="o", repo="r", target_root=target)

        assert result["fetched"] == 2
        assert (target / "README.md").exists()
        assert (target / "campaigns" / "campaign.md").exists()

    def test_404_returns_error_not_crash(self, tmp_path):
        bad_resp = MagicMock(status_code=404, text="Not Found")
        with patch("extguard.ttp_ingestor.requests.get", return_value=bad_resp):
            result = sync_from_github(owner="o", repo="r", target_root=tmp_path)
        assert result["ok"] is False
        assert any("404" in e for e in result["errors"])

    def test_delete_orphans_removes_local_files_not_in_remote(self, tmp_path):
        target = tmp_path / "ttp"
        target.mkdir()
        # Create an old file that the remote doesn't have anymore
        (target / "old.md").write_text("stale content")
        # And one that IS in the remote
        (target / "fresh.md").write_text("kept")

        listing_resp = MagicMock(status_code=200)
        listing_resp.json.return_value = [
            {
                "type": "file",
                "name": "fresh.md",
                "path": "fresh.md",
                "sha": _git_blob_sha1(b"kept"),
                "download_url": "https://raw.githubusercontent.com/o/r/main/fresh",
            }
        ]

        with patch("extguard.ttp_ingestor.requests.get", return_value=listing_resp):
            result = sync_from_github(
                owner="o",
                repo="r",
                target_root=target,
                delete_orphans=True,
            )

        assert result["deleted"] == 1
        assert not (target / "old.md").exists()
        assert (target / "fresh.md").exists()

    def test_delete_orphans_off_by_default(self, tmp_path):
        """Without delete_orphans, the stale file should survive."""
        target = tmp_path / "ttp"
        target.mkdir()
        (target / "old.md").write_text("stale")

        listing_resp = MagicMock(status_code=200)
        listing_resp.json.return_value = []

        with patch("extguard.ttp_ingestor.requests.get", return_value=listing_resp):
            result = sync_from_github(owner="o", repo="r", target_root=target)

        assert result["deleted"] == 0
        assert (target / "old.md").exists()


# ---------------------------------------------------------------------------
# Hardening: token safety, limits, orphans, signed commits
# ---------------------------------------------------------------------------


def _listing(*entries):
    resp = MagicMock(status_code=200)
    resp.json.return_value = list(entries)
    return resp


def _file_entry(name, content, url=None, size=None):
    entry = {
        "type": "file",
        "name": name,
        "path": name,
        "sha": _git_blob_sha1(content),
        "download_url": url or f"https://raw.githubusercontent.com/o/r/main/{name}",
    }
    if size is not None:
        entry["size"] = size
    return entry


def _router(listing, download, commit=None):
    """requests.get stand-in: listing for Contents API calls, else the download."""

    def _route(url, **kwargs):
        if commit is not None and "/commits/" in url:
            return commit
        return listing if "contents" in url else download

    return _route


class TestSyncHardening:
    def test_default_target_is_the_pending_folder(self):
        """A sync must not change what Claude sees until it is activated."""
        listing = _listing(_file_entry("a.md", b"alpha"))
        download = MagicMock(status_code=200, content=b"alpha")

        with patch("extguard.ttp_ingestor.requests.get", side_effect=_router(listing, download)):
            result = sync_from_github(owner="o", repo="r")

        assert result["ok"] is True
        assert (paths.ttp_pending_dir() / "a.md").read_bytes() == b"alpha"
        assert not (paths.ttp_user_dir() / "a.md").exists()

    def test_token_never_sent_off_github(self, tmp_path):
        listing = _listing(_file_entry("a.md", b"x", url="https://evil.example/a.md"))
        with patch("extguard.ttp_ingestor.requests.get", return_value=listing) as mock_get:
            result = sync_from_github(
                owner="o", repo="r", target_root=tmp_path, github_token="ghp_secret"
            )
        assert result["ok"] is False
        assert any("not on GitHub" in e for e in result["errors"])
        # Only the listing call went out - the off-GitHub URL was never fetched
        assert mock_get.call_count == 1

    def test_oversized_file_refused_from_listing(self, tmp_path):
        listing = _listing(_file_entry("big.md", b"x", size=ttp_ingestor.MAX_FILE_BYTES + 1))
        with patch("extguard.ttp_ingestor.requests.get", return_value=listing) as mock_get:
            result = sync_from_github(owner="o", repo="r", target_root=tmp_path)
        assert result["ok"] is False
        assert mock_get.call_count == 1
        assert not (tmp_path / "big.md").exists()

    def test_oversized_download_refused(self, tmp_path):
        big = b"x" * (ttp_ingestor.MAX_FILE_BYTES + 1)
        listing = _listing(_file_entry("big.md", b"small"))
        download = MagicMock(status_code=200, content=big)

        with patch("extguard.ttp_ingestor.requests.get", side_effect=_router(listing, download)):
            result = sync_from_github(owner="o", repo="r", target_root=tmp_path)
        assert result["ok"] is False
        assert not (tmp_path / "big.md").exists()

    def test_path_escaping_target_refused(self, tmp_path):
        entry = _file_entry("x.md", b"x")
        entry["path"] = "../outside.md"
        with patch("extguard.ttp_ingestor.requests.get", return_value=_listing(entry)):
            result = sync_from_github(owner="o", repo="r", target_root=tmp_path / "t")
        assert result["ok"] is False
        assert not (tmp_path / "outside.md").exists()

    def test_delete_orphans_refuses_to_wipe_most_of_the_library(self, tmp_path):
        target = tmp_path / "ttp"
        target.mkdir()
        for i in range(5):
            (target / f"old{i}.md").write_text("old")
        (target / "keep.md").write_text("keep")
        listing = _listing(_file_entry("keep.md", b"keep"))

        with patch("extguard.ttp_ingestor.requests.get", return_value=listing):
            result = sync_from_github(owner="o", repo="r", target_root=target, delete_orphans=True)
        assert result["deleted"] == 0
        assert any("refused" in e for e in result["errors"])
        assert len(list(target.glob("*.md"))) == 6

    def test_delete_orphans_skipped_after_errors(self, tmp_path):
        target = tmp_path / "ttp"
        target.mkdir()
        (target / "old.md").write_text("old")
        (target / "a.md").write_text("a")
        (target / "b.md").write_text("b")
        listing = _listing(_file_entry("a.md", b"a"), _file_entry("b.md", b"new b"))
        failed = MagicMock(status_code=500)

        with patch("extguard.ttp_ingestor.requests.get", side_effect=_router(listing, failed)):
            result = sync_from_github(owner="o", repo="r", target_root=target, delete_orphans=True)
        assert result["deleted"] == 0
        assert (target / "old.md").exists()

    def test_unverified_commit_refused(self, tmp_path):
        commit = MagicMock(status_code=200)
        commit.json.return_value = {
            "commit": {"verification": {"verified": False, "reason": "unsigned"}}
        }
        with patch("extguard.ttp_ingestor.requests.get", return_value=commit) as mock_get:
            result = sync_from_github(
                owner="o", repo="r", target_root=tmp_path, require_verified_commit=True
            )
        assert result["ok"] is False
        assert any("unsigned" in e for e in result["errors"])
        assert mock_get.call_count == 1  # no listing, no downloads

    def test_verified_commit_allows_sync(self, tmp_path):
        commit = MagicMock(status_code=200)
        commit.json.return_value = {"commit": {"verification": {"verified": True}}}
        listing = _listing(_file_entry("a.md", b"alpha"))
        download = MagicMock(status_code=200, content=b"alpha")

        with patch(
            "extguard.ttp_ingestor.requests.get",
            side_effect=_router(listing, download, commit),
        ):
            result = sync_from_github(
                owner="o", repo="r", target_root=tmp_path, require_verified_commit=True
            )
        assert result["ok"] is True


# ---------------------------------------------------------------------------
# Approval gate: pending -> active
# ---------------------------------------------------------------------------


class TestActivation:
    def test_pending_changes_lists_added_changed_removed(self, tmp_path):
        pending, active = tmp_path / "pending", tmp_path / "active"
        pending.mkdir()
        active.mkdir()
        (pending / "new.md").write_text("new")
        (pending / "same.md").write_text("same")
        (active / "same.md").write_text("same")
        (pending / "edit.md").write_text("v2")
        (active / "edit.md").write_text("v1")
        (active / "gone.md").write_text("gone")

        changes = ttp_ingestor.pending_changes(pending, active)
        assert changes["pending"] is True
        assert changes["added"] == ["new.md"]
        assert changes["changed"] == ["edit.md"]
        assert changes["removed"] == ["gone.md"]

    def test_activate_swaps_in_pending_and_keeps_previous(self, tmp_path):
        pending, active = tmp_path / "pending", tmp_path / "active"
        pending.mkdir()
        active.mkdir()
        (pending / "a.md").write_text("new intel")
        (active / "a.md").write_text("old intel")

        result = ttp_ingestor.activate_pending(pending, active)
        assert result["ok"] is True
        assert (active / "a.md").read_text() == "new intel"
        assert (tmp_path / "active.previous" / "a.md").read_text() == "old intel"
        # Pending stays, so the next sync only downloads what changed
        assert (pending / "a.md").exists()
        assert ttp_ingestor.pending_changes(pending, active)["pending"] is False

    def test_activate_without_pending_fails(self, tmp_path):
        result = ttp_ingestor.activate_pending(tmp_path / "none", tmp_path / "active")
        assert result["ok"] is False

    def test_cli_sync_stages_then_activate(self, capsys):
        listing = _listing(_file_entry("a.md", b"alpha"))
        download = MagicMock(status_code=200, content=b"alpha")

        with patch("extguard.ttp_ingestor.requests.get", side_effect=_router(listing, download)):
            assert ttp_ingestor.main(["--owner", "o", "--repo", "r"]) == 0
        assert "--activate" in capsys.readouterr().out
        assert not (paths.ttp_user_dir() / "a.md").exists()

        assert ttp_ingestor.main(["--activate"]) == 0
        assert (paths.ttp_user_dir() / "a.md").read_bytes() == b"alpha"
