# tests/test_ttp_ingestor.py - GitHub webhook + Contents API sync tests
#
# All HTTP is mocked. The HMAC tests use real signatures so we catch any
# regression that breaks the verification math.

import hashlib
import hmac
import json
from unittest.mock import MagicMock, patch

import pytest

from ttp_ingestor import (
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
            self.SECRET.encode("utf-8"), body, hashlib.sha256,
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
        body = b'x'
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
                "type": "file", "name": "a.md", "path": "a.md",
                "sha": _git_blob_sha1(b"alpha content"),
                "download_url": "https://example.com/a",
            },
            {
                "type": "file", "name": "b.md", "path": "b.md",
                "sha": _git_blob_sha1(b"bravo content"),
                "download_url": "https://example.com/b",
            },
            # README should be skipped because it's not .md... wait it IS .md
            # Use a non-md file for the negative case
            {
                "type": "file", "name": "ignored.txt", "path": "ignored.txt",
                "download_url": "https://example.com/ignored",
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

        with patch("ttp_ingestor.requests.get", side_effect=_route):
            result = sync_from_github(
                owner="o", repo="r", target_root=target,
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
        listing_resp.json.return_value = [{
            "type": "file", "name": "x.md", "path": "x.md",
            "sha": existing_sha,
            "download_url": "https://example.com/x",
        }]

        with patch("ttp_ingestor.requests.get", return_value=listing_resp) as mock_get:
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
            {"type": "file", "name": "README.md", "path": "README.md",
             "sha": _git_blob_sha1(b"readme"),
             "download_url": "https://example.com/readme"},
        ]
        sub_listing = MagicMock(status_code=200)
        sub_listing.json.return_value = [
            {"type": "file", "name": "campaign.md", "path": "campaigns/campaign.md",
             "sha": _git_blob_sha1(b"camp"),
             "download_url": "https://example.com/camp"},
        ]
        readme_resp = MagicMock(status_code=200, content=b"readme")
        camp_resp   = MagicMock(status_code=200, content=b"camp")

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

        with patch("ttp_ingestor.requests.get", side_effect=_route):
            result = sync_from_github(owner="o", repo="r", target_root=target)

        assert result["fetched"] == 2
        assert (target / "README.md").exists()
        assert (target / "campaigns" / "campaign.md").exists()

    def test_404_returns_error_not_crash(self, tmp_path):
        bad_resp = MagicMock(status_code=404, text="Not Found")
        with patch("ttp_ingestor.requests.get", return_value=bad_resp):
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
        listing_resp.json.return_value = [{
            "type": "file", "name": "fresh.md", "path": "fresh.md",
            "sha": _git_blob_sha1(b"kept"),
            "download_url": "https://example.com/fresh",
        }]

        with patch("ttp_ingestor.requests.get", return_value=listing_resp):
            result = sync_from_github(
                owner="o", repo="r", target_root=target, delete_orphans=True,
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

        with patch("ttp_ingestor.requests.get", return_value=listing_resp):
            result = sync_from_github(owner="o", repo="r", target_root=target)

        assert result["deleted"] == 0
        assert (target / "old.md").exists()


# ---------------------------------------------------------------------------
# Webhook route integration with the dashboard
# ---------------------------------------------------------------------------

class TestWebhookRoute:
    """Hit the dashboard's /webhook/github route with various scenarios."""

    @pytest.fixture
    def client(self, tmp_path):
        """A dashboard client with webhook config preloaded."""
        from dashboard import create_app
        app = create_app(
            quarantine_root=tmp_path / "quarantine",
            webhook_cfg={
                "owner": "test", "repo": "ttp", "branch": "main",
                "secret": "test-secret",
            },
        )
        app.config["TESTING"] = True
        return app.test_client()

    def test_no_signature_rejected_401(self, client):
        resp = client.post("/webhook/github", data='{"ref":"refs/heads/main"}',
                           content_type="application/json")
        assert resp.status_code == 401

    def test_bad_signature_rejected_401(self, client):
        resp = client.post(
            "/webhook/github",
            data='{"ref":"refs/heads/main"}',
            content_type="application/json",
            headers={"X-Hub-Signature-256": "sha256=00000000"},
        )
        assert resp.status_code == 401

    def test_ping_event_returns_pong(self, client):
        body = b'{"zen": "Always test"}'
        sig = "sha256=" + hmac.new(b"test-secret", body, hashlib.sha256).hexdigest()
        resp = client.post(
            "/webhook/github", data=body, content_type="application/json",
            headers={"X-Hub-Signature-256": sig, "X-GitHub-Event": "ping"},
        )
        assert resp.status_code == 200
        assert b"pong" in resp.data

    def test_non_push_event_ignored(self, client):
        body = b'{"action":"opened"}'
        sig = "sha256=" + hmac.new(b"test-secret", body, hashlib.sha256).hexdigest()
        resp = client.post(
            "/webhook/github", data=body, content_type="application/json",
            headers={"X-Hub-Signature-256": sig,
                     "X-GitHub-Event": "pull_request"},
        )
        assert resp.status_code == 200
        assert b"ignored" in resp.data

    def test_push_to_wrong_branch_ignored(self, client):
        body = b'{"ref":"refs/heads/feature-branch"}'
        sig = "sha256=" + hmac.new(b"test-secret", body, hashlib.sha256).hexdigest()
        resp = client.post(
            "/webhook/github", data=body, content_type="application/json",
            headers={"X-Hub-Signature-256": sig, "X-GitHub-Event": "push"},
        )
        assert resp.status_code == 200
        assert b"ignored_ref" in resp.data

    def test_push_to_configured_branch_triggers_sync(self, client):
        """The HMAC-valid push to the right branch should trigger sync_from_github."""
        body = b'{"ref":"refs/heads/main"}'
        sig = "sha256=" + hmac.new(b"test-secret", body, hashlib.sha256).hexdigest()

        with patch("dashboard.sync_from_github") as mock_sync:
            mock_sync.return_value = {
                "ok": True, "fetched": 3, "skipped": 1,
                "deleted": 0, "errors": [], "files": ["a.md", "b.md", "c.md"],
            }
            resp = client.post(
                "/webhook/github", data=body, content_type="application/json",
                headers={"X-Hub-Signature-256": sig, "X-GitHub-Event": "push"},
            )

        assert resp.status_code == 200
        mock_sync.assert_called_once()
        # Verify the sync was called with the configured owner/repo
        kwargs = mock_sync.call_args.kwargs
        assert kwargs["owner"]  == "test"
        assert kwargs["repo"]   == "ttp"
        assert kwargs["branch"] == "main"

    def test_no_secret_returns_503(self, tmp_path):
        """A dashboard with no webhook secret should reject all webhook calls."""
        from dashboard import create_app
        app = create_app(
            quarantine_root=tmp_path / "quarantine",
            webhook_cfg=None,
        )
        client = app.test_client()
        resp = client.post(
            "/webhook/github", data=b'{}', content_type="application/json",
        )
        assert resp.status_code == 503
