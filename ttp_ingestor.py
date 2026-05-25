# ttp_ingestor.py - Sync TTP library from a GitHub repo
#
# Two ways to trigger a sync:
#   1. WEBHOOK: Configure a push webhook in your GitHub TTP repo pointing at
#      the dashboard's /webhook/github route. Every push triggers an
#      automatic pull. HMAC-SHA256 signature verification protects against
#      forged requests.
#   2. CLI: `extguard-ttp-sync` runs a one-shot pull. Useful for batch jobs
#      or for SOC machines that can't expose an inbound webhook.
#
# How the sync works:
#   - GET /repos/{owner}/{repo}/contents/{path}?ref={branch}
#     returns a JSON listing of files in the path (or one file's content if
#     `path` is a file).
#   - For each .md file, GET its download_url and write to local disk under
#     ttp_library/ at the same relative path.
#   - DELETES are handled by computing the local-set minus the remote-set
#     and removing the difference. (Optional - default is "add/update only"
#     for safety.)
#
# Why GitHub Contents API instead of `git clone`?
#   - No git binary required on SOC machines.
#   - Works behind corporate proxies that allow HTTPS but not git://.
#   - Easier to authenticate via PAT than to script SSH key auth.

import hashlib
import hmac
import os
from pathlib import Path

import requests

from logging_setup import get_logger
from ttp_loader import DEFAULT_TTP_ROOT, clear_cache

log = get_logger(__name__)


# GitHub Contents API base URL
GH_CONTENTS_URL = "https://api.github.com/repos/{owner}/{repo}/contents/{path}"

# HTTP timeout for each GitHub call - short because we may iterate many files
REQUEST_TIMEOUT = 10


# ---------------------------------------------------------------------------
# Webhook signature verification
# ---------------------------------------------------------------------------


def verify_github_signature(
    payload_body: bytes,
    signature_header: str,
    secret: str,
) -> bool:
    """
    Verify a GitHub webhook's X-Hub-Signature-256 header.

    GitHub computes HMAC-SHA256 over the raw request body using the shared
    secret, hex-encodes it, and prefixes with "sha256=". We do the same and
    compare in constant time.

    Args:
        payload_body:     The RAW request body bytes (NOT the parsed JSON).
                          Flask gives us this via `request.get_data()`.
        signature_header: The value of the X-Hub-Signature-256 request header.
        secret:           The shared webhook secret configured in GitHub.

    Returns True iff the signature is valid.
    """
    if not signature_header or not secret:
        return False
    if not signature_header.startswith("sha256="):
        return False

    expected = (
        "sha256="
        + hmac.new(
            secret.encode("utf-8"),
            payload_body,
            digestmod=hashlib.sha256,
        ).hexdigest()
    )

    # Constant-time comparison so an attacker can't timing-leak the signature
    return hmac.compare_digest(expected, signature_header)


# ---------------------------------------------------------------------------
# Sync from GitHub Contents API
# ---------------------------------------------------------------------------


def sync_from_github(
    owner: str,
    repo: str,
    path: str = "",
    branch: str = "main",
    target_root: Path | str | None = None,
    github_token: str | None = None,
    delete_orphans: bool = False,
) -> dict:
    """
    Pull all .md files under `path` from a GitHub repo into the local TTP root.

    Args:
        owner, repo:      The target GitHub repository (e.g. "myorg", "extguard-ttp")
        path:             Subdirectory in the repo to sync (default: repo root)
        branch:           Git ref (branch, tag, or commit SHA)
        target_root:      Local directory to write to (default: ./ttp_library)
        github_token:     Optional PAT for private repos / higher rate limit.
                          Read from GITHUB_TOKEN env if not provided.
        delete_orphans:   If True, delete local .md files that are no longer
                          in the remote repo. Off by default (safer).

    Returns a result dict:
      {
        "ok":         bool,
        "fetched":    int,            # number of files written
        "skipped":    int,            # files unchanged (matching sha)
        "deleted":    int,            # local files removed (if delete_orphans)
        "errors":     list[str],
        "files":      list[str],      # paths written/updated
      }
    """
    target_root = Path(target_root) if target_root else DEFAULT_TTP_ROOT
    target_root.mkdir(parents=True, exist_ok=True)
    token = github_token or os.environ.get("GITHUB_TOKEN")

    result = {
        "ok": False,
        "fetched": 0,
        "skipped": 0,
        "deleted": 0,
        "errors": [],
        "files": [],
    }

    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    # 1. Enumerate the remote tree (recursive)
    try:
        remote_files = _list_remote_md_files(
            owner=owner,
            repo=repo,
            path=path,
            branch=branch,
            headers=headers,
        )
    except Exception as exc:
        result["errors"].append(f"Failed to list remote files: {exc}")
        log.warning("TTP sync: list failed: %s", exc)
        return result

    if not remote_files:
        result["errors"].append("Remote returned 0 .md files - check owner/repo/path/branch")
        return result

    # 2. Download each remote file
    seen_local_paths: set = set()
    for entry in remote_files:
        rel_path = entry["path"]
        # The relative path inside the local target_root strips the configured
        # source prefix `path` (e.g. if we sync from "ttp/" in the remote,
        # the local file goes to target_root/<rest> not target_root/ttp/<rest>)
        local_rel = rel_path
        if path and local_rel.startswith(path.rstrip("/") + "/"):
            local_rel = local_rel[len(path.rstrip("/")) + 1 :]
        local_path = target_root / local_rel
        seen_local_paths.add(local_path.resolve())

        try:
            written = _fetch_file(
                download_url=entry["download_url"],
                expected_sha=entry.get("sha"),
                local_path=local_path,
                headers=headers,
            )
            if written:
                result["fetched"] += 1
                result["files"].append(str(local_rel))
            else:
                result["skipped"] += 1
        except Exception as exc:
            result["errors"].append(f"{rel_path}: {exc}")
            log.warning("TTP sync: failed to write %s: %s", rel_path, exc)

    # 3. Optionally delete orphans
    if delete_orphans:
        for existing in target_root.rglob("*.md"):
            if existing.resolve() not in seen_local_paths:
                try:
                    existing.unlink()
                    result["deleted"] += 1
                    log.info("TTP sync: deleted orphan %s", existing)
                except OSError as exc:
                    result["errors"].append(f"delete {existing}: {exc}")

    result["ok"] = not result["errors"]

    # Invalidate the loader's mtime cache so the very next triage uses fresh content
    clear_cache()

    log.info(
        "TTP sync from %s/%s@%s: fetched=%d skipped=%d deleted=%d errors=%d",
        owner,
        repo,
        branch,
        result["fetched"],
        result["skipped"],
        result["deleted"],
        len(result["errors"]),
    )
    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _list_remote_md_files(
    owner: str,
    repo: str,
    path: str,
    branch: str,
    headers: dict,
) -> list:
    """
    Walk the remote repo tree and return a list of all .md file entries.
    Each entry is the GitHub Contents API "file" object with at least:
      {"path": "subdir/foo.md", "sha": "abc...", "download_url": "https://..."}
    """
    url = GH_CONTENTS_URL.format(owner=owner, repo=repo, path=path)
    resp = requests.get(
        url,
        headers=headers,
        params={"ref": branch},
        timeout=REQUEST_TIMEOUT,
    )
    if resp.status_code == 404:
        raise RuntimeError(f"GitHub: 404 for {owner}/{repo}/{path}@{branch}")
    if resp.status_code != 200:
        raise RuntimeError(f"GitHub HTTP {resp.status_code}: {resp.text[:200]}")

    data = resp.json()
    # The Contents API returns either a single file (dict) or a directory listing (list)
    if isinstance(data, dict) and data.get("type") == "file":
        # Single .md file requested directly
        return [data] if data["name"].endswith(".md") else []

    if not isinstance(data, list):
        raise RuntimeError(f"Unexpected Contents API response shape for {path}")

    files = []
    for entry in data:
        etype = entry.get("type")
        if etype == "file" and entry["name"].endswith(".md"):
            files.append(entry)
        elif etype == "dir":
            # Recurse into subdirectory. Use the raw "path" field from the entry
            # so we don't have to reconstruct the path ourselves.
            sub_files = _list_remote_md_files(
                owner=owner,
                repo=repo,
                path=entry["path"],
                branch=branch,
                headers=headers,
            )
            files.extend(sub_files)

    return files


def _fetch_file(
    download_url: str,
    expected_sha: str | None,
    local_path: Path,
    headers: dict,
) -> bool:
    """
    Download one file from GitHub and write to local_path.

    Returns True if the file was actually written (new or content changed),
    False if the local copy was already up-to-date.

    Optimisation: GitHub returns a `sha` (Git blob SHA-1) for each file. We
    compute the same SHA over the local file and skip the download when they
    match. This dramatically speeds up repeated syncs.
    """
    if expected_sha and local_path.exists():
        local_sha = _git_blob_sha1(local_path.read_bytes())
        if local_sha == expected_sha:
            return False  # Already up-to-date

    resp = requests.get(download_url, headers=headers, timeout=REQUEST_TIMEOUT)
    if resp.status_code != 200:
        raise RuntimeError(f"download HTTP {resp.status_code}")

    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_bytes(resp.content)
    return True


def _git_blob_sha1(content: bytes) -> str:
    """
    Reproduce Git's blob SHA-1 calculation:
      sha1("blob <size>\\x00<content>")
    """
    header = f"blob {len(content)}\x00".encode()
    return hashlib.sha1(header + content).hexdigest()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main():
    """`extguard-ttp-sync` command."""
    import argparse
    import json

    parser = argparse.ArgumentParser(
        description="Pull TTP library files from a GitHub repository.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  extguard-ttp-sync --owner myorg --repo extguard-ttp\n"
            "  extguard-ttp-sync --owner foo --repo bar --path ttps/ --branch main\n"
            "  extguard-ttp-sync --config extguard.conf.json\n"
            "\nAuthentication:\n"
            "  Set GITHUB_TOKEN env var for private repos or higher rate limits.\n"
        ),
    )
    parser.add_argument("--owner", help="Repo owner (org or user)")
    parser.add_argument("--repo", help="Repository name")
    parser.add_argument("--path", default="", help="Subdirectory inside the repo (default: root)")
    parser.add_argument("--branch", default="main", help="Branch/tag/SHA to sync from")
    parser.add_argument(
        "--target", default=None, help="Local target directory (default: ./ttp_library)"
    )
    parser.add_argument(
        "--config",
        default="extguard.conf.json",
        help="Read owner/repo/path/branch from a webhook section of this config file",
    )
    parser.add_argument(
        "--delete-orphans",
        action="store_true",
        help="Remove local .md files no longer in the remote repo",
    )
    args = parser.parse_args()

    # If owner/repo not given, try the config file
    owner, repo, path, branch = args.owner, args.repo, args.path, args.branch
    if not (owner and repo):
        cfg = _load_webhook_cfg(args.config)
        if cfg:
            owner = owner or cfg.get("owner")
            repo = repo or cfg.get("repo")
            path = path or cfg.get("path", "")
            branch = cfg.get("branch", branch)

    if not (owner and repo):
        parser.error(
            "Provide --owner and --repo, OR put them in the webhook section of extguard.conf.json"
        )

    print(f"Syncing TTP library from {owner}/{repo}@{branch}/{path or '<root>'}...")
    result = sync_from_github(
        owner=owner,
        repo=repo,
        path=path,
        branch=branch,
        target_root=args.target,
        delete_orphans=args.delete_orphans,
    )

    print(json.dumps(result, indent=2))
    if not result["ok"]:
        import sys

        sys.exit(1)


def _load_webhook_cfg(config_path) -> dict | None:
    """Pull the `webhook` section from extguard.conf.json if it exists."""
    import json
    from pathlib import Path

    p = Path(config_path)
    if not p.exists():
        return None
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    section = raw.get("webhook", {})
    if not isinstance(section, dict):
        return None
    return {k: v for k, v in section.items() if not k.startswith("_")}


if __name__ == "__main__":
    main()
