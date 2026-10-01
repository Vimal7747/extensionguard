# ttp_ingestor.py - Sync TTP library from a GitHub repo
#
# Two ways to trigger a sync:
#   1. WEBHOOK: `extguard-webhook` (webhook_server.py) receives GitHub push
#      events, verifies the HMAC signature and runs a sync in the background.
#   2. CLI: `extguard-ttp-sync` runs a one-shot pull. Useful for batch jobs
#      or for SOC machines that can't expose an inbound webhook.
#
# Staged sync (approval gate):
#   The TTP library goes straight into Claude's system prompt, so whoever can
#   push to the TTP repo can steer every verdict. A sync therefore writes to a
#   PENDING folder (~/.extguard/ttp_library.pending). Nothing changes for the
#   triage until an analyst reviews the change and runs
#       extguard-ttp-sync --status      # what would change
#       extguard-ttp-sync --activate    # make it live
#   Teams that fully trust their repo can opt out with --auto-activate (CLI)
#   or "auto_activate": true in the webhook config.
#
# How the sync works:
#   - GET /repos/{owner}/{repo}/contents/{path}?ref={branch}
#     returns a JSON listing of files in the path (or one file's content if
#     `path` is a file).
#   - For each .md file, GET its download_url and write it under the pending
#     folder at the same relative path.
#   - Limits: MAX_FILE_BYTES per file, MAX_TOTAL_BYTES and MAX_FILES per sync.
#   - The GitHub token is only ever sent to GitHub hosts.
#
# Why GitHub Contents API instead of `git clone`?
#   - No git binary required on SOC machines.
#   - Works behind corporate proxies that allow HTTPS but not git://.
#   - Easier to authenticate via PAT than to script SSH key auth.

import hashlib
import hmac
import os
import shutil
from pathlib import Path
from urllib.parse import urlparse

import requests

from extguard import paths
from extguard.logging_setup import get_logger, redact
from extguard.ttp_loader import clear_cache

log = get_logger(__name__)


# GitHub Contents API base URL
GH_CONTENTS_URL = "https://api.github.com/repos/{owner}/{repo}/contents/{path}"
GH_COMMIT_URL = "https://api.github.com/repos/{owner}/{repo}/commits/{ref}"

# Hosts the GitHub token may be sent to. A download_url anywhere else is
# refused - the token must never leave GitHub.
GITHUB_HOSTS = {"api.github.com", "raw.githubusercontent.com"}

# HTTP timeout for each GitHub call - short because we may iterate many files
REQUEST_TIMEOUT = 10

# Size limits - the whole library ends up in every triage prompt
MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 1024 * 1024
MAX_FILES = 500

# delete_orphans refuses to remove more than this share of the local files in
# one sync (a wrong `path` or a half-empty listing would otherwise wipe the library)
MAX_ORPHAN_FRACTION = 0.5


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
    require_verified_commit: bool = False,
) -> dict:
    """
    Pull all .md files under `path` from a GitHub repo into a local folder.

    Args:
        owner, repo:      The target GitHub repository (e.g. "myorg", "extguard-ttp")
        path:             Subdirectory in the repo to sync (default: repo root)
        branch:           Git ref (branch, tag, or commit SHA)
        target_root:      Local directory to write to. Default: the PENDING
                          folder - run activate_pending() to make it live.
        github_token:     Optional PAT for private repos / higher rate limit.
                          Read from GITHUB_TOKEN env if not provided.
        delete_orphans:   If True, delete local .md files that are no longer
                          in the remote repo. Off by default (safer).
        require_verified_commit:
                          Refuse to sync unless GitHub reports the head commit
                          of `branch` as signature-verified.

    Returns a result dict:
      {
        "ok":         bool,
        "fetched":    int,            # number of files written
        "skipped":    int,            # files unchanged (matching sha)
        "deleted":    int,            # local files removed (if delete_orphans)
        "errors":     list[str],
        "files":      list[str],      # paths written/updated
        "target":     str,            # where the files went
      }
    """
    # Synced intel goes to the pending folder, never into the installed package
    target_root = Path(target_root) if target_root else paths.ttp_pending_dir()
    target_root.mkdir(parents=True, exist_ok=True)
    token = github_token or os.environ.get("GITHUB_TOKEN")

    result = {
        "ok": False,
        "fetched": 0,
        "skipped": 0,
        "deleted": 0,
        "errors": [],
        "files": [],
        "target": str(target_root),
    }

    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    # 0. Optionally insist on a signed head commit
    if require_verified_commit:
        problem = _check_verified_commit(owner, repo, branch, headers)
        if problem:
            result["errors"].append(problem)
            return _finish(result, owner, repo, branch)

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
        log.warning("TTP sync: list failed: %s", redact(str(exc)))
        return _finish(result, owner, repo, branch)

    if not remote_files:
        result["errors"].append("Remote returned 0 .md files - check owner/repo/path/branch")
        return _finish(result, owner, repo, branch)
    if len(remote_files) > MAX_FILES:
        result["errors"].append(f"Remote has {len(remote_files)} .md files - limit is {MAX_FILES}")
        return _finish(result, owner, repo, branch)

    # 2. Download each remote file
    root_resolved = target_root.resolve()
    seen_local_paths: set = set()
    total_bytes = 0
    for entry in remote_files:
        rel_path = entry["path"]
        # The relative path inside the local target_root strips the configured
        # source prefix `path` (e.g. if we sync from "ttp/" in the remote,
        # the local file goes to target_root/<rest> not target_root/ttp/<rest>)
        local_rel = rel_path
        if path and local_rel.startswith(path.rstrip("/") + "/"):
            local_rel = local_rel[len(path.rstrip("/")) + 1 :]
        local_path = target_root / local_rel
        # Never write outside the target folder, whatever the listing says
        if not local_path.resolve().is_relative_to(root_resolved):
            result["errors"].append(f"{rel_path}: path escapes the target folder")
            continue
        seen_local_paths.add(local_path.resolve())

        size = entry.get("size")
        if isinstance(size, int) and size > MAX_FILE_BYTES:
            result["errors"].append(f"{rel_path}: {size} bytes - limit is {MAX_FILE_BYTES}")
            continue

        try:
            written = _fetch_file(
                download_url=entry.get("download_url") or "",
                expected_sha=entry.get("sha"),
                local_path=local_path,
                headers=headers,
            )
            total_bytes += local_path.stat().st_size
            if written:
                result["fetched"] += 1
                result["files"].append(str(local_rel))
            else:
                result["skipped"] += 1
        except Exception as exc:
            result["errors"].append(f"{rel_path}: {exc}")
            log.warning("TTP sync: failed to write %s: %s", rel_path, redact(str(exc)))

        if total_bytes > MAX_TOTAL_BYTES:
            result["errors"].append(
                f"Library is larger than {MAX_TOTAL_BYTES} bytes - sync stopped"
            )
            break

    # 3. Optionally delete orphans - only after a complete, error-free listing
    # and download, and never most of the library at once
    if delete_orphans:
        if result["errors"]:
            result["errors"].append("delete_orphans skipped because the sync had errors")
        else:
            orphans = [f for f in target_root.rglob("*.md") if f.resolve() not in seen_local_paths]
            local_count = len(list(target_root.rglob("*.md")))
            if local_count and len(orphans) / local_count > MAX_ORPHAN_FRACTION:
                result["errors"].append(
                    f"delete_orphans refused: it would remove {len(orphans)} of "
                    f"{local_count} files (check the configured path)"
                )
            else:
                for existing in orphans:
                    try:
                        existing.unlink()
                        result["deleted"] += 1
                        log.info("TTP sync: deleted orphan %s", existing)
                    except OSError as exc:
                        result["errors"].append(f"delete {existing}: {exc}")

    return _finish(result, owner, repo, branch)


def _finish(result: dict, owner: str, repo: str, branch: str) -> dict:
    result["ok"] = not result["errors"]
    # Errors echo GitHub responses; they are returned to the webhook caller and
    # printed by the CLI, so scrub any token that might be in them
    result["errors"] = [redact(e) for e in result["errors"]]

    # Invalidate the loader's mtime cache so the next triage re-reads the library
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
# Approval gate: pending -> active
# ---------------------------------------------------------------------------


def pending_changes(
    pending_root: Path | str | None = None, active_root: Path | str | None = None
) -> dict:
    """
    Compare the pending library with the active one.
    Returns {"pending": bool, "added": [...], "changed": [...], "removed": [...]}.
    """
    pending = Path(pending_root) if pending_root else paths.ttp_pending_dir()
    active = Path(active_root) if active_root else paths.ttp_user_dir()
    changes = {"pending": False, "added": [], "changed": [], "removed": []}
    if not pending.is_dir():
        return changes

    new = _md_hashes(pending)
    old = _md_hashes(active) if active.is_dir() else {}
    changes["added"] = sorted(set(new) - set(old))
    changes["removed"] = sorted(set(old) - set(new))
    changes["changed"] = sorted(k for k in set(new) & set(old) if new[k] != old[k])
    changes["pending"] = bool(changes["added"] or changes["changed"] or changes["removed"])
    return changes


def activate_pending(
    pending_root: Path | str | None = None, active_root: Path | str | None = None
) -> dict:
    """
    Make the reviewed pending library the active one. The previous active
    library is kept as <active>.previous so a bad update can be rolled back.
    The pending folder stays in place so the next sync only downloads changes.
    """
    pending = Path(pending_root) if pending_root else paths.ttp_pending_dir()
    active = Path(active_root) if active_root else paths.ttp_user_dir()
    if not pending.is_dir() or not any(pending.rglob("*.md")):
        return {"ok": False, "error": f"No pending library at {pending} - run a sync first"}

    changes = pending_changes(pending, active)
    previous = active.with_name(active.name + ".previous")
    # Files are copied rather than the folder renamed: the active folder is
    # often a Docker volume mount point, which can't be renamed.
    try:
        shutil.rmtree(previous, ignore_errors=True)
        if active.exists():
            shutil.copytree(active, previous)
        active.mkdir(parents=True, exist_ok=True)
        for name in changes["removed"]:
            (active / name).unlink()
        for name in changes["added"] + changes["changed"]:
            target = active / name
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp = target.with_name(target.name + ".tmp")
            shutil.copyfile(pending / name, tmp)
            tmp.replace(target)  # each file switches over atomically
    except OSError as exc:
        return {"ok": False, "error": f"Activation failed: {exc}"}

    clear_cache()
    log.info(
        "TTP library activated: +%d ~%d -%d",
        len(changes["added"]),
        len(changes["changed"]),
        len(changes["removed"]),
    )
    return {"ok": True, "changes": changes, "active": str(active), "previous": str(previous)}


def _md_hashes(root: Path) -> dict:
    return {
        f.relative_to(root).as_posix(): hashlib.sha256(f.read_bytes()).hexdigest()
        for f in root.rglob("*.md")
        if f.is_file()
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _check_verified_commit(owner: str, repo: str, branch: str, headers: dict) -> str | None:
    """Return a problem description unless the branch head commit is verified."""
    url = GH_COMMIT_URL.format(owner=owner, repo=repo, ref=branch)
    try:
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        return f"Could not check commit signature: {exc}"
    if resp.status_code != 200:
        return f"Could not check commit signature: GitHub HTTP {resp.status_code}"
    try:
        verification = resp.json()["commit"]["verification"]
    except (ValueError, KeyError, TypeError):
        return "Could not check commit signature: unexpected GitHub response"
    if not verification.get("verified"):
        return (
            f"Head commit of {branch} is not signature-verified "
            f"(reason: {verification.get('reason')}) - sync refused"
        )
    return None


def _list_remote_md_files(
    owner: str,
    repo: str,
    path: str,
    branch: str,
    headers: dict,
    _depth: int = 0,
) -> list:
    """
    Walk the remote repo tree and return a list of all .md file entries.
    Each entry is the GitHub Contents API "file" object with at least:
      {"path": "subdir/foo.md", "sha": "abc...", "download_url": "https://..."}
    """
    if _depth > 10:
        raise RuntimeError(f"Directory tree too deep at {path}")
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
                _depth=_depth + 1,
            )
            files.extend(sub_files)
        if len(files) > MAX_FILES:
            break

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

    parsed = urlparse(download_url)
    if parsed.scheme != "https" or parsed.hostname not in GITHUB_HOSTS:
        # The request carries the GitHub token - refuse anything off GitHub
        raise RuntimeError(f"download URL is not on GitHub: {parsed.hostname!r}")

    resp = requests.get(download_url, headers=headers, timeout=REQUEST_TIMEOUT)
    if resp.status_code != 200:
        raise RuntimeError(f"download HTTP {resp.status_code}")
    content = resp.content
    if len(content) > MAX_FILE_BYTES:
        raise RuntimeError(f"{len(content)} bytes - limit is {MAX_FILE_BYTES}")
    try:
        content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError("not UTF-8 text") from exc

    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_bytes(content)
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


def main(argv: list | None = None) -> int:
    """`extguard-ttp-sync` command."""
    import argparse
    import json

    parser = argparse.ArgumentParser(
        description="Pull TTP library files from a GitHub repository.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  extguard-ttp-sync --owner myorg --repo extguard-ttp   # stage for review\n"
            "  extguard-ttp-sync --status                            # what would change\n"
            "  extguard-ttp-sync --activate                          # make it live\n"
            "  extguard-ttp-sync --config extguard.conf.json --auto-activate\n"
            "\nAuthentication:\n"
            "  Set GITHUB_TOKEN env var for private repos or higher rate limits.\n"
        ),
    )
    parser.add_argument("--owner", help="Repo owner (org or user)")
    parser.add_argument("--repo", help="Repository name")
    parser.add_argument("--path", default="", help="Subdirectory inside the repo (default: root)")
    parser.add_argument(
        "--branch", default=None, help="Branch/tag/SHA to sync from (default: main)"
    )
    parser.add_argument(
        "--target",
        default=None,
        help="Write straight to this directory instead of the pending folder",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Read owner/repo/path/branch from the webhook section of this config file "
        "(default: the usual extguard.conf.json search)",
    )
    parser.add_argument(
        "--delete-orphans",
        action="store_true",
        help="Remove local .md files no longer in the remote repo",
    )
    parser.add_argument(
        "--require-verified",
        action="store_true",
        help="Refuse to sync unless the branch head commit is signature-verified on GitHub",
    )
    parser.add_argument(
        "--status", action="store_true", help="Show what the pending library would change"
    )
    parser.add_argument(
        "--activate", action="store_true", help="Make the reviewed pending library live"
    )
    parser.add_argument(
        "--auto-activate",
        action="store_true",
        help="Sync and activate in one step (skips the review - only for a trusted repo)",
    )
    args = parser.parse_args(argv)

    if args.status:
        _print_changes(pending_changes())
        return 0
    if args.activate:
        result = activate_pending()
        if not result["ok"]:
            print(result["error"])
            return 1
        _print_changes(result["changes"])
        print(f"Activated. Previous library kept at {result['previous']}")
        return 0

    # If owner/repo not given, try the config file
    cfg = _load_webhook_cfg(args.config) or {}
    owner = args.owner or cfg.get("owner")
    repo = args.repo or cfg.get("repo")
    path = args.path or cfg.get("path", "")
    branch = args.branch or cfg.get("branch", "main")
    require_verified = args.require_verified or bool(cfg.get("require_verified_commit"))

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
        require_verified_commit=require_verified,
    )
    print(json.dumps(result, indent=2))
    if not result["ok"]:
        return 1

    if args.target:
        return 0
    if args.auto_activate:
        activated = activate_pending()
        if not activated["ok"]:
            print(activated["error"])
            return 1
        print("Activated (--auto-activate).")
        return 0

    changes = pending_changes()
    _print_changes(changes)
    if changes["pending"]:
        print("Review the files in the pending folder, then run: extguard-ttp-sync --activate")
    return 0


def _print_changes(changes: dict):
    if not changes["pending"]:
        print("The pending library matches the active one - nothing to activate.")
        return
    for label in ("added", "changed", "removed"):
        for name in changes[label]:
            print(f"  {label:8s} {name}")


def _load_webhook_cfg(config_path) -> dict | None:
    """Pull the `webhook` section from extguard.conf.json (see extguard/paths.py)."""
    return paths.load_config_section("webhook", explicit=config_path)


if __name__ == "__main__":
    import sys

    sys.exit(main())
