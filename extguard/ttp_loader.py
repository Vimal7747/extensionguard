# ttp_loader.py - Disk-backed loader for the TTP intelligence library
#
# Why this exists:
#   Stage 2 used to ship a hardcoded TTP_LIBRARY string baked into
#   claude_triage.py. That meant updating threat intel required a code change
#   and a redeploy. Bad for SOC ops where threat intel changes daily.
#
#   Now the library lives as a tree of markdown files under ttp_library/.
#   They're loaded at runtime, concatenated, and fed to Claude via the same
#   cached-system-prompt mechanism. The webhook ingestor (ttp_ingestor.py)
#   keeps them in sync with a central GitHub repo.
#
# Caching:
#   We mtime-cache the assembled library so repeated calls don't re-read all
#   the files. Cache is invalidated when ANY file under the root directory
#   has changed since the last read. Cheap enough to check on every call.
#
# Fallback:
#   If the TTP directory is missing or empty (fresh install, sync hasn't
#   happened yet), we return a minimal built-in fallback so Stage 2 still
#   works — just with reduced detection accuracy.

from pathlib import Path

from extguard import paths
from extguard.logging_setup import get_logger

log = get_logger(__name__)


# Baseline library shipped inside the package (read-only once pip-installed)
DEFAULT_TTP_ROOT = paths.packaged_ttp_dir()


def default_ttp_root() -> Path:
    """
    Which TTP library to read when no root is given:
      - the synced copy in $EXTGUARD_TTP_DIR / ~/.extguard/ttp_library, once
        extguard-ttp-sync (or the webhook) has put .md files there;
      - otherwise the baseline shipped with the package.
    (The sync used to write into the package directory, and the Docker image
    read the packaged copy while syncing into a volume it never read.)
    """
    user_dir = paths.ttp_user_dir()
    if user_dir.is_dir() and any(user_dir.rglob("*.md")):
        return user_dir
    return DEFAULT_TTP_ROOT


# Minimum fallback content if no library files exist on disk.
# Keep this lean - real users get the much richer files from the repo.
_FALLBACK_LIBRARY = """
# ExtensionGuard Threat Intelligence (FALLBACK - sync not yet run)

This is a minimal hardcoded baseline. For accurate detection, sync the
real TTP library from the central repo via the webhook or `extguard-ttp-sync`.

## Common attack signatures

- The TeamPCP supply-chain pattern uses cookies + tabs + storage + <all_urls>
  to harvest session tokens for github.com, npmjs.com, *.aws.amazon.com.
- The Shai-Hulud family abuses debugger + nativeMessaging permissions.

## Relevant MITRE techniques

T1176, T1555, T1555.003, T1071, T1071.001, T1059, T1059.007.
"""


# Size limits (characters, roughly 4 per token). Oversized files are skipped
# and the assembled library is cut, so a bad sync can't blow the prompt budget.
MAX_FILE_CHARS = 256 * 1024
MAX_LIBRARY_CHARS = 400_000


# Module-level cache. Keyed by (root_path, latest_mtime) so changing the
# files invalidates automatically.
_cache: dict = {}


def load_ttp_library(root: Path | str | None = None) -> str:
    """
    Read every .md file under `root` (recursively) and return them
    concatenated as a single string, suitable for sending to Claude as
    the cached system prompt.

    Files are concatenated in a stable order (alphabetical by path) so that
    Claude's prompt-cache hits as often as possible. A single byte changing
    in any file invalidates both our cache AND Claude's prompt cache - which
    is correct: we want a fresh re-tokenisation when intel changes.

    Returns the fallback string if `root` doesn't exist or contains no .md files.
    """
    root = Path(root) if root else default_ttp_root()

    if not root.exists() or not root.is_dir():
        log.warning("TTP library directory not found at %s - using fallback", root)
        return _FALLBACK_LIBRARY.strip()

    md_files = sorted(root.rglob("*.md"))
    if not md_files:
        log.warning("No .md files found under %s - using fallback", root)
        return _FALLBACK_LIBRARY.strip()

    # Find the most recent mtime across all files. If it matches our cached
    # value, return the cached assembled string.
    latest_mtime = max(f.stat().st_mtime for f in md_files)
    cache_key = (str(root.resolve()), latest_mtime, tuple(str(f) for f in md_files))
    if cache_key in _cache:
        return _cache[cache_key]

    # Assemble the library. Each file is prefixed with a separator so Claude
    # can tell where one document ends and the next begins.
    chunks = []
    for md_file in md_files:
        try:
            content = md_file.read_text(encoding="utf-8")
        except OSError as exc:
            log.warning("Failed to read TTP file %s: %s", md_file, exc)
            continue
        relative = md_file.relative_to(root)
        if len(content) > MAX_FILE_CHARS:
            log.warning("Skipping TTP file %s: %d chars is over the limit", relative, len(content))
            continue
        chunks.append(f"\n\n<!-- source: {relative.as_posix()} -->\n\n{content}")

    assembled = "".join(chunks).strip()
    if len(assembled) > MAX_LIBRARY_CHARS:
        log.warning("TTP library is %d chars - truncating to %d", len(assembled), MAX_LIBRARY_CHARS)
        assembled = assembled[:MAX_LIBRARY_CHARS]

    # Wipe any older cache entries for this root (only keep one per root)
    for k in list(_cache.keys()):
        if k[0] == cache_key[0]:
            del _cache[k]
    _cache[cache_key] = assembled

    log.info(
        "Loaded TTP library: %d files, %d chars, latest mtime %.0f",
        len(md_files),
        len(assembled),
        latest_mtime,
    )
    return assembled


def clear_cache():
    """
    Force the next load_ttp_library() call to re-read from disk.
    Called by the webhook ingestor after a successful sync so the very next
    triage uses the fresh content.
    """
    _cache.clear()


def library_stats(root: Path | str | None = None) -> dict:
    """
    Diagnostic helper - returns a dict with file count, size, mtime.
    Used by the dashboard /api/health endpoint and the manual sync CLI.
    """
    root = Path(root) if root else default_ttp_root()
    if not root.exists():
        return {"exists": False, "files": 0, "bytes": 0, "latest_mtime": None}

    md_files = list(root.rglob("*.md"))
    total_bytes = sum(f.stat().st_size for f in md_files)
    latest = max((f.stat().st_mtime for f in md_files), default=0)
    return {
        "exists": True,
        "files": len(md_files),
        "bytes": total_bytes,
        "latest_mtime": latest,
    }
