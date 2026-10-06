# tools/release_check.py - Check that a release tag is consistent, and write
# the GitHub release notes.
#
# Used by .github/workflows/release.yml before anything is built or
# published. A release is only allowed when:
#   - the tag looks like v<major>.<minor>.<patch> (optionally a/b/rc<N>),
#   - pyproject.toml has that exact version,
#   - CHANGELOG.md has a DATED section for it: "## [0.4.0] - 2026-11-02".
#
# The release notes are that CHANGELOG section, plus install instructions.
# (The workflow appends the checksums once the files are built.)
#
# Usage:
#   python tools/release_check.py --tag v0.4.0 --notes notes.md [--pypi]
#   python tools/release_check.py --print-version          # just the version
#
# Exit code 0 = ok, 1 = the release is inconsistent (reason printed).

import argparse
import os
import re
import sys
from pathlib import Path

TAG_PATTERN = re.compile(r"^v(\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?)$")
# version = "0.3.0" in the [project] table (the only `version =` line we write)
PYPROJECT_VERSION = re.compile(r'^version\s*=\s*"([^"]+)"', re.MULTILINE)
# "## [0.3.0] - 2026-10-01" - the dash may be -, – or —
SECTION_HEADER = re.compile(r"^## \[([^\]]+)\](?:\s*[-–—]\s*(\d{4}-\d{2}-\d{2}))?")


class ReleaseError(Exception):
    """The tag, pyproject.toml and CHANGELOG.md don't agree."""


def version_from_tag(tag: str) -> str:
    """'v0.4.0' -> '0.4.0'. Raises ReleaseError for anything else."""
    match = TAG_PATTERN.match(tag)
    if not match:
        raise ReleaseError(
            f"Tag {tag!r} is not a release tag - expected v<major>.<minor>.<patch>, "
            "e.g. v0.4.0 or v0.4.0rc1"
        )
    return match.group(1)


def read_project_version(pyproject_text: str) -> str:
    match = PYPROJECT_VERSION.search(pyproject_text)
    if not match:
        raise ReleaseError('No `version = "..."` line found in pyproject.toml')
    return match.group(1)


def changelog_section(changelog_text: str, version: str) -> tuple:
    """
    Return (date, body) of the CHANGELOG section for `version`.
    The body is everything up to the next "## [" heading, without the heading.
    """
    lines = changelog_text.splitlines()
    for start, line in enumerate(lines):
        header = SECTION_HEADER.match(line)
        if not header or header.group(1) != version:
            continue
        if not header.group(2):
            raise ReleaseError(
                f"CHANGELOG.md section [{version}] has no date - "
                f'write it as "## [{version}] - YYYY-MM-DD"'
            )
        end = start + 1
        while end < len(lines) and not lines[end].startswith("## ["):
            end += 1
        body = "\n".join(lines[start + 1 : end]).strip()
        if not body:
            raise ReleaseError(f"CHANGELOG.md section [{version}] is empty")
        return header.group(2), body
    raise ReleaseError(
        f"CHANGELOG.md has no section for {version} - move the [Unreleased] "
        f'notes under "## [{version}] - YYYY-MM-DD" first'
    )


def is_prerelease(version: str) -> bool:
    """0.4.0rc1 / 0.4.0b2 / 0.4.0a1 are pre-releases; 0.4.0 is not."""
    return bool(re.search(r"(a|b|rc)\d+$", version))


def build_notes(body: str, version: str, tag: str, repository: str, on_pypi: bool) -> str:
    """The GitHub release description."""
    changelog_url = f"https://github.com/{repository}/blob/{tag}/CHANGELOG.md"
    wheel = f"extensionguard-{version}-py3-none-any.whl"
    install = f"pip install extensionguard=={version}" if on_pypi else f"pip install {wheel}"
    where = "" if on_pypi else " (download the wheel from the assets below)"
    return (
        f"{body}\n\n"
        f"Full history: [CHANGELOG.md]({changelog_url})\n\n"
        f"## Install{where}\n\n"
        f"```\n{install}\n```\n"
    )


def check_release(tag: str, root: Path | None = None) -> dict:
    """Run every check. Returns {version, date, body, prerelease}."""
    root = root or Path.cwd()
    version = version_from_tag(tag)
    project_version = read_project_version((root / "pyproject.toml").read_text(encoding="utf-8"))
    if project_version != version:
        raise ReleaseError(
            f"Tag {tag} does not match pyproject.toml version {project_version} - "
            "bump the version in a PR before tagging"
        )
    date, body = changelog_section((root / "CHANGELOG.md").read_text(encoding="utf-8"), version)
    return {"version": version, "date": date, "body": body, "prerelease": is_prerelease(version)}


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check a release tag and write release notes")
    parser.add_argument("--tag", help="The release tag, e.g. v0.4.0")
    parser.add_argument("--notes", help="Write the GitHub release notes to this file")
    parser.add_argument("--pypi", action="store_true", help="The release is also published to PyPI")
    parser.add_argument(
        "--print-version", action="store_true", help="Print pyproject.toml's version and exit"
    )
    args = parser.parse_args(argv)

    try:
        if args.print_version:
            print(read_project_version(Path("pyproject.toml").read_text(encoding="utf-8")))
            return 0
        if not args.tag:
            parser.error("--tag is required")
        result = check_release(args.tag)
    except ReleaseError as exc:
        # "::error::" makes GitHub Actions show it as an annotation on the run
        print(f"::error::{exc}")
        return 1

    if args.notes:
        repository = os.environ.get("GITHUB_REPOSITORY", "Vimal7747/extensionguard")
        notes = build_notes(result["body"], result["version"], args.tag, repository, args.pypi)
        Path(args.notes).write_text(notes, encoding="utf-8")

    # Values the workflow's later steps need
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as out:
            out.write(f"version={result['version']}\n")
            out.write(f"prerelease={'true' if result['prerelease'] else 'false'}\n")

    kind = "pre-release" if result["prerelease"] else "release"
    print(f"OK: {args.tag} is a consistent {kind} (CHANGELOG dated {result['date']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
