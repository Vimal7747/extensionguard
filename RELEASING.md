# Releasing ExtensionGuard

The release flow for a new version. Follow these steps in order — most are
mechanical, but a few involve human judgement (version-bump severity,
changelog wording).

## 1. Decide on the version number

ExtensionGuard uses [SemVer](https://semver.org/):

| Change type | Bump | Examples |
| --- | --- | --- |
| Bug fix only | PATCH (0.2.0 → 0.2.1) | Detection rule edge case, log redaction gap |
| New feature, backwards compatible | MINOR (0.2.0 → 0.3.0) | New adapter, new CLI flag, new detection rule |
| Breaking change | MAJOR (0.2.0 → 1.0.0) | Renamed CLI command, removed config key, changed exit codes |

**Schema migrations** in `chain_of_custody.json` are always MAJOR — they
break the integrity guarantee for existing case folders.

**While the version is 0.x**, breaking changes bump MINOR instead
(0.2.0 → 0.3.0), as SemVer allows for initial development. List them under
a `### Breaking` heading in the CHANGELOG. 1.0.0 is a promise that the CLI,
config and evidence formats are stable.

## 2. Bump the version

```powershell
# Edit pyproject.toml
[project]
version = "0.3.0"
```

Then update `CHANGELOG.md`:

- Move the contents of `## [Unreleased]` (if any) into a new dated section.
- Group entries under `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`.
- Use plain past tense ("Added the X adapter", not "Adds X").
- Cite file names so the reader can jump straight to the change.

## 3. Run the full release checklist

```powershell
# Clean any previous build artefacts
rm -r build dist *.egg-info -ErrorAction SilentlyContinue

# Lint passes with zero findings
ruff check .
ruff format --check .

# Full test suite (NOT including benchmarks)
pytest

# Re-run benchmarks and compare against the previous baseline
pytest tests/benchmarks/ --benchmark-compare=baseline
#   Acceptable: <10% regression on any single benchmark
#   Investigate: 10-25% regression
#   Block release: >25% regression on a hot path

# Build the wheel + sdist
python -m build

# Verify the wheel installs cleanly into a throwaway env
python -m venv /tmp/extguard-release-check
. /tmp/extguard-release-check/Scripts/Activate.ps1
pip install dist/extensionguard-*.whl
extguard --help
extguard-dashboard --help
extguard-monitor --help
extguard-dispatch --help
extguard-remediate --help
extguard-ttp-sync --help
extguard-sigma --help
extguard-webhook --help
deactivate

# Verify the Docker image builds
docker build -t extensionguard:0.3.0 .
docker run --rm extensionguard:0.3.0 extguard --help
```

## 4. Commit + tag

```powershell
`main` is protected by the "Protect main" ruleset (PR + green CI required), so
the release commit goes through a pull request like any other change:

```powershell
git checkout -b release-0.3.0
git add pyproject.toml CHANGELOG.md
git commit -m "Release v0.3.0"
git push -u origin release-0.3.0
# Open the PR, wait for CI, then "Rebase and merge" it on GitHub.
```

Rebase-merging gives the commit a new ID, so tag the commit that landed on
`main` - never the one on the release branch:

```powershell
git checkout main
git pull --ff-only
git tag -a v0.3.0 -m "ExtensionGuard 0.3.0"
git push origin v0.3.0
```

Build the release artefacts (step 3's `python -m build`) from this tagged
commit.

## 5. Publish to PyPI

If you have PyPI publish credentials:

```powershell
pip install --upgrade twine
twine check dist/*
twine upload dist/*
```

For test releases, target TestPyPI first:

```powershell
twine upload --repository testpypi dist/*
```

## 6. Create the GitHub release

```powershell
gh release create v0.3.0 \
    --title "ExtensionGuard 0.3.0" \
    --notes-file <(sed -n '/## \[0.3.0\]/,/## \[/p' CHANGELOG.md | sed '$d') \
    dist/*
```

This uploads the wheel and sdist as release artefacts so users who don't
trust PyPI can download directly.

## 7. Publish the Docker image (optional)

```powershell
docker tag extensionguard:0.3.0 ghcr.io/vimal7747/extensionguard:0.3.0
docker tag extensionguard:0.3.0 ghcr.io/vimal7747/extensionguard:latest
docker push ghcr.io/vimal7747/extensionguard:0.3.0
docker push ghcr.io/vimal7747/extensionguard:latest
```

## 8. Announce

Suggested channels:

- Project README badge — auto-updates via shields.io.
- Internal SOC team Slack — link to the CHANGELOG section.
- For security-relevant changes — file an advisory under
  GitHub > Security > Advisories so dependants get notified.

## After release: open a follow-up

Add an `## [Unreleased]` section back to `CHANGELOG.md` so subsequent
commits have somewhere to record their changes:

```markdown
## [Unreleased]

### Added
- ...
```

## Hotfix flow

For a security-critical fix that can't wait for the next minor release:

1. Branch from the latest release tag (`git checkout -b hotfix/0.2.1 v0.2.0`).
2. Cherry-pick the fix.
3. Bump to a PATCH version (0.2.0 → 0.2.1).
4. Follow steps 3–8 above.
5. After release, merge the hotfix branch back to `main` and forward-port any
   already-merged work that needs it.

## Common pitfalls

- **Don't tag before the wheel builds.** A failed build with a tag pushed
  means an empty release on GitHub.
- **Don't push the tag before the commit.** GitHub's automatic releases
  trigger on tag push and will see the previous tree state.
- **Re-check the optional deps section in pyproject.toml.** If you added a
  new `[security-extras]` or similar group, document it in the CHANGELOG so
  users know to install it.
- **Watch the wheel size.** If `dist/*.whl` suddenly grew by 10 MB, you
  probably added a large file under `package_data` by accident — check
  `.dockerignore` and `pyproject.toml`'s `package-data` glob.
