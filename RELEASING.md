# Releasing ExtensionGuard

Releases are built and published by `.github/workflows/release.yml` when a
version tag is pushed. A maintainer decides the version, writes the
changelog, merges that through a PR, pushes the tag, and approves the PyPI
upload. Everything else is automated and checked.

## 1. Decide on the version number

ExtensionGuard uses [SemVer](https://semver.org/):

| Change type | Bump | Examples |
| --- | --- | --- |
| Bug fix only | PATCH (0.3.0 → 0.3.1) | Detection rule edge case, log redaction gap |
| New feature, backwards compatible | MINOR (0.3.0 → 0.4.0) | New adapter, new CLI flag, new detection rule |
| Breaking change | MAJOR (0.3.0 → 1.0.0) | Renamed CLI command, removed config key, changed exit codes |

**Schema migrations** in `chain_of_custody.json` are always MAJOR — they
break the integrity guarantee for existing case folders.

**While the version is 0.x**, breaking changes bump MINOR instead
(0.2.0 → 0.3.0), as SemVer allows for initial development. List them under
a `### Breaking` heading in the CHANGELOG. 1.0.0 is a promise that the CLI,
config and evidence formats are stable.

Pre-releases use PEP 440 suffixes: `0.4.0rc1`, `0.4.0b1`, `0.4.0a1` (tag
`v0.4.0rc1`). They are marked as pre-releases on GitHub, and `pip` only
installs them when asked for explicitly.

## 2. Release PR: version + changelog

`main` is protected (PR + green CI required), so the release commit goes
through a pull request like any other change:

1. In `pyproject.toml`, set `version = "0.4.0"`.
2. In `CHANGELOG.md`, rename `## [Unreleased]` to `## [0.4.0] - YYYY-MM-DD`
   and add a fresh, empty `## [Unreleased]` above it. The workflow uses this
   section as the GitHub release notes, and refuses to release without a
   dated section.
   - Group entries under `Breaking`, `Added`, `Changed`, `Removed`, `Fixed`,
     `Security`; plain past tense; cite file names.
3. Update any hard-coded version (the `Version` row in README.md, the
   `extensionguard:<version>` image tags in `docker-compose.yml` and the
   Dockerfile comments).
4. Commit as "Release v0.4.0", open the PR, wait for CI, **Rebase and merge**.

Before merging, compare the benchmarks with the previous release - CI only
runs them, it doesn't judge them (shared runners are too noisy):

```powershell
git worktree add ..\eg-prev v0.3.0
pytest ..\eg-prev\tests\benchmarks --benchmark-only --benchmark-storage=..\bench --benchmark-save=prev
pytest tests\benchmarks --benchmark-only --benchmark-storage=..\bench --benchmark-compare=0001
git worktree remove ..\eg-prev
#   <10% on a hot path: fine.  10-25%: explain it.  >25%: find out why first.
```

Record notable changes in `PERFORMANCE.md`.

## 3. Tag the merged commit

Rebase-merging gives the commit a new ID, so tag the commit that landed on
`main` - never the one on the release branch:

```powershell
git checkout main
git pull --ff-only
git tag -a v0.4.0 -m "ExtensionGuard 0.4.0"
git push origin v0.4.0
```

## 4. What the workflow does

Pushing the tag starts **Actions > Release**:

1. **build** - refuses to continue unless the tag is on `main` and the tag,
   `pyproject.toml` and the dated CHANGELOG section agree
   (`tools/release_check.py`). Then it builds the wheel + sdist from the
   tagged commit, runs `twine check --strict`, installs the wheel in a fresh
   virtualenv and smoke-tests every command (`tools/smoke_test.py`), and
   computes SHA-256 checksums.
2. **github** - creates the GitHub release: the CHANGELOG section plus
   install instructions and checksums as the notes; wheel, sdist and
   `SHA256SUMS.txt` attached.
3. **pypi** - uploads the same two files to PyPI. It waits for you to
   **approve** it (the run page shows "Review deployments").

If **build** fails, nothing is published - fix the problem in a PR, then
delete and re-create the tag on the new commit
(`git push origin :refs/tags/v0.4.0`, tag again, push). If **pypi** fails
after the GitHub release exists, re-run just that job.

## 5. Check the result

- The release page shows the notes, three files, and the **Latest** label
  (or **Pre-release**).
- `pip install extensionguard==0.4.0` works in a fresh virtualenv.

## One-time PyPI setup (trusted publishing)

Trusted publishing lets PyPI accept uploads from this workflow without any
password or API token stored in GitHub.

1. **PyPI:** sign in at <https://pypi.org> (with 2FA), go to *Your account →
   Publishing → Add a new pending publisher*, and enter:
   - PyPI project name: `extensionguard`
   - Owner: `Vimal7747` - Repository: `extensionguard`
   - Workflow name: `release.yml` - Environment name: `pypi`
2. **GitHub → Settings → Environments → New environment** named `pypi`.
   Under *Deployment protection rules*, tick **Required reviewers** and add
   yourself, so every upload waits for your approval. Under *Deployment
   branches and tags*, choose *Selected branches and tags* and add the
   branch `main` (hand-run republishing runs from it) and tags matching `v*`.
3. **GitHub → Settings → Secrets and variables → Actions → Variables → New
   repository variable:** `PYPI_PUBLISH` = `true`. Until it is set, the
   workflow creates GitHub releases but skips PyPI.
4. To publish a release that already exists on GitHub (e.g. 0.3.0): *Actions
   → Release → Run workflow*, tag `v0.3.0`. It downloads the files attached
   to that release, re-verifies them, and uploads exactly those to PyPI.

## Docker image (optional, manual)

CI's `docker` job builds and smoke-tests the image on every PR. Publishing
it is not automated yet:

```powershell
docker build -t ghcr.io/vimal7747/extensionguard:0.4.0 .
docker push ghcr.io/vimal7747/extensionguard:0.4.0
```

## Urgent fixes

The workflow only releases commits that are on `main`. For a fix that can't
wait for the next feature release: merge the fix to `main`, then a release PR
bumping the PATCH version (0.4.0 → 0.4.1), then tag as usual. If `main`
already holds unreleased work that must not ship yet, note it in the
release PR and decide case by case.

## Common pitfalls

- **Tag the merged commit, not the branch commit.** The workflow refuses a
  tag that isn't on `main`.
- **Don't reuse a version.** PyPI never accepts the same version twice, even
  after deleting it. A broken release gets a new PATCH version.
- **Re-check the optional deps section in pyproject.toml.** If you added a
  new optional dependency group, document it in the CHANGELOG.
- **Watch the wheel size.** If `dist/*.whl` suddenly grew by megabytes, a
  large file probably matched the `package-data` globs in `pyproject.toml`.
