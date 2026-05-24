# tests/benchmarks/test_bench_pipeline.py
#
# Microbenchmarks for the hot paths of the pipeline. These aren't unit tests -
# they exist to detect performance regressions and to document a baseline so
# the user knows what to expect on their hardware.
#
# Run with:
#   pytest tests/benchmarks/                  # full suite
#   pytest tests/benchmarks/ --benchmark-only # if other tests are present
#   pytest tests/benchmarks/ --benchmark-save=baseline  # snapshot a baseline
#   pytest tests/benchmarks/ --benchmark-compare        # compare to last save
#
# pytest-benchmark prints a table at the end with min/max/mean/median/stddev
# for each benchmark. The default rounds=N is auto-calibrated.

import io
import json
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from alert_dispatcher import AlertState, enrich
from crx_parser import _build_manifest_info, parse_crx
from osv_lookup import _scan_zip_contents
from permission_scorer import score_permissions
from publisher_checker import check_publisher
from remediators import cred_rotation, forensics
from sigma_generator import generate_all_rules
from ttp_loader import clear_cache, load_ttp_library
from update_velocity import analyse_version

# ---------------------------------------------------------------------------
# Stage 1a - CRX parsing
# ---------------------------------------------------------------------------

class TestCrxParserBench:
    """How fast can we crack open a CRX and extract its manifest?"""

    def test_parse_50kb_crx(self, benchmark, medium_crx_bytes, tmp_path):
        """Realistic 50 KB CRX -> ManifestInfo in one call."""
        crx_path = tmp_path / "bench.crx"
        crx_path.write_bytes(medium_crx_bytes)

        def parse():
            return parse_crx(str(crx_path))

        zip_bytes, manifest = benchmark(parse)
        assert manifest.name == "Nx Console (SIMULATED MALICIOUS)"


# ---------------------------------------------------------------------------
# Stage 1b - permission scoring
# ---------------------------------------------------------------------------

class TestPermissionScorerBench:
    def test_score_malicious_manifest(self, benchmark, teamccp_manifest):
        """TeamPCP profile - exercises every combo + content_script + bg checks."""
        manifest = _build_manifest_info(teamccp_manifest)
        result = benchmark(score_permissions, manifest)
        assert result.risk_level == "critical"


# ---------------------------------------------------------------------------
# Stage 1c - publisher checker (offline)
# ---------------------------------------------------------------------------

class TestPublisherBench:
    def test_check_publisher_no_network(self, benchmark, teamccp_manifest):
        """Offline path - no CWS query, just local update_url validation."""
        manifest = _build_manifest_info(teamccp_manifest)
        benchmark(check_publisher, manifest, query_cws=False)


# ---------------------------------------------------------------------------
# Stage 1d - OSV ZIP content scan
# ---------------------------------------------------------------------------

class TestOsvBench:
    def test_scan_zip_contents(self, benchmark, medium_crx_bytes):
        """Scan a 50 KB CRX for npm package refs + CDN URLs."""
        # Strip the CRX header to get raw ZIP bytes (what _scan_zip_contents expects)
        zip_bytes = medium_crx_bytes[12:]
        benchmark(_scan_zip_contents, zip_bytes)


# ---------------------------------------------------------------------------
# Stage 1e - version velocity analysis
# ---------------------------------------------------------------------------

class TestVelocityBench:
    def test_analyse_version_first_run(self, benchmark, tmp_path, monkeypatch):
        """First-run cost: parse + write to history file."""
        import update_velocity
        history_path = tmp_path / "version_history.json"
        monkeypatch.setattr(update_velocity, "HISTORY_FILE", history_path)

        def run():
            return analyse_version("17.3.1", extension_id="test-ext-id",
                                   extension_name="X")

        benchmark(run)


# ---------------------------------------------------------------------------
# TTP library loader - cold vs warm cache
# ---------------------------------------------------------------------------

class TestTtpLoaderBench:
    """The loader is called inside Stage 2 - hot-path performance matters."""

    def test_warm_cache(self, benchmark, tmp_path):
        """Subsequent loads should be O(1) - just an mtime check."""
        # Populate a small library
        (tmp_path / "a.md").write_text("# A\n" + "x " * 500)
        (tmp_path / "b.md").write_text("# B\n" + "y " * 500)
        # Prime the cache once outside the benchmark
        load_ttp_library(tmp_path)
        # Now the benchmark should hit the cache every iteration
        result = benchmark(load_ttp_library, tmp_path)
        assert "# A" in result

    def test_cold_load(self, benchmark, tmp_path):
        """Cold load: read every file from disk."""
        for i in range(10):
            (tmp_path / f"file_{i}.md").write_text("# Title\n" + "x " * 500)

        def cold():
            clear_cache()
            return load_ttp_library(tmp_path)

        benchmark(cold)


# ---------------------------------------------------------------------------
# Stage 4 - dispatcher hot path (without real HTTP)
# ---------------------------------------------------------------------------

class TestDispatcherBench:
    def test_dedup_check(self, benchmark, sample_alert):
        """How fast is the dedup decision per incoming alert?"""
        state = AlertState(dedup_ttl=300, escalation_threshold=3)

        def run():
            return state.should_send(sample_alert)

        benchmark(run)

    def test_enrich_alert(self, benchmark, sample_alert):
        """Per-alert enrichment (sensor host, recommendation, etc.)."""
        benchmark(enrich, sample_alert, False)


# ---------------------------------------------------------------------------
# Stage 5 - forensics preserve + verify
# ---------------------------------------------------------------------------

class TestForensicsBench:
    def test_preserve_50kb_crx(self, benchmark, tmp_path, medium_crx_bytes, teamccp_manifest):
        """Time to write a full case folder: sample.crx + manifest + CoC + hashes."""
        # Each iteration needs a fresh quarantine root or we collide
        counter = {"n": 0}

        def run():
            counter["n"] += 1
            qroot = tmp_path / f"q{counter['n']}"
            return forensics.preserve(
                extension_id    = "abcdefghijklmnopqrstuvwxyzabcdef",
                extension_name  = "Bench",
                crx_bytes       = medium_crx_bytes,
                manifest        = teamccp_manifest,
                quarantine_root = qroot,
            )

        result = benchmark(run)
        assert result["ok"]

    def test_verify_case(self, benchmark, tmp_path, medium_crx_bytes, teamccp_manifest):
        """Time to re-hash every artifact in an existing case folder."""
        result = forensics.preserve(
            extension_id    = "abcdefghijklmnopqrstuvwxyzabcdef",
            extension_name  = "Bench",
            crx_bytes       = medium_crx_bytes,
            manifest        = teamccp_manifest,
            quarantine_root = tmp_path,
        )
        case_dir = result["case_dir"]
        benchmark(forensics.verify_case, case_dir)


# ---------------------------------------------------------------------------
# Credential rotation playbook generator
# ---------------------------------------------------------------------------

class TestCredRotationBench:
    def test_generate_all_urls_playbook(self, benchmark):
        """Generate the full 6-store playbook (worst case: <all_urls>)."""
        result = benchmark(
            cred_rotation.generate_playbook,
            host_permissions=["<all_urls>"],
            iocs=["TeamPCP-shape combo"],
            extension_name="X",
            output_format="both",
        )
        assert len(result["applicable"]) == 6


# ---------------------------------------------------------------------------
# Sigma generator
# ---------------------------------------------------------------------------

class TestSigmaBench:
    def test_generate_all_rules(self, benchmark):
        """Time to emit all 6 Sigma YAML rules as strings."""
        result = benchmark(generate_all_rules)
        assert len(result) == 6
