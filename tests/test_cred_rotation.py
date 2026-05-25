# tests/test_cred_rotation.py - Credential rotation playbook generator tests

import json
from pathlib import Path

import pytest

from remediators import cred_rotation
from remediators.cred_rotation import (
    CREDENTIAL_PLAYBOOKS,
    _detect_applicable_stores,
    _max_severity,
    _pattern_matches,
    generate_playbook,
    save_playbook,
)

# ---------------------------------------------------------------------------
# Host-permission -> store mapping
# ---------------------------------------------------------------------------


class TestStoreDetection:
    def test_all_urls_matches_all_stores(self):
        """<all_urls> should map to every credential store as worst-case."""
        result = _detect_applicable_stores(["<all_urls>"], iocs=[])
        assert set(result) >= {"github", "npm", "aws", "slack", "atlassian", "google"}

    def test_github_specific_host(self):
        """*://github.com/* should only match GitHub."""
        result = _detect_applicable_stores(["*://github.com/*"], iocs=[])
        assert "github" in result
        # Should NOT pull in unrelated stores
        assert "atlassian" not in result

    def test_npm_specific_host(self):
        result = _detect_applicable_stores(["*://*.npmjs.com/*"], iocs=[])
        assert "npm" in result

    def test_aws_console_host(self):
        result = _detect_applicable_stores(["*://*.aws.amazon.com/*"], iocs=[])
        assert "aws" in result

    def test_no_stores_for_unrelated_host(self):
        result = _detect_applicable_stores(["*://docs.google.com/*"], iocs=[])
        # docs.google.com is under *.google.com which we DO track
        assert "google" in result

    def test_empty_host_list_returns_empty(self):
        result = _detect_applicable_stores([], iocs=[])
        assert result == []

    def test_stores_sorted_by_severity(self):
        """Critical-severity stores should appear before high-severity ones."""
        result = _detect_applicable_stores(
            ["*://github.com/*", "*://*.slack.com/*"],
            iocs=[],
        )
        # github is critical, slack is high - github should come first
        github_idx = result.index("github") if "github" in result else 99
        slack_idx = result.index("slack") if "slack" in result else 99
        assert github_idx < slack_idx


class TestPatternMatches:
    def test_wildcard_pattern_matches_subdomain(self):
        assert _pattern_matches("*.github.com", "*://api.github.com/*")

    def test_exact_pattern_matches_exact_host(self):
        assert _pattern_matches("github.com", "https://github.com/*")

    def test_pattern_does_not_match_unrelated(self):
        assert not _pattern_matches("github.com", "https://gitlab.com/*")

    # --- Regression tests for the substring-match bug -----------------------
    # Previously _pattern_matches("github.com", "*://attacker-github.com/*")
    # returned True because of naive substring matching. These tests lock in
    # the proper DNS-suffix matching behaviour.

    def test_typosquat_does_not_match(self):
        """attacker-github.com.evil.tld must NOT match the github.com pattern."""
        assert not _pattern_matches(
            "github.com",
            "*://attacker-github.com.evil.tld/*",
        )

    def test_lookalike_domain_does_not_match(self):
        """mygithub.com (legitimate competitor) must NOT match *.github.com."""
        assert not _pattern_matches("*.github.com", "https://mygithub.com/*")

    def test_subdomain_match_still_works_after_fix(self):
        """api.github.com IS a real GitHub subdomain - should still match."""
        assert _pattern_matches("*.github.com", "https://api.github.com/*")
        assert _pattern_matches("github.com", "https://api.github.com/*")

    def test_exact_host_match_after_fix(self):
        """https://github.com/* matches the github.com pattern exactly."""
        assert _pattern_matches("github.com", "https://github.com/*")

    def test_scheme_wildcard_handled(self):
        """*://github.com/* should be recognised as github.com."""
        assert _pattern_matches("github.com", "*://github.com/*")

    def test_path_does_not_affect_match(self):
        """A pattern's path component should be ignored - only host matters."""
        assert _pattern_matches(
            "github.com",
            "https://github.com/some/deep/path/here",
        )

    def test_empty_inputs_do_not_match(self):
        """Defensive: empty pattern or permission should never match."""
        assert not _pattern_matches("", "https://github.com/*")
        assert not _pattern_matches("github.com", "")


class TestMaxSeverity:
    def test_picks_worst(self):
        assert _max_severity(["low", "medium", "critical", "high"]) == "critical"

    def test_single_value(self):
        assert _max_severity(["high"]) == "high"

    def test_all_low(self):
        assert _max_severity(["low", "low"]) == "low"


# ---------------------------------------------------------------------------
# Playbook generation
# ---------------------------------------------------------------------------


class TestGeneratePlaybook:
    def test_no_applicable_stores_returns_empty_playbook(self):
        result = generate_playbook(
            host_permissions=["*://internal-corp.local/*"],
            iocs=[],
            extension_name="Test",
        )
        assert result["ok"] is True
        assert result["applicable"] == []
        assert result["total_steps"] == 0

    def test_all_urls_triggers_full_playbook(self):
        result = generate_playbook(
            host_permissions=["<all_urls>"],
            iocs=["Permission combo matches TeamPCP"],
            extension_name="Nx Console",
        )
        assert len(result["applicable"]) == 6  # All tracked stores
        assert result["severity"] == "critical"
        assert result["total_steps"] > 10
        assert result["total_time_min"] > 60

    def test_markdown_output_format(self):
        result = generate_playbook(
            host_permissions=["*://github.com/*"],
            iocs=["test ioc"],
            extension_name="X",
            output_format="markdown",
        )
        assert "markdown" in result
        md = result["markdown"]
        assert "# Credential Rotation Playbook" in md
        assert "test ioc" in md
        # Should have step-level details
        assert "**Why:**" in md
        assert "**How:**" in md
        assert "**Verify:**" in md
        # Should have completion checklist
        assert "Completion checklist" in md

    def test_json_output_format(self):
        result = generate_playbook(
            host_permissions=["*://*.npmjs.com/*"],
            iocs=[],
            extension_name="X",
            output_format="json",
        )
        assert "json" in result
        j = result["json"]
        assert "npm" in j["stores"]
        assert "steps" in j["stores"]["npm"]

    def test_both_format(self):
        result = generate_playbook(
            host_permissions=["*://github.com/*"],
            iocs=[],
            extension_name="X",
            output_format="both",
        )
        assert "markdown" in result
        assert "json" in result


# ---------------------------------------------------------------------------
# Save playbook
# ---------------------------------------------------------------------------


class TestSavePlaybook:
    def test_writes_markdown_and_json(self, tmp_path):
        playbook = generate_playbook(
            host_permissions=["*://github.com/*"],
            iocs=[],
            extension_name="X",
            output_format="both",
        )
        paths = save_playbook(playbook, str(tmp_path), prefix="rotation")
        assert Path(paths["markdown"]).exists()
        assert Path(paths["json"]).exists()
        # Markdown file should be readable
        assert "# Credential Rotation" in Path(paths["markdown"]).read_text()
        # JSON file should be valid JSON
        json.loads(Path(paths["json"]).read_text())

    def test_only_writes_what_is_present(self, tmp_path):
        """If only markdown was generated, JSON file should NOT be written."""
        playbook = generate_playbook(
            host_permissions=["*://github.com/*"],
            iocs=[],
            extension_name="X",
            output_format="markdown",
        )
        paths = save_playbook(playbook, str(tmp_path))
        assert "markdown" in paths
        assert "json" not in paths


# ---------------------------------------------------------------------------
# Static playbook content sanity
# ---------------------------------------------------------------------------


class TestPlaybookContent:
    """Catches accidental regressions where a playbook entry loses a field."""

    @pytest.mark.parametrize("store_key", list(CREDENTIAL_PLAYBOOKS.keys()))
    def test_every_store_has_required_fields(self, store_key):
        """Every store entry must have host_patterns, severity, time_estimate_min, steps."""
        store = CREDENTIAL_PLAYBOOKS[store_key]
        assert "host_patterns" in store
        assert "severity" in store
        assert "time_estimate_min" in store
        assert "steps" in store
        assert store["severity"] in ("critical", "high", "medium", "low")

    @pytest.mark.parametrize("store_key", list(CREDENTIAL_PLAYBOOKS.keys()))
    def test_every_step_has_required_fields(self, store_key):
        for step in CREDENTIAL_PLAYBOOKS[store_key]["steps"]:
            assert "step" in step
            assert "title" in step
            assert "why" in step
            assert "how" in step
            assert "verify" in step
            assert isinstance(step["how"], list)
            assert len(step["how"]) > 0
