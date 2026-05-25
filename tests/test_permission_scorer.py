# tests/test_permission_scorer.py - Tests for permission risk scoring

import pytest

from models import ManifestInfo
from permission_scorer import (
    COMBO_BONUSES,
    PERMISSION_WEIGHTS,
    _score_to_level,
    score_permissions,
)


def _make_manifest(
    permissions=None, host_permissions=None, content_scripts=None, persistent_bg=False
) -> ManifestInfo:
    """Build a minimal ManifestInfo for scoring tests."""
    return ManifestInfo(
        name="Test",
        version="1.0",
        manifest_version=3,
        permissions=permissions or [],
        host_permissions=host_permissions or [],
        content_scripts=content_scripts or [],
        background={"persistent": persistent_bg},
        raw={},
    )


# ---------------------------------------------------------------------------
# Score-to-level mapping
# ---------------------------------------------------------------------------


class TestScoreToLevel:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (0, "low"),
            (10, "low"),
            (19, "low"),
            (20, "medium"),
            (44, "medium"),
            (45, "high"),
            (69, "high"),
            (70, "critical"),
            (100, "critical"),
        ],
    )
    def test_boundaries(self, score, expected):
        assert _score_to_level(score) == expected


# ---------------------------------------------------------------------------
# Individual permission scoring
# ---------------------------------------------------------------------------


class TestSinglePermissions:
    """Each named permission should add its weight."""

    def test_debugger_alone(self):
        """The debugger permission is the most dangerous - 35 pts."""
        manifest = _make_manifest(permissions=["debugger"])
        result = score_permissions(manifest)
        assert result.breakdown["debugger"] == 35

    def test_native_messaging(self):
        manifest = _make_manifest(permissions=["nativeMessaging"])
        result = score_permissions(manifest)
        assert result.breakdown["nativeMessaging"] == 35

    def test_low_risk_storage_only(self):
        """Storage alone (no host perms, no combos) should score LOW."""
        manifest = _make_manifest(permissions=["storage"])
        result = score_permissions(manifest)
        assert result.total_score < 20
        assert result.risk_level == "low"

    def test_unknown_permission_ignored(self):
        """Permissions not in the weight table contribute 0 points."""
        manifest = _make_manifest(permissions=["some_made_up_permission"])
        result = score_permissions(manifest)
        assert result.total_score == 0


# ---------------------------------------------------------------------------
# Broad host access
# ---------------------------------------------------------------------------


class TestHostPermissions:
    def test_all_urls_contributes_points(self):
        manifest = _make_manifest(host_permissions=["<all_urls>"])
        result = score_permissions(manifest)
        assert any("all_urls" in k for k in result.breakdown)
        assert result.total_score >= 15

    def test_multiple_broad_patterns_get_combo_bonus(self):
        """Multiple broad patterns trigger the 'broad_host_combo' bonus."""
        manifest = _make_manifest(host_permissions=["<all_urls>", "https://*/*"])
        result = score_permissions(manifest)
        assert "broad_host_combo" in result.breakdown


# ---------------------------------------------------------------------------
# Combo bonuses - the key TTP-matching logic
# ---------------------------------------------------------------------------


class TestComboBonuses:
    """Permission combinations that match known attack chains should be flagged."""

    def test_session_token_harvester_combo(self):
        """cookies + tabs + storage = the TeamPCP session token harvest combo."""
        manifest = _make_manifest(permissions=["cookies", "tabs", "storage"])
        result = score_permissions(manifest)

        combo_keys = [k for k in result.breakdown if k.startswith("combo:")]
        assert any("cookies" in k and "tabs" in k and "storage" in k for k in combo_keys)
        assert any("TeamPCP" in note for note in result.notes)

    def test_debugger_tabs_combo(self):
        """debugger + tabs = the Shai-Hulud in-memory credential extraction combo."""
        manifest = _make_manifest(permissions=["debugger", "tabs"])
        result = score_permissions(manifest)

        combo_keys = [k for k in result.breakdown if k.startswith("combo:")]
        assert any("debugger" in k and "tabs" in k for k in combo_keys)

    def test_no_combo_if_missing_one_perm(self):
        """The TeamPCP combo needs ALL of cookies+tabs+storage. Missing one = no combo."""
        manifest = _make_manifest(permissions=["cookies", "tabs"])  # missing storage
        result = score_permissions(manifest)
        combo_keys = [k for k in result.breakdown if "cookies+storage+tabs" in k]
        assert not combo_keys


# ---------------------------------------------------------------------------
# Score clamping
# ---------------------------------------------------------------------------


class TestScoreClamping:
    """Total scores must be clamped to 0-100."""

    def test_score_clamped_at_100(self):
        """Throw every dangerous permission at the scorer - must still cap at 100."""
        manifest = _make_manifest(
            permissions=list(PERMISSION_WEIGHTS.keys()),
            host_permissions=["<all_urls>", "https://*/*", "http://*/*"],
            content_scripts=[{"matches": ["<all_urls>"]}],
            persistent_bg=True,
        )
        result = score_permissions(manifest)
        assert result.total_score <= 100
        assert result.risk_level == "critical"

    def test_empty_manifest_scores_zero(self):
        """A manifest with no permissions should score 0."""
        manifest = _make_manifest()
        result = score_permissions(manifest)
        assert result.total_score == 0
        assert result.risk_level == "low"


# ---------------------------------------------------------------------------
# Content script + background page
# ---------------------------------------------------------------------------


class TestContentScripts:
    def test_content_script_on_all_urls_flagged(self):
        manifest = _make_manifest(content_scripts=[{"matches": ["<all_urls>"]}])
        result = score_permissions(manifest)
        assert "content_scripts_all_urls" in result.breakdown
        assert any("ALL pages" in note for note in result.notes)

    def test_scoped_content_script_not_flagged(self):
        """A content script only on docs.google.com should not be flagged."""
        manifest = _make_manifest(content_scripts=[{"matches": ["*://docs.google.com/*"]}])
        result = score_permissions(manifest)
        assert "content_scripts_all_urls" not in result.breakdown


class TestBackgroundPage:
    def test_persistent_bg_adds_points(self):
        manifest = _make_manifest(persistent_bg=True)
        result = score_permissions(manifest)
        assert "persistent_background" in result.breakdown


# ---------------------------------------------------------------------------
# End-to-end: real fixtures
# ---------------------------------------------------------------------------


class TestRealManifests:
    """Score the canonical attack fixtures and the benign one."""

    def test_teamccp_scores_critical(self, teamccp_manifest_raw):
        from crx_parser import _build_manifest_info

        manifest = _build_manifest_info(teamccp_manifest_raw)
        result = score_permissions(manifest)
        assert result.risk_level == "critical"
        assert result.total_score >= 70

    def test_benign_scores_low(self, benign_manifest_raw):
        from crx_parser import _build_manifest_info

        manifest = _build_manifest_info(benign_manifest_raw)
        result = score_permissions(manifest)
        assert result.risk_level == "low"
        assert result.total_score < 20

    def test_shai_hulud_scores_high_or_critical(self, shai_hulud_manifest_raw):
        from crx_parser import _build_manifest_info

        manifest = _build_manifest_info(shai_hulud_manifest_raw)
        result = score_permissions(manifest)
        assert result.risk_level in ("high", "critical")
        # debugger + nativeMessaging = 70 points minimum
        assert result.total_score >= 45
