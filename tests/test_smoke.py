# tests/test_smoke.py - One-line sanity tests for the test infrastructure itself.
# If this file passes, the conftest.py is wired correctly and imports resolve.


def test_imports_work():
    """All public modules must import cleanly with no missing deps."""
    from extguard import (
        crx_parser,  # noqa: F401
        models,  # noqa: F401
        osv_lookup,  # noqa: F401
        permission_scorer,  # noqa: F401
        publisher_checker,  # noqa: F401
        update_velocity,  # noqa: F401
    )


def test_benign_fixture_shape(benign_manifest_raw):
    """The benign manifest fixture has the fields tests will reach for."""
    assert benign_manifest_raw["manifest_version"] == 3
    assert "storage" in benign_manifest_raw["permissions"]


def test_teamccp_fixture_shape(teamccp_manifest_raw):
    """The TeamPCP fixture has the exact attack permission combo."""
    perms = teamccp_manifest_raw["permissions"]
    assert {"cookies", "tabs", "storage"}.issubset(set(perms))
    assert "<all_urls>" in perms


def test_crx3_bytes_starts_with_magic(crx3_bytes):
    assert crx3_bytes[:4] == b"Cr24"


def test_crx2_bytes_starts_with_magic(crx2_bytes):
    assert crx2_bytes[:4] == b"Cr24"
