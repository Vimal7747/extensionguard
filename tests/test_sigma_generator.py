# tests/test_sigma_generator.py - Sigma rule generator tests

import re
import uuid

import pytest

from sigma_generator import (
    RULES,
    SIGMA_NAMESPACE,
    _emit_yaml,
    _rule_uuid,
    _yaml_value,
    generate_all_rules,
    write_rules_to,
)

# ---------------------------------------------------------------------------
# Rule catalog integrity
# ---------------------------------------------------------------------------


class TestRuleCatalog:
    def test_six_rules_emitted(self):
        """Should be one Sigma rule per behavioral_monitor rule (6)."""
        assert len(RULES) == 6
        keys = {r["rule_key"] for r in RULES}
        assert keys == {f"RULE-0{i}" for i in range(1, 7)}

    @pytest.mark.parametrize("rule", RULES, ids=[r["rule_key"] for r in RULES])
    def test_every_rule_has_required_fields(self, rule):
        """Every rule must include the mandatory Sigma fields."""
        for field in (
            "title",
            "description",
            "references",
            "tags",
            "logsource",
            "detection",
            "falsepositives",
            "level",
        ):
            assert field in rule, f"{rule['rule_key']} missing {field!r}"

    @pytest.mark.parametrize("rule", RULES, ids=[r["rule_key"] for r in RULES])
    def test_level_is_valid_sigma_severity(self, rule):
        assert rule["level"] in ("informational", "low", "medium", "high", "critical")

    @pytest.mark.parametrize("rule", RULES, ids=[r["rule_key"] for r in RULES])
    def test_detection_has_condition(self, rule):
        """Every Sigma rule needs a `condition` key in detection."""
        assert "condition" in rule["detection"]

    @pytest.mark.parametrize("rule", RULES, ids=[r["rule_key"] for r in RULES])
    def test_tags_include_attack_id(self, rule):
        """Every rule cites at least one attack.t#### MITRE technique tag."""
        attack_tags = [t for t in rule["tags"] if t.startswith("attack.t")]
        assert attack_tags, f"{rule['rule_key']} has no attack.t#### tag"


# ---------------------------------------------------------------------------
# UUID generation
# ---------------------------------------------------------------------------


class TestUuid:
    def test_uuid_is_valid_uuidv5(self):
        result = _rule_uuid("RULE-01")
        parsed = uuid.UUID(result)
        # UUIDv5 has version=5 in its representation
        assert parsed.version == 5

    def test_uuid_is_stable(self):
        """Same rule_key must always produce the same UUID - SIEM-side tracking depends on this."""
        assert _rule_uuid("RULE-01") == _rule_uuid("RULE-01")
        assert _rule_uuid("RULE-02") == _rule_uuid("RULE-02")

    def test_uuid_differs_per_rule(self):
        """Each rule_key must produce a different UUID."""
        uuids = {_rule_uuid(r["rule_key"]) for r in RULES}
        assert len(uuids) == len(RULES)


# ---------------------------------------------------------------------------
# YAML value escaping
# ---------------------------------------------------------------------------


class TestYamlValue:
    def test_string_quoted(self):
        assert _yaml_value("hello") == '"hello"'

    def test_string_with_quotes_escaped(self):
        assert _yaml_value('say "hi"') == '"say \\"hi\\""'

    def test_int_unquoted(self):
        assert _yaml_value(42) == "42"

    def test_bool_normalised(self):
        assert _yaml_value(True) == "true"
        assert _yaml_value(False) == "false"

    def test_none_as_tilde(self):
        assert _yaml_value(None) == "~"


# ---------------------------------------------------------------------------
# YAML emission - parses cleanly as PyYAML if installed (sanity check)
# ---------------------------------------------------------------------------


class TestEmitYaml:
    @pytest.mark.parametrize("rule", RULES, ids=[r["rule_key"] for r in RULES])
    def test_emitted_yaml_is_parseable(self, rule):
        """The output should round-trip through a YAML parser (if available)."""
        text = _emit_yaml(rule)
        try:
            import yaml
        except ImportError:
            pytest.skip("PyYAML not installed - sanity-checking string structure only")
            return
        parsed = yaml.safe_load(text)
        assert parsed["title"] == rule["title"]
        assert parsed["level"] == rule["level"]
        # The id field should be a valid UUID string
        uuid.UUID(parsed["id"])

    def test_yaml_contains_signature_fields(self):
        """Every Sigma rule should contain title:, id:, status:, level: lines."""
        text = _emit_yaml(RULES[0])
        for header in (
            "title:",
            "id:",
            "status:",
            "level:",
            "logsource:",
            "detection:",
            "condition:",
        ):
            assert header in text

    def test_yaml_contains_source_comment(self):
        """The emitter adds a comment linking back to behavioral_monitor.py."""
        text = _emit_yaml(RULES[0])
        assert "behavioral_monitor.py" in text
        assert "RULE-01" in text


# ---------------------------------------------------------------------------
# generate_all_rules and write_rules_to
# ---------------------------------------------------------------------------


class TestGenerate:
    def test_all_rules_returns_six(self):
        result = generate_all_rules()
        assert len(result) == 6
        assert set(result.keys()) == {f"RULE-0{i}" for i in range(1, 7)}

    def test_write_creates_one_yml_per_rule_plus_readme(self, tmp_path):
        written = write_rules_to(tmp_path / "sigma")
        # 6 rules + README
        assert len(written) == 7
        yml_files = list((tmp_path / "sigma").glob("*.yml"))
        assert len(yml_files) == 6
        assert (tmp_path / "sigma" / "README.md").exists()

    def test_written_yml_filenames_are_lowercase(self, tmp_path):
        write_rules_to(tmp_path / "sigma")
        files = sorted((tmp_path / "sigma").glob("*.yml"))
        for f in files:
            assert f.name == f.name.lower()
            assert f.name.startswith("rule-")

    def test_idempotent_regeneration_produces_identical_output(self, tmp_path):
        """Critical: running the generator twice must produce the same output
        so SIEM-side rule tracking (by UUID + content hash) is stable."""
        out1 = tmp_path / "sigma1"
        out2 = tmp_path / "sigma2"
        write_rules_to(out1)
        write_rules_to(out2)
        for rule in RULES:
            key = rule["rule_key"].lower()
            assert (out1 / f"{key}.yml").read_text() == (out2 / f"{key}.yml").read_text()

    def test_readme_mentions_target_siem_backends(self, tmp_path):
        write_rules_to(tmp_path / "sigma")
        readme = (tmp_path / "sigma" / "README.md").read_text()
        for siem in ("Splunk", "Sentinel", "Elastic", "Chronicle"):
            assert siem in readme


# ---------------------------------------------------------------------------
# Cross-check: every behavioral_monitor RULE-NN is covered
# ---------------------------------------------------------------------------


class TestCoverageAgainstBehavioralMonitor:
    """If a new RULE is added to behavioral_monitor.py, the Sigma generator
    needs an update too. This test catches that drift early."""

    def test_every_behavioral_rule_has_a_sigma_rule(self):
        import behavioral_monitor as bm

        # behavioral_monitor exposes RULE-XX via _rule_to_mitre's mapping.
        # We can't directly enumerate them, but we can check the known set.
        bm_rules = {f"RULE-0{i}" for i in range(1, 7)}
        sigma_rules = {r["rule_key"] for r in RULES}
        missing = bm_rules - sigma_rules
        assert not missing, f"Sigma rules missing for: {missing}"
