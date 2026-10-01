# tests/test_sigma_generator.py - Sigma rule generator tests

import inspect
import re
import uuid

import pytest

from extguard.sigma_generator import (
    AUTHOR,
    C2_HOST_SUFFIXES,
    PROXY_RULES,
    RULES,
    RULES_CREATED,
    RULES_MODIFIED,
    SENSOR_RULES,
    _emit_yaml,
    _rule_uuid,
    _yaml_value,
    generate_all_rules,
    main,
    write_rules_to,
)

RULE_IDS = [r["rule_key"] for r in RULES]

# Field names of the Sigma `proxy` log source taxonomy
SIGMA_PROXY_FIELDS = {
    "c-uri",
    "c-uri-extension",
    "c-uri-query",
    "c-uri-stem",
    "c-useragent",
    "cs-bytes",
    "cs-cookie",
    "cs-host",
    "cs-method",
    "cs-referrer",
    "cs-version",
    "r-dns",
    "sc-bytes",
    "sc-status",
    "src_ip",
    "dst_ip",
}


def _monitor_rule_keys() -> set:
    """Every RULE-NN the behavioral monitor can emit, read from its source."""
    from extguard import behavioral_monitor as bm

    return set(re.findall(r'"(RULE-\d\d)"', inspect.getsource(bm)))


# ---------------------------------------------------------------------------
# Rule catalog integrity
# ---------------------------------------------------------------------------


class TestRuleCatalog:
    def test_one_sensor_rule_per_monitor_rule(self):
        """Adding a RULE to behavioral_monitor.py must add a Sigma rule too."""
        monitor_rules = _monitor_rule_keys()
        assert monitor_rules == {f"RULE-0{i}" for i in range(1, 8)}
        assert {r["rule_key"] for r in SENSOR_RULES} == monitor_rules

    @pytest.mark.parametrize("rule", RULES, ids=RULE_IDS)
    def test_every_rule_has_required_fields(self, rule):
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

    @pytest.mark.parametrize("rule", RULES, ids=RULE_IDS)
    def test_level_is_valid_sigma_severity(self, rule):
        assert rule["level"] in ("informational", "low", "medium", "high", "critical")

    @pytest.mark.parametrize("rule", RULES, ids=RULE_IDS)
    def test_condition_only_names_defined_selections(self, rule):
        detection = rule["detection"]
        names = set(re.findall(r"[A-Za-z_]+", detection["condition"])) - {"and", "or", "not"}
        assert names, "empty condition"
        assert names <= set(detection) - {"condition"}

    @pytest.mark.parametrize("rule", RULES, ids=RULE_IDS)
    def test_tags_include_attack_id(self, rule):
        attack_tags = [t for t in rule["tags"] if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)]
        assert attack_tags, f"{rule['rule_key']} has no attack.t#### tag"

    @pytest.mark.parametrize("rule", RULES, ids=RULE_IDS)
    def test_no_rule_targets_a_log_source_siems_do_not_have(self, rule):
        """The old RULE-04/05/06 pointed at `product: browser` sources nobody collects."""
        assert rule["logsource"].get("product") != "browser"

    @pytest.mark.parametrize("rule", PROXY_RULES, ids=[r["rule_key"] for r in PROXY_RULES])
    def test_proxy_rules_use_standard_proxy_fields(self, rule):
        for name, selection in rule["detection"].items():
            if name == "condition":
                continue
            for field, value in selection.items():
                assert field.split("|")[0] in SIGMA_PROXY_FIELDS, field
                # The old RULE-01 had `c-uri-extension: ""`, which never matches
                assert value not in ("", []), f"{field} has an empty value"

    def test_no_proxy_firehose_rules(self):
        """POST-with-cookie / JSON-API-call to github.com matches every logged-in user."""
        for rule in PROXY_RULES:
            detection = repr(rule["detection"]).lower()
            assert "github.com" not in detection
            assert "cookie" not in detection

    def test_proxy_hosts_match_the_monitor(self):
        from extguard.behavioral_monitor import C2_HOST_PATTERNS

        for suffix in C2_HOST_SUFFIXES:
            assert C2_HOST_PATTERNS.search("evil" + suffix), suffix
        # ...and every host the monitor knows is in the Sigma list
        monitor_hosts = re.findall(r"[a-z-]+\\\.[a-z]+", C2_HOST_PATTERNS.pattern)
        for host in monitor_hosts:
            assert "." + host.replace("\\.", ".") in C2_HOST_SUFFIXES

    def test_sensor_rules_match_on_the_alert_rule_field(self):
        for rule in RULES:
            if rule in PROXY_RULES:
                continue
            assert rule["logsource"]["product"] == "extensionguard"
            assert rule["detection"]["selection"] == {"rule": rule["rule_key"]}


# ---------------------------------------------------------------------------
# UUID generation
# ---------------------------------------------------------------------------


class TestUuid:
    def test_uuid_is_valid_uuidv5(self):
        assert uuid.UUID(_rule_uuid("RULE-01")).version == 5

    def test_uuid_is_stable(self):
        """Same rule_key must always produce the same UUID - SIEM-side tracking depends on this."""
        assert _rule_uuid("RULE-01") == _rule_uuid("RULE-01")

    def test_uuid_differs_per_rule(self):
        assert len({_rule_uuid(k) for k in RULE_IDS}) == len(RULES)


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
# YAML emission
# ---------------------------------------------------------------------------


class TestEmitYaml:
    @pytest.mark.parametrize("rule", RULES, ids=RULE_IDS)
    def test_emitted_yaml_is_parseable(self, rule):
        yaml = pytest.importorskip("yaml")
        parsed = yaml.safe_load(_emit_yaml(rule))
        assert parsed["title"] == rule["title"]
        assert parsed["level"] == rule["level"]
        assert parsed["logsource"] == rule["logsource"]
        uuid.UUID(parsed["id"])

    def test_author_and_dates_are_fixed(self):
        text = _emit_yaml(RULES[0])
        assert f'author: "{AUTHOR}"' in text
        assert "Vimal7747" in AUTHOR
        assert "example" not in AUTHOR
        assert f"date: {RULES_CREATED}" in text
        assert f"modified: {RULES_MODIFIED}" in text

    def test_yaml_contains_source_comment(self):
        text = _emit_yaml(RULES[0])
        assert "# Source: ExtensionGuard behavioral_monitor.py RULE-01" in text


# ---------------------------------------------------------------------------
# generate_all_rules, write_rules_to and the CLI
# ---------------------------------------------------------------------------


class TestGenerate:
    def test_all_rules_keyed_by_rule_key(self):
        assert set(generate_all_rules()) == set(RULE_IDS)

    def test_write_creates_one_yml_per_rule_plus_readme(self, tmp_path):
        written = write_rules_to(tmp_path / "sigma")
        assert len(written) == len(RULES) + 1
        assert len(list((tmp_path / "sigma").glob("*.yml"))) == len(RULES)
        assert (tmp_path / "sigma" / "README.md").exists()

    def test_written_yml_filenames_are_lowercase(self, tmp_path):
        write_rules_to(tmp_path / "sigma")
        for f in (tmp_path / "sigma").glob("*.yml"):
            assert f.name == f.name.lower()

    def test_regeneration_is_byte_identical(self, tmp_path):
        """Fixed dates + UUIDv5: running twice (even on another day) changes nothing."""
        write_rules_to(tmp_path / "a")
        write_rules_to(tmp_path / "b")
        for f in (tmp_path / "a").iterdir():
            assert f.read_bytes() == (tmp_path / "b" / f.name).read_bytes()

    def test_readme_documents_log_sources(self, tmp_path):
        write_rules_to(tmp_path / "sigma")
        readme = (tmp_path / "sigma" / "README.md").read_text()
        for text in ("Splunk", "Sentinel", "Elastic", "extguard:alert", "ExtensionGuard_CL"):
            assert text in readme

    def test_cli_prints_one_rule(self, capsys):
        assert main(["--output", "-", "--rule", "rule-05"]) == 0
        out = capsys.readouterr().out
        assert "Disabled or Uninstalled Another Extension" in out

    def test_cli_unknown_rule_exits_2(self, capsys):
        assert main(["--output", "-", "--rule", "RULE-99"]) == 2
