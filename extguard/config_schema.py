# config_schema.py - Validate extguard.conf.json structure on load
#
# Why a hand-rolled validator instead of jsonschema?
#   1. Zero new dependencies - this is a small, readable validator
#   2. Error messages are tailored to ExtensionGuard (point at the right
#      config key with a specific fix suggestion)
#   3. Schema is in code, not a separate .json file the user has to maintain
#
# We validate:
#   - Each enabled adapter has its required credentials filled in
#   - Type checks on the dispatch settings (ints are ints, strings are strings)
#   - Severity values are one of the allowed four
#   - URLs in slack/splunk look like URLs
#
# Validation result is a list of ConfigError dicts. An empty list = valid.
# The user-facing tool prints them and exits with a non-zero code.


VALID_SEVERITIES = ("low", "medium", "high", "critical")


# ---------------------------------------------------------------------------
# Schema definition - what every enabled adapter requires
# ---------------------------------------------------------------------------

ADAPTER_REQUIRED_KEYS = {
    "sentinel": {
        "workspace_id": str,
        "shared_key": str,
    },
    "splunk": {
        "hec_url": str,
        "hec_token": str,
    },
    "pagerduty": {
        "integration_key": str,
    },
    "slack": {
        "webhook_url": str,
    },
}

# VirusTotal is deliberately NOT in ADAPTER_REQUIRED_KEYS because its api_key
# can come from either the config file OR the VT_API_KEY env var. The validator
# can't see env vars, so requiring api_key in config would produce false-positive
# validation errors for users who (correctly) keep their key only in the env.
# When VT is enabled but no key is available from EITHER source,
# virustotal_lookup.lookup_hash() returns a clear "No VT_API_KEY set" error
# at call time rather than at config-validation time.

# Default placeholder strings we expect users to replace.
# If any of these are present in an ENABLED adapter, that's almost certainly
# a config mistake.
PLACEHOLDER_VALUES = {
    "YOUR-WORKSPACE-ID-HERE",
    "YOUR-BASE64-SHARED-KEY-HERE",
    "YOUR-HEC-TOKEN-HERE",
    "YOUR-PD-INTEGRATION-KEY-HERE",
    "YOUR/WEBHOOK/URL",
}


def validate(config: dict) -> list:
    """
    Validate a loaded config dict. Returns a list of error dicts:
      [{"section": "splunk", "key": "hec_url", "problem": "missing"}, ...]
    Empty list = config is valid.
    """
    errors: list = []

    # --- Adapter-section validation ----------------------------------------
    for adapter_name, required in ADAPTER_REQUIRED_KEYS.items():
        section = config.get(adapter_name, {})
        if not isinstance(section, dict):
            errors.append(
                {
                    "section": adapter_name,
                    "key": None,
                    "problem": f"section must be an object, got {type(section).__name__}",
                }
            )
            continue

        if not section.get("enabled", False):
            continue  # Disabled adapters are not validated

        for key, expected_type in required.items():
            value = section.get(key)
            if value is None or value == "":
                errors.append(
                    {
                        "section": adapter_name,
                        "key": key,
                        "problem": "required when enabled, but missing or empty",
                    }
                )
                continue

            if not isinstance(value, expected_type):
                errors.append(
                    {
                        "section": adapter_name,
                        "key": key,
                        "problem": (
                            f"expected {expected_type.__name__}, got {type(value).__name__}"
                        ),
                    }
                )
                continue

            if _is_placeholder(value):
                errors.append(
                    {
                        "section": adapter_name,
                        "key": key,
                        "problem": (
                            f"still set to placeholder value '{value}' - "
                            "replace with your real credential"
                        ),
                    }
                )

        # min_severity validation (optional but, if set, must be valid)
        min_sev = section.get("min_severity")
        if min_sev is not None and min_sev not in VALID_SEVERITIES:
            errors.append(
                {
                    "section": adapter_name,
                    "key": "min_severity",
                    "problem": (f"must be one of {VALID_SEVERITIES}, got '{min_sev}'"),
                }
            )

        # URL fields should look like http(s) URLs
        for url_key in ("hec_url", "webhook_url"):
            if (
                url_key in section
                and section.get(url_key)
                and not section.get(url_key, "").startswith(("http://", "https://"))
            ):
                errors.append(
                    {
                        "section": adapter_name,
                        "key": url_key,
                        "problem": "must start with http:// or https://",
                    }
                )

    # --- Dispatch-section validation ---------------------------------------
    dispatch = config.get("dispatch", {})
    if isinstance(dispatch, dict):
        ttl = dispatch.get("dedup_ttl_seconds")
        if ttl is not None and (not isinstance(ttl, int) or ttl < 0):
            errors.append(
                {
                    "section": "dispatch",
                    "key": "dedup_ttl_seconds",
                    "problem": "must be a non-negative integer (seconds)",
                }
            )

        threshold = dispatch.get("escalation_threshold")
        if threshold is not None and (not isinstance(threshold, int) or threshold < 1):
            errors.append(
                {
                    "section": "dispatch",
                    "key": "escalation_threshold",
                    "problem": "must be a positive integer",
                }
            )

        window = dispatch.get("escalation_window_seconds")
        if window is not None and (not isinstance(window, int) or window < 1):
            errors.append(
                {
                    "section": "dispatch",
                    "key": "escalation_window_seconds",
                    "problem": "must be a positive integer (seconds)",
                }
            )

        min_sev = dispatch.get("min_severity")
        if min_sev is not None and min_sev not in VALID_SEVERITIES:
            errors.append(
                {
                    "section": "dispatch",
                    "key": "min_severity",
                    "problem": f"must be one of {VALID_SEVERITIES}, got '{min_sev}'",
                }
            )

        triage_min = dispatch.get("triage_min_score")
        if triage_min is not None and (
            not isinstance(triage_min, int) or not 0 <= triage_min <= 100
        ):
            errors.append(
                {
                    "section": "dispatch",
                    "key": "triage_min_score",
                    "problem": "must be an integer in 0-100 range",
                }
            )

    return errors


def format_errors(errors: list) -> str:
    """Render a list of validation errors as a human-readable message."""
    if not errors:
        return "Config OK"

    lines = ["Configuration errors:"]
    for e in errors:
        section = e.get("section", "?")
        key = e.get("key")
        problem = e.get("problem", "?")
        if key:
            lines.append(f"  - [{section}].{key}  --  {problem}")
        else:
            lines.append(f"  - [{section}]  --  {problem}")
    return "\n".join(lines)


def _is_placeholder(value: str) -> bool:
    """Detect whether a string looks like an unedited placeholder."""
    if not isinstance(value, str):
        return False
    if value in PLACEHOLDER_VALUES:
        return True
    if "YOUR" in value and "HERE" in value:
        return True
    if value.startswith("YOUR-") or value.endswith("-HERE"):
        return True
    return False
