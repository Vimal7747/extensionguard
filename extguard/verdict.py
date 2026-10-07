# verdict.py - Turn the scores into a verdict that requires EVIDENCE
#
# Why this exists (real-extension test, 2026-10-07):
#   Bitwarden, Grammarly, uBlock Origin Lite, Dark Reader and React Developer
#   Tools - genuine, byte-identical Web Store builds with no suspicious code -
#   all scored CRITICAL ("block immediately") because the score measures what
#   an extension COULD do. A password manager, an ad blocker and a dev tool
#   need the same permissions malware wants. A SOC told to block its own
#   password manager stops trusting every verdict.
#
# So the score still measures capability + findings, but the verdict is
# capped by what we actually know:
#
#   EVIDENCE of malicious behaviour (exfil endpoints, real obfuscation,
#   remote code, a hijacked-update diff, VirusTotal consensus, a tampered or
#   forged build, an attacker-style update feed)        -> no cap (CRITICAL possible)
#
#   ANOMALY (something doesn't add up: not on the store, updates from
#   outside it, an odd version change, 1-2 VirusTotal engines, an update
#   adding endpoints + sensitive APIs, a check that failed)  -> at most HIGH
#
#   Nothing suspicious, but the build can't be verified as the genuine store
#   build (bare manifest, unpacked ZIP, offline, older copy)  -> at most HIGH
#
#   Nothing suspicious in a verified, byte-identical Web Store build
#                                                          -> at most MEDIUM
#
# The uncapped score stays in the report: a MEDIUM verdict on a powerful
# extension still says "review / allowlist it", and the runtime monitor and
# the update diff are what catch it if it ever turns.

from extguard.code_diff import SENSITIVE_APIS

# Highest score each level allows (thresholds: 70 critical, 45 high, 20 medium)
LEVEL_CEILINGS = {"medium": 44, "high": 69}

# VirusTotal: 3+ engines is the consensus the VT stage itself calls "very
# likely real"; 1-2 can be a single engine's false positive
VT_EVIDENCE_ENGINES = 3


def assess(pub: dict, osv: dict, vel: dict, code: dict, stage_errors: dict | None = None) -> dict:
    """
    Classify the Stage 1 findings. Returns:
      evidence              list[str]   evidence of malicious behaviour
      anomalies             list[str]   things that don't add up
      verified_store_build  bool        signed + byte-identical to the Web Store build
      max_level             "medium" / "high" / None (None = no cap)
      reason                str         one sentence for the report
    """
    stage_errors = stage_errors or {}
    evidence: list = []
    anomalies: list = []

    # --- The code (Stage 1f) ------------------------------------------------
    profile = code.get("profile") or {}
    exfil = profile.get("exfil_endpoints") or []
    if code.get("new_exfil_endpoints"):
        evidence.append(
            "an update started sending data to " + ", ".join(code["new_exfil_endpoints"][:3])
        )
    elif exfil:
        evidence.append("code sends data to exfil-style hosting: " + ", ".join(exfil[:3]))
    if profile.get("obfuscated_files"):
        evidence.append("obfuscated code: " + ", ".join(profile["obfuscated_files"][:3]))
    apis = profile.get("apis") or {}
    if apis.get("remote importScripts") or apis.get("remote <script src>"):
        evidence.append("loads code from a remote server")
    new_sensitive = [a for a in code.get("new_apis") or [] if a in SENSITIVE_APIS]
    if code.get("new_hosts") and new_sensitive:
        anomalies.append(
            "an update added new endpoints and sensitive APIs (" + ", ".join(new_sensitive) + ")"
        )

    # --- Packages, CDN code, VirusTotal (Stage 1d) --------------------------
    if osv.get("cdn_refs"):
        evidence.append("loads scripts from a CDN at runtime")
    vt = osv.get("vt") or {}
    engines = vt.get("malicious", 0) if vt.get("found") else 0
    if engines >= VT_EVIDENCE_ENGINES:
        evidence.append(f"VirusTotal: {engines} engines flag this file")
    elif engines:
        anomalies.append(f"VirusTotal: {engines} engine(s) flag this file")

    # --- Identity and the Web Store (Stage 1c) ------------------------------
    if pub.get("identity_conflict"):
        evidence.append("the package's identity contradicts its signature (repackaged or forged)")
    relation = pub.get("store_relation")
    if relation == "tampered":
        evidence.append("same version as the Web Store build but different bytes (tampered)")
    elif relation == "newer_than_store":
        anomalies.append("newer than the Web Store's version - did not come from the store")
    if pub.get("suspicious_update"):
        evidence.append("updates from an attacker-style host")
    elif pub.get("update_url_ok") is False:
        anomalies.append("updates from outside the Chrome Web Store")
    if pub.get("cws_exists") is False:
        anomalies.append("not published on the Chrome Web Store")

    # --- Version history (Stage 1e) -----------------------------------------
    if vel.get("is_suspicious"):
        anomalies.append("unusual version change (see the update-velocity check)")

    # --- A check that failed can't vouch for anything -----------------------
    for stage in ("1c", "1d", "1f"):
        if stage in stage_errors:
            anomalies.append(f"Stage {stage} failed, so evidence may be missing")

    verified = (
        pub.get("id_source") == "crx3-signed-id"
        and relation == "identical"
        and not pub.get("identity_conflict")
    )

    if evidence:
        max_level = None
        reason = "Evidence of malicious behaviour: " + "; ".join(evidence)
    elif anomalies:
        max_level = "high"
        reason = "No evidence of malicious behaviour, but: " + "; ".join(anomalies)
    elif not verified:
        max_level = "high"
        reason = (
            "No evidence of malicious behaviour, but this could not be verified as the "
            "genuine Web Store build (" + _unverified_because(pub) + ")"
        )
    else:
        max_level = "medium"
        reason = (
            "No evidence of malicious behaviour in a signed build that is byte-identical to "
            "the Chrome Web Store's - the permission score shows what it COULD do, so review "
            "or allowlist it"
        )
    return {
        "evidence": evidence,
        "anomalies": anomalies,
        "verified_store_build": verified,
        "max_level": max_level,
        "reason": reason,
    }


def apply_cap(score: int, assessment: dict) -> int:
    """The score, lowered to the highest the assessment allows."""
    ceiling = LEVEL_CEILINGS.get(assessment.get("max_level"))
    return min(score, ceiling) if ceiling is not None else score


def _unverified_because(pub: dict) -> str:
    if pub.get("id_source") != "crx3-signed-id":
        return "no Web Store signature - a bare manifest, unpacked ZIP or sideloaded package"
    if pub.get("cws_exists") is None:
        return "the Web Store was not checked - offline, or the lookup failed"
    if pub.get("store_relation") == "older_than_store":
        return "an older version - the store only serves its latest build, so scan that"
    return "the store's build could not be compared"
