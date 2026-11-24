# Copyright (c) 2026 Shubhan Punde · MIT licence
"""The ATT&CK mapping covers every signal, and the Sigma rules stay in step with the engine."""
import re
from pathlib import Path

import yaml

from irisk.engine import ATTACK, SIGNALS, RiskEngine

RULES = Path(__file__).resolve().parents[1] / "detections" / "sigma"


def test_every_signal_has_an_attack_technique():
    assert set(ATTACK) == set(SIGNALS)
    for tech, name in ATTACK.values():
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", tech) and name


def test_explain_includes_attack_technique():
    out = RiskEngine().explain(["mfa_fatigue", "bulk_download"])
    assert [o["attack"] for o in out] == ["T1621", "T1567"]


def load_rules():
    """The rule that alerts: the correlation when a file has one, else the single rule."""
    rules = {}
    for p in sorted(RULES.glob("*.yml")):
        docs = list(yaml.safe_load_all(p.read_text()))
        rules[p.stem] = next((d for d in docs if "correlation" in d), docs[0])
    assert len(rules) >= 4
    return rules


def test_sigma_rules_are_complete_and_tagged():
    ids = set()
    for name, r in load_rules().items():
        for key in ("title", "id", "status", "description", "level", "tags"):
            assert key in r, f"{name} missing {key}"
        assert "detection" in r or "correlation" in r
        if "logsource" in r:
            assert r["logsource"]["product"] == "okta"
        assert any(re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t) for t in r["tags"]), name
        assert r["id"] not in ids
        ids.add(r["id"])


def test_sigma_thresholds_match_the_engine():
    """Thresholds in the rules are the same ones the engine uses, so the two never drift apart."""
    rules = load_rules()
    expect = {
        "okta_failed_signin_burst": ("10m", 6),        # engine: fails_10m >= 6
        "okta_multi_country_failures": ("10m", 3),     # engine: fail_countries_10m >= 3
        "okta_mfa_push_fatigue": ("30m", 3),           # engine: 3+ denials in 30 min
    }
    for name, (window, n) in expect.items():
        corr = rules[name]["correlation"]
        assert corr["timespan"] == window
        assert corr["condition"]["gte"] == n


def test_rules_convert_to_splunk_and_match_committed_queries():
    """Rules use Sigma correlations (not the deprecated pipe syntax), so they convert to SIEM queries."""
    import sys
    sys.path.insert(0, str(RULES.parents[1] / "tools"))
    from build_splunk import build
    for name, spl in build().items():
        path = RULES.parent / "splunk" / f"{name}.spl"
        assert path.exists() and path.read_text() == spl, f"run python tools/build_splunk.py ({name})"
