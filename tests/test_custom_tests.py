import json
import pathlib
from datetime import datetime, timedelta, timezone

import pytest
import render
import rules
from helpers import flatten

from vipr_drata.batching import SEVERITIES, build_records

ROOT = pathlib.Path(__file__).resolve().parent.parent
CATALOG = json.loads((ROOT / "custom-tests" / "catalog.json").read_text())
PROPS = json.loads((ROOT / "schemas" / "vipr_unified.schema.json").read_text())["properties"]
NOW = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)
ONE = {sev: 1 for sev in SEVERITIES}


def F(i, sev, **kw):
    row = {"id": "f%d" % i, "viprSeverity": sev, "open": True, "hasTicket": True, "missingTicket": False,
           "slaBreached": False, "firstSeen": (NOW - timedelta(days=5)).isoformat()}
    row.update(kw)
    return row


def records(findings, assets, age_days=1):
    dates = {"findings": NOW - timedelta(days=age_days), "assets": NOW - timedelta(days=age_days)}
    return build_records(findings, assets, now=NOW, finding_partitions=ONE, asset_partitions=1, source_dates=dates)


def scoped(test, recs):
    return {r["id"].replace("vipr-", ""): rules.evaluate(test["condition"], r, NOW)
            for r in recs if rules.evaluate(test["filter"]["evaluator"], r, NOW)}


BY_ID = {t["id"]: t for t in CATALOG}
MIXED = records(
    [F(1, "critical", slaBreached=True, firstSeen=(NOW - timedelta(days=40)).isoformat()),
     F(2, "critical", hasTicket=False, missingTicket=True), F(3, "high", slaBreached=None),
     F(4, "high", open=False), F(5, "medium", slaBreached=True), F(6, "low")],
    [{"id": "a1", "viprLastSeenStale": True}, {"id": "a2", "viprLastSeenStale": False}])
CLEAN = records([F(1, "critical"), F(2, "high"), F(3, "medium"), F(4, "low")], [{"id": "a1", "viprLastSeenStale": False}])


@pytest.mark.parametrize("test", CATALOG, ids=lambda t: t["id"])
def test_catalog_entries_are_valid_for_the_schema_and_editor_limits(test):
    for rule in (test["filter"]["evaluator"], test["condition"]):
        assert rules.check(rule, PROPS) == []
        assert rules.count_conditions(rule) <= rules.MAX_CONDITIONS
        assert len(render.fmt(rule).splitlines()) <= rules.MAX_LINES
    assert test["filter"]["mode"] == "inclusion" and test["editor"] in ("Builder", "Advanced")
    assert test["controls"] and len(test["name"]) <= 80


def test_catalog_names_are_unique_and_builder_tests_use_builder_operators():
    assert len({t["name"] for t in CATALOG}) == len(CATALOG)
    hidden = rules.NESTED_OPS | {"in", "notIn", "intersectsAny", "intersectsAll"}

    def ops(node):
        for item in node.get("all") or node.get("any") or []:
            if "operator" in item:
                yield item["operator"]
            else:
                yield from ops(item)
    for t in CATALOG:
        used = set(ops(t["filter"]["evaluator"])) | set(ops(t["condition"]))
        assert (t["editor"] == "Advanced") == bool(used & hidden), t["id"]


def test_reference_document_matches_the_catalog():
    assert (ROOT / "custom-tests" / "README.md").read_text() == render.render()


@pytest.mark.parametrize("test_id, expected", [
    ("scan-data-current", {"summary": True}),
    ("critical-addressed", {"findings-critical-001": False}),
    ("high-addressed", {"findings-high-001": False}),
    ("medium-low-within-sla", {"findings-medium-001": False, "findings-low-001": True}),
    ("critical-high-ticketed", {"findings-critical-001": False, "findings-high-001": True}),
    ("assets-seen-recently", {"assets-001": False}),
    ("critical-high-sla-items", {"findings-critical-001": False, "findings-high-001": True}),
    ("critical-open-age", {"findings-critical-001": False}),
])
def test_tests_score_the_expected_partitions_on_mixed_data(test_id, expected):
    assert scoped(BY_ID[test_id], MIXED) == expected


def test_every_test_passes_on_clean_fresh_data_and_fails_on_stale_data():
    stale = records([F(1, "critical"), F(2, "high"), F(3, "medium"), F(4, "low")],
                    [{"id": "a1", "viprLastSeenStale": False}], age_days=30)
    for t in CATALOG:
        clean, old = scoped(t, CLEAN), scoped(t, stale)
        assert clean and all(clean.values()), t["id"]
        assert old and not any(old.values()), t["id"]


def test_sync_age_rule_fails_when_the_nightly_run_is_old():
    t = BY_ID["scan-data-current"]
    summary = flatten(CLEAN)["summary"]
    assert rules.evaluate(t["condition"], summary, NOW + timedelta(days=2)) is True
    assert rules.evaluate(t["condition"], summary, NOW + timedelta(days=3)) is False


def test_failing_findings_are_listed_for_item_level_tests():
    t = BY_ID["critical-high-sla-items"]
    critical = next(r for r in MIXED if r["id"] == "vipr-findings-critical-001")
    assert [i["id"] for i in rules.offending_items(t["condition"], critical, "findings")] == ["f1"]
    assert rules.evaluate({"all": [{"fact": "findings", "operator": "none", "value": {"all": []}}]}, {"findings": None}) is False


@pytest.mark.parametrize("rule, fragment", [
    ({"all": [{"fact": "sourceFresh", "operator": "equals", "value": True}]}, "not offered"),
    ({"all": [{"fact": "sourceFresh", "operator": "equal", "value": "true"}]}, "invalid for equal"),
    ({"all": [{"fact": "sourceFresh", "operator": "greaterThan", "value": 1}]}, "not offered"),
    ({"all": [{"fact": "nope", "operator": "equal", "value": 1}]}, "unknown fact"),
    ({"all": [{"fact": "findingCount", "operator": "equal", "value": "3"}]}, "invalid for equal"),
    ({"all": [{"fact": "findings.length", "operator": "greaterThan", "value": 0}]}, "unknown fact"),
    ({"all": [{"fact": "findings", "operator": "all", "value": {"all": [{"fact": "bogus", "operator": "equal", "value": 1}]}}]}, "unknown fact"),
    ({"all": [{"fact": "severity", "operator": "in", "value": [1]}]}, "list items"),
    ({"all": [{"fact": "sourceFresh", "operator": "equal", "value": True}], "any": []}, "exactly one"),
])
def test_validator_rejects_what_drata_rejects(rule, fragment):
    assert any(fragment in e for e in rules.check(rule, PROPS))


def test_array_length_path_accepts_number_operators():
    rule = {"all": [{"fact": "findings", "path": "length", "operator": "greaterThan", "value": 0}]}
    assert rules.check(rule, PROPS) == []
    assert rules.evaluate(rule, {"findings": [{}]}, NOW) is True and rules.evaluate(rule, {"findings": []}, NOW) is False


def test_every_test_fails_when_the_nightly_sync_stops():
    for t in CATALOG:
        verdicts = {r["id"]: rules.evaluate(t["condition"], r, NOW + timedelta(days=10))
                    for r in CLEAN if rules.evaluate(t["filter"]["evaluator"], r, NOW + timedelta(days=10))}
        assert verdicts and not any(verdicts.values()), t["id"]


def test_rendered_blocks_are_valid_json_equal_to_the_catalog():
    text = (ROOT / "custom-tests" / "README.md").read_text()
    blocks = [json.loads(b.split("```")[0]) for b in text.split("```json\n")[1:]]
    expected = [r for t in CATALOG for r in (t["filter"]["evaluator"], t["condition"])]
    assert blocks == expected
