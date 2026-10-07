from datetime import datetime, timezone
import json
import pathlib
from unittest import mock

import jsonschema
import pytest
import requests

from vipr_drata.db.queries import is_true, rows_to_records
from helpers import flatten
from vipr_drata.batching import build_records
from vipr_drata.transform import (build_payloads, extract_asset_features, extract_finding_features,
                                  index_tenable_assets, match_tenable, scanner_severity)

NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)


def finding(**kw):
    base = {"silk_id": "f1", "severity": "Medium", "tool_severity": '{"tenable": "High"}',
            "open": "true", "has_ticket": "false", "sla_date": "2026-09-01 00:00:00",
            "asset_silk_id": "a1"}
    base.update(kw)
    return base


def test_bool_string_coercion():
    assert is_true("true") and not is_true("false") and not is_true(None)


def test_null_cleanup():
    assert rows_to_records(["a"], [["null"]]) == [{"a": None}]


def test_severity_downgrade_and_sla():
    f = extract_finding_features(finding(), [{"silk_id": "a1", "name": "h"}], NOW)
    assert f["severity_changed"] and f["severity_direction"] == "downgraded"
    assert f["sla_breached"] and f["missing_ticket"] and f["asset_name"] == "h"


def test_undetermined_when_no_tenable():
    f = extract_finding_features(finding(tool_severity="{}"), [], NOW)
    assert f["severity_changed"] is None and not f["asset_resolved"]


def test_ambiguous_asset_unresolved():
    f = extract_finding_features(finding(), [{"name": "x"}, {"name": "y"}], NOW)
    assert f["asset_name"] is None


def test_rejects_missing_id():
    fs, sc, rej = build_payloads(
        [{"finding": finding(silk_id=None), "assets": []}],
        [{"silk_id": "a1", "last_seen": "2026-09-01 00:00:00", "is_active": "true"}], 7, NOW)
    assert not fs and len(rej) == 1 and sc[0]["viprLastSeenStale"] is True


def _schema():
    return json.loads((pathlib.Path(__file__).parent.parent / "schemas" / "vipr_unified.schema.json").read_text())


def _strict():
    sev = {"enum": ["info", "low", "medium", "high", "critical", None]}
    s = _schema()
    item = s["properties"]["findings"]["items"]
    item["properties"].update(viprSeverity=sev, scannerSeverity=sev, severityDirection={"enum": ["downgraded", "upgraded", None]})
    item["required"] = ["id", "open", "hasTicket", "missingTicket", "slaBreached"]
    asset = s["properties"]["assets"]["items"]
    asset["properties"]["tenableMatch"] = {"enum": ["matched", "none", "ambiguous", "not_configured", "no_data", None]}
    asset["required"] = ["id", "isActive", "viprLastSeenStale"]
    s["properties"]["recordType"] = {"enum": ["summary", "findingBatch", "assetBatch"]}
    s["allOf"] = [
        {"if": {"properties": {"recordType": {"const": "summary"}}, "required": ["recordType"]},
         "then": {"required": ["generatedAt", "sourceFresh", "openFindingCount", "openSlaBreachedCount", "rejectedCount"]}},
        {"if": {"properties": {"recordType": {"const": "findingBatch"}}, "required": ["recordType"]},
         "then": {"required": ["findings", "bucket", "bucketCount", "itemCount"]}},
        {"if": {"properties": {"recordType": {"const": "assetBatch"}}, "required": ["recordType"]},
         "then": {"required": ["assets", "bucket", "bucketCount", "itemCount"]}},
    ]
    return s


def test_shipped_schema_is_plain_drata_subset():
    def keys(node):
        out = set()
        if isinstance(node, dict):
            for k, v in node.items():
                out.add(k)
                out |= keys(v) if k != "properties" else set().union(*[keys(x) for x in v.values()])
        return out
    assert keys(_schema()) <= {"type", "properties", "required", "additionalProperties", "items", "description"}


def test_batch_records_match_shipped_and_strict_schema():
    fs, sc, _ = build_payloads(
        [{"finding": finding(open_cves='["CVE-2026-1"]'), "assets": [{"silk_id": "a1", "name": "h"}]},
         {"finding": finding(silk_id="f2", tool_severity="", open_cves=None), "assets": []}],
        [{"silk_id": "a1", "last_seen": "2026-09-30 00:00:00", "is_active": "true", "open_findings_count": "3"},
         {"silk_id": "a2", "is_active": "false"}], 7, NOW)
    records = build_records(fs, sc, now=NOW, finding_buckets=4, asset_buckets=2)
    plain, strict = jsonschema.Draft202012Validator(_schema()), jsonschema.Draft202012Validator(_strict())
    for rec in records:
        plain.validate(rec)
        strict.validate(rec)
    flat = flatten(records)
    assert flat["findings"]["f1"]["cves"] == ["CVE-2026-1"] and flat["assets"]["a1"]["openFindingsCount"] == 3
    assert flat["findings"]["f1"]["assetId"] == "a1" and flat["findings"]["f2"].get("assetName") is None


def test_same_source_id_in_both_tables_is_fine_because_arrays_are_separate():
    fs, sc, _ = build_payloads([{"finding": finding(silk_id="x"), "assets": []}],
                               [{"silk_id": "x", "is_active": "true"}], 7, NOW)
    flat = flatten(build_records(fs, sc, now=NOW, finding_buckets=2, asset_buckets=2))
    assert "x" in flat["findings"] and "x" in flat["assets"]


@pytest.mark.parametrize("path,bad", [
    (("recordType",), "other"),
    (("findings", 0, "viprSeverity"), "3"),
    (("assets", 0, "tenableMatch"), "maybe"),
    (("findings", 0, "cveCount"), "3"),
    (("itemCount",), "many"),
])
def test_unified_schema_rejects_bad_records(path, bad):
    fs, sc, _ = build_payloads([{"finding": finding(), "assets": []}], [{"silk_id": "a1", "is_active": "true"}], 7, NOW)
    recs = build_records(fs, sc, now=NOW, finding_buckets=1, asset_buckets=1)
    rec = recs[2] if path[0] == "assets" else recs[1] if path[0] == "findings" else recs[1]
    node = rec
    for p in path[:-1]:
        node = node[p]
    node[path[-1]] = bad
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(_strict()).validate(rec)


def test_strict_schema_requires_type_specific_fields():
    fs, sc, _ = build_payloads([{"finding": finding(), "assets": []}], [{"silk_id": "a1", "is_active": "true"}], 7, NOW)
    recs = build_records(fs, sc, now=NOW, finding_buckets=1, asset_buckets=1)
    v = jsonschema.Draft202012Validator(_strict())
    for rec, key in ((recs[0], "sourceFresh"), (recs[1], "findings"), (recs[2], "assets")):
        with pytest.raises(jsonschema.ValidationError):
            v.validate({k: x for k, x in rec.items() if k != key})


def test_severity_aliases_normalize():
    f = extract_finding_features(finding(severity="Informational", tool_severity='{"tenable": "info"}'), [], NOW)
    assert f["severity_changed"] is False


def _run_sql_with(csv_chunks):
    from databricks.sdk.service.sql import StatementState
    from vipr_drata.db import queries

    client = mock.Mock()
    col = mock.Mock()
    col.name = "a"
    col2 = mock.Mock()
    col2.name = "b"
    resp = mock.Mock(statement_id="s")
    resp.status.state = StatementState.SUCCEEDED
    resp.manifest.schema.columns = [col, col2]
    links = [mock.Mock(external_link="http://l/%d" % i) for i in range(len(csv_chunks))]
    chunks = [mock.Mock(external_links=[l], next_chunk_index=i + 1 if i + 1 < len(links) else None)
              for i, l in enumerate(links)]
    resp.result = chunks[0]
    client.statement_execution.execute_statement.return_value = resp
    client.statement_execution.get_statement_result_chunk_n.side_effect = lambda sid, n: chunks[n]
    with mock.patch.object(queries.requests, "get",
                           side_effect=lambda url, timeout: mock.Mock(content=csv_chunks[int(url[-1])].encode("utf-8"))):
        return queries.run_sql(client, "w", "SELECT 1")


def test_run_sql_multichunk_header_only_when_present():
    rows = _run_sql_with(["a,b\n1,2\n", "3,null\n"])
    assert rows == [{"a": "1", "b": "2"}, {"a": "3", "b": None}]


def test_run_sql_decodes_utf8_and_download_error_hides_signed_url():
    from vipr_drata.db import queries
    assert _run_sql_with(["a,b\n\u00e9t\u00e9,2\n"])[0]["a"] == "\u00e9t\u00e9"
    err = requests.HTTPError("403 for https://bucket/x?X-Amz-Signature=SECRET", response=mock.Mock(status_code=403))
    with mock.patch.object(queries.requests, "get", side_effect=err):
        with pytest.raises(RuntimeError) as e:
            queries._download("https://bucket/x?X-Amz-Signature=SECRET", 0)
    assert "SECRET" not in str(e.value) and "403" in str(e.value)


@pytest.mark.parametrize("vipr,tool", [("Medium", '{"tenable":"3"}'), ("Medium", '{"tenable":"unknown"}'),
                                       ("unscored", '{"tenable":"low"}'), ("medium", '{"tenable_io":"high","tenable_sc":"low"}')])
def test_unknown_or_conflicting_severity_is_undetermined(vipr, tool):
    f = extract_finding_features(finding(severity=vipr, tool_severity=tool), [], NOW)
    assert f["severity_changed"] is None and f["severity_direction"] is None


def test_agreeing_multiple_tenable_keys_ok():
    assert scanner_severity('{"tenable_io":"High","tenable_sc":"high"}') == "high"
    assert scanner_severity("{tenable -> medium, qualys -> low}") == "medium"


@pytest.mark.parametrize("sla", ["2026-09-01T00:00:00+00:00", "2026-09-01T00:00:00Z", "2026-09-01 00:00:00.123"])
def test_sla_timestamp_formats(sla):
    f = extract_finding_features(finding(sla_date=sla), [], NOW)
    assert f["sla_breached"] is True and f["sla_date"].startswith("2026-09-01")


def test_unparseable_sla_and_null_flags_are_undetermined():
    f = extract_finding_features(finding(sla_date="not-a-date"), [], NOW)
    assert f["sla_breached"] is None
    f = extract_finding_features(finding(has_ticket=None), [], NOW)
    assert f["missing_ticket"] is None and f["has_ticket"] is None
    f = extract_finding_features(finding(open=None), [], NOW)
    assert f["open"] is None and f["sla_breached"] is None


def test_closed_after_sla():
    f = extract_finding_features(finding(open="false", sla_date="2026-08-01 00:00:00",
                                         closed_timestamp="2026-09-20 00:00:00"), [], NOW)
    assert f["closed_after_sla"] is True and f["sla_breached"] is False


def test_staleness_uses_exact_timedelta():
    a = extract_asset_features({"silk_id": "a", "last_seen": "2026-09-23 18:00:00"}, 7, NOW)
    assert a["days_since_seen"] == 7 and a["vipr_last_seen_stale"] is True


def _t(i, hosts=(), macs=(), scan="2026-09-30 00:00:00"):
    return {"id": i, "hostnames": json.dumps(list(hosts)), "mac_addresses": json.dumps(list(macs)),
            "last_scan_time": scan}


def _asset(i, hosts=(), macs=()):
    return {"silk_id": i, "hostnames": json.dumps(list(hosts)), "mac_addresses": json.dumps(list(macs)),
            "last_seen": "2026-09-30 00:00:00"}


def _status(assets, tenable):
    _, sc, _ = build_payloads([], assets, 7, NOW, tenable_assets=tenable)
    return {a["id"]: a["tenableMatch"] for a in sc}


def test_tenable_shared_target_and_generic_names_are_ambiguous_or_none():
    got = _status([_asset("a0", ["web-1"]), _asset("a1", ["web-1"])], [_t("t1", ["web-1"])])
    assert got == {"a0": "ambiguous", "a1": "ambiguous"}
    assert _status([_asset("a0", ["ubuntu"])], [_t("t1", ["ubuntu"])]) == {"a0": "none"}


def test_tenable_mac_normalised_and_conflict_ambiguous():
    assert _status([_asset("a", [], ["AA-BB-CC-00-00-01"])], [_t("t", [], ["aa:bb:cc:00:00:01"])]) == {"a": "matched"}
    got = _status([_asset("a", ["y"], ["AA:BB:CC:00:00:01"])],
                  [_t("t1", ["x"], ["aa:bb:cc:00:00:01"]), _t("t2", ["y"])])
    assert got == {"a": "ambiguous"}


def test_tenable_empty_and_duplicate_ids_are_undetermined():
    assert _status([_asset("a", ["h"])], []) == {"a": "no_data"}
    assert _status([_asset("a", ["h"])], [_t("t", ["h"]), _t("t", ["h"], scan="2026-01-01 00:00:00")]) == {"a": "ambiguous"}
    assert _status([_asset("a", ["h"])], None) == {"a": "not_configured"}


def test_identical_duplicates_collapse_conflicting_rejected():
    same = {"finding": finding(), "assets": []}
    fs, _, rej = build_payloads([same, dict(same)], [], 7, NOW)
    assert len(fs) == 1 and not rej
    fs, _, rej = build_payloads([same, {"finding": finding(severity="high"), "assets": []}], [], 7, NOW)
    assert not fs and len(rej) == 2 and rej[0]["resource"] == "findings"


def test_null_asset_id_never_joins():
    from vipr_drata.etl.extract import merge
    joined, _ = merge({"findings": [finding(asset_silk_id=None)], "assets": [{"silk_id": None, "name": "ghost"}]})
    assert joined[0]["assets"] == []


def test_parse_list_fallbacks():
    from vipr_drata.transform import _parse_list
    assert _parse_list("[CVE-1, CVE-2]") == ["CVE-1", "CVE-2"] and _parse_list("") == []
