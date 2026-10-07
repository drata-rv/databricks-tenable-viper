import json
from datetime import datetime, timezone
from unittest import mock

import pytest

from helpers import flatten
from vipr_drata.batching import finding_item
from vipr_drata import cli
from vipr_drata.etl.extract import merge
from vipr_drata.profile import build_profile, summary
from vipr_drata.transform import _parse_ts, build_payloads, extract_finding_features, parse_map

NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)


def F(**kw):
    row = {"silk_id": "f1", "severity": "low", "tool_severity": "{}", "open": "true", "has_ticket": "false",
           "asset_silk_id": "a1", "first_seen": "2022-04-19 05:11:36", "last_seen": None,
           "sla_date": "2022-10-16 05:11:36"}
    row.update(kw)
    return row


def A(**kw):
    row = {"silk_id": "a1", "name": "h1", "is_active": "true", "last_seen": "2026-09-30 00:00:00"}
    row.update(kw)
    return row


def profile(findings, assets, tenable=None):
    tables = {"findings": findings, "assets": assets}
    joined, arows = merge(tables)
    fs, sc, _ = build_payloads(joined, arows, 7, NOW, tenable_assets=tenable)
    return build_profile(tables, joined, fs, sc), fs, sc


def test_cli_profile_exact_counts(tmp_path, capsys):
    out = tmp_path / "out"
    assert cli.main(["--local", "--local-data", str(tmp_path / "d"), "--output-dir", str(out)]) == 0
    p = json.load(open(out / "_profile.json"))
    assert p["raw_rows"] == {"findings": 7, "assets": 5, "tenable_assets": 3}
    assert p["raw_tool_severity"]["rows"] == {"parsed": 6, "empty_map": 1}
    assert p["raw_tool_severity"]["keys"] == {"tenable": 6}
    assert p["raw_tool_severity"]["values"]["tenable"] == {"high": 2, "medium": 1, "low": 2, "critical": 1}
    assert p["raw_asset_resolution"] == {"resolved": 5, "conflicting_duplicates": 1, "no_asset_row": 1}
    assert p["unmatched_asset_id_samples"] == ["a-missing"]
    assert p["findings_null"]["scannerSeverity"] == 1 and p["tenable_match"]["matched"] == 1
    assert p["null_counts"]["findings"]["closed_timestamp"] == 6
    assert "profile: raw_findings=7 scannerSeverity_null=1" in capsys.readouterr().out
    dumped = json.dumps(p)
    for leaked in ("f-001", "host-one", "CVE-2026-0001", "VIPR-001"):
        assert leaked not in dumped


def test_profile_distinguishes_tool_severity_causes():
    rows = [F(silk_id=str(i), tool_severity=v) for i, v in enumerate(
        [None, "{}", "garbage", "['tenable', 'high']", '{"tio": "4"}', '{"tenable": null}'])]
    p, _, _ = profile(rows, [A()])
    assert p["raw_tool_severity"]["rows"] == {"null": 1, "empty_map": 1, "unparseable": 2, "parsed": 2}
    assert p["raw_tool_severity"]["values"] == {"tio": {"4": 1}, "tenable": {"<null>": 1}}


def test_profile_distinguishes_null_from_unparseable_timestamp():
    rows = [F(silk_id="1", last_seen=None), F(silk_id="2", last_seen="04/19/2022"),
            F(silk_id="3", last_seen="Apr 19, 2022"), F(silk_id="4", last_seen="2022-04-19 05:11:36")]
    p, _, _ = profile(rows, [A()])
    assert p["null_counts"]["findings"]["last_seen"] == 1
    assert p["unparseable_timestamps"] == {"findings": {"last_seen": {"count": 2, "samples": ["04/19/2022", "Apr 19, 2022"]}}}
    assert "unparseable_ts={'findings': {'last_seen': 2}}" in summary(p)


def test_profile_distinguishes_asset_join_causes():
    findings = [F(silk_id="1", asset_silk_id=None), F(silk_id="2", asset_silk_id="zz"),
                F(silk_id="3", asset_silk_id=" A1 "), F(silk_id="4", asset_silk_id="a1"),
                F(silk_id="5", asset_silk_id="a2")]
    assets = [A(), A(silk_id="a2", name=None), A(silk_id="a3", name="x"), A(silk_id="a3", name="y")]
    p, _, _ = profile(findings, assets)
    assert p["raw_asset_resolution"] == {"no_asset_id": 1, "no_asset_row": 1, "id_format_mismatch": 1,
                                         "resolved": 1, "asset_name_null": 1}
    assert p["unmatched_asset_id_samples"] == ["zz", " A1 "]


def test_profile_value_buckets_are_bounded():
    rows = [F(silk_id=str(i), severity="tok-%s" % ("x" * 40), tool_severity='{"tenable": "%s"}' % ("y" * 500))
            for i in range(30)]
    p, _, _ = profile(rows, [A()])
    assert p["raw_vipr_severity_values"] == {"<other>": 30}
    assert p["raw_tool_severity"]["values"]["tenable"] == {"<other>": 30}
    assert p["raw_vipr_severity_values"] != {"none": 1}
    p2, _, _ = profile([F(severity=None), F(silk_id="2", severity="none")], [A()])
    assert p2["raw_vipr_severity_values"] == {"<null>": 1, "none": 1}


def test_profile_ranks_values_by_frequency_and_unions_columns():
    rows = [F(silk_id="k%d" % i, tool_severity='{"k%d": "low"}' % i) for i in range(25)]
    rows += [F(silk_id="t%d" % i, tool_severity='{"tenable": "high"}') for i in range(100)]
    p, _, _ = profile(rows, [A()])
    assert "tenable" in p["raw_tool_severity"]["values"] and len(p["raw_tool_severity"]["values"]) == 20
    p = build_profile({"findings": [{"silk_id": "f1"}, {"silk_id": "f2", "severity": "x", "open": None}]}, [], [], [])
    assert p["null_counts"]["findings"] == {"open": 2, "severity": 1, "silk_id": 0}


def test_profile_handles_empty_and_missing_tables():
    p = build_profile({"findings": [], "assets": []}, [], [], [])
    assert p["raw_rows"] == {"findings": 0, "assets": 0} and p["raw_asset_resolution"] == {}
    summary(p)


def test_profile_failure_never_aborts_the_run(tmp_path, capsys):
    with mock.patch.object(cli, "build_profile", side_effect=RuntimeError("boom")):
        rc = cli.main(["--local", "--local-data", str(tmp_path / "d"), "--output-dir", str(tmp_path / "o")])
    assert rc == 0 and (tmp_path / "o" / "records.json").exists() and (tmp_path / "o" / "_rejected.json").exists()
    assert "profile skipped: RuntimeError" in capsys.readouterr().err


@pytest.mark.parametrize("raw,expected", [
    ("{tenable -> High, Medium}", {"tenable": "High"}),
    ("{tenable -> high, oops}", {"tenable": "high"}),
    ("{a -> b, c -> d}", {"a": "b", "c": "d"}),
    ('{"tenable": "high"}', {"tenable": "high"}),
    ("{}", {}), (None, {}), ("", {}),
    ("garbage", None), ("['tenable', 'high']", None), ('["tenable","high"]', None), ("{broken", None),
])
def test_parse_map_never_raises(raw, expected):
    assert parse_map(raw) == expected


@pytest.mark.parametrize("raw", [
    "2022-04-19 05:11:36", "2022-04-19T05:11:36Z", "2022-04-19 05:11:36 UTC", "2022-04-19 05:11:36.123456 UTC",
    "2022-04-19 05:11:36.1", "2022-04-19T05:11:36+00:00", "2022-04-19 05:11:36.123456789", "1650345096", "1650345096000",
    "2022-04-19T01:11:36-04:00",
])
def test_parse_ts_formats(raw):
    assert _parse_ts(raw).replace(microsecond=0).isoformat() == "2022-04-19T05:11:36+00:00"


@pytest.mark.parametrize("raw", ["0001-01-01T00:00:00+05:00", "9999-12-31T23:59:59-05:00", "04/19/2022", "", None, "x"])
def test_parse_ts_unparseable_returns_none(raw):
    assert _parse_ts(raw) is None


def test_identical_duplicate_asset_rows_still_resolve():
    joined, _ = merge({"findings": [F()], "assets": [A(), A()]})
    assert len(joined[0]["assets"]) == 1
    f = extract_finding_features(joined[0]["finding"], joined[0]["assets"], NOW)
    assert f["asset_name"] == "h1"
    joined, _ = merge({"findings": [F()], "assets": [A(), A(name="other")]})
    assert len(joined[0]["assets"]) == 2


def test_null_flags_stay_null():
    f = extract_finding_features(F(is_ignored=None), [], NOW)
    assert f["ignored"] is None
    _, sc, _ = build_payloads([], [A(is_active=None)], 7, NOW)
    assert sc[0]["isActive"] is None


REAL_FINDING = F(silk_id="nationwide____DedupedTask____022a", severity="LOW",
                 tool_severity='{"rapid7_insight_vm-1":"2"}', open_cves=None, last_seen=None,
                 asset_silk_id="nationwide____DedupedHostAsset____9fbd")
REAL_ASSET = A(silk_id="nationwide____DedupedHostAsset____9fbd", name=None,
               hostnames='["lapp000626","lapp000626"]', mac_addresses='["00:50:56:91:33:bf"]')


def test_real_rapid7_record_shape():
    p, fs, sc = profile([REAL_FINDING], [REAL_ASSET])
    f, a = finding_item(fs[0]), sc[0]
    assert f["viprSeverity"] == "low" and f.get("scannerSeverity") is None and f.get("severityChanged") is None
    assert "lastSeen" not in f and "cves" not in f and f["cveCount"] == 0
    assert f["slaBreached"] is True and f["assetName"] == "lapp000626" and a["name"] == "lapp000626"
    assert p["raw_tool_severity"]["keys"] == {"rapid7_insight_vm-1": 1}
    assert p["raw_tool_severity"]["vipr_severity_by_tool_value"] == {"rapid7_insight_vm-1": {"2": {"low": 1}}}
    assert p["raw_asset_resolution"] == {"name_from_hostname": 1}


@pytest.mark.parametrize("name", [None, "", "null", "NULL", " - "])
def test_null_like_asset_names_fall_back_to_hostname(name):
    _, fs, _ = profile([REAL_FINDING], [dict(REAL_ASSET, name=name)])
    assert fs[0]["assetName"] == "lapp000626"


def test_real_asset_name_wins_and_no_hostname_stays_null():
    _, fs, _ = profile([REAL_FINDING], [dict(REAL_ASSET, name="Server-1")])
    assert fs[0]["assetName"] == "Server-1"
    _, fs, _ = profile([REAL_FINDING], [dict(REAL_ASSET, hostnames="[]")])
    assert fs[0]["assetName"] is None


def test_crosstab_reveals_numeric_scale_across_findings():
    rows = [F(silk_id=str(i), severity=sev, tool_severity='{"rapid7_insight_vm-1":"%s"}' % val)
            for i, (sev, val) in enumerate([("LOW", "2"), ("LOW", "2"), ("MEDIUM", "3"), ("HIGH", "4"), ("HIGH", "4"),
                                            ("CRITICAL", "5"), ("LOW", "1")])]
    p, _, _ = profile(rows, [A()])
    assert p["raw_tool_severity"]["vipr_severity_by_tool_value"]["rapid7_insight_vm-1"] == {
        "2": {"low": 2}, "3": {"medium": 1}, "4": {"high": 2}, "5": {"critical": 1}, "1": {"low": 1}}


def test_tool_severities_carries_every_raw_rating():
    _, fs, _ = profile([REAL_FINDING, F(silk_id="2", tool_severity='{"tenable_io":"High","rapid7_insight_vm-1":"3"}'),
                        F(silk_id="3", tool_severity="{}")], [REAL_ASSET])
    got = {r["id"]: r.get("toolSeverities") for r in fs}
    assert got == {REAL_FINDING["silk_id"]: "rapid7_insight_vm-1=2", "2": "rapid7_insight_vm-1=3, tenable_io=High", "3": None}


@pytest.mark.parametrize("tool,scale,vipr,expected,direction", [
    ("rapid7", {"2": "medium"}, "LOW", "medium", "downgraded"),
    ("rapid7", {"2": "low"}, "LOW", "low", None),
    ("rapid7", {}, "LOW", None, None),
    ("rapid7", {"3": "high"}, "LOW", None, None),
    ("tenable", {"2": "medium"}, "LOW", None, None),
    ("RAPID7", {"2": "medium"}, "HIGH", "medium", "upgraded"),
])
def test_scanner_tool_and_scale_are_configurable(tool, scale, vipr, expected, direction):
    f = extract_finding_features(dict(REAL_FINDING, severity=vipr), [], NOW, tool, scale)
    assert f["scanner_severity"] == expected and f["severity_direction"] == direction
    assert f["tool_severities"] == "rapid7_insight_vm-1=2"


def test_cli_scanner_flags(tmp_path):
    d = tmp_path / "d"
    cli.main(["--local", "--local-data", str(d), "--output-dir", str(tmp_path / "o1")])
    out = tmp_path / "o2"
    rc = cli.main(["--local", "--local-data", str(d), "--output-dir", str(out), "--scanner-tool", "tenable",
                   "--scanner-severity-map", '{"high": "critical"}'])
    assert rc == 0
    f = flatten(json.load(open(out / "records.json")))["findings"]
    assert f["f-001"]["scannerSeverity"] == "critical" and f["f-001"]["toolSeverities"] == "tenable=high"
    for bad in ('not json', '[1,2]', '{"1": "urgent"}'):
        with pytest.raises(SystemExit) as e:
            cli.main(["--local", "--local-data", str(d), "--output-dir", str(out), "--scanner-severity-map", bad])
        assert e.value.code == 2
