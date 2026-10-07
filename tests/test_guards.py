import json
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest
from helpers import flatten

from vipr_drata import cli
from vipr_drata.batching import MAX_BUCKETS, batch_time, build_records, finding_item, size_of
from vipr_drata.db.secrets import ConfigError

NOW = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)


def F(i, **kw):
    row = {"id": "f%05d" % i, "displayId": "S%d" % i, "viprSeverity": "low", "open": True, "hasTicket": True,
           "missingTicket": False, "slaBreached": False, "slaDate": "2026-12-01T00:00:00+00:00"}
    row.update(kw)
    return row


def local(tmp_path, *extra, rows=0):
    argv = ["--local", "--local-data", str(tmp_path / "d"), "--output-dir", str(tmp_path / "o")] + list(extra)
    return cli.main(argv + (["--local-rows", str(rows)] if rows else []))


def test_cli_auto_grows_in_session_mode_and_is_exact_in_upsert_mode(tmp_path, capsys):
    assert local(tmp_path, "--max-record-bytes", "150000", rows=20000) == 0
    recs = json.load(open(tmp_path / "o" / "records.json"))
    lanes = {r["severityLane"]: r["bucketCount"] for r in recs if r["recordType"] == "findingBatch"}
    assert max(lanes.values()) > 4 and recs[0]["assetBuckets"] > 4
    assert max(size_of(r) for r in recs) < 150_000
    assert "batches: critical=" in capsys.readouterr().out
    assert local(tmp_path, "--max-record-bytes", "150000", "--push-mode", "upsert", rows=20000) == 2
    err = capsys.readouterr().err
    assert "raise FINDING_LANE_BUCKETS[" in err or "raise ASSET_BUCKETS" in err


def test_grow_mode_message_does_not_suggest_an_impossible_bucket_count():
    findings = [F(i, cves=["C" * 200] * 25) for i in range(5)]
    with pytest.raises(ConfigError) as e:
        build_records(findings, [], now=NOW, max_record_bytes=3000, grow_buckets=True)
    assert "even after auto-sizing" in str(e.value) and "MAX_RECORD_BYTES" in str(e.value) and "raise FINDING_LANE" not in str(e.value)


def test_auto_growth_is_capped_at_the_bucket_limit():
    findings = [F(i, displayId="x" * 150) for i in range(3000)]
    with pytest.raises(ConfigError, match="low findings needs \\d+ batches \\(limit %d\\)" % MAX_BUCKETS):
        build_records(findings, [], now=NOW, max_record_bytes=2000, grow_buckets=True)


def test_closed_lookback_boundary_is_exclusive_of_the_cutoff():
    cutoff = NOW - timedelta(days=90)
    at, before = cutoff.isoformat(), (cutoff - timedelta(seconds=1)).isoformat()
    recs = build_records([F(1, open=False, closedAt=at), F(2, open=False, closedAt=before), F(3, open=False, closedAt="garbage")],
                         [], now=NOW, closed_lookback_days=90)
    assert sorted(flatten(recs)["findings"]) == ["f00001", "f00003"] and recs[0]["closedExcludedCount"] == 1


def test_items_keep_the_sla_date_and_cap_free_text():
    item = finding_item(F(1, displayId="d" * 500, assetName="a" * 500, toolSeverities="t" * 500, id="i" * 500))
    assert item["slaDate"] == "2026-12-01T00:00:00+00:00"
    assert all(len(item[k]) == 200 and item[k].endswith("...") for k in ("displayId", "assetName", "toolSeverities"))
    assert len(item["id"]) == 500


def test_freshness_considers_the_tenable_table():
    old = NOW - timedelta(days=30)
    s = build_records([], [], now=NOW, source_dates={"findings": NOW, "assets": NOW, "tenable_assets": old})[0]
    assert s["sourceFresh"] is False and s["tenableBatchDate"] == old.isoformat() and s["sourceBatchAgeDays"] == 30


def test_batch_time_survives_overflow_and_date_with_time_of_day():
    assert batch_time([{"__date": "2026-02-03", "__hour": "1e999"}]) == datetime(2026, 2, 3, tzinfo=timezone.utc)
    assert batch_time([{"__date": "2026-02-03 23:30:00", "__hour": "5"}]) == datetime(2026, 2, 3, 5, tzinfo=timezone.utc)


def _run(monkeypatch, tmp_path, findings, assets, *extra):
    monkeypatch.setenv("VIPR_FINDINGS_TABLE", "c.s.f")
    monkeypatch.setenv("VIPR_ASSETS_TABLE", "c.s.a")
    monkeypatch.setenv("DRATA_CONNECTION_ID", "1")
    monkeypatch.setenv("DRATA_RESOURCE_ID", "2")
    monkeypatch.setenv("DRATA_API_KEY", "k")
    rows = lambda c, w, sql: findings if "FROM c.s.f" in sql else assets
    with mock.patch.object(cli, "get_client_for_env"), mock.patch("vipr_drata.etl.extract.run_sql", rows), \
            mock.patch.object(cli, "DrataClient") as DC:
        DC.return_value.replace_via_session.return_value = (1, [], "complete")
        DC.return_value.upsert.return_value = (1, [])
        DC.return_value.unverified = 0
        rc = cli.main(["--warehouse-id", "w", "--output-dir", str(tmp_path)] + list(extra))
    return rc, DC


def _f(**kw):
    row = {"silk_id": "f1", "severity": "low", "tool_severity": "{}", "open": "false", "has_ticket": "true",
           "closed_timestamp": "2000-01-01 00:00:00", "asset_silk_id": "a1", "__date": "2026-10-01", "__hour": "1"}
    row.update(kw)
    return row


A1 = {"silk_id": "a1", "name": "h", "is_active": "true", "last_seen": "2026-10-01 00:00:00", "__date": "2026-10-01", "__hour": "1"}


def test_all_findings_older_than_the_lookback_cannot_wipe_the_dataset(monkeypatch, tmp_path, capsys):
    rc, DC = _run(monkeypatch, tmp_path, [_f()], [A1])
    assert rc == 2 and DC.return_value.replace_via_session.call_count == 0
    assert "ABORT: extracted too few findings" in capsys.readouterr().err
    assert json.load(open(tmp_path / "records.json"))[0]["closedExcludedCount"] == 1


def test_reject_ratio_boundary_and_validation(monkeypatch, tmp_path):
    ok = _f(closed_timestamp="", open="true")
    dup = [_f(silk_id="d", severity="a"), _f(silk_id="d", severity="b")]
    rc, _ = _run(monkeypatch, tmp_path, [ok] + dup, [A1], "--max-reject-ratio", "0.5")
    assert rc == 0
    rc, _ = _run(monkeypatch, tmp_path, [ok] + dup, [A1], "--max-reject-ratio", "0.49")
    assert rc == 2
    for bad in ("1.5", "-0.1", "nan"):
        with pytest.raises(SystemExit) as e:
            _run(monkeypatch, tmp_path, [ok], [A1], "--max-reject-ratio", bad)
        assert e.value.code == 2
    monkeypatch.setenv("MAX_REJECT_RATIO", "5")
    with pytest.raises(SystemExit):
        _run(monkeypatch, tmp_path, [ok], [A1])


def test_outputs_from_a_previous_run_are_removed_before_an_abort(monkeypatch, tmp_path):
    for name in ("records.json", "_profile.json", "_rejected.json", "_failed.json", "partial.json"):
        (tmp_path / name).write_text("{}")
    rc, _ = _run(monkeypatch, tmp_path, [_f()], [A1], "--max-record-bytes", "100000", "--finding-lane-buckets", '{"low": 1}',
                 "--push-mode", "upsert", "--min-findings", "5")
    assert rc == 2
    assert not (tmp_path / "partial.json").exists() and not (tmp_path / "_failed.json").exists()
    assert json.load(open(tmp_path / "records.json"))[0]["id"] == "summary"


@pytest.mark.parametrize("name,value,check", [
    ("LOCAL_DATA_DIR", "  ", lambda a: a.local_data == "local_data"),
    ("OUTPUT_DIR", "", lambda a: a.output_dir == "output"),
    ("DATABRICKS_WORKSPACE", " ", lambda a: a.workspace == "test"),
    ("DRATA_PROD", "", lambda a: a.drata_prod is False),
    ("DRATA_API_BASE", "", lambda a: cli._env_str("DRATA_API_BASE", "https://public-api.drata.com") == "https://public-api.drata.com"),
    ("DRATA_PUSH_MODE", "  ", lambda a: cli._env_str("DRATA_PUSH_MODE", "session") == "session")])
def test_blank_env_values_mean_the_default(monkeypatch, name, value, check):
    monkeypatch.setenv(name, value)
    assert check(cli.build_parser().parse_args([]))


@pytest.mark.parametrize("value,expected", [("true", True), ("TRUE", True), ("1", True), ("yes", True), ("on", True),
                                            ("false", False), ("0", False), ("no", False), ("off", False)])
def test_drata_prod_accepts_the_usual_spellings(monkeypatch, value, expected):
    monkeypatch.setenv("DRATA_PROD", value)
    assert cli.build_parser().parse_args([]).drata_prod is expected


def test_drata_prod_rejects_unrecognised_values_and_local_explains_it(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("DRATA_PROD", "enabled")
    assert cli.main(["--local", "--local-data", str(tmp_path / "d")]) == 2
    assert "DRATA_PROD must be true or false" in capsys.readouterr().err
    monkeypatch.setenv("DRATA_PROD", "true")
    with pytest.raises(SystemExit):
        cli.main(["--local", "--local-data", str(tmp_path / "d")])
    assert "unset DRATA_PROD" in capsys.readouterr().err


@pytest.mark.parametrize("flag,value", [("--closed-lookback-days", "99999999"), ("--max-source-age-days", "99999999"),
                                        ("--stale-days", "99999999"), ("--local-rows", "99999999"),
                                        ("--min-findings", "99999999999")])
def test_absurd_numbers_are_config_errors_not_tracebacks(tmp_path, flag, value):
    with pytest.raises(SystemExit) as e:
        local(tmp_path, flag, value)
    assert e.value.code == 2


def test_local_push_in_session_mode_warns_that_it_replaces_the_resource(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("DRATA_CONNECTION_ID", "1")
    monkeypatch.setenv("DRATA_RESOURCE_ID", "2")
    monkeypatch.setenv("DRATA_API_KEY", "k")
    with mock.patch.object(cli, "DrataClient") as DC:
        DC.return_value.replace_via_session.return_value = (1, [], "complete")
        DC.return_value.unverified = 0
        assert local(tmp_path, "--push") == 0
    assert "replaces the whole resource with synthetic data" in capsys.readouterr().err


def test_a_failed_complete_is_reported_as_failed_not_as_complete(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("DRATA_CONNECTION_ID", "1")
    monkeypatch.setenv("DRATA_RESOURCE_ID", "2")
    monkeypatch.setenv("DRATA_API_KEY", "k")
    failure = [{"id": None, "error": "session complete failed: HTTP 500"}]
    with mock.patch.object(cli, "DrataClient") as DC:
        DC.return_value.replace_via_session.return_value = (18, failure, "complete")
        DC.return_value.unverified = 0
        assert local(tmp_path, "--push") == 1
    assert "-> complete FAILED" in capsys.readouterr().out and (tmp_path / "o" / "_failed.json").exists()
