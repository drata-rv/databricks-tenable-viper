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


@pytest.mark.parametrize("mode", ["session", "upsert"])
def test_cli_sizes_its_own_batches_in_either_push_mode(tmp_path, capsys, mode):
    assert local(tmp_path, "--max-record-bytes", "150000", "--push-mode", mode, rows=20000) == 0
    recs = json.load(open(tmp_path / "o" / "records.json"))
    lanes = {r["severityLane"]: r["bucketCount"] for r in recs if r["recordType"] == "findingBatch"}
    assert max(lanes.values()) > 4 and recs[0]["assetBuckets"] > 4
    assert max(size_of(r) for r in recs) < 150_000
    assert "batches: critical=" in capsys.readouterr().out


def test_an_old_env_with_upsert_and_default_sizes_no_longer_aborts_on_real_volume(monkeypatch, tmp_path):
    monkeypatch.setenv("DRATA_PUSH_MODE", "upsert")
    assert local(tmp_path, rows=60000) == 0
    recs = json.load(open(tmp_path / "o" / "records.json"))
    assert max(size_of(r) for r in recs) < 2_500_000 and recs[0]["findingCount"] > 40000


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
    ("DRATA_PUSH_MODE", "  ", lambda a: cli._env_str("DRATA_PUSH_MODE", "upsert") == "upsert")])
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


def _listing_client(pages):
    from vipr_drata.db.drata_client import DrataClient
    sess = mock.Mock()
    responses = [mock.Mock(status_code=200, json=lambda p=p: p) for p in pages]
    sess.get.side_effect = responses
    c = DrataClient("http://x", "k", backoff=0, workers=1)
    c._build_session = lambda: sess
    return c, sess


def test_list_records_reads_plain_lists_wrapped_pages_and_totals():
    c, sess = _listing_client([[{"id": "a"}, {"id": "b"}]])
    assert c.list_records(1, 2) == (["a", "b"], None)
    assert "limit=100&page=1" in sess.get.call_args.args[0]
    c, _ = _listing_client([{"data": [{"id": "a"}, {"data": {"id": "b"}}], "total": 2}])
    assert c.list_records(1, 2) == (["a", "b"], 2)
    page = [{"id": str(i)} for i in range(100)]
    c, sess = _listing_client([{"results": page, "count": 150}, {"results": [{"id": "x"}], "count": 150}])
    ids, total = c.list_records(1, 2)
    assert len(ids) == 101 and total == 150 and sess.get.call_count == 2


@pytest.mark.parametrize("body", ["junk", {"nope": 1}, None])
def test_list_records_returns_none_for_unrecognised_bodies(body):
    c, _ = _listing_client([body])
    assert c.list_records(1, 2) is None


def _push_with_listing(monkeypatch, tmp_path, listing):
    monkeypatch.setenv("DRATA_CONNECTION_ID", "27")
    monkeypatch.setenv("DRATA_RESOURCE_ID", "2")
    monkeypatch.setenv("DRATA_API_KEY", "k")
    with mock.patch.object(cli, "DrataClient") as DC:
        client = DC.return_value
        client.replace_via_session.return_value = (18, [], "complete")
        client.unverified = 0
        client.http_counts = {200: 1, 201: 2}
        client.list_records.side_effect = listing if isinstance(listing, Exception) else None
        if not isinstance(listing, Exception):
            client.list_records.return_value = listing
        return local(tmp_path, "--push")


def test_push_prints_the_target_http_counts_and_confirms_records_landed(monkeypatch, tmp_path, capsys):
    recs_ids = []
    assert _push_with_listing(monkeypatch, tmp_path, (["summary", "assets-000", "other"], 3)) == 0
    out = capsys.readouterr()
    assert "target: https://public-api.drata.com connection=27 resource=2" in out.out or "invalid.test" in out.out
    assert "connection=27 resource=2" in out.out and "drata http responses: {200: 1, 201: 2}" in out.out
    assert "verify: Drata lists 3 record(s) (total=3); 2 of our 18 record ids are present" in out.out
    assert "WARNING: none of the submitted" not in out.err


def test_push_warns_loudly_when_none_of_our_records_are_visible(monkeypatch, tmp_path, capsys):
    assert _push_with_listing(monkeypatch, tmp_path, ([], 0)) == 0
    err = capsys.readouterr().err
    assert "none of the submitted records are visible in Drata" in err and "DRATA_CONNECTION_ID" in err


def test_push_survives_an_unreadable_or_failing_readback(monkeypatch, tmp_path, capsys):
    assert _push_with_listing(monkeypatch, tmp_path, None) == 0
    assert "could not read the records back from Drata" in capsys.readouterr().err
    assert _push_with_listing(monkeypatch, tmp_path, RuntimeError("boom")) == 0
    assert "verify skipped: RuntimeError" in capsys.readouterr().err


def test_http_counts_are_recorded_per_response():
    from vipr_drata.db.drata_client import DrataClient
    sess = mock.Mock()
    sess.post.side_effect = [mock.Mock(status_code=429, headers={}, text=""), mock.Mock(status_code=201, headers={}, text="")]
    c = DrataClient("http://x", "k", backoff=0, workers=1)
    c._build_session = lambda: sess
    c._sleep = lambda s: None
    c.upsert(1, 2, [{"id": "a"}])
    assert c.http_counts == {201: 1, 429: 1}


def test_push_flags_old_per_finding_records_that_bury_the_new_ones(monkeypatch, tmp_path, capsys):
    old = ["asset:nationwide____DedupedHostAsset____f0cc07", "finding:nationwide____DedupedTask____022a"]
    assert _push_with_listing(monkeypatch, tmp_path, (old + ["summary"], 3)) == 0
    err = capsys.readouterr().err
    assert "old per-finding records (2+, e.g. asset:nationwide____DedupedHostAsset____f0cc07)" in err
    assert "NEW custom connection" in err
    assert _push_with_listing(monkeypatch, tmp_path, (["summary"], 1)) == 0
    assert "old per-finding records" not in capsys.readouterr().err


def test_cli_falls_back_to_upsert_when_sessions_do_not_hold_records(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("DRATA_CONNECTION_ID", "1")
    monkeypatch.setenv("DRATA_RESOURCE_ID", "2")
    monkeypatch.setenv("DRATA_API_KEY", "k")
    with mock.patch.object(cli, "DrataClient") as DC:
        client = DC.return_value
        client.replace_via_session.return_value = (0, [{"id": None, "error": "session complete failed: HTTP 422: no data records"}], "unusable")
        client.upsert.return_value = (18, [])
        client.unverified = 0
        client.http_counts = {200: 3}
        client.list_records.return_value = None
        assert local(tmp_path, "--push") == 0
    captured = capsys.readouterr()
    assert "falling back to upsert" in captured.err and "create a new custom connection" in captured.err
    assert client.upsert.call_count == 1 and "-> upsert fallback" in captured.out


def test_progress_lines_show_every_stage_and_quiet_removes_them(tmp_path, capsys):
    assert local(tmp_path) == 0
    out = capsys.readouterr().out
    for stage in ("vipr-drata ", "loaded findings=", "joining findings to assets", "derived ", "built ", "writing "):
        assert stage in out, stage
    assert out.count("[00:") >= 5
    assert local(tmp_path, "--quiet") == 0
    quiet = capsys.readouterr().out
    assert "[00:" not in quiet and "findings=" in quiet and "records=" in quiet


def test_progress_shows_retries_and_each_request(monkeypatch, capsys):
    from vipr_drata import progress
    from vipr_drata.db.drata_client import DrataClient
    progress.start()
    sess = mock.Mock()
    sess.post.side_effect = [mock.Mock(status_code=429, headers={"Retry-After": "7"}, text=""),
                             mock.Mock(status_code=200, headers={}, text='[{"statusCode":201}]', json=lambda: [{"statusCode": 201}])]
    c = DrataClient("http://x", "k", backoff=0, workers=1)
    c._build_session = lambda: sess
    c._sleep = lambda s: None
    c.upsert(1, 2, [{"id": "a"}])
    out = capsys.readouterr().out
    assert "rate limited (HTTP 429), waiting 7s, retry 1/10" in out
    assert "sending 1 records (upsert) in 1 request(s)" in out and "request 1/1: 1 record(s) a" in out
    assert "first Drata response: HTTP 200" in out


def test_readback_does_not_cry_wolf_when_it_only_saw_part_of_a_large_resource(monkeypatch, tmp_path, capsys):
    legacy = ["asset:old-%d" % i for i in range(500)]
    assert _push_with_listing(monkeypatch, tmp_path, (legacy, 190000)) == 0
    err = capsys.readouterr().err
    assert "checked only the first 500 of 190000 records" in err and "WARNING: none of the submitted" not in err
    assert "old per-finding records (500+" in err
