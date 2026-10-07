import json
from unittest import mock

import pytest

from helpers import flatten
from datetime import datetime, timezone

from vipr_drata import cli

FINDINGS = [{"silk_id": "f1", "severity": "medium", "tool_severity": '{"tenable": "high"}', "open": "true",
             "has_ticket": "true", "sla_date": "2999-01-01 00:00:00", "asset_silk_id": "a1"}]
ASSETS = [{"silk_id": "a1", "name": "host1", "is_active": "true", "last_seen": "2000-01-01 00:00:00"}]
CONN, RES = "11", "12"


def fake_run_sql(client, wh, sql):
    assert "SELECT *" not in sql and "__raw" not in sql
    assert "MAX(__date)" in sql
    return FINDINGS if "FROM c.s.t_vipr_all_findings" in sql else ASSETS


def _env(monkeypatch, tmp_path):
    monkeypatch.setenv("VIPR_FINDINGS_TABLE", "c.s.t_vipr_all_findings")
    monkeypatch.setenv("VIPR_ASSETS_TABLE", "c.s.t_vipr_all_assets")
    monkeypatch.setenv("DRATA_CONNECTION_ID", CONN)
    monkeypatch.setenv("DRATA_RESOURCE_ID", RES)
    return ["--warehouse-id", "w", "--output-dir", str(tmp_path)]


def _patched(**kw):
    stack = [mock.patch.object(cli, "get_client_for_env"), mock.patch("vipr_drata.etl.extract.run_sql", fake_run_sql)]
    return stack


def test_dry_run_end_to_end(monkeypatch, tmp_path):
    args = _env(monkeypatch, tmp_path)
    with mock.patch.object(cli, "get_client_for_env"), mock.patch("vipr_drata.etl.extract.run_sql", fake_run_sql):
        assert cli.main(args + ["--dry-run"]) == 0
    flat = flatten(json.load(open(tmp_path / "records.json")))
    f, a = flat["findings"]["f1"], flat["assets"]["a1"]
    assert f["severityDirection"] == "downgraded" and f["slaBreached"] is False and f["assetId"] == "a1"
    assert a["viprLastSeenStale"] is True and a["tenableMatch"] == "not_configured"
    assert flat["summary"]["openFindingCount"] == 1 and flat["summary"]["assetCount"] == 1


def _patched_run(monkeypatch, tmp_path, extra=(), upsert=False):
    args = _env(monkeypatch, tmp_path)
    monkeypatch.setenv("DRATA_API_KEY", "sandbox-key")
    with mock.patch.object(cli, "get_client_for_env"), mock.patch("vipr_drata.etl.extract.run_sql", fake_run_sql), \
            mock.patch.object(cli, "DrataClient") as DC:
        DC.return_value.upsert.return_value = (18, [])
        DC.return_value.replace_via_session.return_value = (18, [], "complete")
        DC.return_value.unverified = 0
        rc = cli.main(args + list(extra))
    return rc, DC


def test_push_defaults_to_one_atomic_session_with_the_fixed_record_set(monkeypatch, tmp_path, capsys):
    rc, DC = _patched_run(monkeypatch, tmp_path)
    assert rc == 0 and DC.call_args.args[1] == "sandbox-key"
    DC.return_value.upsert.assert_not_called()
    (call,) = DC.return_value.replace_via_session.call_args_list
    assert call.args[:2] == (CONN, RES)
    ids = [r["id"] for r in call.args[2]]
    assert ids[0] == "summary" and len(ids) == 1 + 13 + 4 and len(set(ids)) == len(ids)
    assert "findings-medium-003" in ids and "assets-003" in ids
    assert "Drata tenant: sandbox | push mode: session" in capsys.readouterr().out


def test_upsert_mode_sends_the_same_record_set_without_a_session(monkeypatch, tmp_path):
    rc, DC = _patched_run(monkeypatch, tmp_path, ["--push-mode", "upsert"])
    assert rc == 0
    DC.return_value.replace_via_session.assert_not_called()
    (call,) = DC.return_value.upsert.call_args_list
    assert len(call.args[2]) == 18


def test_push_mode_env_and_invalid_values(monkeypatch, tmp_path):
    monkeypatch.setenv("DRATA_PUSH_MODE", "upsert")
    rc, DC = _patched_run(monkeypatch, tmp_path)
    assert rc == 0 and DC.return_value.upsert.call_count == 1
    monkeypatch.setenv("DRATA_PUSH_MODE", "Session")
    with pytest.raises(SystemExit) as e:
        _patched_run(monkeypatch, tmp_path)
    assert e.value.code == 2


def test_unverified_bulk_responses_print_a_warning(monkeypatch, tmp_path, capsys):
    args = _env(monkeypatch, tmp_path)
    monkeypatch.setenv("DRATA_API_KEY", "k")
    with mock.patch.object(cli, "get_client_for_env"), mock.patch("vipr_drata.etl.extract.run_sql", fake_run_sql), \
            mock.patch.object(cli, "DrataClient") as DC:
        DC.return_value.replace_via_session.return_value = (18, [], "complete")
        DC.return_value.unverified = 3
        assert cli.main(args) == 0
    assert "3 bulk response(s) carried no per-item results" in capsys.readouterr().err


def test_prod_flag_uses_prod_key_and_never_sandbox(monkeypatch, tmp_path):
    args = _env(monkeypatch, tmp_path)
    monkeypatch.setenv("DRATA_API_KEY", "sandbox-key")
    with mock.patch.object(cli, "get_client_for_env"), mock.patch("vipr_drata.etl.extract.run_sql", fake_run_sql):
        assert cli.main(args + ["--drata-prod"]) == 2
        monkeypatch.setenv("DRATA_API_KEY_PROD", "prod-key")
        with mock.patch.object(cli, "DrataClient") as DC:
            DC.return_value.replace_via_session.return_value = (18, [], "complete")
            DC.return_value.unverified = 0
            assert cli.main(args + ["--drata-prod"]) == 0
    assert DC.call_args.args[1] == "prod-key"


def test_session_mode_failure_returns_nonzero(monkeypatch, tmp_path):
    args = _env(monkeypatch, tmp_path)
    monkeypatch.setenv("DRATA_API_KEY", "k")
    with mock.patch.object(cli, "get_client_for_env"), mock.patch("vipr_drata.etl.extract.run_sql", fake_run_sql), \
            mock.patch.object(cli.DrataClient, "replace_via_session",
                              return_value=(0, [{"id": "f1", "error": "x"}], "cancel")):
        assert cli.main(args + ["--push-mode", "session"]) == 1
    assert (tmp_path / "_failed.json").exists()


def test_rejected_items_do_not_block_the_session_replace(monkeypatch, tmp_path):
    args = _env(monkeypatch, tmp_path)
    monkeypatch.setenv("DRATA_API_KEY", "k")
    bad = FINDINGS + [dict(FINDINGS[0], silk_id="")]
    with mock.patch.object(cli, "get_client_for_env"), \
            mock.patch("vipr_drata.etl.extract.run_sql", lambda c, w, sql: bad if "FROM c.s.t_vipr_all_findings" in sql else ASSETS), \
            mock.patch.object(cli.DrataClient, "replace_via_session", return_value=(18, [], "complete")) as sess:
        assert cli.main(args + ["--max-reject-ratio", "0.9"]) == 0
    (call,) = sess.call_args_list
    assert call.args[2][0]["rejectedCount"] == 1


@pytest.mark.parametrize("which,flag", [("findings", "--min-findings"), ("assets", "--min-assets")])
def test_empty_source_aborts_before_any_push(monkeypatch, tmp_path, capsys, which, flag):
    args = _env(monkeypatch, tmp_path)
    monkeypatch.setenv("DRATA_API_KEY", "k")
    def rows(c, w, sql):
        is_findings = "FROM c.s.t_vipr_all_findings" in sql
        return [] if (is_findings == (which == "findings")) else (FINDINGS if is_findings else ASSETS)
    with mock.patch.object(cli, "get_client_for_env"), mock.patch("vipr_drata.etl.extract.run_sql", rows), \
            mock.patch.object(cli, "DrataClient") as DC:
        assert cli.main(args) == 2
        DC.assert_not_called()
        assert "ABORT: extracted too few %s" % which in capsys.readouterr().err
        assert cli.main(args + [flag, "0", "--dry-run"]) == 0
        assert cli.main(args + ["--dry-run"]) == 0
        assert "WARNING: extracted too few" in capsys.readouterr().err


def test_a_stale_findings_table_is_not_hidden_by_a_fresh_assets_table(monkeypatch, tmp_path):
    args = _env(monkeypatch, tmp_path)
    old = [dict(FINDINGS[0], __date="2020-01-01", __hour="3")]
    fresh = [dict(ASSETS[0], __date=datetime.now(timezone.utc).date().isoformat(), __hour="1")]
    with mock.patch.object(cli, "get_client_for_env"), \
            mock.patch("vipr_drata.etl.extract.run_sql", lambda c, w, sql: old if "FROM c.s.t_vipr_all_findings" in sql else fresh):
        assert cli.main(args + ["--dry-run"]) == 0
    s = flatten(json.load(open(tmp_path / "records.json")))["summary"]
    assert s["sourceFresh"] is False and s["findingsBatchDate"].startswith("2020-01-01T03") and s["sourceBatchAgeDays"] > 1000


@pytest.mark.parametrize("flags", [["--asset-buckets", "0"], ["--asset-buckets", "257"], ["--closed-lookback-days", "0"],
                                   ["--max-record-bytes", "5000000"], ["--max-record-bytes", "99999"],
                                   ["--max-source-age-days", "-1"], ["--min-findings", "-1"], ["--stale-days", "-1"],
                                   ["--finding-lane-buckets", "{\"high\": 0}"], ["--finding-lane-buckets", "x"]])
def test_invalid_sizing_settings_exit_2(monkeypatch, tmp_path, flags):
    args = _env(monkeypatch, tmp_path)
    with mock.patch.object(cli, "get_client_for_env"), mock.patch("vipr_drata.etl.extract.run_sql", fake_run_sql):
        try:
            code = cli.main(args + ["--dry-run"] + flags)
        except SystemExit as e:
            code = e.code
    assert code == 2


def test_sizing_settings_reach_the_records(monkeypatch, tmp_path):
    args = _env(monkeypatch, tmp_path)
    monkeypatch.setenv("ASSET_BUCKETS", "3")
    monkeypatch.setenv("FINDING_LANE_BUCKETS", '{"low": 2, "high": 1, "medium": 1, "critical": 1, "info": 1, "unknown": 1}')
    monkeypatch.setenv("MAX_SOURCE_AGE_DAYS", "100000")
    with mock.patch.object(cli, "get_client_for_env"), mock.patch("vipr_drata.etl.extract.run_sql", fake_run_sql):
        assert cli.main(args + ["--dry-run"]) == 0
    recs = json.load(open(tmp_path / "records.json"))
    assert [r["id"] for r in recs] == ["summary", "findings-critical-000", "findings-high-000", "findings-medium-000",
                                       "findings-low-000", "findings-low-001", "findings-info-000", "findings-unknown-000",
                                       "assets-000", "assets-001", "assets-002"]
    assert recs[0]["assetBuckets"] == 3 and recs[0]["sourceFresh"] is None
    monkeypatch.setenv("CLOSED_LOOKBACK_DAYS", "x")
    assert cli.main(args + ["--dry-run"]) == 2


def test_sigterm_cancels_through_the_interrupt_path(monkeypatch, tmp_path):
    import os
    import signal
    args = _env(monkeypatch, tmp_path)
    monkeypatch.setenv("DRATA_API_KEY", "k")
    def term(*a, **k):
        os.kill(os.getpid(), signal.SIGTERM)
    before = signal.getsignal(signal.SIGTERM)
    with mock.patch.object(cli, "get_client_for_env"), mock.patch("vipr_drata.etl.extract.run_sql", fake_run_sql), \
            mock.patch.object(cli.DrataClient, "replace_via_session", side_effect=term):
        with pytest.raises(KeyboardInterrupt):
            cli.main(args)
    assert signal.getsignal(signal.SIGTERM) == before


def test_reject_ratio_guard_aborts_before_push(monkeypatch, tmp_path):
    args = _env(monkeypatch, tmp_path)
    monkeypatch.setenv("DRATA_API_KEY", "k")
    bad = [dict(FINDINGS[0], silk_id="")] * 3 + FINDINGS
    with mock.patch.object(cli, "get_client_for_env"), \
            mock.patch("vipr_drata.etl.extract.run_sql", lambda c, w, sql: bad if "FROM c.s.t_vipr_all_findings" in sql else ASSETS), \
            mock.patch.object(cli, "DrataClient") as DC:
        assert cli.main(args) == 2
    DC.assert_not_called()


def test_prod_with_test_catalog_source_refused(monkeypatch, tmp_path):
    args = _env(monkeypatch, tmp_path)
    monkeypatch.setenv("VIPR_FINDINGS_TABLE", "si_test_catalog.s.t")
    with pytest.raises(SystemExit) as e:
        cli.main(args + ["--drata-prod"])
    assert e.value.code == 2


def test_bad_env_values_fail_loudly(monkeypatch, tmp_path):
    with pytest.raises(SystemExit):
        cli.main(["--local", "--env", "NOEQUALS", "--local-data", str(tmp_path / "d")])
    monkeypatch.setenv("DRATA_PUSH_MODE", "Session")
    with pytest.raises(SystemExit):
        cli.main(["--local", "--local-data", str(tmp_path / "d"), "--output-dir", str(tmp_path)])


def test_env_flag_forms_and_precedence(monkeypatch, tmp_path):
    monkeypatch.setenv("OUTPUT_DIR", "ignored")
    out = tmp_path / "o"
    rc = cli.main(["--local", "--local-data", str(tmp_path / "d"), "--env", "OUTPUT_DIR=" + str(out),
                   "--env=SCAN_STALE_DAYS=3"])
    assert rc == 0 and (out / "records.json").exists()
    import os
    assert os.environ["SCAN_STALE_DAYS"] == "3"


def test_run_exits_with_main_status(monkeypatch):
    monkeypatch.setattr(cli, "main", lambda: 1)
    with pytest.raises(SystemExit) as e:
        cli.run()
    assert e.value.code == 1


def test_local_mode_runs_without_databricks(tmp_path):
    out = tmp_path / "out"
    with mock.patch.object(cli, "get_client_for_env") as gc, mock.patch.object(cli.DrataClient, "upsert") as up:
        assert cli.main(["--local", "--local-data", str(tmp_path / "data"), "--output-dir", str(out)]) == 0
    gc.assert_not_called()
    up.assert_not_called()
    flat = flatten(json.load(open(out / "records.json")))
    f, a = flat["findings"], flat["assets"]
    rej = json.load(open(out / "_rejected.json"))
    assert f["f-001"]["viprSeverity"] == "medium" and f["f-001"]["severityDirection"] == "downgraded"
    assert f["f-002"]["slaBreached"] and f["f-002"]["missingTicket"]
    assert f["f-005"]["severityChanged"] is None and f["f-006"].get("assetName") is None
    assert a["a-001"]["tenableMatch"] == "matched" and a["a-002"]["tenableMatch"] == "ambiguous"
    assert a["a-002"]["viprLastSeenStale"] is True and "a-004" not in a
    assert {(r["resource"], r["reason"]) for r in rej} == {
        ("findings", "missing silk_id"), ("assets", "conflicting duplicate asset id in latest batch")}
    assert flat["summary"]["rejectedCount"] == 3 and flat["summary"]["sourceFresh"] is True
    lanes = {r["severityLane"] for r in flat["batches"]["findingBatch"] if r["itemCount"]}
    assert lanes == {"critical", "high", "medium", "low"}


def test_local_regenerates_when_dir_empty_and_rejects_prod(monkeypatch, tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    assert cli.main(["--local", "--local-data", str(d), "--output-dir", str(tmp_path / "o")]) == 0
    assert (d / "findings.csv").exists()
    with pytest.raises(SystemExit):
        cli.main(["--local", "--drata-prod", "--local-data", str(d), "--output-dir", str(tmp_path)])


def test_local_push_goes_to_sandbox_only(monkeypatch, tmp_path):
    monkeypatch.setenv("DRATA_CONNECTION_ID", CONN)
    monkeypatch.setenv("DRATA_RESOURCE_ID", RES)
    monkeypatch.setenv("DRATA_API_KEY", "sandbox-key")
    monkeypatch.setenv("DRATA_API_KEY_PROD", "prod-key")
    with mock.patch.object(cli, "DrataClient") as DC:
        DC.return_value.replace_via_session.return_value = (18, [], "complete")
        DC.return_value.unverified = 0
        assert cli.main(["--local", "--push", "--local-data", str(tmp_path / "d"), "--output-dir", str(tmp_path)]) == 0
    assert DC.call_args.args[1] == "sandbox-key"
    assert DC.return_value.replace_via_session.call_count == 1


def test_local_rows_generates_scale_data_in_its_own_directory(tmp_path, capsys):
    base = tmp_path / "ld"
    assert cli.main(["--local", "--local-data", str(base), "--output-dir", str(tmp_path / "o"), "--local-rows", "2000"]) == 0
    assert (base / "scale" / "findings.csv").exists() and not (base / "findings.csv").exists()
    recs = json.load(open(tmp_path / "o" / "records.json"))
    assert 18 <= len(recs) <= 40 and recs[0]["findingCount"] <= 2000 and recs[0]["assetCount"] == 250
    assert "records=%d" % len(recs) in capsys.readouterr().out
