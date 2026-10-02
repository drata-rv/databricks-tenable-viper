import json
from unittest import mock

import pytest

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
    recs = {r["id"]: r for r in json.load(open(tmp_path / "records.json"))}
    f, a = recs["finding:f1"], recs["asset:a1"]
    assert f["recordType"] == "finding" and f["severityDirection"] == "downgraded" and f["slaBreached"] is False
    assert f["assetId"] == "asset:a1"
    assert a["recordType"] == "asset" and a["viprLastSeenStale"] is True and a["tenableMatch"] == "not_configured"


def test_push_sends_one_unified_batch_to_one_resource(monkeypatch, tmp_path, capsys):
    args = _env(monkeypatch, tmp_path)
    monkeypatch.setenv("DRATA_API_KEY", "sandbox-key")
    with mock.patch.object(cli, "get_client_for_env"), mock.patch("vipr_drata.etl.extract.run_sql", fake_run_sql), \
            mock.patch.object(cli, "DrataClient") as DC:
        DC.return_value.upsert.return_value = (1, [])
        assert cli.main(args) == 0
    assert DC.call_args.args[1] == "sandbox-key"
    (call,) = DC.return_value.upsert.call_args_list
    assert call.args[:2] == (CONN, RES)
    assert [r["id"] for r in call.args[2]] == ["finding:f1", "asset:a1"]
    assert "Drata tenant: sandbox | push mode: upsert" in capsys.readouterr().out


def test_prod_flag_uses_prod_key_and_never_sandbox(monkeypatch, tmp_path):
    args = _env(monkeypatch, tmp_path)
    monkeypatch.setenv("DRATA_API_KEY", "sandbox-key")
    with mock.patch.object(cli, "get_client_for_env"), mock.patch("vipr_drata.etl.extract.run_sql", fake_run_sql):
        with pytest.raises(RuntimeError):
            cli.main(args + ["--drata-prod"])
        monkeypatch.setenv("DRATA_API_KEY_PROD", "prod-key")
        with mock.patch.object(cli, "DrataClient") as DC:
            DC.return_value.upsert.return_value = (1, [])
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


def test_session_mode_refused_when_anything_rejected(monkeypatch, tmp_path):
    args = _env(monkeypatch, tmp_path)
    monkeypatch.setenv("DRATA_API_KEY", "k")
    bad = FINDINGS + [dict(FINDINGS[0], silk_id="")]
    with mock.patch.object(cli, "get_client_for_env"), \
            mock.patch("vipr_drata.etl.extract.run_sql", lambda c, w, sql: bad if "FROM c.s.t_vipr_all_findings" in sql else ASSETS), \
            mock.patch.object(cli.DrataClient, "replace_via_session", return_value=(2, [], "complete")) as sess:
        rc = cli.main(args + ["--push-mode", "session", "--max-reject-ratio", "0.9"])
    assert rc == 1
    sess.assert_not_called()


def test_session_mode_clean_run_replaces_everything_in_one_session(monkeypatch, tmp_path):
    args = _env(monkeypatch, tmp_path)
    monkeypatch.setenv("DRATA_API_KEY", "k")
    with mock.patch.object(cli, "get_client_for_env"), mock.patch("vipr_drata.etl.extract.run_sql", fake_run_sql), \
            mock.patch.object(cli.DrataClient, "replace_via_session", return_value=(2, [], "complete")) as sess:
        assert cli.main(args + ["--push-mode", "session"]) == 0
    (call,) = sess.call_args_list
    assert call.args[:2] == (CONN, RES) and len(call.args[2]) == 2


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
    recs = {r["id"]: r for r in json.load(open(out / "records.json"))}
    f = {k[len("finding:"):]: v for k, v in recs.items() if v["recordType"] == "finding"}
    a = {k[len("asset:"):]: v for k, v in recs.items() if v["recordType"] == "asset"}
    rej = json.load(open(out / "_rejected.json"))
    assert f["f-001"]["viprSeverity"] == "medium" and f["f-001"]["severityDirection"] == "downgraded"
    assert f["f-002"]["slaBreached"] and f["f-002"]["missingTicket"]
    assert f["f-005"]["severityChanged"] is None and f["f-006"]["assetName"] is None
    assert a["a-001"]["tenableMatch"] == "matched" and a["a-002"]["tenableMatch"] == "ambiguous"
    assert a["a-002"]["viprLastSeenStale"] is True and "a-004" not in a
    assert {(r["resource"], r["reason"]) for r in rej} == {
        ("findings", "missing silk_id"), ("assets", "conflicting duplicate asset id in latest batch")}


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
        DC.return_value.upsert.return_value = (1, [])
        assert cli.main(["--local", "--push", "--local-data", str(tmp_path / "d"), "--output-dir", str(tmp_path)]) == 0
    assert DC.call_args.args[1] == "sandbox-key"
    assert DC.return_value.upsert.call_count == 1
