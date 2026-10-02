import json
from unittest import mock

import pytest

from vipr_drata import cli

FINDINGS = [{"silk_id": "f1", "severity": "medium", "tool_severity": '{"tenable": "high"}', "open": "true",
             "has_ticket": "true", "sla_date": "2999-01-01 00:00:00", "asset_silk_id": "a1"}]
ASSETS = [{"silk_id": "a1", "name": "host1", "is_active": "true", "last_seen": "2000-01-01 00:00:00"}]


def fake_run_sql(client, wh, sql):
    assert "MAX(__date)" in sql  # latest-batch filter applied to every table
    assert "SELECT *" not in sql and "__raw" not in sql  # explicit columns only
    return FINDINGS if "FROM c.s.t_vipr_all_findings" in sql else ASSETS


def _env(monkeypatch, tmp_path):
    monkeypatch.setenv("VIPR_FINDINGS_TABLE", "c.s.t_vipr_all_findings")
    monkeypatch.setenv("VIPR_ASSETS_TABLE", "c.s.t_vipr_all_assets")
    for n in ("FINDINGS", "ASSETS"):
        monkeypatch.setenv("DRATA_%s_CONNECTION_ID" % n, "1")
        monkeypatch.setenv("DRATA_%s_RESOURCE_ID" % n, "2")
    return ["--warehouse-id", "w", "--output-dir", str(tmp_path)]


def test_dry_run_end_to_end(monkeypatch, tmp_path):
    args = _env(monkeypatch, tmp_path)
    with mock.patch.object(cli, "get_client_for_env"), mock.patch("vipr_drata.etl.extract.run_sql", fake_run_sql):
        assert cli.main(args + ["--dry-run"]) == 0
    f = json.load(open(tmp_path / "findings.json"))
    a = json.load(open(tmp_path / "asset_scan_coverage.json"))
    assert f[0]["severityDirection"] == "downgraded" and not f[0]["slaBreached"]
    assert a[0]["scanStale"] is True


def test_push_end_to_end(monkeypatch, tmp_path):
    args = _env(monkeypatch, tmp_path)
    monkeypatch.setenv("DRATA_API_KEY", "k")
    with mock.patch.object(cli, "get_client_for_env"), mock.patch("vipr_drata.etl.extract.run_sql", fake_run_sql), \
            mock.patch.object(cli.DrataClient, "upsert", return_value=(1, [])) as push:
        assert cli.main(args) == 0
    assert push.call_count == 2 and push.call_args.args[:2] == ("1", "2")
    assert push.call_args.args[2][0]["id"] == "a1"


def test_session_mode_failure_returns_nonzero(monkeypatch, tmp_path):
    args = _env(monkeypatch, tmp_path)
    monkeypatch.setenv("DRATA_API_KEY", "k")
    with mock.patch.object(cli, "get_client_for_env"), mock.patch("vipr_drata.etl.extract.run_sql", fake_run_sql), \
            mock.patch.object(cli.DrataClient, "replace_via_session",
                              return_value=(0, [{"id": "f1", "error": "x"}], "cancel")):
        assert cli.main(args + ["--push-mode", "session"]) == 1
    assert (tmp_path / "_failed_findings.json").exists()


def test_local_mode_runs_without_databricks(tmp_path):
    out = tmp_path / "out"
    with mock.patch.object(cli, "get_client_for_env") as gc, mock.patch.object(cli.DrataClient, "upsert") as up:
        assert cli.main(["--local", "--local-data", str(tmp_path / "data"), "--output-dir", str(out)]) == 0
    gc.assert_not_called()
    up.assert_not_called()  # --local never pushes unless --push
    f = {r["id"]: r for r in json.load(open(out / "findings.json"))}
    a = {r["id"]: r for r in json.load(open(out / "asset_scan_coverage.json"))}
    rej = json.load(open(out / "_rejected.json"))
    assert f["f-001"]["viprSeverity"] == "medium" and f["f-001"]["severityDirection"] == "downgraded"  # old batch ignored
    assert f["f-002"]["slaBreached"] and f["f-002"]["missingTicket"]
    assert f["f-005"]["severityChanged"] is None and f["f-006"]["assetName"] is None
    assert a["a-001"]["tenableMatch"] == "matched" and a["a-002"]["tenableMatch"] == "ambiguous"
    assert a["a-002"]["scanStale"] is True and "a-004" not in a
    assert {r["reason"] for r in rej} == {"missing silk_id", "duplicate asset id in latest batch"}


def test_local_rejects_prod_and_pushes_only_with_flag(monkeypatch, tmp_path):
    with pytest.raises(SystemExit):
        cli.main(["--local", "--drata-prod", "--local-data", str(tmp_path / "d"), "--output-dir", str(tmp_path)])
    for n in ("FINDINGS", "ASSETS"):
        monkeypatch.setenv("DRATA_%s_CONNECTION_ID" % n, "1")
        monkeypatch.setenv("DRATA_%s_RESOURCE_ID" % n, "2")
    monkeypatch.setenv("DRATA_API_KEY", "k")
    with mock.patch.object(cli.DrataClient, "upsert", return_value=(1, [])) as up:
        assert cli.main(["--local", "--push", "--local-data", str(tmp_path / "d"), "--output-dir", str(tmp_path)]) == 0
    assert up.call_count == 2
