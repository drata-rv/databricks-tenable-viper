import json
from unittest import mock

from vipr_drata import cli

FINDINGS = [{"silk_id": "f1", "severity": "medium", "tool_severity": '{"tenable": "high"}', "open": "true",
             "has_ticket": "true", "sla_date": "2999-01-01 00:00:00", "asset_silk_id": "a1"}]
ASSETS = [{"silk_id": "a1", "name": "host1", "is_active": "true", "last_seen": "2000-01-01 00:00:00"}]


def fake_run_sql(client, wh, sql):
    assert "MAX(__date)" in sql  # latest-batch filter applied to every table
    return FINDINGS if "findings" in sql else ASSETS


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
