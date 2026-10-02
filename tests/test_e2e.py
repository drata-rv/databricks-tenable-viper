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
    monkeypatch.setenv("DRATA_CONNECTION_ID", "1")
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
            mock.patch.object(cli.DrataClient, "push_all", return_value=(1, [])) as push:
        assert cli.main(args) == 0
    assert [c.args[0] for c in push.call_args_list] == ["vulnerability_findings", "asset_scan_coverage"]
