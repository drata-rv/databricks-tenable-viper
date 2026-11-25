import json
from unittest import mock

import pytest

from vipr_drata import cli
from vipr_drata.db import auth
from vipr_drata.db.access import classify
from vipr_drata.etl import extract

DENIED = "PERMISSION_DENIED: User daada051 does not have secret-scopes.secrets/get permission on scope vipr-drata-test"
NO_TABLE = "[TABLE_OR_VIEW_NOT_FOUND] The table or view `c`.`s`.`t` cannot be found"


@pytest.mark.parametrize("text,kind", [
    (DENIED, "denied"), ("Error: 403 Forbidden", "denied"), ("User does not have USE SCHEMA on schema c.s", "denied"),
    (NO_TABLE, "missing"), ("[SCHEMA_NOT_FOUND] schema x", "missing"), ("connection reset", "error")])
def test_classify(text, kind):
    assert classify(Exception(text)) == kind


def test_secret_scope_denied_falls_back_to_the_job_identity(monkeypatch, capsys):
    monkeypatch.setattr(auth, "get_secret", mock.Mock(side_effect=Exception(DENIED)))
    monkeypatch.setattr(auth, "on_databricks", lambda: True)
    with mock.patch("databricks.sdk.WorkspaceClient") as WC:
        assert auth.get_client_for_env("test") is WC.return_value
    WC.assert_called_once_with()
    assert "auth fallback source=job_identity reason=secret_scope_denied" in capsys.readouterr().err


def test_secret_errors_still_raise_off_databricks_and_when_not_a_permission_error(monkeypatch):
    monkeypatch.setattr(auth, "get_secret", mock.Mock(side_effect=Exception(DENIED)))
    monkeypatch.setattr(auth, "on_databricks", lambda: False)
    with pytest.raises(Exception, match="PERMISSION_DENIED"):
        auth.get_client_for_env("test")
    monkeypatch.setattr(auth, "get_secret", mock.Mock(side_effect=Exception("connection reset")))
    monkeypatch.setattr(auth, "on_databricks", lambda: True)
    with pytest.raises(Exception, match="connection reset"):
        auth.get_client_for_env("test")


def _tables(monkeypatch, failures):
    for k, v in (("VIPR_FINDINGS_TABLE", "c.s.f"), ("VIPR_ASSETS_TABLE", "c.s.a"), ("TENABLE_ASSETS_TABLE", "c.s.t")):
        monkeypatch.setenv(k, v)

    def run(client, warehouse, sql):
        for table, message in failures.items():
            if "FROM %s " % table in sql:
                raise Exception(message)
        return []

    monkeypatch.setattr(extract, "run_sql", run)


def test_optional_table_without_access_is_skipped(monkeypatch, capsys):
    _tables(monkeypatch, {"c.s.t": DENIED})
    assert sorted(extract.extract_all(None, "w")) == ["assets", "findings"]
    assert "extract table.skipped table=tenable_assets reason=denied" in capsys.readouterr().err


def test_every_unavailable_required_table_is_reported_in_one_run(monkeypatch, capsys):
    _tables(monkeypatch, {"c.s.f": DENIED, "c.s.a": NO_TABLE})
    with pytest.raises(RuntimeError, match="findings, assets"):
        extract.extract_all(None, "w")
    err = capsys.readouterr().err
    assert "table=findings reason=denied" in err and "table=assets reason=missing" in err


def test_optional_table_failing_for_another_reason_still_fails(monkeypatch):
    _tables(monkeypatch, {"c.s.t": "connection reset"})
    with pytest.raises(RuntimeError, match="tenable_assets"):
        extract.extract_all(None, "w")


def test_denied_drata_key_builds_the_records_and_skips_the_push(monkeypatch, tmp_path, capsys):
    from tests.test_guards import A1, _f
    monkeypatch.setenv("VIPR_FINDINGS_TABLE", "c.s.f")
    monkeypatch.setenv("VIPR_ASSETS_TABLE", "c.s.a")
    monkeypatch.setenv("DRATA_CONNECTION_ID", "1")
    monkeypatch.setenv("DRATA_RESOURCE_ID", "2")
    rows = lambda c, w, sql: [_f(open="true", closed_timestamp="")] if "FROM c.s.f" in sql else [A1]
    with mock.patch.object(cli, "get_client_for_env"), mock.patch("vipr_drata.etl.extract.run_sql", rows), \
            mock.patch.object(cli, "drata_api_key", side_effect=Exception(DENIED)), mock.patch.object(cli, "DrataClient") as DC:
        assert cli.main(["--warehouse-id", "w", "--output-dir", str(tmp_path)]) == 1
    DC.assert_not_called()
    assert json.load(open(tmp_path / "records.json"))[0]["findingCount"] == 1
    assert "drata push.skipped reason=api_key_denied records=" in capsys.readouterr().err
