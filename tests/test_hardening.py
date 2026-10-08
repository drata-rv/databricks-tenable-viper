import json
import os
import pathlib
import re
from unittest import mock

import pytest
import requests

from helpers import flatten
from vipr_drata import cli
from vipr_drata.db.drata_client import DrataClient
from vipr_drata.db.secrets import ConfigError, get_secret
from vipr_drata.profile import build_profile
from vipr_drata.transform import _int, asset_name, scanner_severity, tool_severities

ROOT = pathlib.Path(__file__).parent.parent


def local(tmp_path, *extra):
    return cli.main(["--local", "--local-data", str(tmp_path / "d"), "--output-dir", str(tmp_path / "o")] + list(extra))


def test_missing_databricks_config_is_a_clean_exit_2(monkeypatch, capsys):
    assert cli.main(["--dry-run", "--warehouse-id", "w"]) == 2
    assert "missing source table setting(s): VIPR_FINDINGS_TABLE, VIPR_ASSETS_TABLE" in capsys.readouterr().err
    monkeypatch.setenv("VIPR_FINDINGS_TABLE", "c.s.f")
    monkeypatch.setenv("VIPR_ASSETS_TABLE", "  ")
    assert cli.main(["--dry-run", "--warehouse-id", "w"]) == 2
    assert "VIPR_ASSETS_TABLE" in capsys.readouterr().err and "VIPR_FINDINGS_TABLE" not in capsys.readouterr().err
    monkeypatch.setenv("VIPR_ASSETS_TABLE", "c.s.a")
    assert cli.main(["--dry-run", "--warehouse-id", "w"]) == 2
    err = capsys.readouterr().err
    assert "error: Missing secret" in err and "Traceback" not in err


def test_local_dir_with_unusable_files_is_a_clean_exit_2(tmp_path, capsys):
    d = tmp_path / "d"
    d.mkdir()
    (d / "stray.json").write_text("[]")
    assert local(tmp_path) == 2
    assert "error:" in capsys.readouterr().err


def test_databricks_extraction_failure_is_exit_1_without_traceback(monkeypatch, capsys):
    monkeypatch.setenv("VIPR_FINDINGS_TABLE", "c.s.f")
    monkeypatch.setenv("VIPR_ASSETS_TABLE", "c.s.a")
    with mock.patch.object(cli, "get_client_for_env"), \
            mock.patch.object(cli, "extract_all", side_effect=RuntimeError("SQL failed: PERMISSION_DENIED")):
        assert cli.main(["--dry-run", "--warehouse-id", "w"]) == 1
    assert "Databricks extraction failed: RuntimeError: SQL failed" in capsys.readouterr().err


@pytest.mark.parametrize("name,value,ok", [("SCAN_STALE_DAYS", "", True), ("SCAN_STALE_DAYS", "  ", True),
                                           ("SCAN_STALE_DAYS", "3", True), ("SCAN_STALE_DAYS", "x", False),
                                           ("MAX_REJECT_RATIO", "", True), ("MAX_REJECT_RATIO", "abc", False)])
def test_numeric_env_values(monkeypatch, tmp_path, name, value, ok):
    monkeypatch.setenv(name, value)
    assert local(tmp_path) == (0 if ok else 2)


def test_secrets_are_stripped(monkeypatch):
    monkeypatch.setenv("DRATA_API_KEY", "good-key\n")
    assert get_secret("drata-api-key", env_var="DRATA_API_KEY") == "good-key"
    monkeypatch.setenv("DRATA_API_KEY", " \n")
    with pytest.raises(ConfigError):
        get_secret("drata-api-key", env_var="DRATA_API_KEY")


def test_invalid_header_is_permanent_and_never_echoes_the_key(tmp_path):
    secret = "good-key-SECRET"
    sess = mock.Mock()
    sess.post.side_effect = requests.exceptions.InvalidHeader("Invalid return character in header value: %r" % secret)
    c = DrataClient("http://x", secret, backoff=0, workers=1)
    c._build_session = lambda: sess
    ok, failed = c.upsert(1, 2, [{"id": "a"}, {"id": "b"}])
    assert ok == 0 and sess.post.call_count == 1
    assert all(f["error"] == "not sent: request rejected locally: InvalidHeader" or f["error"].startswith("request rejected")
               for f in failed)
    assert secret not in json.dumps(failed)


def test_generic_network_errors_report_type_only():
    sess = mock.Mock()
    sess.post.side_effect = requests.ConnectionError("HTTPSConnectionPool(host='x', port=443): Authorization: Bearer SECRET")
    c = DrataClient("http://x", "k", backoff=0, workers=1)
    c._build_session = lambda: sess
    _, failed = c.upsert(1, 2, [{"id": "a"}])
    assert failed == [{"id": "a", "error": "ConnectionError"}]


def test_stale_output_files_are_removed_and_abort_leaves_no_partial(monkeypatch, tmp_path):
    out = tmp_path / "o"
    out.mkdir()
    (out / "_failed.json").write_text("[]")
    (out / "partial.json").write_text("{}")
    assert local(tmp_path) == 0
    assert not (out / "_failed.json").exists() and not (out / "partial.json").exists()
    monkeypatch.setenv("DRATA_CONNECTION_ID", "1")
    monkeypatch.setenv("DRATA_RESOURCE_ID", "2")
    monkeypatch.setenv("DRATA_API_KEY", "k")
    with mock.patch.object(cli, "DrataClient") as DC:
        assert local(tmp_path, "--push", "--max-reject-ratio", "0.0001") == 2
    DC.assert_not_called()
    assert not (out / "partial.json").exists()


def test_dotenv_is_read_from_cwd(monkeypatch, tmp_path):
    work = tmp_path / "w"
    work.mkdir()
    (work / ".env").write_text("SCAN_STALE_DAYS=1\nOUTPUT_DIR=%s\n" % (tmp_path / "from_env_file"))
    monkeypatch.setattr(os, "environ", os.environ.copy())
    monkeypatch.delenv("VIPR_DRATA_NO_DOTENV")
    monkeypatch.chdir(work)
    assert cli.main(["--local", "--local-data", str(tmp_path / "d")]) == 0
    assert (tmp_path / "from_env_file" / "records.json").exists()


def test_scale_keys_are_case_insensitive_and_empty_tool_defaults():
    ts = '{"tenable_io":"High","other":"4"}'
    assert scanner_severity(ts, "tenable", {"high": "critical"}) == "critical"
    assert scanner_severity(ts, "tenable", {"HIGH": "critical"}) == "high"
    assert cli.parse_scale('{"High": "Critical"}') == {"high": "critical"}
    assert scanner_severity(ts, "", {}) == "high" and scanner_severity(ts, "  ", {}) == "high"
    assert scanner_severity('{"rapid7":"2"}', "", {"2": "low"}) is None


def test_scanner_tool_env_blank_falls_back_to_tenable(monkeypatch, tmp_path):
    monkeypatch.setenv("SCANNER_TOOL", "")
    assert local(tmp_path) == 0
    recs = flatten(json.load(open(tmp_path / "o" / "records.json")))["findings"]
    assert recs["f-001"]["scannerSeverity"] == "high"
    assert local(tmp_path, "--scanner-tool", "   ") == 0


def test_tool_severities_nulls_and_cap():
    assert tool_severities('{"t": null, "a": "x"}') == "a=x, t=null"
    big = json.dumps({"tool%d" % i: "v" for i in range(500)})
    out = tool_severities(big)
    assert len(out) == 1000 and out.endswith("...")


@pytest.mark.parametrize("raw", ["1e999", "inf", "-inf", "nan", "abc", None, ""])
def test_int_never_raises(raw):
    assert _int(raw) is None


def test_profile_and_records_agree_on_empty_names():
    for name in (None, "", "null", "-", " "):
        asset = {"silk_id": "a", "name": name, "hostnames": '["h1"]'}
        assert asset_name(asset) == "h1"
        tables = {"findings": [{"silk_id": "f", "asset_silk_id": "a"}], "assets": [asset]}
        p = build_profile(tables, [{"finding": tables["findings"][0], "assets": [asset]}], [], [])
        assert p["raw_asset_resolution"] == {"name_from_hostname": 1}


def test_bundle_passes_every_job_setting_the_code_reads():
    yml = (ROOT / "databricks.yml").read_text()
    env = (ROOT / ".env.example").read_text()
    passed = set(re.findall(r"^\s+- ([A-Z][A-Z0-9_]+)=\$\{var\.", yml, flags=re.M))
    assert {"SCANNER_TOOL", "SCANNER_SEVERITY_MAP", "DRATA_PUSH_MODE", "DRATA_CONNECTION_ID", "DRATA_RESOURCE_ID",
            "VIPR_FINDINGS_TABLE", "VIPR_ASSETS_TABLE", "TENABLE_ASSETS_TABLE", "FINDING_LANE_BUCKETS", "ASSET_BUCKETS",
            "CLOSED_LOOKBACK_DAYS", "MAX_SOURCE_AGE_DAYS", "MAX_RECORD_BYTES", "MIN_FINDINGS", "MIN_ASSETS",
            "SCAN_STALE_DAYS", "MAX_REJECT_RATIO", "DRATA_PROD"} <= passed
    assert all(re.search(r"^%s=" % k, env, flags=re.M) for k in passed)
    for var in re.findall(r"\$\{var\.(\w+)\}", yml):
        assert re.search(r"^  %s:\n" % var, yml, flags=re.M), var


def test_env_example_covers_every_env_var_the_code_reads():
    env = (ROOT / ".env.example").read_text()
    code = "\n".join(p.read_text() for p in (ROOT / "src").rglob("*.py"))
    read = set(re.findall(r'getenv\(\s*"([A-Z][A-Z0-9_]+)"', code))
    read |= {"DATABRICKS_%s_%s" % (k, w) for k in ("HOST", "TOKEN", "CLIENT_ID", "CLIENT_SECRET") for w in ("TEST", "PROD")}
    internal = {"VIPR_DRATA_NO_DOTENV", "DATABRICKS_RUNTIME_VERSION", "DATABRICKS_SECRET_SCOPE"}
    missing = sorted(k for k in read - internal if not re.search(r"^%s=" % k, env, flags=re.M))
    assert not missing, missing


def test_bundle_defaults_match_the_code_defaults():
    yml = (ROOT / "databricks.yml").read_text()
    default = lambda name: re.search(r"^  %s:\n    default: \"?([^\"\n]*)\"?$" % name, yml, flags=re.M).group(1)
    args = cli.build_parser().parse_args([])
    assert default("asset_buckets") == str(args.asset_buckets)
    assert default("closed_lookback_days") == str(args.closed_lookback_days)
    assert default("max_source_age_days") == str(args.max_source_age_days)
    assert default("max_record_bytes") == str(args.max_record_bytes)
    assert default("min_findings") == str(args.min_findings) and default("min_assets") == str(args.min_assets)
    assert default("scanner_tool") == args.scanner_tool and default("finding_lane_buckets") == args.finding_lane_buckets == ""
    assert default("push_mode") == "upsert" and args.push_mode is None
    assert default("scan_stale_days") == str(args.stale_days) and default("max_reject_ratio") == ""
    assert re.search(r"^      max_concurrent_runs: 1$", yml, flags=re.M)
    env = (ROOT / ".env.example").read_text()
    for key, value in (("ASSET_BUCKETS", args.asset_buckets), ("CLOSED_LOOKBACK_DAYS", args.closed_lookback_days),
                       ("MAX_SOURCE_AGE_DAYS", args.max_source_age_days), ("MAX_RECORD_BYTES", args.max_record_bytes),
                       ("MIN_FINDINGS", args.min_findings), ("MIN_ASSETS", args.min_assets), ("DRATA_PUSH_MODE", "upsert")):
        assert re.search(r"^%s=%s$" % (key, value), env, flags=re.M), key


def test_every_tunable_the_cli_reads_reaches_the_job():
    code = (ROOT / "src" / "vipr_drata" / "cli.py").read_text()
    read = set(re.findall(r'_env_(?:number|str)\(\s*"([A-Z][A-Z0-9_]+)"', code)) | set(re.findall(r'getenv\(\s*"([A-Z][A-Z0-9_]+)"', code))
    job_only_skipped = {"OUTPUT_DIR", "LOCAL_DATA_DIR", "LOCAL_ROWS", "DATABRICKS_WORKSPACE", "DATABRICKS_WAREHOUSE_ID", "DRATA_API_BASE",
                        "VIPR_DRATA_NO_DOTENV"}
    yml = (ROOT / "databricks.yml").read_text()
    passed = set(re.findall(r"^\s+- ([A-Z][A-Z0-9_]+)=\$\{var\.", yml, flags=re.M))
    assert not sorted(k for k in read - job_only_skipped - passed if not k.startswith("DRATA_API_KEY")), "not passed to the job"
