from datetime import datetime, timezone
from unittest import mock

from vipr_drata.db.drata_client import DrataClient
from vipr_drata.db.queries import is_true, rows_to_records
from vipr_drata.transform import build_payloads, extract_finding_features

NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)


def finding(**kw):
    base = {"silk_id": "f1", "severity": "Medium", "tool_severity": '{"tenable": "High"}',
            "open": "true", "has_ticket": "false", "sla_date": "2026-09-01 00:00:00",
            "asset_silk_id": "a1"}
    base.update(kw)
    return base


def test_bool_string_coercion():
    assert is_true("true") and not is_true("false") and not is_true(None)


def test_null_cleanup():
    assert rows_to_records(["a"], [["null"]]) == [{"a": None}]


def test_severity_downgrade_and_sla():
    f = extract_finding_features(finding(), [{"silk_id": "a1", "name": "h"}], NOW)
    assert f["severity_changed"] and f["severity_direction"] == "downgraded"
    assert f["sla_breached"] and f["missing_ticket"] and f["asset_name"] == "h"


def test_undetermined_when_no_tenable():
    f = extract_finding_features(finding(tool_severity="{}"), [], NOW)
    assert f["severity_changed"] is None and not f["asset_resolved"]


def test_ambiguous_asset_unresolved():
    f = extract_finding_features(finding(), [{"name": "x"}, {"name": "y"}], NOW)
    assert f["asset_name"] is None


def test_rejects_missing_id():
    fs, sc, rej = build_payloads(
        [{"finding": finding(silk_id=None), "assets": []}],
        [{"silk_id": "a1", "last_seen": "2026-09-01 00:00:00", "is_active": "true"}], 7, NOW)
    assert not fs and len(rej) == 1 and sc[0]["scanStale"] is True


def test_client_retry_budgets():
    c = DrataClient("http://x", "k", "c", "/{connection_id}/{resource}", backoff=0)
    resp = lambda code: mock.Mock(status_code=code, headers={}, text="")
    sess = mock.Mock()
    sess.put.side_effect = [resp(429), resp(429), resp(500), resp(200)]
    c._build_session = lambda: sess
    assert c.push_one("r", {}) == (True, None)
    sess.put.side_effect = [resp(400)]
    assert c.push_one("r", {})[0] is False
