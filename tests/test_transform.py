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


def _resp(code, headers=None):
    return mock.Mock(status_code=code, headers=headers or {}, text="")


def _client(sess, **kw):
    c = DrataClient("http://x", "k", backoff=0, **kw)
    c._build_session = lambda: sess
    return c


def test_client_retry_budgets():
    sess = mock.Mock()
    c = _client(sess)
    sess.post.side_effect = [_resp(429), _resp(429), _resp(500), _resp(200)]
    assert c._post("u", {}) == (True, None)
    sess.post.side_effect = [_resp(400)]
    assert c._post("u", {})[0] is False


def test_batch_400_isolates_bad_record():
    sess = mock.Mock()
    sess.post.side_effect = [_resp(400), _resp(200), _resp(400)]  # batch, rec a ok, rec b bad
    ok, failed = _client(sess)._push_batch("u", [{"id": "a"}, {"id": "b"}])
    assert ok == 1 and failed[0]["id"] == "b"


def test_upsert_url_and_body():
    sess = mock.Mock()
    sess.post.return_value = _resp(201)
    ok, failed = _client(sess, batch_size=2).upsert(7, 9, [{"id": str(i)} for i in range(3)])
    assert ok == 3 and not failed and sess.post.call_count == 2
    assert sess.post.call_args.args[0] == "http://x/public/v2/custom-connections/7/resources/9/records"
    assert "data" in sess.post.call_args.kwargs["json"]


def test_session_completes_only_when_clean():
    sess = mock.Mock()
    sess.post.return_value = _resp(200)
    ok, failed, action = _client(sess).replace_via_session(1, 2, [{"id": "a"}], "s-1")
    assert action == "complete" and sess.post.call_args.kwargs["json"] == {"action": "complete"}
    sess.post.side_effect = [_resp(400), _resp(200)]  # single-record batch fails, then cancel
    ok, failed, action = _client(sess).replace_via_session(1, 2, [{"id": "a"}], "s-2")
    assert action == "cancel" and failed
