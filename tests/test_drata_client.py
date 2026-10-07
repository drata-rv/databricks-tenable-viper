from unittest import mock

import pytest
import requests

from helpers import sent
from vipr_drata.db import drata_client as dc
from vipr_drata.db.auth import drata_api_key
from vipr_drata.db.drata_client import DrataClient


def _resp(code, headers=None):
    return mock.Mock(status_code=code, headers=headers or {}, text="body")


def _client(sess, **kw):
    c = DrataClient("http://x", "k", backoff=0, workers=1, **kw)
    c._build_session = lambda: sess
    return c


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    sleeps = []
    monkeypatch.setattr(dc.time, "sleep", sleeps.append)
    return sleeps


def test_rate_limit_and_error_budgets_are_separate():
    s = mock.Mock()
    s.post.side_effect = [_resp(429)] * 10 + [_resp(500)] * 3 + [_resp(200)]
    assert _client(s)._post("u", {}) == (True, None)


def test_budget_exhaustion():
    s = mock.Mock()
    s.post.side_effect = [_resp(429)] * 11
    assert _client(s)._post("u", {}) == (False, "rate limited")
    s.post.side_effect = [_resp(500)] * 4
    assert _client(s)._post("u", {}) == (False, "HTTP 500")
    s.post.side_effect = [requests.ConnectionError("boom")] * 4
    ok, err = _client(s)._post("u", {})
    assert not ok and err == "ConnectionError"


def test_network_error_then_success():
    s = mock.Mock()
    s.post.side_effect = [requests.ConnectionError("x"), _resp(200)]
    assert _client(s)._post("u", {})[0] is True


@pytest.mark.parametrize("header,expected", [("7", 7.0), ("nan", 2.0), ("-5", 2.0), ("inf", 2.0),
                                             ("Wed, 21 Oct 2026 07:28:00 GMT", 2.0), ("99999", 120.0)])
def test_retry_after_is_validated_and_clamped(header, expected, no_sleep):
    s = mock.Mock()
    s.post.side_effect = [_resp(429, {"Retry-After": header}), _resp(200)]
    c = DrataClient("http://x", "k", backoff=2.0, workers=1)
    c._build_session = lambda: s
    assert c._post("u", {})[0] is True
    assert no_sleep == [expected]


def test_record_error_isolates_but_server_errors_do_not():
    s = mock.Mock()
    s.post.side_effect = [_resp(400), _resp(200), _resp(400)]
    ok, failed = _client(s)._push_batch("u", [{"id": "a"}, {"id": "b"}])
    assert ok == 1 and failed[0]["id"] == "b"
    s.reset_mock()
    s.post.side_effect = [_resp(500)] * 4
    ok, failed = _client(s)._push_batch("u", [{"id": "a"}, {"id": "b"}])
    assert ok == 0 and len(failed) == 2 and s.post.call_count == 4


def test_auth_error_is_fatal_and_stops_remaining_batches():
    s = mock.Mock()
    s.post.return_value = _resp(401)
    c = _client(s, batch_size=1)
    ok, failed = c.upsert(1, 2, [{"id": str(i)} for i in range(5)])
    assert ok == 0 and len(failed) == 5 and s.post.call_count == 1
    assert all("401" in f["error"] for f in failed)


def test_upsert_url_body_and_batching():
    s = mock.Mock()
    s.post.return_value = _resp(201)
    ok, failed = _client(s, batch_size=2).upsert(7, 9, [{"id": str(i)} for i in range(3)])
    assert ok == 3 and not failed and s.post.call_count == 2
    urls = {c.args[0] for c in s.post.call_args_list}
    assert urls == {"http://x/public/v2/custom-connections/7/resources/9/records"}
    assert [len(sent(c)["data"]) for c in s.post.call_args_list] == [2, 1]


def test_chunking_respects_byte_cap():
    batches = list(dc.chunk_records([{"id": "a" * 50}] * 10, batch_size=100, max_bytes=200))
    assert all(len(b) <= 3 for b in batches) and sum(map(len, batches)) == 10


def test_session_complete_flow_urls_and_bodies():
    s = mock.Mock()
    s.post.return_value = _resp(200)
    ok, failed, action = _client(s).replace_via_session(1, 2, [{"id": "a"}], "s-1")
    assert (ok, failed, action) == (1, [], "complete")
    calls = [(c.args[0], sent(c)) for c in s.post.call_args_list]
    base = "http://x/public/v2/custom-connections/1/resources/2/sessions/s-1"
    assert calls == [(base, {"data": [{"id": "a"}]}), (base + "/actions", {"action": "complete"})]


def test_session_cancels_on_failure_and_reports_action_failure():
    s = mock.Mock()
    s.post.side_effect = [_resp(400), _resp(200)]
    ok, failed, action = _client(s).replace_via_session(1, 2, [{"id": "a"}], "s-2")
    assert action == "cancel" and failed and sent(s.post.call_args) == {"action": "cancel"}
    s.post.side_effect = [_resp(200)] + [_resp(500)] * 4
    ok, failed, action = _client(s).replace_via_session(1, 2, [{"id": "a"}], "s-3")
    assert action == "complete" and "session complete failed" in failed[-1]["error"]


def test_session_empty_snapshot_refused_without_http():
    s = mock.Mock()
    ok, failed, action = _client(s).replace_via_session(1, 2, [], "s-4")
    assert action == "skipped" and failed and s.post.call_count == 0


def test_session_cancelled_if_staging_raises():
    c = _client(mock.Mock())
    c._push_all = mock.Mock(side_effect=RuntimeError("worker died"))
    c._post = mock.Mock(return_value=(True, None))
    with pytest.raises(RuntimeError):
        c.replace_via_session(1, 2, [{"id": "a"}], "s-5")
    assert c._post.call_args.args[1] == {"action": "cancel"}


def test_prod_key_never_falls_back_to_sandbox(monkeypatch):
    monkeypatch.setenv("DRATA_API_KEY", "sandbox-key")
    assert drata_api_key(False) == "sandbox-key"
    with pytest.raises(RuntimeError):
        drata_api_key(True)
    monkeypatch.setenv("DRATA_API_KEY_PROD", "prod-key")
    assert drata_api_key(True) == "prod-key"


def test_interrupt_stops_queued_batches_and_cancels_session_once():
    import threading
    started, calls = threading.Event(), []
    s = mock.Mock()

    def post(url, data, timeout):
        json = __import__("json").loads(data)
        calls.append(json)
        if "data" in json and not started.is_set():
            started.set()
            raise KeyboardInterrupt
        return _resp(200)

    s.post.side_effect = post
    c = _client(s, batch_size=1)
    with pytest.raises(KeyboardInterrupt):
        c.replace_via_session(1, 2, [{"id": str(i)} for i in range(200)], "s-9")
    assert sum(1 for x in calls if x == {"action": "cancel"}) == 1
    assert len(calls) < 20 and not any(x == {"action": "complete"} for x in calls)
