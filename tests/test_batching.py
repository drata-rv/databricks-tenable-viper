import json
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest
import requests
from helpers import flatten, sent
from rules import evaluate, failing_items

from vipr_drata.batching import (DEFAULT_ASSET_BUCKETS, DEFAULT_LANE_BUCKETS, LANES, auto_buckets, batch_time, bucket_of, build_records, finding_item, lane_of,
                                 parse_lane_buckets, size_of)
from vipr_drata.db.drata_client import DrataClient
from vipr_drata.db.secrets import ConfigError

NOW = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)
SMALL = {"critical": 2, "high": 2, "medium": 3, "low": 3, "info": 1, "unknown": 1}


def F(i, **kw):
    row = {"id": "f%05d" % i, "displayId": "SILK-%d" % i, "viprSeverity": "low", "open": True, "hasTicket": True,
           "missingTicket": False, "slaBreached": False, "slaDate": "2026-12-01T00:00:00+00:00", "assetId": "a1"}
    row.update(kw)
    return row


def A(i, **kw):
    row = {"id": "a%04d" % i, "name": "h%d" % i, "isActive": True, "viprLastSeenStale": False, "tenableMatch": "none"}
    row.update(kw)
    return row


def build(findings, assets, **kw):
    kw.setdefault("lane_buckets", SMALL)
    kw.setdefault("asset_buckets", 4)
    kw.setdefault("source_dates", {"findings": NOW, "assets": NOW})
    return build_records(findings, assets, now=NOW, **kw)


def ids(recs):
    return [r["id"] for r in recs]


def expected_ids(lanes=SMALL, assets=4):
    return (["summary"] + ["findings-%s-%03d" % (lane, i) for lane in LANES for i in range(lanes[lane])]
            + ["assets-%03d" % i for i in range(assets)])


def test_record_set_is_fixed_whatever_the_data():
    for findings, assets in (([], []), ([F(1)], [A(1)]), ([F(i, viprSeverity=LANES[i % 6]) for i in range(500)], [A(i) for i in range(50)])):
        assert ids(build(findings, assets)) == expected_ids()
    assert sum(DEFAULT_LANE_BUCKETS.values()) == 13 and DEFAULT_ASSET_BUCKETS == 4
    assert len(build([], [], lane_buckets=None, asset_buckets=DEFAULT_ASSET_BUCKETS)) == 1 + 13 + 4 == 18


def test_empty_buckets_are_still_submitted_with_empty_arrays():
    recs = build([F(1)], [])
    empty = [r for r in recs if r["recordType"] == "findingBatch" and r["itemCount"] == 0]
    assert len(empty) == sum(SMALL.values()) - 1 and all(r["findings"] == [] for r in empty)


def test_findings_are_grouped_by_severity_lane():
    findings = [F(1, viprSeverity="critical"), F(2, viprSeverity="high"), F(3, viprSeverity="medium"),
                F(4, viprSeverity="low"), F(5, viprSeverity="info"), F(6, viprSeverity=None), F(7, viprSeverity="bogus")]
    recs = build(findings, [])
    for r in recs:
        if r["recordType"] == "findingBatch":
            assert all(lane_of(i) == r["severityLane"] for i in r["findings"])
            assert r["id"].startswith("findings-%s-" % r["severityLane"]) and r["bucketCount"] == SMALL[r["severityLane"]]
    lanes = {i["id"]: r["severityLane"] for r in recs if r["recordType"] == "findingBatch" for i in r["findings"]}
    assert lanes == {"f00001": "critical", "f00002": "high", "f00003": "medium", "f00004": "low", "f00005": "info",
                     "f00006": "unknown", "f00007": "unknown"}


def test_a_re_rated_finding_moves_lane_and_leaves_no_copy_behind():
    before = flatten(build([F(1, viprSeverity="low")], []))
    after = build([F(1, viprSeverity="critical")], [])
    assert ids(after) == expected_ids()
    holders = [r["id"] for r in after if r["recordType"] == "findingBatch" and any(i["id"] == "f00001" for i in r["findings"])]
    assert len(holders) == 1 and holders[0].startswith("findings-critical-")
    assert "f00001" in before["findings"]


def test_every_item_lands_in_exactly_one_stable_bucket():
    findings = [F(i, viprSeverity=LANES[i % 6]) for i in range(300)]
    recs = build(findings, [])
    flat = flatten(recs)
    assert sorted(flat["findings"]) == sorted(f["id"] for f in findings)
    assert sum(r["itemCount"] for r in recs if r["recordType"] == "findingBatch") == 300
    for r in recs:
        if r["recordType"] == "findingBatch":
            assert all(bucket_of(i["id"], r["bucketCount"]) == r["bucket"] for i in r["findings"])
            assert r["itemCount"] == len(r["findings"])
    assert [bucket_of(k, 8) for k in ("f00001", "f00002", "f00003")] == [2, 0, 6]
    assert bucket_of("abc", 1000003) == 891568578 % 1000003


def test_output_is_deterministic_regardless_of_input_order():
    findings = [F(i, viprSeverity=LANES[i % 6]) for i in range(200)]
    a = json.dumps(build(findings, [A(i) for i in range(20)]), sort_keys=True)
    b = json.dumps(build(list(reversed(findings)), [A(i) for i in reversed(range(20))]), sort_keys=True)
    assert a == b


def test_changing_data_changes_only_the_affected_record():
    findings = [F(i) for i in range(400)]
    before = {r["id"]: r for r in build(findings, [])}
    changed = [dict(f, slaBreached=True) if f["id"] == "f00007" else f for f in findings]
    after = {r["id"]: r for r in build(changed, [])}
    diff = [k for k in before if before[k] != after[k]]
    assert diff == ["summary", "findings-low-%03d" % bucket_of("f00007", SMALL["low"])]


def test_display_names_are_stable_and_unique():
    a = build([F(i) for i in range(10)], [A(1)])
    b = build([F(i) for i in range(500)], [A(i) for i in range(30)])
    assert [r["displayName"] for r in a] == [r["displayName"] for r in b]
    assert len({r["displayName"] for r in a}) == len(a)


def test_shrinking_data_blanks_buckets_instead_of_leaving_stale_records():
    big = build([F(i) for i in range(400)], [])
    small = build([F(1)], [])
    assert ids(big) == ids(small)
    assert sum(r["itemCount"] for r in small if r["recordType"] == "findingBatch") == 1


def test_size_guard_names_the_setting_and_a_workable_value():
    findings = [F(i, displayId="x" * 400) for i in range(3000)]
    with pytest.raises(ConfigError) as e:
        build(findings, [], lane_buckets=dict(SMALL, low=1), max_record_bytes=500_000)
    msg = str(e.value)
    assert "FINDING_LANE_BUCKETS[low]" in msg and "raise" in msg
    needed = int(msg.rsplit("at least ", 1)[1])
    recs = build(findings, [], lane_buckets=dict(SMALL, low=needed), max_record_bytes=500_000)
    assert max(size_of(r) for r in recs) <= 500_000
    with pytest.raises(ConfigError, match="ASSET_BUCKETS"):
        build([], [A(i, name="y" * 600) for i in range(3000)], asset_buckets=1, max_record_bytes=500_000)
    with pytest.raises(ConfigError, match="summary record"):
        build([], [], max_record_bytes=100)


def test_bucket_count_validation():
    with pytest.raises(ConfigError):
        build([], [], asset_buckets=0)
    with pytest.raises(ConfigError):
        build([], [], lane_buckets=dict(SMALL, high=0))


@pytest.mark.parametrize("raw,expected", [
    (None, DEFAULT_LANE_BUCKETS), ("", DEFAULT_LANE_BUCKETS), ("  ", DEFAULT_LANE_BUCKETS), ("{}", DEFAULT_LANE_BUCKETS),
    ('{"medium": 40}', dict(DEFAULT_LANE_BUCKETS, medium=40)),
    ('{"critical": 1, "unknown": 256}', dict(DEFAULT_LANE_BUCKETS, critical=1, unknown=256))])
def test_parse_lane_buckets_ok(raw, expected):
    assert parse_lane_buckets(raw) == expected


@pytest.mark.parametrize("raw", ["not json", "[1]", '{"urgent": 2}', '{"high": 0}', '{"high": 257}', '{"high": "8"}',
                                 '{"high": 2.5}', '{"high": true}', '{"high": -1}'])
def test_parse_lane_buckets_rejects(raw):
    with pytest.raises(ConfigError):
        parse_lane_buckets(raw)


def test_closed_lookback_only_drops_old_closed_findings():
    old = (NOW - timedelta(days=200)).isoformat()
    recent = (NOW - timedelta(days=5)).isoformat()
    findings = [F(1, open=False, closedAt=old), F(2, open=False, closedAt=recent), F(3, open=False),
                F(4, open=True, closedAt=old), F(5, open=None, closedAt=old)]
    flat = flatten(build(findings, [], closed_lookback_days=90))
    assert sorted(flat["findings"]) == ["f00002", "f00003", "f00004", "f00005"]
    assert flat["summary"]["closedExcludedCount"] == 1 and flat["summary"]["findingCount"] == 4
    assert len(flatten(build(findings, [], closed_lookback_days=100000))["findings"]) == 5


def test_summary_counts():
    findings = [F(1), F(2, slaBreached=True), F(3, slaBreached=None), F(4, missingTicket=True),
                F(5, missingTicket=None), F(6, open=False, slaBreached=True), F(7, severityChanged=True)]
    assets = [A(1, viprLastSeenStale=True), A(2, tenableScanStale=True, tenableMatch="matched"),
              A(3, tenableMatch="ambiguous"), A(4, tenableMatch="no_data")]
    s = build(findings, assets, rejected=4)[0]
    assert (s["findingCount"], s["openFindingCount"], s["openSlaBreachedCount"], s["openSlaUnknownCount"]) == (7, 6, 1, 1)
    assert (s["openMissingTicketCount"], s["openTicketUnknownCount"], s["severityChangedCount"]) == (1, 1, 1)
    assert (s["assetCount"], s["assetsViprStaleCount"], s["assetsTenableStaleCount"], s["assetsTenableUnmatchedCount"]) == (4, 1, 1, 2)
    assert s["rejectedCount"] == 4 and s["findingBuckets"] == sum(SMALL.values()) and s["assetBuckets"] == 4


def _fresh(dates, max_age=3):
    return build([], [], source_dates=dates, max_source_age_days=max_age)[0]


def test_freshness_uses_the_oldest_table_not_the_newest():
    s = _fresh({"findings": NOW - timedelta(days=10), "assets": NOW})
    assert s["sourceFresh"] is False and s["sourceBatchAgeDays"] == 10
    assert s["findingsBatchDate"] != s["assetsBatchDate"] and s["sourceBatchDate"] == s["findingsBatchDate"]
    s = _fresh({"findings": NOW, "assets": NOW - timedelta(days=10), "tenable_assets": NOW})
    assert s["sourceFresh"] is False and s["tenableBatchDate"] == NOW.isoformat()
    assert _fresh({"findings": NOW - timedelta(days=2), "assets": NOW - timedelta(days=1)})["sourceFresh"] is True
    assert _fresh({"findings": NOW - timedelta(days=3), "assets": NOW})["sourceFresh"] is True
    assert _fresh({"findings": NOW - timedelta(days=3, hours=1), "assets": NOW})["sourceFresh"] is False


@pytest.mark.parametrize("dates", [{}, {"findings": None, "assets": NOW}, {"findings": NOW, "assets": None}])
def test_missing_batch_date_means_unknown_not_fresh(dates):
    s = _fresh(dates)
    assert s["sourceFresh"] is None and s["sourceBatchAgeDays"] is None and s["sourceBatchDate"] is None


def test_batch_time_uses_date_and_hour_and_ignores_garbage():
    rows = [{"__date": "2026-02-03", "__hour": "5"}, {"__date": "2026-02-03", "__hour": "20"},
            {"__date": "2026-02-02", "__hour": "23"}, {"__date": "garbage", "__hour": "x"}, {"__date": None}]
    assert batch_time(rows) == datetime(2026, 2, 3, 20, tzinfo=timezone.utc)
    assert batch_time([{"__date": "2026-02-03 00:00:00", "__hour": "x"}]) == datetime(2026, 2, 3, tzinfo=timezone.utc)
    assert batch_time([{"__date": "2026-02-03", "__hour": "99"}]) == datetime(2026, 2, 3, 23, tzinfo=timezone.utc)
    assert batch_time([]) is None and batch_time([{"x": 1}]) is None


def test_items_are_compact_and_cves_capped():
    item = finding_item(F(1, cves=["CVE-%d" % i for i in range(60)], closedAt=None, scannerSeverity=None, slaBreached=None,
                          ignored=None, severityChanged=None, closedAfterSla=None))
    assert len(item["cves"]) == 25 and item["cveCount"] == 60
    assert "closedAt" not in item and "scannerSeverity" not in item
    for key in ("slaBreached", "ignored", "severityChanged", "closedAfterSla"):
        assert key in item and item[key] is None
    assert "cves" not in finding_item(F(2, cves=[]))


def test_single_item_far_below_limit_at_realistic_size():
    item = finding_item(F(1, id="nationwide____DedupedTask____" + "a" * 40, cves=["CVE-2026-0001"] * 3, assetName="lapp000626",
                          toolSeverities="rapid7_insight_vm-1=2", firstSeen="2022-04-19T05:11:36+00:00"))
    assert size_of(item) < 700


def test_170k_scale_stays_within_limits():
    findings = [F(i, id="nationwide____DedupedTask____%040x" % i, viprSeverity=LANES[i % 5], toolSeverities="rapid7_insight_vm-1=2",
                  assetId="nationwide____DedupedHostAsset____%040x" % (i % 20000), assetName="lapp%06d" % (i % 20000),
                  firstSeen="2022-04-19T05:11:36+00:00") for i in range(170_000)]
    recs = build(findings, [A(i, id="nationwide____DedupedHostAsset____%040x" % i) for i in range(20_000)],
                 lane_buckets=None, asset_buckets=4, grow_buckets=True)
    assert 14 <= len(recs) <= 120 and max(size_of(r) for r in recs) < 3_000_000
    assert sum(r["itemCount"] for r in recs if r["recordType"] == "findingBatch") == 170_000


SLA_TEST = {"all": [{"fact": "findings", "operator": "all", "value": {"any": [
    {"fact": "open", "operator": "equal", "value": False},
    {"fact": "slaBreached", "operator": "equal", "value": False}]}}]}
LANE_FILTER = {"all": [{"fact": "recordType", "operator": "equal", "value": "findingBatch"},
                       {"any": [{"fact": "severityLane", "operator": "equal", "value": "critical"},
                                {"fact": "severityLane", "operator": "equal", "value": "high"}]}]}


def test_drata_style_rules_score_lanes_and_expose_the_failing_items():
    findings = [F(1, viprSeverity="critical"), F(2, viprSeverity="critical", slaBreached=True),
                F(3, viprSeverity="high", slaBreached=None), F(4, viprSeverity="high", open=False, slaBreached=True),
                F(5, viprSeverity="low", slaBreached=True)]
    recs = build(findings, [A(1)], lane_buckets=dict(SMALL, critical=1, high=1, low=1))
    scoped = [r for r in recs if evaluate(LANE_FILTER, r)]
    assert sorted(ids(scoped)) == ["findings-critical-000", "findings-high-000"]
    verdict = {r["id"]: evaluate(SLA_TEST, r) for r in scoped}
    assert verdict == {"findings-critical-000": False, "findings-high-000": False}
    assert [i["id"] for i in failing_items(SLA_TEST, scoped[0], "findings")] == ["f00002"]
    low = next(r for r in recs if r["id"] == "findings-low-000")
    assert evaluate(SLA_TEST, low) is False and not evaluate(LANE_FILTER, low)
    assert evaluate(SLA_TEST, next(r for r in recs if r["id"] == "findings-medium-000")) is True


def test_freshness_rule_on_summary_record():
    rule = {"all": [{"fact": "sourceFresh", "operator": "equal", "value": True}]}
    assert evaluate(rule, _fresh({"findings": NOW, "assets": NOW})) is True
    assert evaluate(rule, _fresh({"findings": NOW - timedelta(days=30), "assets": NOW})) is False
    assert evaluate(rule, _fresh({})) is False


def _client(sess, **kw):
    c = DrataClient("http://x", "k", backoff=0, workers=1, **kw)
    c._build_session = lambda: sess
    return c


def _resp(code, body=None):
    r = mock.Mock(status_code=code, headers={}, text="")
    r.json.return_value = body
    return r


def test_per_item_errors_in_a_2xx_bulk_response_are_reported():
    sess = mock.Mock()
    sess.post.return_value = _resp(200, [{"statusCode": 201, "data": {}},
                                          {"statusCode": 400, "data": None, "error": {"message": "schema mismatch"}},
                                          {"statusCode": 200, "data": {}}])
    ok, failed = _client(sess).upsert(1, 2, [{"id": "a"}, {"id": "b"}, {"id": "c"}])
    assert ok == 2 and failed == [{"id": "b", "error": "item status 400: schema mismatch"}]


@pytest.mark.parametrize("key", ["data", "results", "items", "records"])
def test_wrapped_bulk_responses_are_unwrapped(key):
    sess = mock.Mock()
    sess.post.return_value = _resp(200, {key: [{"statusCode": 201}, {"statusCode": 400, "error": {"message": "bad"}}]})
    c = _client(sess)
    ok, failed = c.upsert(1, 2, [{"id": "a"}, {"id": "b"}])
    assert ok == 1 and failed == [{"id": "b", "error": "item status 400: bad"}] and c.unverified == 0


def test_unrecognised_bulk_bodies_are_counted_as_unverified():
    sess = mock.Mock()
    sess.post.return_value = _resp(200, {"ok": True})
    c = _client(sess)
    assert c.upsert(1, 2, [{"id": "a"}, {"id": "b"}]) == (2, []) and c.unverified == 1
    sess.post.return_value = _resp(201, {"id": "a"})
    c2 = _client(sess)
    assert c2.upsert(1, 2, [{"id": "a"}]) == (1, []) and c2.unverified == 0


def test_short_per_item_response_and_unparseable_bodies():
    sess = mock.Mock()
    sess.post.return_value = _resp(200, [{"statusCode": 201}])
    ok, failed = _client(sess).upsert(1, 2, [{"id": "a"}, {"id": "b"}])
    assert ok == 1 and failed == [{"id": "b", "error": "no per-item result returned"}]
    bad = mock.Mock(status_code=200, headers={}, text="")
    bad.json.side_effect = ValueError
    sess.post.return_value = bad
    assert _client(sess).upsert(1, 2, [{"id": "a"}]) == (1, [])


def test_fallback_resend_is_a_list_and_checks_per_item_status():
    sess = mock.Mock()
    sess.post.side_effect = [_resp(413), _resp(200, [{"statusCode": 201}]),
                             _resp(200, [{"statusCode": 400, "error": {"message": "too big"}}])]
    ok, failed = _client(sess).upsert(1, 2, [{"id": "a"}, {"id": "b"}])
    assert ok == 1 and failed == [{"id": "b", "error": "item status 400: too big"}]
    assert [sent(c)["data"] for c in sess.post.call_args_list[1:]] == [[{"id": "a"}], [{"id": "b"}]]


def test_wire_body_is_compact_and_the_guard_measures_the_same_bytes():
    sess = mock.Mock()
    sess.post.return_value = _resp(201, None)
    rec = {"id": "r", "findings": [{"id": "x" * 40, "open": True, "n": None}] * 50}
    _client(sess).upsert(1, 2, [rec])
    body = sess.post.call_args.kwargs["data"]
    assert len(body.encode()) == size_of({"data": [rec]}) and ", " not in body and ": " not in body
    assert size_of(rec) < len(body.encode()) <= size_of(rec) + 20


def test_large_records_are_packed_under_the_request_cap():
    sess = mock.Mock()
    sess.post.return_value = _resp(201, None)
    recs = [{"id": "r%d" % i, "findings": [{"id": "x" * 100}] * 9000} for i in range(10)]
    ok, failed = _client(sess).upsert(1, 2, recs)
    assert ok == 10 and not failed
    sizes = [len(c.kwargs["data"].encode()) for c in sess.post.call_args_list]
    assert max(sizes) <= 4 * 1024 * 1024 + 20 and sess.post.call_count >= 3


def _sid(delta):
    return "vipr-" + (datetime.now(timezone.utc) - delta).strftime("%Y%m%dT%H%M%S")


def _posted(sess):
    return [(c.args[0].rsplit("/sessions/", 1)[1] if "/sessions/" in c.args[0] else "records", sent(c))
            for c in sess.post.call_args_list]


def test_only_old_sessions_of_this_tool_are_cancelled_before_staging():
    old, recent = _sid(timedelta(days=1)), _sid(timedelta(minutes=10))
    sess = mock.Mock()
    sess.get.return_value = _resp(200, [{"sessionId": old}, {"id": recent}, {"sessionId": "someone-else"},
                                         {"sessionId": "vipr-garbage"}, {"sessionId": "mine", "status": "IN_PROGRESS"},
                                         {"sessionId": _sid(timedelta(days=3)), "status": "ACTIVE"}])
    sess.post.return_value = _resp(200, None)
    ok, failed, action = _client(sess).replace_via_session(1, 2, [{"id": "a"}], "mine")
    posted = _posted(sess)
    assert action == "complete" and sess.get.call_args.args[0].endswith("/sessions?status=IN_PROGRESS")
    assert posted[0] == ("%s/actions" % old, {"action": "cancel"})
    cancelled = [p for p, body in posted if body == {"action": "cancel"}]
    assert cancelled == ["%s/actions" % old]
    assert posted[-1] == ("mine/actions", {"action": "complete"})


def test_listing_is_retried_and_failures_never_block_the_push():
    sess = mock.Mock()
    sess.get.side_effect = [_resp(429), _resp(500), _resp(200, [])]
    sess.post.return_value = _resp(200, None)
    assert _client(sess).replace_via_session(1, 2, [{"id": "a"}], "s")[2] == "complete" and sess.get.call_count == 3
    for listing in (_resp(500), _resp(200, "junk"), _resp(200, {"nope": 1}), _resp(404)):
        sess = mock.Mock()
        sess.get.return_value = listing
        sess.post.return_value = _resp(200, None)
        assert _client(sess, max_errors=1, max_rate_limits=1).replace_via_session(1, 2, [{"id": "a"}], "s")[2] == "complete"
    sess = mock.Mock()
    sess.get.side_effect = requests.ConnectionError("x")
    sess.post.return_value = _resp(200, None)
    assert _client(sess).replace_via_session(1, 2, [{"id": "a"}], "s")[2] == "complete"


def test_a_failed_complete_cancels_its_own_session_and_explains_when_listing_failed():
    sess = mock.Mock()
    sess.get.return_value = _resp(500)
    sess.post.side_effect = [_resp(200)] + [_resp(409)] * 5
    ok, failed, action = _client(sess, max_errors=1, max_rate_limits=1).replace_via_session(1, 2, [{"id": "a"}], "s")
    assert action == "complete" and failed[0]["error"].startswith("session complete failed: HTTP 409")
    assert "could not be listed" in failed[1]["error"]
    assert _posted(sess)[-1] == ("s/actions", {"action": "cancel"})
    sess.post.side_effect = [_resp(200)] + [_resp(500)] * 8
    sess.get.return_value = _resp(200, [])
    ok, failed, action = _client(sess).replace_via_session(1, 2, [{"id": "a"}], "s")
    assert len(failed) == 1 and _posted(sess)[-1][1] == {"action": "cancel"}


def test_interrupt_during_the_final_action_still_cancels_but_never_after_a_successful_complete():
    sess = mock.Mock()
    sess.get.return_value = _resp(200, [])
    sess.post.side_effect = [_resp(200), KeyboardInterrupt, _resp(200)]
    with pytest.raises(KeyboardInterrupt):
        _client(sess).replace_via_session(1, 2, [{"id": "a"}], "s")
    assert [b for _, b in _posted(sess)][-1] == {"action": "cancel"}
    sess = mock.Mock()
    sess.get.return_value = _resp(200, [])
    sess.post.return_value = _resp(200, None)
    assert _client(sess).replace_via_session(1, 2, [{"id": "a"}], "s")[2] == "complete"
    assert [b for _, b in _posted(sess)].count({"action": "cancel"}) == 0


def test_persistent_rate_limiting_stops_the_remaining_batches_after_one_exhausts():
    sess = mock.Mock()
    sess.post.return_value = _resp(429)
    c = _client(sess, batch_size=1, max_rate_limits=2)
    ok, failed = c.upsert(1, 2, [{"id": str(i)} for i in range(10)])
    assert ok == 0 and len(failed) == 10 and sess.post.call_count == 3
    assert all("rate limited" in f["error"] for f in failed)


def test_sleeping_is_interruptible():
    import threading
    import time
    c = DrataClient("http://x", "k", workers=1)
    started = time.monotonic()
    threading.Timer(0.1, c._stop.set).start()
    c._sleep(30)
    assert time.monotonic() - started < 5


def test_in_flight_workers_stop_retrying_once_any_worker_gives_up():
    sess = mock.Mock()
    sess.post.return_value = _resp(200, None)
    c = _client(sess)
    c._fatal = "rate limited: retries exhausted"
    assert c._send("http://x/y", {"data": []}) == (False, "rate limited: retries exhausted", None)
    assert sess.post.call_count == 0
    assert c._send("http://x/y", {"action": "cancel"}, force=True)[0] is True and sess.post.call_count == 1
