import json
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest
import requests
from helpers import flatten
from rules import evaluate, failing_items

from vipr_drata.batching import bucket_of, build_records, finding_item, size_of
from vipr_drata.db.drata_client import DrataClient
from vipr_drata.db.secrets import ConfigError

NOW = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)


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
    kw.setdefault("finding_buckets", 8)
    kw.setdefault("asset_buckets", 4)
    return build_records(findings, assets, now=NOW, **kw)


def test_record_set_is_fixed_whatever_the_data():
    for findings, assets in (([], []), ([F(1)], [A(1)]), ([F(i) for i in range(500)], [A(i) for i in range(50)])):
        recs = build(findings, assets)
        assert [r["id"] for r in recs] == (["summary"] + ["findings-%03d" % i for i in range(8)]
                                           + ["assets-%03d" % i for i in range(4)])
        assert [r["recordType"] for r in recs] == ["summary"] + ["findingBatch"] * 8 + ["assetBatch"] * 4


def test_empty_buckets_are_still_submitted_with_empty_arrays():
    recs = build([F(1)], [])
    empty = [r for r in recs if r["recordType"] == "findingBatch" and r["itemCount"] == 0]
    assert len(empty) == 7 and all(r["findings"] == [] for r in empty)


def test_every_item_lands_in_exactly_one_stable_bucket():
    findings = [F(i) for i in range(300)]
    recs = build(findings, [])
    flat = flatten(recs)
    assert sorted(flat["findings"]) == sorted(f["id"] for f in findings)
    assert sum(r["itemCount"] for r in recs if r["recordType"] == "findingBatch") == 300
    for r in recs:
        if r["recordType"] == "findingBatch":
            assert all(bucket_of(i["id"], 8) == r["bucket"] for i in r["findings"]) and r["itemCount"] == len(r["findings"])
    assert [bucket_of(k, 8) for k in ("f00001", "f00002", "f00003")] == [2, 0, 6]
    assert bucket_of("abc", 1000003) == 891568578 % 1000003


def test_output_is_deterministic_regardless_of_input_order():
    findings = [F(i) for i in range(200)]
    a = json.dumps(build(findings, [A(i) for i in range(20)]), sort_keys=True)
    b = json.dumps(build(list(reversed(findings)), [A(i) for i in reversed(range(20))]), sort_keys=True)
    assert a == b


def test_changing_data_changes_only_the_affected_bucket():
    findings = [F(i) for i in range(400)]
    before = {r["id"]: r for r in build(findings, []) if r["recordType"] == "findingBatch"}
    changed = [dict(f, slaBreached=True) if f["id"] == "f00007" else f for f in findings]
    after = {r["id"]: r for r in build(changed, []) if r["recordType"] == "findingBatch"}
    diff = [k for k in before if before[k] != after[k]]
    assert diff == ["findings-%03d" % bucket_of("f00007", 8)]


def test_shrinking_data_blanks_buckets_instead_of_leaving_stale_records():
    big = {r["id"]: r for r in build([F(i) for i in range(400)], [])}
    small = {r["id"]: r for r in build([F(1)], [])}
    assert set(big) == set(small)
    assert sum(r["itemCount"] for r in small.values() if r["recordType"] == "findingBatch") == 1


def test_size_guard_names_the_setting_and_a_workable_value():
    findings = [F(i, displayId="x" * 400) for i in range(3000)]
    with pytest.raises(ConfigError) as e:
        build(findings, [], finding_buckets=2, max_record_bytes=500_000)
    assert "FINDING_BUCKETS" in str(e.value) and "raise" in str(e.value)
    needed = int(str(e.value).rsplit("at least ", 1)[1])
    recs = build(findings, [], finding_buckets=needed, max_record_bytes=500_000)
    assert max(size_of(r) for r in recs) <= 500_000
    with pytest.raises(ConfigError):
        build([], [A(i, name="y" * 600) for i in range(3000)], asset_buckets=1, max_record_bytes=500_000)


def test_bucket_count_validation():
    with pytest.raises(ConfigError):
        build([], [], finding_buckets=0)


def test_closed_lookback_only_drops_old_closed_findings():
    old = (NOW - timedelta(days=200)).isoformat()
    recent = (NOW - timedelta(days=5)).isoformat()
    findings = [F(1, open=False, closedAt=old), F(2, open=False, closedAt=recent), F(3, open=False),
                F(4, open=True, closedAt=old), F(5, open=None, closedAt=old)]
    recs = build(findings, [], closed_lookback_days=90)
    flat = flatten(recs)
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
    assert s["rejectedCount"] == 4 and s["findingBuckets"] == 8 and s["assetBuckets"] == 4


@pytest.mark.parametrize("source,expected_fresh,age", [
    (NOW - timedelta(days=1), True, 1), (NOW - timedelta(days=3), True, 3), (NOW - timedelta(days=4), False, 4),
    (NOW - timedelta(days=240), False, 240), (None, None, None)])
def test_freshness_fields(source, expected_fresh, age):
    s = build([], [], source_date=source, max_source_age_days=3)[0]
    assert s["sourceFresh"] is expected_fresh and s["sourceBatchAgeDays"] == age
    assert all(r["sourceBatchDate"] == s["sourceBatchDate"] for r in build([], [], source_date=source))


def test_items_are_compact_and_cves_capped():
    item = finding_item(F(1, cves=["CVE-%d" % i for i in range(60)], closedAt=None, scannerSeverity=None, slaBreached=None))
    assert len(item["cves"]) == 25 and item["cveCount"] == 60
    assert "closedAt" not in item and "scannerSeverity" not in item
    assert item["slaBreached"] is None and item["open"] is True
    assert "cves" not in finding_item(F(2, cves=[]))


def test_single_item_far_below_limit_at_realistic_size():
    item = finding_item(F(1, id="nationwide____DedupedTask____" + "a" * 40, cves=["CVE-2026-0001"] * 3,
                          assetName="lapp000626", toolSeverities="rapid7_insight_vm-1=2", firstSeen="2022-04-19T05:11:36+00:00"))
    assert size_of(item) < 700


def test_170k_scale_stays_within_limits():
    findings = [F(i, id="nationwide____DedupedTask____%040x" % i, assetId="nationwide____DedupedHostAsset____%040x" % (i % 20000),
                  toolSeverities="rapid7_insight_vm-1=2", assetName="lapp%06d" % (i % 20000), firstSeen="2022-04-19T05:11:36+00:00")
                for i in range(170_000)]
    recs = build(findings, [A(i, id="nationwide____DedupedHostAsset____%040x" % i) for i in range(20_000)],
                 finding_buckets=64, asset_buckets=16)
    assert len(recs) == 81 and max(size_of(r) for r in recs) < 4_000_000
    assert sum(r["itemCount"] for r in recs if r["recordType"] == "findingBatch") == 170_000


SLA_TEST = {"all": [{"fact": "findings", "operator": "all", "value": {"any": [
    {"fact": "open", "operator": "equal", "value": False},
    {"fact": "slaBreached", "operator": "equal", "value": False}]}}]}


def test_drata_style_sla_rule_gives_per_item_outcomes_inside_one_record():
    findings = [F(1), F(2, slaBreached=True), F(3, slaBreached=None), F(4, open=False, slaBreached=True), F(5)]
    flat = flatten(build(findings, [], finding_buckets=1))
    (batch,) = flat["batches"]["findingBatch"]
    assert evaluate(SLA_TEST, batch) is False
    assert [i["id"] for i in failing_items(SLA_TEST, batch, "findings")] == ["f00002", "f00003"]
    assert evaluate(SLA_TEST, {"findings": [F(1), F(4, open=False, slaBreached=True)]}) is True
    assert evaluate(SLA_TEST, {"findings": []}) is True


def test_freshness_rule_on_summary_record():
    rule = {"all": [{"fact": "sourceFresh", "operator": "equal", "value": True}]}
    assert evaluate(rule, build([], [], source_date=NOW - timedelta(days=1))[0]) is True
    assert evaluate(rule, build([], [], source_date=NOW - timedelta(days=30))[0]) is False
    assert evaluate(rule, build([], [])[0]) is False


def _client(sess):
    c = DrataClient("http://x", "k", backoff=0, workers=1)
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


def test_short_per_item_response_and_non_list_bodies():
    sess = mock.Mock()
    sess.post.return_value = _resp(200, [{"statusCode": 201}])
    ok, failed = _client(sess).upsert(1, 2, [{"id": "a"}, {"id": "b"}])
    assert ok == 1 and failed == [{"id": "b", "error": "no per-item result returned"}]
    sess.post.return_value = _resp(201, {"id": "a"})
    assert _client(sess).upsert(1, 2, [{"id": "a"}]) == (1, [])
    bad = mock.Mock(status_code=200, headers={}, text="")
    bad.json.side_effect = ValueError
    sess.post.return_value = bad
    assert _client(sess).upsert(1, 2, [{"id": "a"}]) == (1, [])


def test_large_records_are_sent_one_or_two_per_request_under_the_size_cap():
    sess = mock.Mock()
    sess.post.return_value = _resp(201, None)
    recs = [{"id": "r%d" % i, "findings": [{"id": "x" * 100}] * 9000} for i in range(10)]
    ok, failed = _client(sess).upsert(1, 2, recs)
    assert ok == 10 and not failed
    sizes = [len(json.dumps(c.kwargs["json"], separators=(",", ":"))) for c in sess.post.call_args_list]
    assert max(sizes) <= 4 * 1024 * 1024 and sess.post.call_count >= 3
