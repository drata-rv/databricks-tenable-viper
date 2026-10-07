import json
import math
import zlib
from datetime import timedelta

from .db.secrets import ConfigError
from .transform import _iso, _parse_ts

LANES = ("critical", "high", "medium", "low", "info", "unknown")
DEFAULT_LANE_BUCKETS = {"critical": 1, "high": 2, "medium": 4, "low": 4, "info": 1, "unknown": 1}
DEFAULT_ASSET_BUCKETS = 4
MAX_BUCKETS = 256
MAX_RECORD_BYTES_LIMIT = 4_500_000
TRISTATE = ("open", "ignored", "hasTicket", "missingTicket", "slaBreached", "severityChanged", "closedAfterSla",
            "isActive", "viprLastSeenStale", "tenableScanStale")
CVE_CAP = 25
FINDING_KEYS = ("id", "displayId", "viprSeverity", "scannerSeverity", "severityChanged", "severityDirection",
                "toolSeverities", "open", "ignored", "hasTicket", "missingTicket", "slaDate", "slaBreached",
                "closedAfterSla", "firstSeen", "closedAt", "assetId", "assetName", "cves", "cveCount")
ASSET_KEYS = ("id", "name", "assetType", "isActive", "lastSeen", "daysSinceSeen", "viprLastSeenStale",
              "openFindingsCount", "tenableMatch", "tenableLastScan", "tenableDaysSinceScan", "tenableScanStale",
              "tenableLastAuthenticatedScan")


def bucket_of(key, buckets):
    return zlib.crc32(str(key).encode("utf-8")) % buckets


def lane_of(item):
    sev = item.get("viprSeverity")
    return sev if sev in LANES[:-1] else "unknown"


def parse_lane_buckets(raw):
    out = dict(DEFAULT_LANE_BUCKETS)
    if raw is None or not str(raw).strip():
        return out
    try:
        given = json.loads(raw)
    except ValueError:
        given = None
    if not isinstance(given, dict) or any(k not in LANES for k in given):
        raise ConfigError("FINDING_LANE_BUCKETS must be a JSON object with keys from %s" % ", ".join(LANES))
    for lane, n in given.items():
        if isinstance(n, bool) or not isinstance(n, int) or not 1 <= n <= MAX_BUCKETS:
            raise ConfigError("FINDING_LANE_BUCKETS[%s] must be an integer from 1 to %d" % (lane, MAX_BUCKETS))
        out[lane] = n
    return out


def compact(item, keys):
    return {k: item[k] for k in keys if k in item and (k in TRISTATE or item[k] not in (None, []))}


def finding_item(f):
    item = dict(f)
    cves = item.get("cves") or []
    item["cveCount"] = len(cves)
    item["cves"] = cves[:CVE_CAP]
    return compact(item, FINDING_KEYS)


def asset_item(a):
    return compact(a, ASSET_KEYS)


def size_of(record):
    return len(json.dumps(record, separators=(",", ":"), default=str).encode("utf-8"))


def batch_time(rows):
    best = None
    for r in rows:
        d = _parse_ts(r.get("__date"))
        if d is None:
            continue
        try:
            hour = min(max(int(float(r.get("__hour") or 0)), 0), 23)
        except ValueError:
            hour = 0
        t = d + timedelta(hours=hour)
        best = t if best is None or t > best else best
    return best


def _count(items, key):
    return sum(1 for i in items if i.get(key) is True)


def _summary(findings, assets, *, now, source_dates, max_source_age_days, lane_buckets, asset_buckets,
             closed_excluded, rejected):
    open_f = [f for f in findings if f.get("open") is True]
    dates = list(source_dates.values())
    oldest = None if not dates or any(d is None for d in dates) else min(dates)
    fresh = None if oldest is None else (now - oldest) <= timedelta(days=max_source_age_days)
    return {
        "id": "summary", "recordType": "summary", "displayName": "Vipr vulnerability evidence summary",
        "generatedAt": _iso(now), "sourceBatchDate": _iso(oldest),
        "findingsBatchDate": _iso(source_dates.get("findings")), "assetsBatchDate": _iso(source_dates.get("assets")),
        "tenableBatchDate": _iso(source_dates.get("tenable_assets")),
        "sourceBatchAgeDays": None if oldest is None else (now - oldest).days, "sourceFresh": fresh,
        "findingBuckets": sum(lane_buckets.values()), "assetBuckets": asset_buckets,
        "findingCount": len(findings), "openFindingCount": len(open_f),
        "openSlaBreachedCount": _count(open_f, "slaBreached"),
        "openSlaUnknownCount": sum(1 for f in open_f if f.get("slaBreached") is None),
        "openMissingTicketCount": _count(open_f, "missingTicket"),
        "openTicketUnknownCount": sum(1 for f in open_f if f.get("missingTicket") is None),
        "severityChangedCount": _count(findings, "severityChanged"),
        "closedExcludedCount": closed_excluded, "rejectedCount": rejected,
        "assetCount": len(assets), "assetsViprStaleCount": _count(assets, "viprLastSeenStale"),
        "assetsTenableStaleCount": _count(assets, "tenableScanStale"),
        "assetsTenableUnmatchedCount": sum(1 for a in assets if a.get("tenableMatch") in ("none", "ambiguous")),
    }


def auto_buckets(items, minimum, target_bytes):
    need = max(1, math.ceil(sum(size_of(i) + 1 for i in items) / target_bytes))
    n = 1
    while n < need:
        n *= 2
    return max(minimum, n)


def _group(items, buckets):
    groups = [[] for _ in range(buckets)]
    for it in items:
        groups[bucket_of(it["id"], buckets)].append(it)
    for grp in groups:
        grp.sort(key=lambda x: x["id"])
    return groups


def build_records(findings, assets, *, now, lane_buckets=None, asset_buckets=DEFAULT_ASSET_BUCKETS,
                  closed_lookback_days=90, max_source_age_days=3, max_record_bytes=4_000_000, source_dates=None,
                  rejected=0, grow_buckets=False):
    lane_buckets = dict(lane_buckets or DEFAULT_LANE_BUCKETS)
    if asset_buckets < 1 or any(n < 1 for n in lane_buckets.values()):
        raise ConfigError("bucket counts must be >= 1")
    cutoff = now - timedelta(days=closed_lookback_days)
    kept, excluded = [], 0
    for f in findings:
        closed = _parse_ts(f.get("closedAt"))
        if f.get("open") is False and closed is not None and closed < cutoff:
            excluded += 1
        else:
            kept.append(finding_item(f))
    asset_items = [asset_item(a) for a in assets]
    by_lane = {lane: [] for lane in LANES}
    for it in kept:
        by_lane[lane_of(it)].append(it)
    if grow_buckets:
        target = max_record_bytes // 2
        lane_buckets = {lane: auto_buckets(by_lane[lane], lane_buckets.get(lane, 1), target) for lane in LANES}
        asset_buckets = auto_buckets(asset_items, asset_buckets, target)
    records = [_summary(kept, asset_items, now=now, source_dates=source_dates or {},
                        max_source_age_days=max_source_age_days, lane_buckets=lane_buckets,
                        asset_buckets=asset_buckets, closed_excluded=excluded, rejected=rejected)]
    for lane in LANES:
        n = lane_buckets.get(lane, DEFAULT_LANE_BUCKETS[lane])
        for i, grp in enumerate(_group(by_lane[lane], n)):
            records.append({
                "id": "findings-%s-%03d" % (lane, i), "recordType": "findingBatch", "severityLane": lane,
                "displayName": "Vipr %s findings batch %d of %d" % (lane, i + 1, n),
                "generatedAt": _iso(now), "sourceBatchDate": records[0]["sourceBatchDate"],
                "bucket": i, "bucketCount": n, "itemCount": len(grp), "findings": grp})
    for i, grp in enumerate(_group(asset_items, asset_buckets)):
        records.append({
            "id": "assets-%03d" % i, "recordType": "assetBatch",
            "displayName": "Vipr assets batch %d of %d" % (i + 1, asset_buckets),
            "generatedAt": _iso(now), "sourceBatchDate": records[0]["sourceBatchDate"],
            "bucket": i, "bucketCount": asset_buckets, "itemCount": len(grp), "assets": grp})
    for r in records:
        size = size_of(r)
        if size > max_record_bytes:
            current = r.get("bucketCount")
            if current is None:
                raise ConfigError("summary record is %.1f MB: raise MAX_RECORD_BYTES" % (size / 1e6))
            target = ("FINDING_LANE_BUCKETS[%s]" % r["severityLane"]) if r["recordType"] == "findingBatch" else "ASSET_BUCKETS"
            need = math.ceil(current * size / (max_record_bytes * 0.6))
            raise ConfigError("record %s is %.1f MB (limit %.1f MB): raise %s from %d to at least %d"
                              % (r["id"], size / 1e6, max_record_bytes / 1e6, target, current, need))
    return records
