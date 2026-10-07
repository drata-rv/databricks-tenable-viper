import json
import math
import zlib
from datetime import timedelta

from .db.secrets import ConfigError
from .transform import _iso, _parse_ts

TRISTATE = ("open", "hasTicket", "missingTicket", "slaBreached", "isActive", "viprLastSeenStale", "tenableScanStale")
CVE_CAP = 25
FINDING_KEYS = ("id", "displayId", "viprSeverity", "scannerSeverity", "severityChanged", "severityDirection",
                "toolSeverities", "open", "ignored", "hasTicket", "missingTicket", "slaDate", "slaBreached",
                "closedAfterSla", "firstSeen", "closedAt", "assetId", "assetName", "cves", "cveCount")
ASSET_KEYS = ("id", "name", "assetType", "isActive", "lastSeen", "daysSinceSeen", "viprLastSeenStale",
              "openFindingsCount", "tenableMatch", "tenableLastScan", "tenableDaysSinceScan", "tenableScanStale",
              "tenableLastAuthenticatedScan")


def bucket_of(key, buckets):
    return zlib.crc32(str(key).encode("utf-8")) % buckets


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


def batch_date(*row_sets):
    dates = [d for rows in row_sets for d in (_parse_ts(r.get("__date")) for r in rows) if d]
    return max(dates) if dates else None


def _count(items, key, value=True):
    return sum(1 for i in items if i.get(key) is value)


def _summary(findings, assets, *, now, source_date, max_source_age_days, finding_buckets, asset_buckets,
             closed_excluded, rejected):
    open_f = [f for f in findings if f.get("open") is True]
    age = None if source_date is None else (now - source_date).days
    fresh = None if source_date is None else (now - source_date) <= timedelta(days=max_source_age_days)
    return {
        "id": "summary", "recordType": "summary", "displayName": "Vipr vulnerability evidence summary",
        "generatedAt": _iso(now), "sourceBatchDate": _iso(source_date), "sourceBatchAgeDays": age,
        "sourceFresh": fresh, "findingBuckets": finding_buckets, "assetBuckets": asset_buckets,
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


def _batches(kind, record_type, label, field, items, buckets, *, now, source_date):
    groups = [[] for _ in range(buckets)]
    for it in items:
        groups[bucket_of(it["id"], buckets)].append(it)
    out = []
    for i, grp in enumerate(groups):
        grp.sort(key=lambda x: x["id"])
        out.append({
            "id": "%s-%03d" % (kind, i), "recordType": record_type,
            "displayName": "Vipr %s batch %d of %d (%d)" % (label, i + 1, buckets, len(grp)),
            "generatedAt": _iso(now), "sourceBatchDate": _iso(source_date),
            "bucket": i, "bucketCount": buckets, "itemCount": len(grp), field: grp,
        })
    return out


def build_records(findings, assets, *, now, finding_buckets=64, asset_buckets=16, closed_lookback_days=90,
                  max_source_age_days=3, max_record_bytes=4_000_000, source_date=None, rejected=0):
    if finding_buckets < 1 or asset_buckets < 1:
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
    records = [_summary(kept, asset_items, now=now, source_date=source_date, max_source_age_days=max_source_age_days,
                        finding_buckets=finding_buckets, asset_buckets=asset_buckets, closed_excluded=excluded,
                        rejected=rejected)]
    records += _batches("findings", "findingBatch", "findings", "findings", kept, finding_buckets,
                        now=now, source_date=source_date)
    records += _batches("assets", "assetBatch", "assets", "assets", asset_items, asset_buckets,
                        now=now, source_date=source_date)
    for r in records:
        size = size_of(r)
        if size > max_record_bytes:
            kind = "FINDING_BUCKETS" if r["recordType"] == "findingBatch" else "ASSET_BUCKETS"
            current = r["bucketCount"]
            need = math.ceil(current * size / (max_record_bytes * 0.6))
            raise ConfigError("record %s is %.1f MB (limit %.1f MB): raise %s from %d to at least %d"
                              % (r["id"], size / 1e6, max_record_bytes / 1e6, kind, current, need))
    return records
