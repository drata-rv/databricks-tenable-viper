import json
import math
import zlib
from datetime import timedelta

from .db.secrets import ConfigError
from .transform import _iso, _parse_ts

SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
RECORD_PREFIX = "vipr"
DEFAULT_FINDING_PARTITIONS = {"critical": 1, "high": 2, "medium": 4, "low": 4, "info": 1, "unknown": 1}
DEFAULT_ASSET_PARTITIONS = 4
MAX_PARTITIONS = 256
MAX_RECORD_BYTES_LIMIT = 4_500_000
TRISTATE = ("open", "ignored", "hasTicket", "missingTicket", "slaBreached", "severityChanged", "closedAfterSla",
            "isActive", "viprLastSeenStale", "tenableScanStale")
CVE_CAP = 25
TEXT_CAP = 200
TEXT_KEYS = ("displayId", "assetName", "name", "assetId", "toolSeverities")
FINDING_KEYS = ("id", "displayId", "viprSeverity", "scannerSeverity", "severityChanged", "severityDirection",
                "toolSeverities", "open", "ignored", "hasTicket", "missingTicket", "slaDate", "slaBreached",
                "closedAfterSla", "firstSeen", "closedAt", "assetId", "assetName", "cves", "cveCount")
ASSET_KEYS = ("id", "name", "assetType", "isActive", "lastSeen", "daysSinceSeen", "viprLastSeenStale",
              "openFindingsCount", "tenableMatch", "tenableLastScan", "tenableDaysSinceScan", "tenableScanStale",
              "tenableLastAuthenticatedScan")


def partition_of(key, partitions):
    return zlib.crc32(str(key).encode("utf-8")) % partitions


def severity_of(item):
    sev = item.get("viprSeverity")
    return sev if sev in SEVERITIES[:-1] else "unknown"


def parse_finding_partitions(raw):
    out = dict(DEFAULT_FINDING_PARTITIONS)
    if raw is None or not str(raw).strip():
        return out
    try:
        given = json.loads(raw)
    except ValueError:
        given = None
    if not isinstance(given, dict) or any(k not in SEVERITIES for k in given):
        raise ConfigError("FINDING_PARTITIONS must be a JSON object with keys from %s" % ", ".join(SEVERITIES))
    for severity, n in given.items():
        if isinstance(n, bool) or not isinstance(n, int) or not 1 <= n <= MAX_PARTITIONS:
            raise ConfigError("FINDING_PARTITIONS[%s] must be an integer from 1 to %d" % (severity, MAX_PARTITIONS))
        out[severity] = n
    return out


def compact(item, keys):
    out = {k: item[k] for k in keys if k in item and (k in TRISTATE or item[k] not in (None, []))}
    for k in TEXT_KEYS:
        if isinstance(out.get(k), str) and len(out[k]) > TEXT_CAP:
            out[k] = out[k][:TEXT_CAP - 3] + "..."
    return out


def finding_item(f):
    item = dict(f)
    cves = [str(c).strip() for c in (item.get("cves") or [])
            if isinstance(c, (str, int)) and not isinstance(c, bool) and str(c).strip().lower() not in ("", "null", "none")]
    item["cveCount"] = len(cves)
    item["cves"] = cves[:CVE_CAP]
    return compact(item, FINDING_KEYS)


def asset_item(a):
    return compact(a, ASSET_KEYS)


def size_of(record):
    return len(json.dumps(record, separators=(",", ":"), default=str).encode("utf-8"))


def source_as_of(rows):
    best = None
    for r in rows:
        d = _parse_ts(r.get("__date"))
        if d is None:
            continue
        try:
            hour = min(max(int(float(r.get("__hour") or 0)), 0), 23)
        except (ValueError, OverflowError):
            hour = 0
        t = d.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(hours=hour)
        best = t if best is None or t > best else best
    return best


def _count(items, key):
    return sum(1 for i in items if i.get(key) is True)


def _summary(findings, assets, *, now, source_dates, max_source_age_days, finding_partitions, asset_partitions,
             closed_excluded, rejected):
    open_f = [f for f in findings if f.get("open") is True]
    dates = list(source_dates.values())
    oldest = None if not dates or any(d is None for d in dates) else min(dates)
    fresh = None if oldest is None else (now - oldest) <= timedelta(days=max_source_age_days)
    return {
        "id": "%s-summary" % RECORD_PREFIX, "recordType": "scanSummary", "displayName": "Vipr Scan Summary",
        "generatedAt": _iso(now), "sourceAsOf": _iso(oldest),
        "findingsSourceAsOf": _iso(source_dates.get("findings")), "assetsSourceAsOf": _iso(source_dates.get("assets")),
        "tenableSourceAsOf": _iso(source_dates.get("tenable_assets")),
        "sourceAgeDays": None if oldest is None else (now - oldest).days, "sourceFresh": fresh,
        "findingPartitionCount": sum(finding_partitions.values()), "assetPartitionCount": asset_partitions,
        "findingCount": len(findings), "openFindingCount": len(open_f),
        "openSlaBreachedCount": _count(open_f, "slaBreached"),
        "openSlaUnknownCount": sum(1 for f in open_f if f.get("slaBreached") is None),
        "openMissingTicketCount": _count(open_f, "missingTicket"),
        "openTicketUnknownCount": sum(1 for f in open_f if f.get("missingTicket") is None),
        "severityChangedCount": _count(findings, "severityChanged"),
        "closedFindingsExcludedCount": closed_excluded, "rejectedCount": rejected,
        "assetCount": len(assets), "staleAssetCount": _count(assets, "viprLastSeenStale"),
        "tenableStaleAssetCount": _count(assets, "tenableScanStale"),
        "tenableUnmatchedAssetCount": sum(1 for a in assets if a.get("tenableMatch") in ("none", "ambiguous")),
    }


def auto_partitions(items, minimum, target_bytes, label="findings"):
    need = max(1, math.ceil(sum(size_of(i) + 1 for i in items) / target_bytes))
    n = 1
    while n < need:  # powers of two: counts change rarely between runs
        n *= 2
    if n > MAX_PARTITIONS:
        raise ConfigError("%s need %d partitions (limit %d): raise MAX_RECORD_BYTES or reduce the data" % (label, n, MAX_PARTITIONS))
    return max(minimum, n)


def _group(items, partitions):
    groups = [[] for _ in range(partitions)]
    for it in items:
        groups[partition_of(it["id"], partitions)].append(it)
    for grp in groups:
        grp.sort(key=lambda x: x["id"])
    return groups


def build_records(findings, assets, *, now, finding_partitions=None, asset_partitions=DEFAULT_ASSET_PARTITIONS,
                  closed_lookback_days=90, max_source_age_days=3, max_record_bytes=4_000_000, source_dates=None,
                  rejected=0, auto_size=False):
    finding_partitions = dict(finding_partitions or DEFAULT_FINDING_PARTITIONS)
    if asset_partitions < 1 or any(n < 1 for n in finding_partitions.values()):
        raise ConfigError("partition counts must be >= 1")
    cutoff = now - timedelta(days=closed_lookback_days)
    kept, excluded = [], 0
    for f in findings:
        closed = _parse_ts(f.get("closedAt"))
        if f.get("open") is False and closed is not None and closed < cutoff:
            excluded += 1
        else:
            kept.append(finding_item(f))
    asset_items = [asset_item(a) for a in assets]
    by_severity = {sev: [] for sev in SEVERITIES}
    for it in kept:
        by_severity[severity_of(it)].append(it)
    if auto_size:
        target = max_record_bytes // 2
        finding_partitions = {sev: auto_partitions(by_severity[sev], finding_partitions.get(sev, 1), target, sev + " findings")
                              for sev in SEVERITIES}
        asset_partitions = auto_partitions(asset_items, asset_partitions, target, "assets")
    records = [_summary(kept, asset_items, now=now, source_dates=source_dates or {},
                        max_source_age_days=max_source_age_days, finding_partitions=finding_partitions,
                        asset_partitions=asset_partitions, closed_excluded=excluded, rejected=rejected)]
    stamp = {"generatedAt": _iso(now), "sourceAsOf": records[0]["sourceAsOf"]}
    for sev in SEVERITIES:
        n = finding_partitions.get(sev, DEFAULT_FINDING_PARTITIONS[sev])
        for i, grp in enumerate(_group(by_severity[sev], n), 1):
            records.append({
                "id": "%s-findings-%s-%03d" % (RECORD_PREFIX, sev, i), "recordType": "findingPartition",
                "displayName": "Vipr Findings - %s - Partition %d of %d" % (sev.capitalize(), i, n),
                "severity": sev, **stamp, "partition": i, "partitionCount": n, "itemCount": len(grp), "findings": grp})
    for i, grp in enumerate(_group(asset_items, asset_partitions), 1):
        records.append({
            "id": "%s-assets-%03d" % (RECORD_PREFIX, i), "recordType": "assetPartition",
            "displayName": "Vipr Assets - Partition %d of %d" % (i, asset_partitions),
            **stamp, "partition": i, "partitionCount": asset_partitions, "itemCount": len(grp), "assets": grp})
    for r in records:  # Drata rejects bodies over 5 MB
        size = size_of(r)
        if size > max_record_bytes:
            current = r.get("partitionCount")
            if current is None:
                raise ConfigError("summary record is %.1f MB: raise MAX_RECORD_BYTES" % (size / 1e6))
            if auto_size:
                raise ConfigError("record %s is %.1f MB (limit %.1f MB) after auto-sizing: raise MAX_RECORD_BYTES (max %d)"
                                  % (r["id"], size / 1e6, max_record_bytes / 1e6, MAX_RECORD_BYTES_LIMIT))
            target = ("FINDING_PARTITIONS[%s]" % r["severity"]) if r["recordType"] == "findingPartition" else "ASSET_PARTITIONS"
            need = min(math.ceil(current * size / (max_record_bytes * 0.6)), MAX_PARTITIONS)
            raise ConfigError("record %s is %.1f MB (limit %.1f MB): raise %s from %d to at least %d"
                              % (r["id"], size / 1e6, max_record_bytes / 1e6, target, current, need))
    return records
