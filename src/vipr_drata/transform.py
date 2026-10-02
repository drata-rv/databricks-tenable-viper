"""extract_*: business logic (raw -> signals). format_*: pure mapping to Drata JSON."""
import json
from datetime import datetime, timezone

from .db.queries import is_true

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _parse_map(v):
    if isinstance(v, dict):
        return v
    if not v:
        return {}
    try:
        out = json.loads(v)
        return out if isinstance(out, dict) else {}
    except (ValueError, TypeError):
        return {}


def _parse_ts(v):
    if not v:
        return None
    s = str(v).replace("T", " ").rstrip("Z")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


def _iso(dt):
    return dt.isoformat() if dt else None


_SEV_ALIASES = {"informational": "info", "none": "info", "moderate": "medium", "important": "high"}


def _sev(v):
    if not v:
        return None
    v = str(v).strip().lower()
    return _SEV_ALIASES.get(v, v)


def _parse_list(v):
    if isinstance(v, list):
        return v
    if not v:
        return []
    try:
        out = json.loads(v)
        return out if isinstance(out, list) else [out]
    except (ValueError, TypeError):
        return [v]


def _int(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return None


def scanner_severity(tool_severity, tool="tenable"):
    """Raw scanner rating from Vipr's per-tool map; None if Tenable didn't report it."""
    for k, v in _parse_map(tool_severity).items():
        if tool in k.lower():
            return _sev(v)
    return None


def extract_finding_features(finding, assets, now=None):
    now = now or datetime.now(timezone.utc)
    vipr = _sev(finding.get("severity"))
    scan = scanner_severity(finding.get("tool_severity"))
    is_open = is_true(finding.get("open"))
    sla = _parse_ts(finding.get("sla_date"))
    if vipr is None or scan is None:
        changed = None  # undetermined, not guessed
    else:
        changed = vipr != scan
    # one asset expected per silk_id; anything else -> unresolved, not arbitrary
    asset = assets[0] if len(assets) == 1 else None
    return {
        "id": finding.get("silk_id"),
        "display_id": finding.get("finding_display_id"),
        "name": finding.get("display_name"),
        "vipr_severity": vipr,
        "scanner_severity": scan,
        "severity_changed": changed,
        "severity_direction": (
            None if not changed else
            ("downgraded" if SEVERITY_ORDER.get(vipr, 0) < SEVERITY_ORDER.get(scan, 0) else "upgraded")
        ),
        "open": is_open,
        "ignored": is_true(finding.get("is_ignored")),
        "has_ticket": is_true(finding.get("has_ticket")),
        "missing_ticket": is_open and not is_true(finding.get("has_ticket")),
        "sla_date": _iso(sla),
        "sla_breached": bool(is_open and sla and sla < now),
        "first_seen": _iso(_parse_ts(finding.get("first_seen"))),
        "last_seen": _iso(_parse_ts(finding.get("last_seen"))),
        "closed_at": _iso(_parse_ts(finding.get("closed_timestamp"))),
        "cves": _parse_list(finding.get("open_cves")),
        "asset_silk_id": finding.get("asset_silk_id"),
        "asset_resolved": asset is not None,
        "asset_name": asset.get("name") if asset else None,
    }


def index_tenable_assets(tenable_assets):
    """Lowercased MAC / hostname / FQDN -> set of Tenable asset ids, plus id -> row."""
    keys, rows = {}, {}
    for t in tenable_assets or []:
        tid = t.get("id")
        if not tid:
            continue
        rows[tid] = t
        for field in ("mac_addresses", "hostnames", "fqdns"):
            for v in _parse_list(t.get(field)):
                if v:
                    keys.setdefault((field == "mac_addresses", str(v).strip().lower()), set()).add(tid)
    return keys, rows


def match_tenable(asset, tenable_index):
    """-> (status, tenable_row). Exact MAC then exact hostname; exactly one candidate or undetermined."""
    if tenable_index is None:
        return "not_configured", None
    keys, rows = tenable_index
    for is_mac, field in ((True, "mac_addresses"), (False, "hostnames")):
        cands = set()
        for v in _parse_list(asset.get(field)):
            cands |= keys.get((is_mac, str(v).strip().lower()), set())
        if len(cands) == 1:
            return "matched", rows[next(iter(cands))]
        if len(cands) > 1:
            return "ambiguous", None
    return "none", None


def extract_asset_features(asset, stale_days=7, now=None, tenable_index=None):
    now = now or datetime.now(timezone.utc)
    seen = _parse_ts(asset.get("last_seen"))
    days = (now - seen).days if seen else None
    status, trow = match_tenable(asset, tenable_index)
    t_scan = _parse_ts(trow.get("last_scan_time")) if trow else None
    t_days = (now - t_scan).days if t_scan else None
    return {
        "tenable_match": status,
        "tenable_last_scan": _iso(t_scan),
        "tenable_days_since_scan": t_days,
        "tenable_scan_stale": None if t_days is None else t_days > stale_days,
        "tenable_last_auth_scan": _iso(_parse_ts(trow.get("last_authenticated_scan_date"))) if trow else None,
        "id": asset.get("silk_id"),
        "name": asset.get("name"),
        "asset_type": asset.get("asset_type"),
        "is_active": is_true(asset.get("is_active")),
        "last_seen": _iso(seen),
        "days_since_seen": days,
        "scan_stale": None if days is None else days > stale_days,  # None = undetermined
        "open_findings_count": _int(asset.get("open_findings_count")),
    }


def format_finding_for_drata(f):
    return {
        "id": f["id"], "displayName": f["name"] or f["display_id"] or f["id"],
        "displayId": f["display_id"], "name": f["name"],
        "viprSeverity": f["vipr_severity"], "scannerSeverity": f["scanner_severity"],
        "severityChanged": f["severity_changed"], "severityDirection": f["severity_direction"],
        "open": f["open"], "ignored": f["ignored"], "hasTicket": f["has_ticket"],
        "missingTicket": f["missing_ticket"], "slaDate": f["sla_date"],
        "slaBreached": f["sla_breached"], "firstSeen": f["first_seen"],
        "lastSeen": f["last_seen"], "closedAt": f["closed_at"], "cves": f["cves"],
        "assetId": f["asset_silk_id"], "assetName": f["asset_name"],
    }


def format_asset_for_drata(a):
    return {
        "id": a["id"], "displayName": a["name"] or a["id"], "name": a["name"],
        "assetType": a["asset_type"],
        "isActive": a["is_active"], "lastSeen": a["last_seen"],
        "daysSinceSeen": a["days_since_seen"], "scanStale": a["scan_stale"],
        "openFindingsCount": a["open_findings_count"],
        "tenableMatch": a["tenable_match"], "tenableLastScan": a["tenable_last_scan"],
        "tenableDaysSinceScan": a["tenable_days_since_scan"], "tenableScanStale": a["tenable_scan_stale"],
        "tenableLastAuthenticatedScan": a["tenable_last_auth_scan"],
    }


def _split_duplicates(rows, key, label, rejected):
    """Ids appearing more than once in the latest batch are rejected, never last-write-wins."""
    counts = {}
    for r in rows:
        counts[key(r)] = counts.get(key(r), 0) + 1
    keep = []
    for r in rows:
        if key(r) and counts[key(r)] > 1:
            rejected.append({"reason": "duplicate %s id in latest batch" % label, "record": r})
        else:
            keep.append(r)
    return keep


def build_payloads(joined, assets, stale_days=7, now=None, tenable_assets=None):
    """Returns (findings, asset_records, rejected). Records w/o a stable id, or with a duplicated
    id, are rejected (and logged by the caller), not dropped or arbitrarily picked."""
    rejected = []
    joined = _split_duplicates(joined, lambda j: j["finding"].get("silk_id"), "finding", rejected)
    assets = _split_duplicates(assets, lambda a: a.get("silk_id"), "asset", rejected)
    findings = []
    for j in joined:
        feat = extract_finding_features(j["finding"], j["assets"], now)
        if not feat["id"]:
            rejected.append({"reason": "missing silk_id", "record": j["finding"]})
        else:
            findings.append(format_finding_for_drata(feat))
    scans = []
    tindex = index_tenable_assets(tenable_assets) if tenable_assets is not None else None
    for a in assets:
        feat = extract_asset_features(a, stale_days, now, tindex)
        if not feat["id"]:
            rejected.append({"reason": "asset missing silk_id", "record": a})
        else:
            scans.append(format_asset_for_drata(feat))
    return findings, scans, rejected
