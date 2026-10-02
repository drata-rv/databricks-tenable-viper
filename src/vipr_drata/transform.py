import json
from datetime import datetime, timedelta, timezone

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
        pass
    v = str(v).strip()
    if v.startswith("{") and v.endswith("}") and "->" in v:
        pairs = (p.split("->", 1) for p in v[1:-1].split(","))
        return {k.strip(): val.strip() for k, val in pairs}
    return {}


def _parse_ts(v):
    if not v:
        return None
    s = str(v).strip().replace(" ", "T", 1).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _iso(dt):
    return dt.isoformat() if dt else None


_SEV_ALIASES = {"informational": "info", "none": "info", "moderate": "medium", "important": "high"}


_SEV_ALIASES = {"informational": "info", "none": "info", "moderate": "medium", "important": "high"}


def _sev(v):
    if not v:
        return None
    v = str(v).strip().lower()
    v = _SEV_ALIASES.get(v, v)
    # unknown vocab (numeric codes, "unscored") is undetermined, not ranked
    return v if v in SEVERITY_ORDER else None


def _parse_list(v):
    if isinstance(v, list):
        return v
    if not v:
        return []
    try:
        out = json.loads(v)
        return out if isinstance(out, list) else [out]
    except (ValueError, TypeError):
        v = str(v).strip()
        if v.startswith("[") and v.endswith("]"):
            return [x.strip().strip("'\"") for x in v[1:-1].split(",") if x.strip()]
        return [v]


def _tri(v):
    return None if v is None or v == "" else is_true(v)


def _int(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return None


def scanner_severity(tool_severity, tool="tenable"):
    vals = {_sev(v) for k, v in _parse_map(tool_severity).items() if tool in k.lower()}
    return vals.pop() if len(vals) == 1 and None not in vals else None


def extract_finding_features(finding, assets, now=None):
    now = now or datetime.now(timezone.utc)
    vipr = _sev(finding.get("severity"))
    scan = scanner_severity(finding.get("tool_severity"))
    is_open = _tri(finding.get("open"))
    has_ticket = _tri(finding.get("has_ticket"))
    sla = _parse_ts(finding.get("sla_date"))
    closed_at = _parse_ts(finding.get("closed_timestamp"))
    changed = None if vipr is None or scan is None else vipr != scan
    if is_open is None or (finding.get("sla_date") and sla is None):
        breached = None
    else:
        breached = bool(is_open and sla and sla < now)
    closed_late = (closed_at > sla) if (is_open is False and sla and closed_at) else None
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
            ("downgraded" if SEVERITY_ORDER[vipr] < SEVERITY_ORDER[scan] else "upgraded")
        ),
        "open": is_open,
        "ignored": is_true(finding.get("is_ignored")),
        "has_ticket": has_ticket,
        "missing_ticket": None if has_ticket is None or is_open is None else (is_open and not has_ticket),
        "sla_date": _iso(sla),
        "sla_breached": breached,
        "closed_after_sla": closed_late,
        "first_seen": _iso(_parse_ts(finding.get("first_seen"))),
        "last_seen": _iso(_parse_ts(finding.get("last_seen"))),
        "closed_at": _iso(closed_at),
        "cves": _parse_list(finding.get("open_cves")),
        "asset_silk_id": finding.get("asset_silk_id"),
        "asset_resolved": asset is not None,
        "asset_name": asset.get("name") if asset else None,
    }


GENERIC_HOSTNAMES = {"localhost", "localhost.localdomain", "ubuntu", "debian", "centos", "default",
                     "unknown", "host", "server", "windows", "linux", "android", "iphone"}


def _norm_mac(m):
    return "".join(ch for ch in str(m).lower() if ch in "0123456789abcdef")


def index_tenable_assets(tenable_assets):
    idx = {"mac": {}, "host": {}, "rows": {}, "dup": set(), "claims": {}}
    for t in tenable_assets or []:
        tid = t.get("id")
        if not tid:
            continue
        if tid in idx["rows"]:
            # duplicate id in latest batch: undetermined, not last-row-wins
            idx["dup"].add(tid)
        idx["rows"][tid] = t
        for v in _parse_list(t.get("mac_addresses")):
            if _norm_mac(v):
                idx["mac"].setdefault(_norm_mac(v), set()).add(tid)
        for field in ("hostnames", "fqdns"):
            for v in _parse_list(t.get(field)):
                v = str(v).strip().lower()
                if v and v not in GENERIC_HOSTNAMES:
                    idx["host"].setdefault(v, set()).add(tid)
    return idx


def _candidates(asset, idx):
    macs, hosts = set(), set()
    for v in _parse_list(asset.get("mac_addresses")):
        macs |= idx["mac"].get(_norm_mac(v), set())
    for v in _parse_list(asset.get("hostnames")):
        hosts |= idx["host"].get(str(v).strip().lower(), set())
    return macs, hosts


def claim_tenable(assets, idx):
    for a in assets:
        macs, hosts = _candidates(a, idx)
        for tid in (macs or hosts):
            idx["claims"][tid] = idx["claims"].get(tid, 0) + 1


def match_tenable(asset, idx):
    if idx is None:
        return "not_configured", None
    if not idx["rows"]:
        # empty batch is not evidence of "unscanned"
        return "no_data", None
    macs, hosts = _candidates(asset, idx)
    if macs and hosts and macs != hosts and not (macs & hosts):
        return "ambiguous", None
    cands = macs or hosts
    if not cands:
        return "none", None
    if len(cands) > 1:
        return "ambiguous", None
    tid = next(iter(cands))
    if tid in idx["dup"] or idx["claims"].get(tid, 0) > 1:
        return "ambiguous", None
    return "matched", idx["rows"][tid]


def extract_asset_features(asset, stale_days=7, now=None, tenable_index=None):
    now = now or datetime.now(timezone.utc)
    limit = timedelta(days=stale_days)
    seen = _parse_ts(asset.get("last_seen"))
    days = (now - seen).days if seen else None
    status, trow = match_tenable(asset, tenable_index)
    t_scan = _parse_ts(trow.get("last_scan_time")) if trow else None
    t_days = (now - t_scan).days if t_scan else None
    return {
        "tenable_match": status,
        "tenable_last_scan": _iso(t_scan),
        "tenable_days_since_scan": t_days,
        "tenable_scan_stale": None if t_scan is None else (now - t_scan) > limit,
        "tenable_last_auth_scan": _iso(_parse_ts(trow.get("last_authenticated_scan_date"))) if trow else None,
        "id": asset.get("silk_id"),
        "name": asset.get("name"),
        "asset_type": asset.get("asset_type"),
        "is_active": is_true(asset.get("is_active")),
        "last_seen": _iso(seen),
        "days_since_seen": days,
        # Vipr last_seen is not scanner activity
        "vipr_last_seen_stale": None if seen is None else (now - seen) > limit,
        "open_findings_count": _int(asset.get("open_findings_count")),
    }


def format_finding_for_drata(f):
    return {
        "id": "finding:" + f["id"], "recordType": "finding", "sourceId": f["id"],
        "displayName": f["name"] or f["display_id"] or f["id"],
        "displayId": f["display_id"], "name": f["name"],
        "viprSeverity": f["vipr_severity"], "scannerSeverity": f["scanner_severity"],
        "severityChanged": f["severity_changed"], "severityDirection": f["severity_direction"],
        "open": f["open"], "ignored": f["ignored"], "hasTicket": f["has_ticket"],
        "missingTicket": f["missing_ticket"], "slaDate": f["sla_date"],
        "slaBreached": f["sla_breached"], "closedAfterSla": f["closed_after_sla"], "firstSeen": f["first_seen"],
        "lastSeen": f["last_seen"], "closedAt": f["closed_at"], "cves": f["cves"],
        "assetId": "asset:" + f["asset_silk_id"] if f["asset_silk_id"] else None, "assetName": f["asset_name"],
    }


def format_asset_for_drata(a):
    return {
        "id": "asset:" + a["id"], "recordType": "asset", "sourceId": a["id"],
        "displayName": a["name"] or a["id"], "name": a["name"],
        "assetType": a["asset_type"],
        "isActive": a["is_active"], "lastSeen": a["last_seen"],
        "daysSinceSeen": a["days_since_seen"], "viprLastSeenStale": a["vipr_last_seen_stale"],
        "openFindingsCount": a["open_findings_count"],
        "tenableMatch": a["tenable_match"], "tenableLastScan": a["tenable_last_scan"],
        "tenableDaysSinceScan": a["tenable_days_since_scan"], "tenableScanStale": a["tenable_scan_stale"],
        "tenableLastAuthenticatedScan": a["tenable_last_auth_scan"],
    }


def _split_duplicates(rows, key, label, rejected):
    groups = {}
    for r in rows:
        groups.setdefault(key(r), []).append(r)
    keep = []
    for k, grp in groups.items():
        distinct = {json.dumps(g, sort_keys=True, default=str) for g in grp}
        if not k or len(distinct) == 1:
            keep.append(grp[0]) if k else keep.extend(grp)
        else:
            rejected.extend({"resource": label + "s", "reason": "conflicting duplicate %s id in latest batch" % label, "record": g} for g in grp)
    return keep


def build_payloads(joined, assets, stale_days=7, now=None, tenable_assets=None):
    rejected = []
    joined = _split_duplicates(joined, lambda j: j["finding"].get("silk_id"), "finding", rejected)
    assets = _split_duplicates(assets, lambda a: a.get("silk_id"), "asset", rejected)
    findings = []
    for j in joined:
        feat = extract_finding_features(j["finding"], j["assets"], now)
        if not feat["id"]:
            rejected.append({"resource": "findings", "reason": "missing silk_id", "record": j["finding"]})
        else:
            findings.append(format_finding_for_drata(feat))
    scans = []
    tindex = index_tenable_assets(tenable_assets) if tenable_assets is not None else None
    if tindex is not None:
        claim_tenable([a for a in assets if a.get("silk_id")], tindex)
    for a in assets:
        feat = extract_asset_features(a, stale_days, now, tindex)
        if not feat["id"]:
            rejected.append({"resource": "assets", "reason": "missing silk_id", "record": a})
        else:
            scans.append(format_asset_for_drata(feat))
    return findings, scans, rejected
