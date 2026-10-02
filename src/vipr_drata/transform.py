"""extract_*: business logic (raw -> signals). format_*: pure mapping to Drata JSON."""
import json
from datetime import datetime, timezone

from .db.queries import is_true

SEVERITY_ORDER = {"info": 0, "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


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


def _sev(v):
    return str(v).strip().lower() if v else None


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
        "cves": finding.get("open_cves"),
        "asset_silk_id": finding.get("asset_silk_id"),
        "asset_resolved": asset is not None,
        "asset_name": asset.get("name") if asset else None,
    }


def extract_asset_features(asset, stale_days=7, now=None):
    now = now or datetime.now(timezone.utc)
    seen = _parse_ts(asset.get("last_seen"))
    days = (now - seen).days if seen else None
    return {
        "id": asset.get("silk_id"),
        "name": asset.get("name"),
        "asset_type": asset.get("asset_type"),
        "is_active": is_true(asset.get("is_active")),
        "last_seen": _iso(seen),
        "days_since_seen": days,
        "scan_stale": None if days is None else days > stale_days,  # None = undetermined
        "open_findings_count": asset.get("open_findings_count"),
    }


def format_finding_for_drata(f):
    return {
        "externalId": f["id"], "displayId": f["display_id"], "name": f["name"],
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
        "externalId": a["id"], "name": a["name"], "assetType": a["asset_type"],
        "isActive": a["is_active"], "lastSeen": a["last_seen"],
        "daysSinceSeen": a["days_since_seen"], "scanStale": a["scan_stale"],
        "openFindingsCount": a["open_findings_count"],
    }


def build_payloads(joined, assets, stale_days=7, now=None):
    """Returns (findings, asset_records, rejected). Records w/o a stable id are rejected, not dropped."""
    findings, rejected = [], []
    for j in joined:
        feat = extract_finding_features(j["finding"], j["assets"], now)
        if not feat["id"]:
            rejected.append({"reason": "missing silk_id", "record": j["finding"]})
        else:
            findings.append(format_finding_for_drata(feat))
    scans = []
    for a in assets:
        feat = extract_asset_features(a, stale_days, now)
        if not feat["id"]:
            rejected.append({"reason": "asset missing silk_id", "record": a})
        else:
            scans.append(format_asset_for_drata(feat))
    return findings, scans, rejected
