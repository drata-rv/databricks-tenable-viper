import re
from collections import Counter

from .transform import _SEV_ALIASES, SEVERITY_ORDER, _parse_ts, asset_name, parse_map

TOP = 20
SAMPLES = 3
TS_COLUMNS = {
    "findings": ("first_seen", "last_seen", "sla_date", "closed_timestamp"),
    "assets": ("last_seen",),
    "tenable_assets": ("last_scan_time", "last_authenticated_scan_date", "last_seen"),
}
VOCAB = set(SEVERITY_ORDER) | set(_SEV_ALIASES)
SAFE = re.compile(r"^[A-Za-z0-9_. -]{1,16}$")


def _empty(v):
    return v is None or v == ""


def _value(v):
    if _empty(v):
        return "<null>"
    v = str(v).strip().lower()
    return v if v in VOCAB or SAFE.match(v) else "<other>"


def _null_counts(rows):
    cols = {c for r in rows for c in r}
    return {c: sum(1 for r in rows if _empty(r.get(c))) for c in sorted(cols)}


def _unparseable_timestamps(tables):
    out = {}
    for table, cols in TS_COLUMNS.items():
        for col in cols:
            bad = [r[col] for r in tables.get(table, []) if not _empty(r.get(col)) and _parse_ts(r[col]) is None]
            if bad:
                out.setdefault(table, {})[col] = {"count": len(bad), "samples": [str(b)[:40] for b in bad[:SAMPLES]]}
    return out


def _tool_severity(findings):
    state, keys, values, cross = Counter(), Counter(), {}, {}
    for f in findings:
        raw = f.get("tool_severity")
        m = parse_map(raw)
        if _empty(raw):
            state["null"] += 1
        elif m is None:
            state["unparseable"] += 1
        elif not m:
            state["empty_map"] += 1
        else:
            state["parsed"] += 1
            for k, v in m.items():
                k = str(k)[:40]
                keys[k] += 1
                values.setdefault(k, Counter())[_value(v)] += 1
                cross.setdefault(k, {}).setdefault(_value(v), Counter())[_value(f.get("severity"))] += 1
    top = [k for k, _ in keys.most_common(TOP)]
    return {"rows": dict(state), "keys": dict(keys.most_common(TOP)),
            "values": {k: dict(values[k].most_common(TOP)) for k in top},
            "vipr_severity_by_tool_value": {
                k: {v: dict(cross[k][v].most_common(TOP)) for v, _ in values[k].most_common(TOP)} for k in top}}


def _asset_resolution(joined, assets):
    known = {str(a["silk_id"]).strip().lower() for a in assets if a.get("silk_id")}
    out, unmatched = Counter(), []
    for j in joined:
        aid = j["finding"].get("asset_silk_id")
        n = len(j["assets"])
        if _empty(aid):
            out["no_asset_id"] += 1
        elif n == 0:
            out["id_format_mismatch" if str(aid).strip().lower() in known else "no_asset_row"] += 1
            if len(unmatched) < SAMPLES + 2:
                unmatched.append(str(aid)[:100])
        elif n > 1:
            out["conflicting_duplicates"] += 1
        elif _empty(j["assets"][0].get("name")) or str(j["assets"][0]["name"]).strip().lower() == "null":
            out["name_from_hostname" if asset_name(j["assets"][0]) else "asset_name_null"] += 1
        else:
            out["resolved"] += 1
    return dict(out), unmatched


def build_profile(tables, joined, records):
    findings = [r for r in records if r["recordType"] == "finding"]
    assets = [r for r in records if r["recordType"] == "asset"]
    resolution, unmatched = _asset_resolution(joined, tables.get("assets", []))
    return {
        "note": "raw_* counts cover every pulled row, including rows later rejected",
        "raw_rows": {t: len(r) for t, r in tables.items()},
        "null_counts": {t: _null_counts(r) for t, r in tables.items()},
        "unparseable_timestamps": _unparseable_timestamps(tables),
        "raw_vipr_severity_values": dict(Counter(_value(f.get("severity")) for f in tables.get("findings", [])).most_common(TOP)),
        "raw_tool_severity": _tool_severity(tables.get("findings", [])),
        "raw_asset_resolution": resolution,
        "unmatched_asset_id_samples": unmatched,
        "findings_null": {k: sum(1 for r in findings if r.get(k) is None)
                          for k in ("scannerSeverity", "severityChanged", "firstSeen", "lastSeen", "slaDate",
                                    "slaBreached", "assetName")},
        "tenable_match": dict(Counter(a["tenableMatch"] for a in assets)),
    }


def summary(p):
    ts = {t: {c: v["count"] for c, v in cols.items()} for t, cols in p["unparseable_timestamps"].items()}
    return ("profile: raw_findings=%d scannerSeverity_null=%d tool_severity_rows=%s keys=%s asset_resolution=%s "
            "unparseable_ts=%s" % (p["raw_rows"].get("findings", 0), p["findings_null"]["scannerSeverity"],
                                    p["raw_tool_severity"]["rows"], p["raw_tool_severity"]["keys"],
                                    p["raw_asset_resolution"], ts))
