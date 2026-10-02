import csv
import json
import os
from datetime import datetime, timedelta, timezone

from .extract import TABLE_REGISTRY


def _ts(now, days):
    return (now - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")


def sample_rows(now=None):
    now = now or datetime.now(timezone.utc)
    today, yesterday = now.date().isoformat(), (now - timedelta(days=1)).date().isoformat()
    cur = {"__date": today, "__hour": "5"}
    old = {"__date": yesterday, "__hour": "22"}
    J = json.dumps

    def f(i, sev, tool, **kw):
        row = {"silk_id": i, "finding_display_id": "VIPR-" + i[-3:], "display_name": "Finding " + i,
               "severity": sev, "tool_severity": J({"tenable": tool}) if tool else "{}", "open": "true",
               "is_ignored": "false", "has_ticket": "true", "sla_date": _ts(now, -14),
               "first_seen": _ts(now, 40), "last_seen": _ts(now, 1), "closed_timestamp": None,
               "open_cves": J(["CVE-2026-0001"]), "asset_silk_id": "a-001"}
        row.update(kw)
        row.update(cur)
        return row

    findings = [
        f("f-001", "medium", "high"),
        f("f-002", "high", "medium", has_ticket="false", sla_date=_ts(now, 3), asset_silk_id="a-002"),
        f("f-003", "low", "low", asset_silk_id="a-003"),
        f("f-004", "high", "high", open="false", closed_timestamp=_ts(now, 2), asset_silk_id="a-004"),
        f("f-005", "medium", None),
        f("f-006", "critical", "critical", asset_silk_id="a-missing"),
        f("", "low", "low"),
        dict(f("f-001", "critical", "high"), **old),  # old batch: must be ignored
    ]
    def a(i, name, seen, **kw):
        row = {"silk_id": i, "name": name, "asset_type": "HOST", "is_active": "true", "last_seen": _ts(now, seen),
               "open_findings_count": "2", "hostnames": J([name]), "mac_addresses": J([])}
        row.update(kw)
        row.update(cur)
        return row

    assets = [
        a("a-001", "host-one", 1, mac_addresses=J(["AA:BB:CC:00:00:01"])),
        a("a-002", "host-two", 30),
        a("a-003", "host-three", 2),
        a("a-004", "host-four", 2),
        a("a-004", "host-four-dup", 2),  # conflicting duplicate id
        dict(a("a-001", "host-one-old", 50), **old),
    ]
    def t(i, hosts, scan, **kw):
        row = {"id": i, "hostnames": J(hosts), "fqdns": J([]), "mac_addresses": J([]),
               "last_scan_time": _ts(now, scan), "last_authenticated_scan_date": _ts(now, scan),
               "last_seen": _ts(now, scan), "has_agent": "true", "tenable_agent_days_since_active": "1"}
        row.update(kw)
        row.update(cur)
        return row

    tenable = [
        t("t-1", ["host-one"], 2, mac_addresses=J(["aa:bb:cc:00:00:01"])),
        t("t-2", ["host-two"], 5),
        t("t-3", ["HOST-TWO"], 9),
    ]
    return {"findings": findings, "assets": assets, "tenable_assets": tenable}


def write_sample_data(directory, now=None):
    os.makedirs(directory, exist_ok=True)
    cols = {s.label: list(s.columns) + ["__date", "__hour"] for s in TABLE_REGISTRY}
    for label, rows in sample_rows(now).items():
        with open(os.path.join(directory, label + ".csv"), "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=cols[label], extrasaction="ignore")
            w.writeheader()
            w.writerows([{k: ("null" if v is None else v) for k, v in r.items()} for r in rows])
    return directory
