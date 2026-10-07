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
    cols = {s.label: list(dict.fromkeys(list(s.columns) + ["__date", "__hour"])) for s in TABLE_REGISTRY}
    for label, rows in sample_rows(now).items():
        with open(os.path.join(directory, label + ".csv"), "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=cols[label], extrasaction="ignore")
            w.writeheader()
            w.writerows([{k: ("null" if v is None else v) for k, v in r.items()} for r in rows])
    return directory


def write_scale_data(directory, n_findings):
    os.makedirs(directory, exist_ok=True)
    now = datetime.now(timezone.utc)
    today = now.date().isoformat()
    n_assets = max(1, n_findings // 8)
    cols = {s.label: list(dict.fromkeys(list(s.columns) + ["__date", "__hour"])) for s in TABLE_REGISTRY}
    sev = ("LOW", "MEDIUM", "HIGH", "CRITICAL", "INFO")
    with open(os.path.join(directory, "findings.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols["findings"])
        w.writeheader()
        for i in range(n_findings):
            opn = i % 5 != 0
            w.writerow({
                "silk_id": "nationwide____DedupedTask____%040x" % i, "finding_display_id": "SILK-%07d" % i,
                "display_name": "SILK-%07d" % i, "severity": sev[i % 5],
                "tool_severity": json.dumps({"rapid7_insight_vm-1": str(i % 5 + 1)}) if i % 3 else json.dumps({"tenable_io": sev[(i + 1) % 5].title()}),
                "open": "true" if opn else "false", "is_ignored": "false", "has_ticket": "true" if i % 4 else "false",
                "sla_date": _ts(now, 200 - i % 400), "first_seen": _ts(now, 400 - i % 300),
                "last_seen": "" if i % 2 else _ts(now, i % 30), "closed_timestamp": "" if opn else _ts(now, i % 200),
                "open_cves": json.dumps(["CVE-2026-%04d" % (j % 9999) for j in range(i % 4)]) if i % 4 else "",
                "asset_silk_id": "nationwide____DedupedHostAsset____%040x" % (i % n_assets), "__date": today, "__hour": "5"})
    with open(os.path.join(directory, "assets.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols["assets"])
        w.writeheader()
        for i in range(n_assets):
            w.writerow({
                "silk_id": "nationwide____DedupedHostAsset____%040x" % i, "name": "" if i % 3 == 0 else "host-%06d" % i,
                "asset_type": "host", "is_active": "true", "last_seen": _ts(now, i % 12), "open_findings_count": str(i % 40),
                "hostnames": json.dumps(["lapp%06d" % i]), "mac_addresses": json.dumps([]), "__date": today, "__hour": "5"})
    stale = os.path.join(directory, "tenable_assets.csv")
    if os.path.exists(stale):
        os.remove(stale)
