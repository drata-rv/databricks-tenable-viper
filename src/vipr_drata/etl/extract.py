"""Table registry (add a table = one entry) and parallel pull + join.

Column lists are verified against docs/*.xlsx by tests/test_schema_contract.py. Never SELECT *:
every landing table carries a large __raw column.
"""
import os
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor

from ..db.queries import latest_batch_clause, run_sql

TableSpec = namedtuple("TableSpec", "label env_var key required columns")

TABLE_REGISTRY = [
    TableSpec("findings", "VIPR_FINDINGS_TABLE", "silk_id", True, (
        "silk_id", "finding_display_id", "display_name", "severity", "tool_severity", "open",
        "is_ignored", "has_ticket", "sla_date", "first_seen", "last_seen", "closed_timestamp",
        "open_cves", "asset_silk_id")),
    TableSpec("assets", "VIPR_ASSETS_TABLE", "silk_id", True, (
        "silk_id", "name", "asset_type", "is_active", "last_seen", "open_findings_count",
        "hostnames", "mac_addresses")),
    # Optional: Tenable scanner-activity evidence (si_prod_catalog...t_tenable_assets)
    TableSpec("tenable_assets", "TENABLE_ASSETS_TABLE", "id", False, (
        "id", "hostnames", "fqdns", "mac_addresses", "last_scan_time",
        "last_authenticated_scan_date", "last_seen", "has_agent", "tenable_agent_days_since_active")),
    # TableSpec("cves", "VIPR_CVES_TABLE", "cve", False, ("cve", "cvss_score", "epss_score", "threat_intel_is_listed_on_cisa_kev")),
    # TableSpec("evidence", "VIPR_EVIDENCE_TABLE", "id", False, ("id", "tool_evidence")),
]


def active_specs():
    return [s for s in TABLE_REGISTRY if s.required or os.getenv(s.env_var)]


def _pull(client, warehouse_id, spec):
    table = os.getenv(spec.env_var)
    if not table:
        raise RuntimeError("%s not set" % spec.env_var)
    # Landing tables hold one copy of every row per ingest batch: always filter to the latest.
    sql = "SELECT %s FROM %s WHERE %s" % (", ".join(spec.columns), table, latest_batch_clause(table))
    return spec.label, run_sql(client, warehouse_id, sql)


def extract_all(client, warehouse_id):
    specs = active_specs()
    with ThreadPoolExecutor(max_workers=len(specs)) as ex:
        return dict(ex.map(lambda s: _pull(client, warehouse_id, s), specs))


def merge(tables):
    """Findings drive scope. Assets indexed {silk_id: [rows]} (list, not last-wins)."""
    assets = {}
    for a in tables.get("assets", []):
        if a.get("silk_id"):  # null ids never join
            assets.setdefault(a["silk_id"], []).append(a)
    return [
        {"finding": f, "assets": assets.get(f.get("asset_silk_id"), []) if f.get("asset_silk_id") else []}
        for f in tables.get("findings", [])
    ], tables.get("assets", [])
