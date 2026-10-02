import os
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor

from ..db.queries import latest_batch_clause, run_sql
from ..transform import collapse_identical

TableSpec = namedtuple("TableSpec", "label env_var key required columns")

TABLE_REGISTRY = [
    TableSpec("findings", "VIPR_FINDINGS_TABLE", "silk_id", True, (
        "silk_id", "finding_display_id", "display_name", "severity", "tool_severity", "open",
        "is_ignored", "has_ticket", "sla_date", "first_seen", "last_seen", "closed_timestamp",
        "open_cves", "asset_silk_id")),
    TableSpec("assets", "VIPR_ASSETS_TABLE", "silk_id", True, (
        "silk_id", "name", "asset_type", "is_active", "last_seen", "open_findings_count",
        "hostnames", "mac_addresses")),
    TableSpec("tenable_assets", "TENABLE_ASSETS_TABLE", "id", False, (
        "id", "hostnames", "fqdns", "mac_addresses", "last_scan_time",
        "last_authenticated_scan_date", "last_seen", "has_agent", "tenable_agent_days_since_active")),
]


def active_specs():
    return [s for s in TABLE_REGISTRY if s.required or os.getenv(s.env_var)]


# never SELECT *: __raw is large
# landing tables keep one copy per ingest batch: latest batch only
def _pull(client, warehouse_id, spec):
    table = os.getenv(spec.env_var)
    if not table:
        raise RuntimeError("%s not set" % spec.env_var)
    sql = "SELECT %s FROM %s WHERE %s" % (", ".join(spec.columns), table, latest_batch_clause(table))
    return spec.label, run_sql(client, warehouse_id, sql)


def extract_all(client, warehouse_id):
    specs = active_specs()
    with ThreadPoolExecutor(max_workers=len(specs)) as ex:
        return dict(ex.map(lambda s: _pull(client, warehouse_id, s), specs))


def merge(tables):
    assets = {}
    for a in tables.get("assets", []):
        # null ids never join
        if a.get("silk_id"):
            assets.setdefault(a["silk_id"], []).append(a)
    assets = {k: collapse_identical(v) for k, v in assets.items()}
    return [
        {"finding": f, "assets": assets.get(f.get("asset_silk_id"), []) if f.get("asset_silk_id") else []}
        for f in tables.get("findings", [])
    ], tables.get("assets", [])
