import os
import time
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor

from .. import log
from ..db.access import classify
from ..db.queries import latest_batch_clause, run_sql
from ..transform import collapse_identical

TableSpec = namedtuple("TableSpec", "label env_var key required columns")

TABLE_REGISTRY = [
    TableSpec("findings", "VIPR_FINDINGS_TABLE", "silk_id", True, (
        "silk_id", "finding_display_id", "display_name", "severity", "tool_severity", "open",
        "is_ignored", "ignored_info", "remediation_owner", "security_owner", "has_ticket", "sla_date",
        "first_seen", "last_seen", "closed_timestamp", "open_cves", "asset_silk_id", "__date", "__hour")),
    TableSpec("assets", "VIPR_ASSETS_TABLE", "silk_id", True, (
        "silk_id", "name", "asset_type", "is_active", "last_seen", "open_findings_count",
        "hostnames", "mac_addresses", "__date", "__hour")),
    TableSpec("tenable_assets", "TENABLE_ASSETS_TABLE", "id", False, (
        "id", "hostnames", "fqdns", "mac_addresses", "last_scan_time",
        "last_authenticated_scan_date", "last_seen", "has_agent", "tenable_agent_days_since_active",
        "__date", "__hour")),
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
    with log.context(table=spec.label):
        log.info("extract", "table.start", source=table, columns=len(spec.columns), batch="latest")
        started = time.time()
        rows = run_sql(client, warehouse_id, sql)
        log.info("extract", "table.complete", rows=len(rows), seconds=round(time.time() - started))
    return spec.label, rows


def _pull_checked(client, warehouse_id, spec):
    try:
        return _pull(client, warehouse_id, spec)
    except Exception as e:
        reason = classify(e)
        if spec.required or reason == "error":
            log.error("extract", "table.failed", table=spec.label, reason=reason, error_type=type(e).__name__, detail=str(e)[:300])
            return spec.label, e
        log.warn("extract", "table.skipped", table=spec.label, reason=reason, effect="fields_unavailable")
        return spec.label, None


def extract_all(client, warehouse_id):
    specs = active_specs()
    log.info("extract", "start", tables=[s.label for s in specs], parallel=True)
    with ThreadPoolExecutor(max_workers=len(specs)) as ex:
        results = list(ex.map(lambda s: _pull_checked(client, warehouse_id, s), specs))
    failed = [label for label, rows in results if isinstance(rows, Exception)]
    if failed:
        raise RuntimeError("tables unavailable: " + ", ".join(failed))
    return {label: rows for label, rows in results if rows is not None}


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
