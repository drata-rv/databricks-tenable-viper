"""Table registry (add a table = one line) and parallel pull + join."""
import os
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor

from ..db.queries import latest_batch_clause, run_sql

TableSpec = namedtuple("TableSpec", "label env_var key required")

# key = column holding the join key in that table
TABLE_REGISTRY = [
    TableSpec("findings", "VIPR_FINDINGS_TABLE", "silk_id", True),
    TableSpec("assets", "VIPR_ASSETS_TABLE", "silk_id", True),
    # TableSpec("cves", "VIPR_CVES_TABLE", "cve", False),
    # TableSpec("evidence", "VIPR_EVIDENCE_TABLE", "id", False),
]


def _pull(client, warehouse_id, spec):
    table = os.getenv(spec.env_var)
    if not table:
        if spec.required:
            raise RuntimeError("%s not set" % spec.env_var)
        return spec.label, []
    # Every Vipr table carries __date/__hour: always filter to the latest batch.
    sql = "SELECT * FROM %s WHERE %s" % (table, latest_batch_clause(table))
    return spec.label, run_sql(client, warehouse_id, sql)


def extract_all(client, warehouse_id):
    with ThreadPoolExecutor(max_workers=len(TABLE_REGISTRY)) as ex:
        return dict(ex.map(lambda s: _pull(client, warehouse_id, s), TABLE_REGISTRY))


def merge(tables):
    """Findings drive scope. Assets indexed {silk_id: [rows]} (list, not last-wins)."""
    assets = {}
    for a in tables.get("assets", []):
        assets.setdefault(a.get("silk_id"), []).append(a)
    return [
        {"finding": f, "assets": assets.get(f.get("asset_silk_id"), [])}
        for f in tables.get("findings", [])
    ], tables.get("assets", [])
