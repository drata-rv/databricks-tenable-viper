"""--local mode: read source tables from local CSV/JSON files shaped like the Databricks tables.

CSV cells follow the same round trip as run_sql() (strings, "null" -> None); the latest-batch
filter is applied here too so fixtures exercise it.
"""
import csv
import json
import os

from ..db.queries import _clean
from .extract import TABLE_REGISTRY


def _latest_batch(rows):
    if not any(r.get("__date") for r in rows):
        return rows
    def hour(r):
        try:
            return int(float(r.get("__hour") or 0))
        except ValueError:
            return 0
    d = max(r["__date"] for r in rows if r.get("__date"))
    rows = [r for r in rows if r.get("__date") == d]
    h = max(hour(r) for r in rows)
    return [r for r in rows if hour(r) == h]


def _read(path):
    if path.endswith(".json"):
        with open(path) as f:
            return json.load(f)
    with open(path, newline="") as f:
        return [{k: _clean(v) for k, v in row.items()} for row in csv.DictReader(f)]


def load_local_tables(directory):
    out = {}
    for spec in TABLE_REGISTRY:
        path = next((p for p in (os.path.join(directory, spec.label + e) for e in (".csv", ".json"))
                     if os.path.exists(p)), None)
        if path is None:
            if spec.required:
                raise FileNotFoundError("missing %s.csv/.json in %s (run scripts/generate_local_data.py)"
                                        % (spec.label, directory))
            continue
        out[spec.label] = _latest_batch(_read(path))
    return out
