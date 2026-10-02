"""SQL Statement Execution API pull: EXTERNAL_LINKS + CSV, chunked, polled."""
import csv
import io
import time

import requests


def _clean(v):
    return None if v is None or v == "null" or v == "" else v


def rows_to_records(columns, rows):
    return [{c: _clean(v) for c, v in zip(columns, r)} for r in rows]


def is_true(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in ("true", "1", "t", "yes")


def _download(url, chunk_index):
    """Fetch one result chunk. Errors never carry the pre-signed URL (it is a short-lived credential)."""
    try:
        r = requests.get(url, timeout=300)
        r.raise_for_status()
    except requests.RequestException as e:
        status = getattr(getattr(e, "response", None), "status_code", None)
        raise RuntimeError("result chunk %s download failed (%s)" % (chunk_index, status or type(e).__name__)) from None
    return r.content.decode("utf-8-sig")


def run_sql(client, warehouse_id, sql, timeout_s=1800):
    from databricks.sdk.service.sql import Disposition, Format, StatementState

    resp = client.statement_execution.execute_statement(
        statement=sql, warehouse_id=warehouse_id, wait_timeout="50s",
        disposition=Disposition.EXTERNAL_LINKS, format=Format.CSV,
    )
    deadline = time.time() + timeout_s
    while resp.status.state in (StatementState.PENDING, StatementState.RUNNING):
        if time.time() > deadline:
            raise TimeoutError("statement %s timed out" % resp.statement_id)
        time.sleep(2)
        resp = client.statement_execution.get_statement(resp.statement_id)
    if resp.status.state != StatementState.SUCCEEDED:
        raise RuntimeError("SQL failed: %s" % (resp.status.error,))
    columns = [c.name for c in resp.manifest.schema.columns]
    records = []
    chunk = resp.result
    while chunk is not None:
        for link in chunk.external_links or []:
            rows = list(csv.reader(io.StringIO(_download(link.external_link, chunk.chunk_index))))
            if rows and [c.lower() for c in rows[0]] == [c.lower() for c in columns]:
                rows = rows[1:]  # header row present only on some chunks/configs
            records.extend(rows_to_records(columns, rows))
        if chunk.next_chunk_index is None:
            break
        chunk = client.statement_execution.get_statement_result_chunk_n(
            resp.statement_id, chunk.next_chunk_index
        )
    return records


def latest_batch_clause(table):
    return (
        "__date = (SELECT MAX(__date) FROM {t}) AND __hour = "
        "(SELECT MAX(__hour) FROM {t} WHERE __date = (SELECT MAX(__date) FROM {t}))"
    ).format(t=table)
