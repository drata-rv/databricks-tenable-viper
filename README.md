# vipr-drata

Databricks Vipr vulnerability tables to one Drata Custom Connection resource.

## Records

A run submits a fixed set of records, never one per finding.

| Record id | `recordType` | Content |
|---|---|---|
| `vipr-summary` | `scanSummary` | freshness, counts, source dates |
| `vipr-findings-<severity>-NNN` | `findingPartition` | one severity, counts, `findings[]` |
| `vipr-assets-NNN` | `assetPartition` | counts, `assets[]` |

Severities: `critical high medium low info unknown`. NNN starts at 001. Items are assigned to a partition by a stable hash of their id. Empty partitions are still sent. Partition counts grow in powers of two to keep each record near half of `MAX_RECORD_BYTES`. Closed findings older than `CLOSED_LOOKBACK_DAYS` are omitted.

Every record carries `generatedAt`, `sourceAsOf`, `sourceAgeDays` and `sourceFresh`. Partition records carry scalar counts (`openSlaBreachedCount`, `openMissingTicketCount`, `staleAssetCount`) for the guided test builder; the arrays serve Advanced-editor tests.

Schema: [`schemas/vipr_unified.schema.json`](schemas/vipr_unified.schema.json). Tests: [`custom-tests/README.md`](custom-tests/README.md).

## Setup

Python 3.10+, from the repo root.

```
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
pytest
```

## Run

```
vipr-drata --local                       # synthetic data, no Databricks, no push
vipr-drata --local --local-rows 170000   # volume check
vipr-drata --dry-run                     # Databricks, no push
vipr-drata                               # push (sandbox unless --drata-prod)
vipr-drata --push-mode session           # atomic replace
```

Output in `./output`: `_run.log`, `records.json`, `_profile.json`, `_rejected.json`, `_failed.json` (on push errors). Log lines: `<UTC timestamp> <LEVEL> <component> <event> key=value`; INFO to stdout, WARN and ERROR to stderr, `--quiet` suppresses INFO.

## Configuration

Environment variables; blank means default. All reach the Databricks job.

| Variable | Default | Meaning |
|---|---|---|
| `DRATA_PUSH_MODE` | `upsert` | `upsert` updates in place and never deletes; `session` replaces the dataset atomically |
| `FINDING_PARTITIONS` | `{"critical":1,"high":2,"medium":4,"low":4,"info":1,"unknown":1}` | minimum partitions per severity, 1-256 |
| `ASSET_PARTITIONS` | `4` | minimum asset partitions, 1-256 |
| `MAX_RECORD_BYTES` | `4000000` | record size limit, 100000-4500000 |
| `CLOSED_LOOKBACK_DAYS` | `90` | closed findings older than this are omitted |
| `MAX_SOURCE_AGE_DAYS` | `3` | `sourceFresh` is false when the oldest source table is older |
| `SCAN_STALE_DAYS` | `7` | asset staleness window |
| `MIN_FINDINGS`, `MIN_ASSETS` | `1` | abort when fewer remain after the lookback |
| `MAX_REJECT_RATIO` | `0.05` | abort when rejected/total exceeds it; off with `--local` |
| `SCANNER_TOOL` | `tenable` | `tool_severity` key compared with Vipr severity |
| `SCANNER_SEVERITY_MAP` | | JSON map of numeric tool values, e.g. `{"1":"low","2":"medium"}` |
| `TENABLE_ASSETS_TABLE` | | optional Tenable scan evidence |

## Drata

1. Create a Custom connection from `schemas/vipr_unified.schema.json`; display name key `displayName`.
2. Set `DRATA_CONNECTION_ID`, `DRATA_RESOURCE_ID`, `DRATA_API_KEY` (`DRATA_API_KEY_PROD` with `--drata-prod`).
3. Build the tests in [`custom-tests/README.md`](custom-tests/README.md).

Resource id: `GET /public/v2/custom-connections/{id}?expand[]=customResources`, `customResources[0].id`.

A resource schema that requires fields the records lack aborts the run before sending (exit 2). Upgrading from 0.13 or earlier renames fields: edit the resource schema in Drata and paste the schema file before building tests, or use a new connection. Records from earlier versions are not removed by upsert; run once with `--push-mode session` or use a new connection.

## Databricks

Set `DATABRICKS_{HOST,TOKEN,CLIENT_ID,CLIENT_SECRET}_{TEST|PROD}`, `DATABRICKS_WAREHOUSE_ID`, `VIPR_FINDINGS_TABLE` and `VIPR_ASSETS_TABLE` in `.env`.

Deploy: bump `version` in `pyproject.toml`, then `databricks bundle deploy -t test|prod`. Prod needs `findings_table`, `assets_table`, `run_as` and `workspace.host`.

`_profile.json` explains null fields: tool severity keys and values, asset join outcomes, null counts.

## Exit codes

`0` ok, `1` push or extraction failure, `2` configuration or guard abort, `130` interrupted.
