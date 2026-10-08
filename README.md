# vipr-drata

Databricks Vipr tables -> one Drata Custom Connection.

## Data model
Each run submits a small set of records (about 20 for small data, under 100 at 170k findings), never one record per finding:

| Record id | `recordType` | Content |
|---|---|---|
| `summary` | `summary` | counts, `generatedAt`, `sourceFresh`, per-table batch dates, `rejectedCount` |
| `findings-<lane>-000` ... | `findingBatch` | `severityLane` + `findings[]`, one item per finding |
| `assets-000` ... | `assetBatch` | `assets[]`, one item per asset |

Findings are grouped by Vipr severity lane (`critical high medium low info unknown`), then spread over batches by a stable hash of the finding id, so an item stays in the same record. Drata scores, lists and excludes per record, so a lane makes a failing record meaningful and lets tests target critical/high SLAs. Empty batches are still sent. Closed findings older than `CLOSED_LOOKBACK_DAYS` (90) are left out.

Batch counts: `FINDING_LANE_BUCKETS` (default `{"critical":1,"high":2,"medium":4,"low":4,"info":1,"unknown":1}`) and `ASSET_BUCKETS` (4) are minimums. They grow automatically in both push modes, in powers of two (max 256 per lane), so every record stays near `MAX_RECORD_BYTES`/2 (2 MB); nothing needs tuning. Each run prints the effective counts; when a lane sits near a power-of-two boundary, pin `FINDING_LANE_BUCKETS` to the printed numbers so record ids stop moving between nights.

Default push mode is `upsert`: fixed record ids are updated in place, nothing is deleted, no Drata session state is involved. `--push-mode session` stages all records, then atomically replace the dataset. Records not staged (old per-finding records, orphaned batches) are deleted. Any failure, including a failed `complete`, SIGINT or SIGTERM, cancels the session and leaves the previous data. Sessions of this tool older than 2 hours that were left `IN_PROGRESS` by a killed run are cancelled first; other sessions are never touched. The bundle sets `max_concurrent_runs: 1`. `--push-mode upsert` only updates and never deletes, so if batch counts shrink later the higher-numbered records keep stale items (use session mode).

Progress is printed step by step with elapsed time (`--quiet` hides it). If Drata does not attach staged records to the session (probe fails or `complete` returns 422 "no data records"), the run cancels the session and falls back to upsert, which leaves old records in place; start clean with a new custom connection.

Migrating from the old one-record-per-finding design: create a NEW custom connection from `schemas/vipr_unified.schema.json` and point `DRATA_CONNECTION_ID` / `DRATA_RESOURCE_ID` at it (upsert never deletes, so ~190k old `finding:*` / `asset:*` records would stay and bury the new ones; the push prints a note when it sees them).

Reference run, 170k findings + 21k assets: 78 records, ~91 MB, largest record 1.6 MB, 28 requests (list, 26 stage, complete), ~12 s, ~0.6 GB memory (`--local --local-rows 170000`).
Aborts (exit 2) before pushing if a record exceeds `MAX_RECORD_BYTES` (4 MB on the wire, max 4.5 MB; Drata limit 5 MB), if fewer than `MIN_FINDINGS`/`MIN_ASSETS` remain after the closed-finding lookback (an empty source would make every array test pass), or if rejected/total exceeds the reject ratio.

## Setup
Python 3.10+ (create the venv with an explicit `python3.12`/`python3.11`/`python3.10` if your default `python3` is older). Run everything from the repo root; `.env` lives there.
```
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
pytest
```

## Run
```
vipr-drata --local                    # synthetic data in ./local_data, no Databricks, no push
vipr-drata --local --local-rows 170000   # volume check (data in ./local_data/scale): records, sizes
vipr-drata --local --push             # pushes SYNTHETIC data to the configured resource
vipr-drata --dry-run                  # real Databricks, no push
vipr-drata                            # push (sandbox unless --drata-prod)
vipr-drata --push-mode session        # atomic replace; deletes records not in this run
```
Output in `./output`: `records.json` (exactly what is submitted), `_rejected.json`, `_profile.json` (`_failed.json` on push errors).
`_profile.json` explains null fields: `raw_tool_severity` (keys/values seen, `vipr_severity_by_tool_value`), asset join outcomes, per-column null counts.
Tunables (env vars, blank = default; see `.env.example`; all reach the Databricks job): `FINDING_LANE_BUCKETS` (lane minimums, 1-256 each), `ASSET_BUCKETS` (4, 1-256), `CLOSED_LOOKBACK_DAYS` (90), `MAX_SOURCE_AGE_DAYS` (3), `MAX_RECORD_BYTES` (4000000, 100000-4500000), `MIN_FINDINGS` / `MIN_ASSETS` (1), `MAX_REJECT_RATIO` (0.05; 0-1; off with `--local`), `SCAN_STALE_DAYS` (7).

## Drata
1. Create one CUSTOM connection with `schemas/vipr_unified.schema.json`, display name key `displayName`.
2. Set `DRATA_CONNECTION_ID`, `DRATA_RESOURCE_ID` and `DRATA_API_KEY` (create/update scope).
3. Prod: `DRATA_API_KEY_PROD` and `--drata-prod`.

Custom tests (Advanced editor). SLA for critical and high findings: filtering criteria, Inclusion:
```json
{"all":[{"fact":"recordType","operator":"equal","value":"findingBatch"},
        {"any":[{"fact":"severityLane","operator":"equal","value":"critical"},
                {"fact":"severityLane","operator":"equal","value":"high"}]}]}
```
Condition (every open finding within SLA):
```json
{"all":[{"fact":"findings","operator":"all","value":{"any":[
  {"fact":"open","operator":"equal","value":false},
  {"fact":"slaBreached","operator":"equal","value":false}]}}]}
```
Freshness: filter `recordType` equal `summary`; condition `sourceFresh` equal `true` (source data age at push time) plus `generatedAt` Within Last (Days) 2 (the nightly job ran).

## Databricks
Set `DATABRICKS_{HOST,TOKEN,CLIENT_ID,CLIENT_SECRET}_{TEST|PROD}` (chosen by `--workspace`), `DATABRICKS_WAREHOUSE_ID` and `VIPR_FINDINGS_TABLE` / `VIPR_ASSETS_TABLE` in `.env`. Optional `TENABLE_ASSETS_TABLE` adds Tenable scan evidence.

Deploy: bump `version` in `pyproject.toml`, then `databricks bundle deploy -t test|prod`. Prod needs `findings_table`, `assets_table`, `run_as` and `workspace.host` set.

## Scanner comparison
`scannerSeverity` is the `tool_severity` entry whose key contains `SCANNER_TOOL` (default `tenable`), compared with Vipr severity. Numeric tool values stay undetermined until `SCANNER_SEVERITY_MAP` maps them, e.g. `{"1":"low","2":"medium","3":"high","4":"critical"}`. Read the scale from `_profile.json` (`vipr_severity_by_tool_value`). `toolSeverities` always carries every raw tool rating (`rapid7_insight_vm-1=2`).

## Exit codes
`0` ok, `1` push or Databricks extraction failure, `2` config or guard abort (missing or invalid settings, too few items, oversized record, reject ratio, test tables with `--drata-prod`), `130` interrupted (SIGINT/SIGTERM).
Previous `records.json`, `_profile.json`, `_rejected.json` and `_failed.json` are deleted at the start of each run, so what is on disk always belongs to the last run.
