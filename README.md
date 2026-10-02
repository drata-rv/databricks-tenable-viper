# vipr-drata

Databricks (Vipr tables) -> Drata vulnerability evidence. Architecture follows `docs/DATABRICKS_INTEGRATION_PLAYBOOK.md`; requirements in `docs/nationwide_vulnerability_connection_outcomes.md`.

Outputs per run: `vulnerability_findings` (Vipr severity vs Tenable scanner severity, ticket/SLA signals) and `asset_scan_coverage` (scan-freshness assurance). Each goes to its own Drata CUSTOM connection resource via `POST /public/v2/custom-connections/{conn}/resources/{res}/records` (`{"data": [...]}`, upsert on `id`, 100 records/batch; a 4xx batch is retried per record to isolate the bad one).

## Local
```
python3.12 -m venv .venv && . .venv/bin/activate && pip install -e '.[dev]'
cp .env.example .env   # fill in
pytest
vipr-drata --local     # initial testing: synthetic tables in ./local_data, no Databricks, no push
vipr-drata --local --push   # same, but push to the Drata *sandbox* connection (never prod)
vipr-drata --dry-run   # real Databricks (.env creds), extract + transform only
vipr-drata             # upsert push (sandbox unless DRATA_PROD=true)
vipr-drata --push-mode session   # atomic snapshot replace; completes only if 0 failures, else cancels
```

### Local mode
`--local` reads `findings.csv`, `assets.csv` and optionally `tenable_assets.csv` (or `.json`) from `--local-data`
(default `./local_data`, auto-generated with fake rows on first run, gitignored; delete to regenerate). Files use the
same columns as the real tables (`docs/*.xlsx`), including `__date/__hour`, so the latest-batch filter is exercised.
To test with your own rows, drop CSVs in the directory (arrays/maps as JSON strings, like the Databricks CSV export).
Outputs go to `./output`; inspect `findings.json`, `asset_scan_coverage.json`, `_rejected.json`.

Optional `TENABLE_ASSETS_TABLE` adds scanner-activity evidence: each Vipr asset is matched to a Tenable asset by exact
MAC, then exact hostname, only when exactly one Tenable asset matches (`tenableMatch` = matched/none/ambiguous);
anything else stays undetermined.

Schema contract: `tests/test_schema_contract.py` checks every pulled column and the default table names against
`docs/*.xlsx`. Duplicate ids in the latest batch are rejected to `_rejected.json`, never last-write-wins.
Schemas for creating the Drata connections are in `schemas/`.

## Deploy
Bump `version` in `pyproject.toml` every deploy, `python -m build --wheel`, `databricks bundle deploy -t test|prod`.

## Open items (not assumed)
- Create two CUSTOM connections in Drata (findings, asset scan coverage; `displayNameKey` = `displayName`, sample data = `output/*.json` from a dry run), then set the four `DRATA_*_CONNECTION_ID/RESOURCE_ID` vars. API key needs Custom Connections Data: create/update.
- Upsert never deletes records that disappear from Vipr; session mode does (hard delete). Pick per customer decision.
- Stale-scan threshold (`SCAN_STALE_DAYS=7`), SLA/ticket pass-fail rules: customer decisions pending.
- Tables are Vipr-only; Tenable raw tables (`docs/Tenable Tables.xlsx`) not yet pulled. Vipr `tool_severity` map key for Tenable is matched by substring "tenable" — verify against real rows.
- Verify column names/cardinality with live `DESCRIBE`/sample rows before prod.
