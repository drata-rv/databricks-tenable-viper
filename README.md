# vipr-drata

Databricks (Vipr tables) -> Drata vulnerability evidence. Architecture follows `docs/DATABRICKS_INTEGRATION_PLAYBOOK.md`; requirements in `docs/nationwide_vulnerability_connection_outcomes.md`.

Outputs per run: `vulnerability_findings` (Vipr severity vs Tenable scanner severity, ticket/SLA signals) and `asset_scan_coverage` (scan-freshness assurance). Each goes to its own Drata CUSTOM connection resource via `POST /public/v2/custom-connections/{conn}/resources/{res}/records` (`{"data": [...]}`, upsert on `id`, 100 records/batch; a 4xx batch is retried per record to isolate the bad one).

## Local
```
python3.12 -m venv .venv && . .venv/bin/activate && pip install -e '.[dev]'
cp .env.example .env   # fill in
pytest
vipr-drata --dry-run   # extract + transform only
vipr-drata             # upsert push (sandbox unless DRATA_PROD=true)
vipr-drata --push-mode session   # atomic snapshot replace; completes only if 0 failures, else cancels
```

## Deploy
Bump `version` in `pyproject.toml` every deploy, `python -m build --wheel`, `databricks bundle deploy -t test|prod`.

## Open items (not assumed)
- Create two CUSTOM connections in Drata (findings, asset scan coverage; `displayNameKey` = `displayName`, sample data = `output/*.json` from a dry run), then set the four `DRATA_*_CONNECTION_ID/RESOURCE_ID` vars. API key needs Custom Connections Data: create/update.
- Upsert never deletes records that disappear from Vipr; session mode does (hard delete). Pick per customer decision.
- Stale-scan threshold (`SCAN_STALE_DAYS=7`), SLA/ticket pass-fail rules: customer decisions pending.
- Tables are Vipr-only; Tenable raw tables (`docs/Tenable Tables.xlsx`) not yet pulled. Vipr `tool_severity` map key for Tenable is matched by substring "tenable" — verify against real rows.
- Verify column names/cardinality with live `DESCRIBE`/sample rows before prod.
