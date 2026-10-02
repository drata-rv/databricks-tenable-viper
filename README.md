# vipr-drata

Databricks (Vipr tables) -> Drata vulnerability evidence. Architecture follows `docs/DATABRICKS_INTEGRATION_PLAYBOOK.md`; requirements in `docs/nationwide_vulnerability_connection_outcomes.md`.

Outputs per run: `vulnerability_findings` (Vipr severity vs Tenable scanner severity, ticket/SLA signals) and `asset_scan_coverage` (scan-freshness assurance). Both upsert on `externalId`.

## Local
```
python3.12 -m venv .venv && . .venv/bin/activate && pip install -e '.[dev]'
cp .env.example .env   # fill in
pytest
vipr-drata --dry-run   # extract + transform only
vipr-drata             # push (sandbox unless DRATA_PROD=true)
```

## Deploy
Bump `version` in `pyproject.toml` every deploy, `python -m build --wheel`, `databricks bundle deploy -t test|prod`.

## Open items (not assumed)
- Drata push endpoint/payload: `DRATA_PUSH_PATH` and record shape are placeholders; confirm against the Drata custom connection API.
- Stale-scan threshold (`SCAN_STALE_DAYS=7`), SLA/ticket pass-fail rules: customer decisions pending.
- Tables are Vipr-only; Tenable raw tables (`docs/Tenable Tables.xlsx`) not yet pulled. Vipr `tool_severity` map key for Tenable is matched by substring "tenable" — verify against real rows.
- Verify column names/cardinality with live `DESCRIBE`/sample rows before prod.
