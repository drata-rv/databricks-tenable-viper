# vipr-drata

Databricks Vipr tables -> Drata Custom Connections (findings + asset scan coverage).

## Setup
```
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
pytest
```

## Run
```
vipr-drata --local                    # synthetic data in ./local_data, no Databricks, no push
vipr-drata --local --push             # same, push to Drata sandbox
vipr-drata --dry-run                  # real Databricks, no push
vipr-drata                            # push (sandbox unless --drata-prod)
vipr-drata --push-mode session        # atomic replace; default is upsert
```
Output in `./output`: `findings.json`, `asset_scan_coverage.json`, `_rejected.json`.

## Drata
1. Create two CUSTOM connections using `schemas/*.schema.json`, display name key `displayName`.
2. Set `DRATA_{FINDINGS,ASSETS}_{CONNECTION,RESOURCE}_ID` and `DRATA_API_KEY` (create/update scope).
3. Prod: `DRATA_API_KEY_PROD` and `--drata-prod`.

## Databricks
Set `DATABRICKS_*` and `VIPR_*_TABLE` in `.env`. Optional `TENABLE_ASSETS_TABLE` adds Tenable scan evidence.

Deploy: bump `version` in `pyproject.toml`, then `databricks bundle deploy -t test|prod`. Prod needs `findings_table`, `assets_table`, `run_as` and `workspace.host` set.

## Exit codes
`0` ok, `1` push failures, `2` guard abort (reject ratio, test tables with `--drata-prod`).
