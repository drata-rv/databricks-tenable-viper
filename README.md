# vipr-drata

Databricks Vipr tables -> one Drata Custom Connection. Each record has `recordType` `finding` or `asset`; ids are `finding:<silk_id>` / `asset:<silk_id>`.

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
Output in `./output`: `records.json`, `_rejected.json`, `_profile.json` (`_failed.json` on push errors).
`_profile.json` explains null fields: `tool_severity` keys/values seen, asset join outcomes, per-column null counts.

## Drata
1. Create one CUSTOM connection with `schemas/vipr_unified.schema.json`, display name key `displayName`.
2. Set `DRATA_CONNECTION_ID`, `DRATA_RESOURCE_ID` and `DRATA_API_KEY` (create/update scope).
3. Filter custom tests on `recordType`.
4. Prod: `DRATA_API_KEY_PROD` and `--drata-prod`.

## Databricks
Set `DATABRICKS_*` and `VIPR_*_TABLE` in `.env`. Optional `TENABLE_ASSETS_TABLE` adds Tenable scan evidence.

Deploy: bump `version` in `pyproject.toml`, then `databricks bundle deploy -t test|prod`. Prod needs `findings_table`, `assets_table`, `run_as` and `workspace.host` set.

## Scanner comparison
`scannerSeverity` is the `tool_severity` entry whose key contains `SCANNER_TOOL` (default `tenable`), compared with Vipr severity. Numeric tool values stay undetermined until `SCANNER_SEVERITY_MAP` maps them, e.g. `{"1":"low","2":"medium","3":"high","4":"critical"}`. Read the scale from `_profile.json` (`vipr_severity_by_tool_value`). `toolSeverities` always carries every raw tool rating (`rapid7_insight_vm-1=2`).

## Exit codes
`0` ok, `1` push failures, `2` guard abort (reject ratio, test tables with `--drata-prod`).
