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

Optional `TENABLE_ASSETS_TABLE` adds scanner-activity evidence. A Vipr asset is `matched` to a Tenable asset only when
normalised MAC and/or exact non-generic hostname point to exactly one Tenable asset, that asset is claimed by no other
Vipr asset, its id appears once, and MAC/hostname agree. Otherwise `ambiguous`/`none`; an empty Tenable batch is `no_data`
(never "unscanned"), unconfigured is `not_configured`. `viprLastSeenStale` is *Vipr's* last_seen, not scanner activity;
`tenableScanStale` (from Tenable `last_scan_time`) is the scanner-assurance signal.

Undetermined, never guessed: unknown severity vocab, conflicting Tenable keys, unparseable SLA dates and null
open/has_ticket flags yield `null` (schemas allow it).

Schema contract: `tests/test_schema_contract.py` checks every pulled column and the default table names against
`docs/*.xlsx`. Duplicate ids in the latest batch are rejected to `_rejected.json`, never last-write-wins.
Schemas for creating the Drata connections are in `schemas/`.

## Safety guards (non-local runs)
- Exit codes: `0` ok, `1` push failures (job fails), `2` config/guard abort. `--env KEY=VALUE` / `--env=KEY=VALUE` feed job params into the environment.
- Aborts before pushing if rejected/total > `--max-reject-ratio` (default 0.05).
- `--push-mode session` hard-deletes records not staged: refused for a resource with any rejected records, for an empty snapshot, and cancelled on any staging failure.
- `--drata-prod` needs `DRATA_API_KEY_PROD` (never falls back to the sandbox key) and refuses `*test_catalog*` source tables unless `--allow-test-source-with-prod`.
- 401/403/404 from Drata stop the run immediately; 400/413/422 on a batch retries per record to isolate the bad one.

## Deploy
Bump `version` in `pyproject.toml` every deploy, then `databricks bundle deploy -t test|prod` (the bundle cleans `build/` and `dist/` and builds the wheel). Prod leaves `findings_table`/`assets_table` empty so it fails closed until Nationwide confirms prod Vipr tables; set `workspace.host` per target and `run_as` for prod before deploying.

## Open items (not assumed)
- Create two CUSTOM connections in Drata (findings, asset scan coverage; `displayNameKey` = `displayName`, sample data = `output/*.json` from a dry run), then set the four `DRATA_*_CONNECTION_ID/RESOURCE_ID` vars. API key needs Custom Connections Data: create/update.
- Upsert never deletes records that disappear from Vipr; session mode does (hard delete). Pick per customer decision.
- Stale-scan threshold (`SCAN_STALE_DAYS=7`), SLA/ticket pass-fail rules: customer decisions pending.
- Vipr `tool_severity` Tenable key is matched by substring "tenable" and values must be info/low/medium/high/critical (else undetermined) — verify against real rows. Array/map columns are parsed as JSON (with a bracket fallback); confirm how the Databricks CSV export renders them.
- Verify column names/cardinality with live `DESCRIBE`/sample rows before prod.
