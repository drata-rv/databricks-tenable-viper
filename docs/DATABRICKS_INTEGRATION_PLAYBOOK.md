# Databricks Integration Playbook

How the SCCM → Drata device-compliance integration was built, so a new engineer building a
**Tenable → \<destination\>** Databricks integration can reuse the architecture instead of
rediscovering the same failure modes. Written from this project's real build history —
every "lesson learned" below is a real incident that happened on this project, not a
hypothetical.

This repo's actual code is the reference implementation. Line numbers aren't quoted here
since they drift; file names are stable.

---

## 1. What this integration does, in one paragraph

Pull a handful of SCCM tables from a Databricks Unity Catalog metastore via the SQL
Statement Execution REST API (no Spark job, no cluster), join them in Python on a shared key,
derive a small set of boolean compliance signals from the raw columns, shape the result into
the destination API's expected JSON, and push it record-by-record with retries. The same
Python code runs two ways: as a local CLI against `.env` credentials, and as a native
Databricks Job (`python_wheel_task`) deployed via a Databricks Asset Bundle. Same code path,
two credential sources — nothing else differs.

A Tenable integration is structurally the same shape: pull Tenable-ingested tables from
Databricks, join, transform into whatever the destination system's API wants, push. Almost
everything below carries over unchanged; only the actual table names, columns, and
destination-shape logic are new.

---

## 2. Architecture at a glance

```
Databricks Unity Catalog (SQL Statement Execution API)
        │
        ▼
  db/queries.py::run_sql()  ──  EXTERNAL_LINKS + CSV disposition, chunked fetch
        │
        ▼
  etl/extract_devices.py::TABLE_REGISTRY  ──  one entry per source table, pulled in parallel
        │
        ▼
  merge()  ──  anchor table drives scope; everything else indexed by a shared key and joined in Python
        │
        ▼
  db/transform.py::extract_features()  ──  raw columns → booleans/signals (all the business logic lives here)
        │
        ▼
  db/transform.py::format_for_drata()  ──  signals → destination API's JSON shape (pure mapping, no logic)
        │
        ▼
  db/drata_client.py  ──  push client: retry budgets, rate-limit handling, parallel push, upsert key
```

Runs identically locally (`.env`) and as a Databricks Job (secret scope + `--env` job
parameters) — see §3 and §5.

---

## 3. Authentication

### 3.1 Credential resolution chain (`db/secrets.py`, `db/auth.py`)

One function, `get_secret(name, *, scope=None, env_var=None, required=True)`, is the only
place that knows "where do credentials come from":

- **Locally**: `os.getenv(env_var)`, loaded from `.env` via `python-dotenv`.
- **Inside a Databricks Job**: `dbutils.secrets.get(scope=scope, key=name)` via the SDK's
  `WorkspaceClient`. Detected by checking for the `DATABRICKS_RUNTIME_VERSION` env var, which
  every Databricks cluster/serverless runtime sets automatically — more reliable than
  checking for `dbutils`, which isn't ambiently available in a `python_wheel_task` the way it
  is in a notebook.
- **`required=False`** matters: a missing key on Databricks **raises** by default — the
  deliberate, correct failure mode for a credential the pipeline can't run without. But a
  genuinely optional value (e.g. a custom API host override) needs `required=False` to
  return `None` on a missing key instead of crashing. Get this wrong in either direction and
  you either silently run with blank credentials, or hard-fail on something that was never
  required. (This project shipped the wrong-direction bug once — see §7.)

`db/auth.py::get_client_for_env(workspace)` layers workspace selection on top: it resolves
`databricks-host-{workspace}`, `databricks-client-id-{workspace}` /
`databricks-client-secret-{workspace}` (OAuth M2M), falling back to
`databricks-token-{workspace}` (PAT) if no OAuth pair is set. **Try OAuth first, PAT as
fallback** — many enterprise customers' security policy prefers service-principal OAuth over
long-lived personal access tokens, but PAT keeps local dev working without a provisioned
service principal.

### 3.2 Per-workspace secret scopes, not one shared scope

Assume the customer provisions **one secret scope per workspace** (e.g. one for a test/dev
workspace, a separate one for prod) rather than a single shared scope — that was true here
and is a common enterprise pattern. `DATABRICKS_SECRET_SCOPE_PROD` / `_TEST` resolve
independently; a shared `DATABRICKS_SECRET_SCOPE` is a reasonable fallback default but don't
assume it'll be true in prod.

**Real incident**: the prod target's scope default was inherited from the dev target's
top-level default — which pointed at the *test* workspace's scope name. Deploying to prod hit
`PERMISSION_DENIED` on `secrets.get` because the prod service principal has no access to a
scope that only exists in the test workspace. Fix: the prod *target* in the bundle config
must explicitly override the scope-name variable — never let it fall through to a top-level
default that was written with dev in mind. **When you add a new per-workspace variable,
immediately ask: does every target override this, or does at least one silently inherit the
wrong default?**

### 3.3 Service principal (`run_as`) setup — the parts that are easy to half-do

If the job runs as a service principal (`databricks.yml`'s `run_as.service_principal_name`),
there are **four separate steps**, each independently necessary:

1. Create the SP at the account level, **and separately assign it to the specific
   workspace** (account console → Workspaces → *workspace* → Permissions). A correctly
   created SP that was never assigned to the workspace looks identical to a misconfigured one
   until you try to run something.
2. `run_as.service_principal_name` in the bundle config wants the **Application ID (a UUID)**,
   not the display name, despite the field's name.
3. Whoever/whatever runs `databricks bundle deploy` needs `CAN_USE` granted **on the service
   principal object itself** (not the job, not the workspace) — a separate permission surface
   that's easy to miss since it's not where you'd naturally look.
4. The SP's own OAuth credentials (`databricks-client-id-prod` / `databricks-client-secret-prod`)
   still need to land in the secret scope for the *running job* to authenticate — step 2 only
   covers who can *deploy*, not what the job authenticates as once running.

Missing any one of the four produces a deploy-time or run-time failure that looks unrelated
to service principals at first glance.

### 3.4 Workspace root path for a service-principal-run job

A bundle's default workspace root path is under the deploying human's own
`/Workspace/Users/<them>/...`, which the `run_as` service principal has no read access to —
deploy succeeds but the job fails trying to install its own wheel ("Library installation
failed... file does not exist or the user does not have permission to read the library
file"). Fix: set `targets.<prod-target>.workspace.root_path` to a `/Shared/...` path instead,
which both the deploying human and the `run_as` SP can read.

---

## 4. Pulling data from Databricks

### 4.1 No Spark job — the SQL Statement Execution REST API

This integration does zero Spark distribution. `db/queries.py::run_sql()` calls
`client.statement_execution.execute_statement()` with `disposition=EXTERNAL_LINKS,
format=Format.CSV` — Databricks writes results to cloud storage and hands back pre-signed
URLs, which this process downloads directly with `requests`. **Use `EXTERNAL_LINKS`, not
`INLINE`** — inline results are capped (25 MB here) and fail silently-ish on any
real-sized table. Poll `get_statement()` until `SUCCEEDED`, respecting the ~50s server-side
wait cap by looping client-side for anything longer, and handle multi-chunk results via
`next_chunk_index`.

**CSV nulls aren't Python `None`** — a CSV cell literally containing the string `"null"`
needs to be converted back to `None` after parsing (`rows_to_records()`'s `_clean()`). Easy to
miss and easy to get silently wrong (a string `"null"` is truthy).

### 4.2 Table registry pattern — make adding a new table a one-line change

`TABLE_REGISTRY` is a list of `TableSpec(label, env_var, client_key, filter_type, required,
batched)` namedtuples. Adding a new source table is: set an env var, uncomment one line.
Nothing else in the pipeline needs to change — the generic pull/merge/feature-extraction code
already handles it via the registry. **Build the Tenable integration's table list the same
way from day one** — it's what made six months of incrementally adding tables (encryption,
computer system, antivirus, firewall, screen lock...) a one-line change each time instead of
a new code path each time.

### 4.3 Raw landing tables need an explicit "latest batch" filter

If the customer's data lake ingests a source system's tables as periodic snapshots (common
with Fivetran-style or custom ingestion into tables carrying `__date`/`__hour`/`__ingest_ts`/
`__row_hash` columns), **every one of those tables accumulates one copy of every row per
ingestion batch, forever**, unless you filter to the latest batch explicitly:

```sql
AND __date = (SELECT MAX(__date) FROM table)
AND __hour = (SELECT MAX(__hour) FROM table WHERE __date = (SELECT MAX(__date) FROM table))
```

**Real incident**: this was applied to six of seven source tables early on, and the seventh
(the personnel/user table) was missed — its row count silently grew every day for weeks
before anyone noticed the production push had started covering far fewer people than
expected. **Don't assume a table is "probably fine" because it wasn't flagged initially —
check every single source table for these ingestion-metadata columns before writing its
pull query**, not just the ones that were obviously log-like.

### 4.4 Verify real cardinality before writing a "one row per entity" join

This is the single most expensive lesson from this project, and it recurred **three separate
times** on three different tables before the pattern was recognized:

A source table that looks like "one row per device" from its name often isn't:
- A device inventory table pulling Windows Update policy is genuinely one row per device.
- A device inventory table pulling *desktop/profile settings* is one row **per local Windows
  profile on that device** (SYSTEM, every service account, and the actual user each get a
  row) — picking "the" row without filtering to the real user's profile silently reads a
  service account's settings instead.
- A device inventory table pulling *disk encryption status* is one row **per volume/partition**
  (C:, D:, a recovery partition) — picking "the" row without filtering to the boot volume
  silently reads an arbitrary other partition's encryption state.
- A table pulling *network adapters* is one row per NIC (Ethernet, WiFi, Bluetooth, VPN) for
  the same reason.

The code pattern that broke each time: indexing a joined table into `{resource_id: row}` (a
single dict, last-row-wins, no tiebreak) when the real data has more than one legitimate row
per key. The fix is always the same shape: index into `{resource_id: [rows]}` and have the
feature-extraction step select the *correct* row by an explicit, justified criterion (the
device's own logged-in username, the boot drive letter) — and **return "undetermined," not an
arbitrary row's value, when that correct row can't be identified.** Confidently wrong is
worse than honestly unknown.

**Before wiring any new source table into a join, ask: is this genuinely one row per entity, or could the same entity legitimately have more than one row for a structural reason (multiple volumes, multiple profiles, multiple adapters, multiple installed products)?** Check a few real rows for one entity before assuming either answer.

### 4.5 Anchor on the authoritative identity source, not a copy of it

This pipeline originally anchored its personnel list on the endpoint-management system's own
user table (an SCCM-side copy of user identity). That table's own identity fields stopped
reflecting reality (quietly out of sync with the customer's real headcount) long before
anyone noticed, because nothing cross-checked it against anything else. The fix was
re-anchoring personnel on the customer's actual authoritative IAM/HR source table (available
in the same data lake) and using the endpoint-management table only as a *bridge* (to map an
authoritative employee ID to whatever device-login username the endpoint system tracks).

**For Tenable: don't assume Tenable's own asset/user records are the authoritative identity
source either** — check whether the customer has a real IAM/HR table in the same catalog and
anchor personnel-linked logic there if so, using Tenable's own tables only for what they're
actually authoritative for (vulnerability/scan/asset data itself).

### 4.6 Column names are not consistent across tables from the same source system

Different tables ingested from the very same source system can use different column-naming
conventions from each other (`PascalCase` vs `snake_case`, with-or-without underscores before
trailing digits) — don't assume consistency. **Verify every column name against a real,
current `DESCRIBE TABLE` output before writing a lookup that depends on it being spelled a
particular way** — a stale schema doc (even one that was accurate a few months ago) is not
sufficient. When genuine uncertainty remains, a case-insensitive lookup helper that checks
exact-match first costs nothing and prevents an entire class of silent-wrong-value bugs:

```python
def _ci_get(d, key):
    if key in d:
        return d[key]
    lowered = key.lower()
    for k, v in d.items():
        if k.lower() == lowered:
            return v
    return None
```

### 4.7 CSV round-trip boolean gotcha

A genuine Databricks `boolean` column comes back through `run_sql()`'s CSV path as the
*string* `"true"`/`"false"`, not a Python `bool` — and `bool("false")` is `True` in Python.
Every boolean-looking column needs an explicit string-aware coercion, not a bare `if row.get(col):`:

```python
def _is_true(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in ('true', '1', 't', 'yes')
```

### 4.8 Chunked processing + crash recovery

For a large population, process in fixed-size chunks (500 users here) rather than one giant
query — keeps per-query result sizes and memory bounded, and lets a failure partway through
still have something to show for it. Register an `atexit` handler that flushes whatever's
been merged/transformed so far to disk if the process exits abnormally mid-run (a required
table exhausting retries, an uncaught exception) — without it, a multi-hour run's entire
output is lost on any failure near the end, including hours of already-completed Databricks
query time. Push targets that upsert on a stable external ID make "fix the failure and
re-run from the start" safe — no special resume logic needed if the destination API is
already idempotent on your chosen key.

---

## 5. Deploying as a native Databricks Job (serverless `python_wheel_task`)

### 5.1 Serverless has no environment-variable injection, at any level

This is the single most important platform fact for this entire architecture, confirmed
directly against Databricks' own docs: serverless `python_wheel_task` has no
`spark_env_vars`-equivalent mechanism — not at the job level, task level, or environment-spec
level. Job/task **parameters** (i.e., CLI arguments to your wheel's entry point) are the only
channel into the running process.

**The fix that makes the rest of this codebase portable**: a repeatable `--env KEY=VALUE`
CLI flag, applied to `os.environ` *before* anything else (including argparse's own defaults)
reads any config:

```python
def _apply_cli_env_overrides():
    argv = sys.argv[1:]
    i = 0
    while i < len(argv):
        if argv[i] == "--env" and i + 1 < len(argv):
            key, sep, value = argv[i + 1].partition("=")
            if sep:
                os.environ[key] = value
            i += 2
        else:
            i += 1
```

Every table path, warehouse ID, and secret-scope *name* (never scope contents) flows through
this flag from a bundle job parameter. The rest of the codebase keeps calling `os.getenv()`
exactly as it always did — **nothing downstream needs to know it's running on serverless.**
Build this in from the start of the Tenable integration; retrofitting it after the fact (as
happened here) means rediscovering the "serverless ignores my env vars" failure the hard way
first.

### 5.2 Wheel versioning is manual, and must be bumped every time

Serverless compute caches the built environment by dependency spec / version string. **Bump
`pyproject.toml`'s `version` before every deploy that changes wheel code or dependencies** —
otherwise it silently keeps running the old wheel with no error, and you'll debug a "fix"
that was never actually deployed.

**Do not use `dynamic_version: true`** to automate this. It hits a real, unfixed Databricks
CLI bug (`databricks/cli#2784`, closed "not planned"): combined with a glob path in
`environments.spec.dependencies` (`./dist/*.whl`), the CLI can deploy two wheels — one
correctly version-bumped, one stale — and silently select the stale one. Manual version
bumps are more reliable than this specific piece of automation today.

### 5.3 Vendor your dependency wheels if PyPI isn't reachable from serverless compute

If the customer's serverless compute doesn't have open PyPI egress (common in locked-down
enterprise environments), commit pre-downloaded wheels for the full dependency closure and
reference them directly in `environments.spec.dependencies` instead of letting pip resolve
from PyPI at deploy time.

Hard-won specifics that will very likely recur on any new integration against the same
platform:

- **Confirm the actual Python version serverless compute runs, from a real error or by
  printing `sys.version` in a minimal task** — don't trust the public docs' `client` version
  mapping. It was wrong here (documented as 3.10, actually 3.12).
- **Pin `--only-binary=:all:`** when downloading vendor wheels, or pip may fall back to a
  source tarball with no prebuilt wheel, which can't build without a C compiler on serverless.
- **Never vendor a newer `protobuf` than whatever serverless pre-installs** — overwriting it
  breaks the platform's own Python kernel bootstrap outright. Check what's actually
  pre-installed on a real run before vendoring anything that touches it.
- **Hard-pin (not range-pin) any dependency whose transitive requirements could silently
  conflict with something the platform pre-installs** (here: `databricks-sdk` and
  `google-auth`, both of which have had versions that pulled in a `protobuf`/`cryptography`
  requirement incompatible with serverless's pre-installed set). A loose range resolves to
  "whatever's newest on PyPI today," which drifts out from under you with no warning.
- **A stray local `build/` directory can shadow the real `build` package.** `python -m build`
  resolves `import build` against the current working directory first — a leftover
  `./build/` directory (a normal setuptools byproduct of prior builds) is picked up by Python
  3 as an implicit namespace package and produces `No module named build.__main__; 'build' is
  a package and cannot be directly executed`. This isn't a code regression; it's local build
  residue. `rm -rf build dist` before rebuilding if this happens, and if it happens on a venv
  that otherwise looks healthy, check whether `pip` itself still works in that venv — a
  broken/incomplete venv (e.g. after migrating to a new machine) is a much likelier real
  cause than anything in your own recent commits.

### 5.4 Smoke-test the platform independently of your own code

Keep a trivial, zero-dependency second job (standard library only, no custom package, no
vendored wheels) in the same bundle. If the real job fails with a platform-shaped error
("Failed to restart Python," a `dbruntime` traceback) and the smoke-test job *also* fails the
same way, the problem is the workspace/platform itself, not your code — saves a lot of wasted
debugging effort chasing a problem that isn't in your pipeline.

### 5.5 Output persistence is a decision you need to make, not an accident

Writing output JSON to a plain local path works fine on serverless (it has writable local
disk) but nothing retrieves or persists it afterward unless you explicitly wire up a Unity
Catalog Volume, DBFS path, or upload step. Decide whether the destination push being
successful is sufficient on its own, or whether an audit trail of what was actually extracted
needs to survive the job container recycling — don't let this be an unexamined gap.

---

## 6. Transform logic — where the real domain risk lives

### 6.1 Keep "extract features" and "format for destination" as two separate stages

`extract_features()` does all business-logic triangulation from raw columns into named
booleans/values. `format_for_drata()` is a pure mapping from those named values into the
destination API's exact JSON shape — no logic, just key renaming. This separation makes both
halves independently testable with plain dict fixtures, no mocking, no network — and makes it
obvious where a bug belongs when something's wrong (wrong field mapping vs. wrong business
logic are different bug classes with different code locations).

### 6.2 Validate what a raw signal actually *means* with the customer, not just whether it's populated

The most expensive bugs on this project weren't missing data — they were a raw column
existing, being populated, and being *mis-interpreted*:

- A "disable Windows Update access" flag looks like it should mean "non-compliant." On a
  centrally-managed fleet, it actually means "users can't touch the local WU settings because
  patching is handled centrally" — treating it as an auto-fail punished the *best*-managed
  devices specifically. The real signal for "is this centrally managed and therefore
  compliant" was a completely different field (`UseWUServer`/`usewuserver0`).
- A classic per-user screensaver setting reading uniformly inactive across an entire fleet
  isn't necessarily evidence the fleet doesn't lock its screens — modern Windows security
  baselines enforce lock via a machine-level inactivity-timeout policy that doesn't touch the
  screensaver mechanism at all. The columns weren't broken; they were measuring a mechanism
  the customer doesn't use.

**Don't assume a plausible-sounding interpretation of a policy/config column is correct just
because it compiles and produces a boolean.** Where the business meaning of a raw signal is
ambiguous, get the actual domain owner (the customer's security/IT team) to confirm what a
given raw value means in *their* environment before shipping a pass/fail rule built on an
assumption. This applies at least as much to Tenable data — a vulnerability "severity" or
"state" field's real meaning in the customer's own risk model is exactly this class of
question.

### 6.3 Don't remove an existing check because a new signal correlates with it

When replacing or supplementing a data source, a new signal matching an old check's numbers
closely is evidence worth noting, not evidence the two answer the *same question*. One
real example here: replacing an internal "is this employee active" check with an external
system-of-record's own personnel-status lookup, on the reasoning that the internal field's
numbers lined up closely enough to make the external check feel redundant — they didn't
actually answer the same question (one reflects internal HR status, the other reflects
whether the destination system itself recognizes the person as linkable), and removing the
external check broke a real, deliberate guardrail. When in doubt, keep both checks running
until the data actually shows whether they diverge.

---

## 7. Pushing to the destination API

`db/drata_client.py` is a reasonable template for any destination push client:

- **Separate retry budgets for rate-limiting vs. genuine errors.** A 429 means "slow down,"
  not "this record is broken" — counting it against the same small retry budget as a 5xx/
  network error risks reporting a perfectly good record as permanently failed purely from
  throttling under concurrent push workers. Give rate-limit retries their own, more generous
  budget, and respect a `Retry-After` header when present (falling back to a fixed backoff if
  it's missing or non-numeric — `Retry-After` can legally be an HTTP-date string, not just
  seconds).
- **Parallel push via a thread pool, with a thread-local HTTP session per worker.** Building
  one `requests.Session` per thread (lazily, via `threading.local()`) rather than sharing one
  across all workers avoids connection-pool contention; a `_build_session()` method (not a
  directly-set attribute) is also what makes this mockable cleanly in tests (override the
  method, not the session object, so every thread's lazy session build gets the same fake).
- **A 4xx (other than 429) should fail immediately, not retry** — it's not a transient
  condition.
- **Upsert on a stable external ID**, not create-only — makes retries, partial-failure
  recovery, and simply re-running a chunk from scratch all safe by construction, which is
  what makes the crash-recovery pattern in §4.8 actually work in practice.
- **Pre-push quality gates**: reject and separately log (not silently drop) any record
  missing a field the destination API requires to be meaningful at all (e.g. no way to
  identify who/what the record is about) — write those to a separate `_rejected.json` with a
  reason, rather than letting the destination API's own validation error be the first anyone
  hears about it.
- **Make the sandbox/test vs. production destination tenant an explicit, deliberate
  credential selection — never inferred from context.** This project discovered, well into
  production use, that every previous "real" push had actually gone to the destination
  vendor's sandbox tenant the entire time, because the sandbox-vs-prod distinction was never
  wired as its own switch — it had been silently riding on an unrelated flag. Design this as
  one explicit parameter from day one: a boolean (or enum) that selects which secret names to
  resolve for the destination API's credentials, independent of which Databricks
  workspace/catalog is being read from. Keep the existing (sandbox) credential names
  unchanged so nothing already working has to change, and require a **new, deliberately
  distinct** name for production credentials that must be explicitly provisioned — never let
  "missing prod credentials" silently fall back to reusing sandbox ones.

---

## 8. Testing approach

- Every Databricks-facing function takes a `WorkspaceClient` as an explicit argument rather
  than constructing one internally — makes every query function trivially mockable with zero
  refactoring (`mock.patch("databricks.sdk.WorkspaceClient")` and set
  `.return_value.dbutils.secrets.get.return_value = ...` or similar). No part of the test
  suite needs real network access or live credentials.
- Transform/feature-extraction functions are pure (`dict in → dict/tuple out`) — test them
  with plain dict fixtures, no mocking at all. This is where the majority of real bugs on
  this project lived, and it's exactly the code that's cheapest to get real unit coverage on.
- When a mocked object is shared across `ThreadPoolExecutor` worker threads (testing a
  parallel-push client, for instance), setting a thread-local attribute from the main thread
  does **not** reach worker threads — override the *method* that lazily builds the
  thread-local object instead, as an instance attribute, so every thread's own lazy
  construction returns the same fake.

---

## 9. Starting point for the Tenable integration

**Reuse near-verbatim:**
- `db/auth.py`, `db/secrets.py` — credential resolution chain, OAuth-then-PAT preference,
  per-workspace secret scope logic. Swap nothing except the actual env var / secret-key
  prefixes if they differ.
- `db/queries.py::run_sql()` / `rows_to_records()` — the Statement Execution API pull
  mechanics, CSV null handling, external-links chunked fetch.
- The `_apply_cli_env_overrides()` `--env` pattern, and the overall `databricks.yml` bundle
  shape (job parameters → `--env` pairs → `os.getenv()`), including the nightly
  `schedule:`/`pause_status` block if the new job should also run unattended.
- The vendoring approach and its specific gotchas (§5.3) if the new job also needs to run on
  the same serverless platform without PyPI egress.
- The `TableSpec`/`TABLE_REGISTRY` extensibility pattern for adding Tenable source tables.
- The retry-budget-separated, thread-pooled push-client shape in `db/drata_client.py` —
  rewrite the endpoint/payload shape, keep the retry/concurrency architecture.
- The atexit crash-recovery flush pattern, if the new job also processes in chunks against a
  large population.

**Must redo from scratch, verified against the real system, not assumed:**
- Every Tenable table name and column name/casing — get a live `DESCRIBE TABLE` for each one
  before writing a single pull query or lookup. Do not trust a vendor-provided schema doc, an
  export sheet, or this playbook's own examples as ground truth for Tenable's actual tables.
- Whether each Tenable-sourced table is a raw, multi-batch landing table needing the
  latest-batch filter (§4.3), and whether any of them have the "more than one legitimate row
  per entity" shape described in §4.4 — check real data, don't assume either way.
- All business-logic/compliance interpretation of Tenable's own fields (severity, state,
  remediation status, asset criticality, whatever the integration's actual output signals
  are) — validate meaning with the customer's own security team per §6.2, don't infer it from
  field names alone.
- The destination system's actual API shape, auth model, and idempotency key — `db/
  drata_client.py` is a shape to imitate, not code to directly reuse, since the destination is
  different.
- Whichever workspace/catalog/scope names are specific to this customer's actual Databricks
  setup for Tenable data — don't assume they match the SCCM/Drata integration's names.
