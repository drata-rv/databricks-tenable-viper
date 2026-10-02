"""CLI / python_wheel_task entry point.

--env KEY=VALUE (repeatable) feeds os.environ before anything reads config: serverless
python_wheel_task has no env-var injection, job parameters are the only channel in.
Exit codes: 0 ok, 1 push failures, 2 config/guard abort.
"""
import argparse
import atexit
import json
import os
import sys
from datetime import datetime, timezone

from .db.auth import drata_api_key, get_client_for_env
from .db.drata_client import DrataClient
from .db.queries import is_true
from .etl.extract import extract_all, merge
from .etl.local import load_local_tables
from .etl.sample_data import write_sample_data
from .transform import build_payloads


def apply_env_pairs(argv):
    """Apply every `--env K=V` / `--env=K=V` in argv to os.environ. Returns malformed tokens."""
    bad, i = [], 0
    while i < len(argv):
        tok = argv[i]
        if tok == "--env" and i + 1 < len(argv):
            pair, i = argv[i + 1], i + 2
        elif tok.startswith("--env="):
            pair, i = tok[len("--env="):], i + 1
        else:
            i += 1
            continue
        key, sep, value = pair.partition("=")
        if sep and key:
            os.environ[key] = value
        else:
            bad.append(pair)
    return bad


def _dump(path, data):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def _has_tables(directory):
    return os.path.isdir(directory) and any(f.endswith((".csv", ".json")) for f in os.listdir(directory))


def build_parser():
    p = argparse.ArgumentParser(prog="vipr-drata")
    p.add_argument("--workspace", default=os.getenv("DATABRICKS_WORKSPACE", "test"), help="test|prod (Databricks source)")
    p.add_argument("--warehouse-id", default=os.getenv("DATABRICKS_WAREHOUSE_ID"))
    p.add_argument("--output-dir", default=os.getenv("OUTPUT_DIR", "output"))
    p.add_argument("--stale-days", type=int, default=int(os.getenv("SCAN_STALE_DAYS", "7")))
    p.add_argument("--drata-prod", action="store_true", default=is_true(os.getenv("DRATA_PROD")),
                   help="push to Drata prod tenant (separate credentials, no sandbox fallback)")
    p.add_argument("--push-mode", choices=["upsert", "session"], default=None,
                   help="upsert (default, never deletes) | session (atomic snapshot replace; hard-deletes records "
                        "not in this run; refused if anything was rejected). Env: DRATA_PUSH_MODE")
    p.add_argument("--max-reject-ratio", type=float, default=float(os.getenv("MAX_REJECT_RATIO", "-1")),
                   help="abort before pushing if rejected/total exceeds this (default 0.05; disabled with --local, "
                        "whose sample data has deliberate rejects)")
    p.add_argument("--allow-test-source-with-prod", action="store_true",
                   help="allow *test_catalog* source tables together with --drata-prod")
    p.add_argument("--local", action="store_true",
                   help="local test mode: read tables from --local-data files, no Databricks, no push unless --push (sandbox only)")
    p.add_argument("--local-data", default=os.getenv("LOCAL_DATA_DIR", "local_data"),
                   help="directory with findings/assets[/tenable_assets] .csv|.json; synthetic rows are generated "
                        "when it has none (delete files to regenerate)")
    p.add_argument("--push", action="store_true", help="with --local: also push to the Drata sandbox connection")
    p.add_argument("--dry-run", action="store_true", help="extract+transform only, no push")
    p.add_argument("--env", action="append", metavar="KEY=VALUE", help="set an environment variable (job parameters)")
    return p


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not os.getenv("VIPR_DRATA_NO_DOTENV"):
        try:
            from dotenv import load_dotenv

            load_dotenv()  # never overrides already-set vars
        except ImportError:
            pass
    bad = apply_env_pairs(argv)  # after .env so --env wins; before the parser reads env defaults
    p = build_parser()
    if bad:
        p.error("malformed --env (need KEY=VALUE): " + ", ".join(bad))
    args = p.parse_args(argv)

    if args.max_reject_ratio < 0:
        args.max_reject_ratio = 1.0 if args.local else 0.05
    push_mode = args.push_mode or os.getenv("DRATA_PUSH_MODE") or "upsert"
    if push_mode not in ("upsert", "session"):
        p.error("invalid push mode %r (DRATA_PUSH_MODE): use upsert or session" % push_mode)
    if args.local and args.drata_prod:
        p.error("--local never pushes to Drata prod; drop --drata-prod")
    if args.local and not args.push:
        args.dry_run = True
    if not args.local and not args.warehouse_id:
        p.error("warehouse id required (--warehouse-id or DATABRICKS_WAREHOUSE_ID), or use --local")
    if not args.dry_run:
        missing = [k for n in ("FINDINGS", "ASSETS") for k in ("DRATA_%s_CONNECTION_ID" % n, "DRATA_%s_RESOURCE_ID" % n)
                   if not os.getenv(k)]
        if missing:
            p.error("missing Drata config: " + ", ".join(missing))
    if args.drata_prod and not args.local and not args.allow_test_source_with_prod:
        test_src = [k for k in ("VIPR_FINDINGS_TABLE", "VIPR_ASSETS_TABLE")
                    if "test_catalog" in (os.getenv(k) or "").lower()]
        if test_src:
            p.error("refusing to push to Drata PROD from test-catalog tables (%s); set prod tables or pass "
                    "--allow-test-source-with-prod" % ", ".join(test_src))

    state = {"incomplete": True}
    atexit.register(lambda: state.get("incomplete") and len(state) > 1 and
                    _dump(os.path.join(args.output_dir, "partial.json"), state))

    if args.local:
        if not _has_tables(args.local_data):
            write_sample_data(args.local_data)
            print("LOCAL MODE: generated synthetic sample tables in %s" % args.local_data)
        tables = load_local_tables(args.local_data)
        print("LOCAL MODE: tables from %s (no Databricks)" % args.local_data)
    else:
        tables = extract_all(get_client_for_env(args.workspace), args.warehouse_id)
    joined, assets = merge(tables)
    findings, scans, rejected = build_payloads(joined, assets, args.stale_days,
                                               tenable_assets=tables.get("tenable_assets"))
    state.update(findings=findings, assets=scans, rejected=rejected)

    _dump(os.path.join(args.output_dir, "findings.json"), findings)
    _dump(os.path.join(args.output_dir, "asset_scan_coverage.json"), scans)
    _dump(os.path.join(args.output_dir, "_rejected.json"), rejected)
    print("findings=%d assets=%d rejected=%d" % (len(findings), len(scans), len(rejected)))
    if rejected:
        print("rejected sample: %s" % [(r["resource"], r["reason"]) for r in rejected[:5]])

    if args.dry_run:
        state["incomplete"] = False
        return 0

    total = len(findings) + len(scans) + len(rejected)
    if total and len(rejected) / total > args.max_reject_ratio:
        print("ABORT: rejected ratio %.1f%% > %.1f%%; nothing pushed" %
              (100.0 * len(rejected) / total, 100.0 * args.max_reject_ratio), file=sys.stderr)
        return 2

    print("Drata tenant: %s | push mode: %s" % ("PROD" if args.drata_prod else "sandbox", push_mode))
    dc = DrataClient(os.getenv("DRATA_API_BASE", "https://public-api.drata.com"),
                     drata_api_key(args.drata_prod, args.workspace))
    session_id = "vipr-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    failed_total = 0
    for name, recs in (("FINDINGS", findings), ("ASSETS", scans)):
        conn, res = os.environ["DRATA_%s_CONNECTION_ID" % name], os.environ["DRATA_%s_RESOURCE_ID" % name]
        if push_mode == "session":
            nrej = sum(1 for r in rejected if r["resource"] == name.lower())
            if nrej:  # completing would hard-delete the previously-good Drata records for rejected ids
                failed = [{"id": None, "error": "%d rejected record(s): session replace refused" % nrej}]
                ok, action = 0, "skipped"
            else:
                ok, failed, action = dc.replace_via_session(conn, res, recs, session_id)
            print("%s session=%s pushed=%d failed=%d -> %s" % (name, session_id, ok, len(failed), action))
        else:
            ok, failed = dc.upsert(conn, res, recs) if recs else (0, [])
            print("%s upsert pushed=%d failed=%d" % (name, ok, len(failed)))
        failed_total += len(failed)
        if failed:
            _dump(os.path.join(args.output_dir, "_failed_%s.json" % name.lower()), failed)
            print("%s failures (first 5): %s" % (name, failed[:5]), file=sys.stderr)
    state["incomplete"] = False
    return 1 if failed_total else 0


def run():
    """Console-script / python_wheel_task entry point: a non-zero result must fail the process."""
    sys.exit(main())


if __name__ == "__main__":
    run()
