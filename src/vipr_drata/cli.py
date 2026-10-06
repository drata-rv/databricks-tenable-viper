import argparse
import atexit
import json
import os
import sys
from datetime import datetime, timezone

from .db.auth import drata_api_key, get_client_for_env
from .db.drata_client import DrataClient
from .db.queries import is_true
from .db.secrets import ConfigError
from .etl.extract import extract_all, merge
from .etl.local import load_local_tables
from .etl.sample_data import write_sample_data
from .profile import build_profile, summary
from .transform import SEVERITY_ORDER, build_payloads


def apply_env_pairs(argv):
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


def _env_number(name, default, cast):
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        return cast(raw)
    except ValueError:
        raise ConfigError("%s must be a number, got %r" % (name, raw))


def parse_scale(raw):
    if not raw or not raw.strip():
        return {}
    try:
        scale = json.loads(raw)
    except ValueError:
        return None
    ok = isinstance(scale, dict) and all(str(v).lower() in SEVERITY_ORDER for v in scale.values())
    return {str(k).strip().lower(): str(v).lower() for k, v in scale.items()} if ok else None


def build_parser():
    p = argparse.ArgumentParser(prog="vipr-drata")
    p.add_argument("--workspace", default=os.getenv("DATABRICKS_WORKSPACE", "test"), help="test|prod (Databricks source)")
    p.add_argument("--warehouse-id", default=os.getenv("DATABRICKS_WAREHOUSE_ID"))
    p.add_argument("--output-dir", default=os.getenv("OUTPUT_DIR", "output"))
    p.add_argument("--stale-days", type=int, default=_env_number("SCAN_STALE_DAYS", 7, int))
    p.add_argument("--drata-prod", action="store_true", default=is_true(os.getenv("DRATA_PROD")),
                   help="push to Drata prod tenant (separate credentials, no sandbox fallback)")
    p.add_argument("--push-mode", choices=["upsert", "session"], default=None,
                   help="upsert (default, never deletes) | session (atomic snapshot replace; hard-deletes records "
                        "not in this run; refused if anything was rejected). Env: DRATA_PUSH_MODE")
    p.add_argument("--scanner-tool", default=os.getenv("SCANNER_TOOL") or "tenable",
                   help="substring of the tool_severity key compared with Vipr severity (default tenable)")
    p.add_argument("--scanner-severity-map", default=os.getenv("SCANNER_SEVERITY_MAP", ""),
                   help='JSON map of raw tool values to info|low|medium|high|critical, e.g. {"1":"low","2":"medium"}')
    p.add_argument("--max-reject-ratio", type=float, default=_env_number("MAX_REJECT_RATIO", -1.0, float),
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
    try:
        return _main(list(sys.argv[1:] if argv is None else argv))
    except ConfigError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2


def _main(argv):
    if not os.getenv("VIPR_DRATA_NO_DOTENV"):
        try:
            from dotenv import find_dotenv, load_dotenv

            path = find_dotenv(usecwd=True) or find_dotenv()
            if path:
                load_dotenv(path)
        except ImportError:
            pass
    # --env overrides .env; must run before parser env defaults
    bad = apply_env_pairs(argv)
    p = build_parser()
    if bad:
        p.error("malformed --env (need KEY=VALUE): " + ", ".join(bad))
    args = p.parse_args(argv)

    if args.max_reject_ratio < 0:
        args.max_reject_ratio = 1.0 if args.local else 0.05
    push_mode = args.push_mode or os.getenv("DRATA_PUSH_MODE") or "upsert"
    if push_mode not in ("upsert", "session"):
        p.error("invalid push mode %r (DRATA_PUSH_MODE): use upsert or session" % push_mode)
    scale = parse_scale(args.scanner_severity_map)
    if scale is None:
        p.error("--scanner-severity-map must be a JSON object mapping to info|low|medium|high|critical")
    if args.local and args.drata_prod:
        p.error("--local never pushes to Drata prod; drop --drata-prod")
    if args.local and not args.push:
        args.dry_run = True
    if not args.local and not args.warehouse_id:
        p.error("warehouse id required (--warehouse-id or DATABRICKS_WAREHOUSE_ID), or use --local")
    if not args.dry_run:
        missing = [k for k in ("DRATA_CONNECTION_ID", "DRATA_RESOURCE_ID") if not os.getenv(k)]
        if missing:
            p.error("missing Drata config: " + ", ".join(missing))
    if args.drata_prod and not args.local and not args.allow_test_source_with_prod:
        test_src = [k for k in ("VIPR_FINDINGS_TABLE", "VIPR_ASSETS_TABLE")
                    if "test_catalog" in (os.getenv(k) or "").lower()]
        if test_src:
            p.error("refusing to push to Drata PROD from test-catalog tables (%s); set prod tables or pass "
                    "--allow-test-source-with-prod" % ", ".join(test_src))

    args.scanner_tool = (args.scanner_tool or "").strip() or "tenable"
    for stale in ("_failed.json", "partial.json"):
        if os.path.exists(os.path.join(args.output_dir, stale)):
            os.remove(os.path.join(args.output_dir, stale))
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
        try:
            tables = extract_all(get_client_for_env(args.workspace), args.warehouse_id)
        except ConfigError:
            raise
        except Exception as e:
            print("error: Databricks extraction failed: %s: %s" % (type(e).__name__, str(e)[:300]), file=sys.stderr)
            return 1
    joined, assets = merge(tables)
    findings, scans, rejected = build_payloads(joined, assets, args.stale_days,
                                               tenable_assets=tables.get("tenable_assets"),
                                               scanner_tool=args.scanner_tool, scanner_scale=scale)
    records = findings + scans
    state.update(records=records, rejected=rejected)

    _dump(os.path.join(args.output_dir, "records.json"), records)
    try:
        profile = build_profile(tables, joined, records)
        _dump(os.path.join(args.output_dir, "_profile.json"), profile)
        print(summary(profile))
    except Exception as e:
        print("profile skipped: %s" % type(e).__name__, file=sys.stderr)
    _dump(os.path.join(args.output_dir, "_rejected.json"), rejected)
    print("findings=%d assets=%d rejected=%d" % (len(findings), len(scans), len(rejected)))
    if rejected:
        print("rejected sample: %s" % [(r["resource"], r["reason"]) for r in rejected[:5]])

    if args.dry_run:
        state["incomplete"] = False
        return 0

    total = len(records) + len(rejected)
    if total and len(rejected) / total > args.max_reject_ratio:
        print("ABORT: rejected ratio %.1f%% > %.1f%%; nothing pushed" %
              (100.0 * len(rejected) / total, 100.0 * args.max_reject_ratio), file=sys.stderr)
        state["incomplete"] = False
        return 2

    print("Drata tenant: %s | push mode: %s" % ("PROD" if args.drata_prod else "sandbox", push_mode))
    dc = DrataClient(os.getenv("DRATA_API_BASE", "https://public-api.drata.com"),
                     drata_api_key(args.drata_prod, args.workspace))
    session_id = "vipr-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    conn, res = os.environ["DRATA_CONNECTION_ID"], os.environ["DRATA_RESOURCE_ID"]
    if push_mode == "session":
        # completing would hard-delete live records for rejected ids
        if rejected:
            failed = [{"id": None, "error": "%d rejected record(s): session replace refused" % len(rejected)}]
            ok, action = 0, "skipped"
        else:
            ok, failed, action = dc.replace_via_session(conn, res, records, session_id)
        print("session=%s pushed=%d failed=%d -> %s" % (session_id, ok, len(failed), action))
    else:
        ok, failed = dc.upsert(conn, res, records) if records else (0, [])
        print("upsert pushed=%d failed=%d" % (ok, len(failed)))
    if failed:
        _dump(os.path.join(args.output_dir, "_failed.json"), failed)
        print("failures (first 5): %s" % failed[:5], file=sys.stderr)
    failed_total = len(failed)
    state["incomplete"] = False
    return 1 if failed_total else 0


def run():
    sys.exit(main())


if __name__ == "__main__":
    run()
