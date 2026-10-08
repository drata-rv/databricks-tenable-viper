import argparse
import json
import os
import signal
import sys
from datetime import datetime, timezone

from .db.auth import drata_api_key, get_client_for_env
from .db.drata_client import DrataClient
from .db.queries import is_true
from .db.secrets import ConfigError
from .etl.extract import active_specs, extract_all, merge
from .etl.local import load_local_tables
from .batching import (DEFAULT_ASSET_BUCKETS, MAX_BUCKETS, MAX_RECORD_BYTES_LIMIT, batch_time, build_records,
                       parse_lane_buckets, size_of)
from .etl.sample_data import write_scale_data, write_sample_data
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


def _dump(path, data, indent=2):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=indent, separators=None if indent else (",", ":"), default=str)


def _has_tables(directory):
    return os.path.isdir(directory) and any(f.endswith((".csv", ".json")) for f in os.listdir(directory))


def _env_str(name, default):
    return (os.getenv(name) or "").strip() or default


def _env_bool(name):
    raw = _env_str(name, "").lower()
    if raw in ("", "false", "0", "no", "off"):
        return False
    if raw in ("true", "1", "yes", "on"):
        return True
    raise ConfigError("%s must be true or false, got %r" % (name, raw))


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
    p.add_argument("--workspace", default=_env_str("DATABRICKS_WORKSPACE", "test"), help="test|prod (Databricks source)")
    p.add_argument("--warehouse-id", default=os.getenv("DATABRICKS_WAREHOUSE_ID"))
    p.add_argument("--output-dir", default=_env_str("OUTPUT_DIR", "output"))
    p.add_argument("--stale-days", type=int, default=_env_number("SCAN_STALE_DAYS", 7, int),
                   help="days after which an asset's last_seen / Tenable last scan counts as stale (default 7)")
    p.add_argument("--drata-prod", action="store_true", default=_env_bool("DRATA_PROD"),
                   help="push to Drata prod tenant (separate credentials, no sandbox fallback)")
    p.add_argument("--push-mode", choices=["upsert", "session"], default=None,
                   help="session (default): stage everything, then atomically replace the dataset, removing any "
                        "record not in this run | upsert: update only, never deletes. Env: DRATA_PUSH_MODE")
    p.add_argument("--scanner-tool", default=os.getenv("SCANNER_TOOL") or "tenable",
                   help="substring of the tool_severity key compared with Vipr severity (default tenable)")
    p.add_argument("--scanner-severity-map", default=os.getenv("SCANNER_SEVERITY_MAP", ""),
                   help='JSON map of raw tool values to info|low|medium|high|critical, e.g. {"1":"low","2":"medium"}')
    p.add_argument("--finding-lane-buckets", default=os.getenv("FINDING_LANE_BUCKETS", ""),
                   help='JSON minimum batches per severity lane, default {"critical":1,"high":2,"medium":4,"low":4,"info":1,"unknown":1}; '
                        "grows automatically in session mode, exact in upsert mode")
    p.add_argument("--asset-buckets", type=int, default=_env_number("ASSET_BUCKETS", DEFAULT_ASSET_BUCKETS, int),
                   help="minimum asset batch records (default 4); grows automatically in session mode")
    p.add_argument("--closed-lookback-days", type=int, default=_env_number("CLOSED_LOOKBACK_DAYS", 90, int),
                   help="closed findings older than this are left out (default 90)")
    p.add_argument("--max-source-age-days", type=int, default=_env_number("MAX_SOURCE_AGE_DAYS", 3, int),
                   help="summary sourceFresh is false when the oldest source batch is older (default 3)")
    p.add_argument("--max-record-bytes", type=int, default=_env_number("MAX_RECORD_BYTES", 4000000, int),
                   help="abort before pushing if any record is larger (max 4500000; Drata limit is 5 MB)")
    p.add_argument("--min-findings", type=int, default=_env_number("MIN_FINDINGS", 1, int),
                   help="abort before pushing if fewer findings were extracted (default 1)")
    p.add_argument("--min-assets", type=int, default=_env_number("MIN_ASSETS", 1, int),
                   help="abort before pushing if fewer assets were extracted (default 1)")
    p.add_argument("--local-rows", type=int, default=_env_number("LOCAL_ROWS", 0, int),
                   help="with --local: generate this many synthetic findings (assets = rows/8) under <local-data>/scale")
    p.add_argument("--max-reject-ratio", type=float, default=_env_number("MAX_REJECT_RATIO", None, float),
                   help="abort before pushing if rejected/total exceeds this (default 0.05; disabled with --local, "
                        "whose sample data has deliberate rejects)")
    p.add_argument("--allow-test-source-with-prod", action="store_true",
                   help="allow *test_catalog* source tables together with --drata-prod")
    p.add_argument("--local", action="store_true",
                   help="local test mode: read tables from --local-data files, no Databricks, no push unless --push (sandbox only)")
    p.add_argument("--local-data", default=_env_str("LOCAL_DATA_DIR", "local_data"),
                   help="directory with findings/assets[/tenable_assets] .csv|.json; synthetic rows are generated "
                        "when it has none (delete files to regenerate)")
    p.add_argument("--push", action="store_true",
                   help="with --local: also push the SYNTHETIC data (in session mode it replaces the whole resource)")
    p.add_argument("--dry-run", action="store_true", help="extract+transform only, no push")
    p.add_argument("--env", action="append", metavar="KEY=VALUE", help="set an environment variable (job parameters)")
    return p


def _terminate(signum, frame):
    raise KeyboardInterrupt


def main(argv=None):
    previous = None
    try:
        previous = signal.signal(signal.SIGTERM, _terminate)
    except (ValueError, OSError):
        pass
    try:
        return _main(list(sys.argv[1:] if argv is None else argv))
    except ConfigError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted: any open Drata session was cancelled", file=sys.stderr)
        return 130
    finally:
        signal.signal(signal.SIGTERM, previous if previous is not None else signal.SIG_DFL)


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

    if args.max_reject_ratio is None:
        args.max_reject_ratio = 1.0 if args.local else 0.05
    push_mode = args.push_mode or _env_str("DRATA_PUSH_MODE", "session")
    if push_mode not in ("upsert", "session"):
        p.error("invalid push mode %r (DRATA_PUSH_MODE): use upsert or session" % push_mode)
    lane_buckets = parse_lane_buckets(args.finding_lane_buckets)
    for name, ok, hint in (
            ("--asset-buckets", 1 <= args.asset_buckets <= MAX_BUCKETS, "1-%d" % MAX_BUCKETS),
            ("--closed-lookback-days", 1 <= args.closed_lookback_days <= 36500, "1-36500"),
            ("--max-source-age-days", 0 <= args.max_source_age_days <= 36500, "0-36500"),
            ("--max-record-bytes", 100_000 <= args.max_record_bytes <= MAX_RECORD_BYTES_LIMIT, "100000-%d" % MAX_RECORD_BYTES_LIMIT),
            ("--min-findings", 0 <= args.min_findings <= 10**9, "0-1000000000"),
            ("--min-assets", 0 <= args.min_assets <= 10**9, "0-1000000000"),
            ("--stale-days", 0 <= args.stale_days <= 36500, "0-36500"),
            ("--local-rows", 0 <= args.local_rows <= 5_000_000, "0-5000000"),
            ("--max-reject-ratio", 0.0 <= args.max_reject_ratio <= 1.0, "0-1")):
        if not ok:
            p.error("%s out of range (%s)" % (name, hint))
    scale = parse_scale(args.scanner_severity_map)
    if scale is None:
        p.error("--scanner-severity-map must be a JSON object mapping to info|low|medium|high|critical")
    if args.local and args.drata_prod:
        p.error("--local never pushes to Drata prod; drop --drata-prod and unset DRATA_PROD")
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

    if not args.local:
        unset = [s.env_var for s in active_specs() if s.required and not (os.getenv(s.env_var) or "").strip()]
        if unset:
            raise ConfigError("missing source table setting(s): " + ", ".join(unset))
    args.scanner_tool = (args.scanner_tool or "").strip() or "tenable"
    for stale in ("_failed.json", "partial.json", "records.json", "_profile.json", "_rejected.json"):
        if os.path.exists(os.path.join(args.output_dir, stale)):
            os.remove(os.path.join(args.output_dir, stale))

    if args.local:
        if args.local_rows > 0:
            args.local_data = os.path.join(args.local_data, "scale")
            write_scale_data(args.local_data, args.local_rows)
            print("LOCAL MODE: generated %d synthetic findings in %s" % (args.local_rows, args.local_data))
        elif not _has_tables(args.local_data):
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
    now = datetime.now(timezone.utc)
    source_dates = {label: batch_time(tables.get(label, [])) for label in ("findings", "assets")}
    if tables.get("tenable_assets") is not None:
        source_dates["tenable_assets"] = batch_time(tables["tenable_assets"])
    records = build_records(
        findings, scans, now=now, lane_buckets=lane_buckets, asset_buckets=args.asset_buckets,
        closed_lookback_days=args.closed_lookback_days, max_source_age_days=args.max_source_age_days,
        max_record_bytes=args.max_record_bytes, rejected=len(rejected), source_dates=source_dates,
        grow_buckets=True)

    _dump(os.path.join(args.output_dir, "records.json"), records, indent=None)
    try:
        profile = build_profile(tables, joined, findings, scans)
        _dump(os.path.join(args.output_dir, "_profile.json"), profile)
        print(summary(profile))
    except Exception as e:
        print("profile skipped: %s" % type(e).__name__, file=sys.stderr)
    _dump(os.path.join(args.output_dir, "_rejected.json"), rejected)
    print("findings=%d assets=%d rejected=%d records=%d largest_record=%.2fMB total=%.1fMB" % (
        len(findings), len(scans), len(rejected), len(records), max(size_of(r) for r in records) / 1e6,
        sum(size_of(r) for r in records) / 1e6))
    if rejected:
        print("rejected sample: %s" % [(r["resource"], r["reason"]) for r in rejected[:5]])
    lane_counts = {r["severityLane"]: r["bucketCount"] for r in records if r["recordType"] == "findingBatch"}
    print("batches: %s assets=%d (pin with FINDING_LANE_BUCKETS / ASSET_BUCKETS to stop counts moving)" %
          (" ".join("%s=%d" % kv for kv in lane_counts.items()), records[0]["assetBuckets"]))

    # count what is actually submitted: an empty array makes every array test pass
    kept_findings, kept_assets = records[0]["findingCount"], records[0]["assetCount"]
    short = [n for n, have, need in (("findings", kept_findings, args.min_findings), ("assets", kept_assets, args.min_assets))
             if have < need]
    if short:
        print("%s: extracted too few %s (need MIN_FINDINGS=%d / MIN_ASSETS=%d); nothing pushed" %
              ("WARNING" if args.dry_run else "ABORT", " and ".join(short), args.min_findings, args.min_assets),
              file=sys.stderr)
    if args.dry_run:
        return 0
    if short:
        return 2

    total = len(findings) + len(scans) + len(rejected)
    if total and len(rejected) / total > args.max_reject_ratio:
        print("ABORT: rejected ratio %.1f%% > %.1f%%; nothing pushed" %
              (100.0 * len(rejected) / total, 100.0 * args.max_reject_ratio), file=sys.stderr)
        return 2

    base_url = _env_str("DRATA_API_BASE", "https://public-api.drata.com")
    print("Drata tenant: %s | push mode: %s | target: %s connection=%s resource=%s" % (
        "PROD" if args.drata_prod else "sandbox", push_mode, base_url, os.environ["DRATA_CONNECTION_ID"],
        os.environ["DRATA_RESOURCE_ID"]))
    if push_mode == "upsert":
        print("note: upsert never deletes; if batch counts shrink later, records with higher numbers keep old items "
              "(session mode removes them)", file=sys.stderr)
    if args.local and push_mode == "session":
        print("WARNING: --local --push in session mode replaces the whole resource with synthetic data", file=sys.stderr)
    dc = DrataClient(base_url,
                     drata_api_key(args.drata_prod, args.workspace))
    session_id = "vipr-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    conn, res = os.environ["DRATA_CONNECTION_ID"], os.environ["DRATA_RESOURCE_ID"]
    if push_mode == "session":
        ok, failed, action = dc.replace_via_session(conn, res, records, session_id)
        outcome = action if not any(f["error"].startswith("session %s failed" % action) for f in failed) else action + " FAILED"
        print("session=%s pushed=%d failed=%d -> %s" % (session_id, ok, len(failed), outcome))
    else:
        ok, failed = dc.upsert(conn, res, records)
        print("upsert pushed=%d failed=%d" % (ok, len(failed)))
    print("drata http responses: %s" % (dc.http_counts,))
    if not failed:
        _verify(dc, conn, res, records)
    if dc.unverified:
        print("warning: %d bulk response(s) carried no per-item results; failures inside them would be invisible"
              % dc.unverified, file=sys.stderr)
    if failed:
        _dump(os.path.join(args.output_dir, "_failed.json"), failed)
        print("failures (first 5): %s" % failed[:5], file=sys.stderr)
    return 1 if failed else 0


def _verify(dc, conn, res, records):
    try:
        listed = dc.list_records(conn, res)
        if listed is None:
            print("verify: could not read the records back from Drata (the key may lack read scope)", file=sys.stderr)
            return
        ids, total = listed
        ours = {r["id"] for r in records}
        seen = len(ours & set(ids))
        print("verify: Drata lists %d record(s) (total=%s); %d of our %d record ids are present" % (len(ids), total, seen, len(ours)))
        if not seen:
            print("WARNING: none of the submitted records are visible in Drata. Check that DRATA_CONNECTION_ID and "
                  "DRATA_RESOURCE_ID are the connection you are viewing, and that DRATA_API_KEY belongs to the same "
                  "Drata workspace.", file=sys.stderr)
    except Exception as e:
        print("verify skipped: %s" % type(e).__name__, file=sys.stderr)


def run():
    sys.exit(main())


if __name__ == "__main__":
    run()
