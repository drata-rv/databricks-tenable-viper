import argparse
import json
import os
import signal
import sys
import threading
from datetime import datetime, timezone

from .db.auth import drata_api_key, get_client_for_env
from .db.drata_client import DrataClient
from .db.queries import is_true
from .db.secrets import ConfigError
from .etl.extract import active_specs, extract_all, merge
from .etl.local import load_local_tables
from .batching import (DEFAULT_ASSET_PARTITIONS, MAX_PARTITIONS, MAX_RECORD_BYTES_LIMIT, source_as_of, build_records,
                       parse_finding_partitions, size_of)
from .etl.sample_data import write_scale_data, write_sample_data
from . import __version__, log
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
    p.add_argument("--workspace", default=_env_str("DATABRICKS_WORKSPACE", "test"), help="Databricks source: test|prod")
    p.add_argument("--warehouse-id", default=os.getenv("DATABRICKS_WAREHOUSE_ID"))
    p.add_argument("--output-dir", default=_env_str("OUTPUT_DIR", "output"))
    p.add_argument("--stale-days", type=int, default=_env_number("SCAN_STALE_DAYS", 7, int), help="asset staleness window, days")
    p.add_argument("--drata-prod", action="store_true", default=_env_bool("DRATA_PROD"), help="push to the Drata prod tenant")
    p.add_argument("--push-mode", choices=["upsert", "session"], default=None,
                   help="upsert: update in place, never delete (default) | session: atomic replace. Env: DRATA_PUSH_MODE")
    p.add_argument("--scanner-tool", default=os.getenv("SCANNER_TOOL") or "tenable", help="tool_severity key compared with Vipr severity")
    p.add_argument("--scanner-severity-map", default=os.getenv("SCANNER_SEVERITY_MAP", ""),
                   help='JSON map of numeric tool values to severities, e.g. {"1":"low"}')
    p.add_argument("--finding-partitions", default=os.getenv("FINDING_PARTITIONS", ""), help="JSON minimum partitions per severity")
    p.add_argument("--asset-partitions", type=int, default=_env_number("ASSET_PARTITIONS", DEFAULT_ASSET_PARTITIONS, int),
                   help="minimum asset partitions")
    p.add_argument("--closed-lookback-days", type=int, default=_env_number("CLOSED_LOOKBACK_DAYS", 90, int),
                   help="omit closed findings older than this")
    p.add_argument("--max-source-age-days", type=int, default=_env_number("MAX_SOURCE_AGE_DAYS", 3, int),
                   help="sourceFresh is false beyond this age")
    p.add_argument("--max-record-bytes", type=int, default=_env_number("MAX_RECORD_BYTES", 4000000, int),
                   help="record size limit, at most 4500000")
    p.add_argument("--min-findings", type=int, default=_env_number("MIN_FINDINGS", 1, int), help="abort below this finding count")
    p.add_argument("--min-assets", type=int, default=_env_number("MIN_ASSETS", 1, int), help="abort below this asset count")
    p.add_argument("--local-rows", type=int, default=_env_number("LOCAL_ROWS", 0, int), help="with --local: synthetic finding count")
    p.add_argument("--max-reject-ratio", type=float, default=_env_number("MAX_REJECT_RATIO", None, float),
                   help="abort above this rejected/total ratio (default 0.05, off with --local)")
    p.add_argument("--allow-test-source-with-prod", action="store_true", help="allow test_catalog tables with --drata-prod")
    p.add_argument("--local", action="store_true", help="read --local-data files; no Databricks, no push unless --push")
    p.add_argument("--local-data", default=_env_str("LOCAL_DATA_DIR", "local_data"), help="directory for local tables")
    p.add_argument("--push", action="store_true", help="with --local: push the synthetic data")
    p.add_argument("--dry-run", action="store_true", help="extract and transform only")
    p.add_argument("--quiet", action="store_true", help="suppress INFO log lines")
    p.add_argument("--cancel-open-sessions", action="store_true", help="cancel open Drata sessions this tool did not create")
    p.add_argument("--env", action="append", metavar="KEY=VALUE", help="set an environment variable")
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
        log.error("cli", "config.invalid", detail=str(e))
        return 2
    except KeyboardInterrupt:
        log.warn("cli", "interrupted", exit_code=130, open_session="cancelled")
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
    log.start(quiet=args.quiet, path=os.path.join(args.output_dir, "_run.log"))

    if args.max_reject_ratio is None:
        args.max_reject_ratio = 1.0 if args.local else 0.05
    push_mode = args.push_mode or _env_str("DRATA_PUSH_MODE", "upsert")
    if push_mode not in ("upsert", "session"):
        p.error("invalid push mode %r (DRATA_PUSH_MODE): use upsert or session" % push_mode)
    finding_partitions = parse_finding_partitions(args.finding_partitions)
    for name, ok, hint in (
            ("--asset-partitions", 1 <= args.asset_partitions <= MAX_PARTITIONS, "1-%d" % MAX_PARTITIONS),
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
    log.info("cli", "run.start", version=__version__, source="local" if args.local else "databricks",
             workspace=None if args.local else args.workspace, warehouse_id=None if args.local else args.warehouse_id,
             push_mode="none" if args.dry_run else push_mode, scanner_tool=args.scanner_tool)
    for stale in ("_failed.json", "partial.json", "records.json", "_profile.json", "_rejected.json"):
        if os.path.exists(os.path.join(args.output_dir, stale)):
            os.remove(os.path.join(args.output_dir, stale))

    if args.local:
        if args.local_rows > 0:
            args.local_data = os.path.join(args.local_data, "scale")
            write_scale_data(args.local_data, args.local_rows)
            log.info("local", "data.generated", kind="scale", findings=args.local_rows, path=args.local_data)
        elif not _has_tables(args.local_data):
            write_sample_data(args.local_data)
            log.info("local", "data.generated", kind="sample", path=args.local_data)
        tables = load_local_tables(args.local_data)
        log.info("local", "tables.loaded", path=args.local_data, **{k: len(v) for k, v in tables.items()})
    else:
        try:
            log.info("extract", "connect", workspace=args.workspace)
            tables = extract_all(get_client_for_env(args.workspace), args.warehouse_id)
            log.info("extract", "complete", **{k: len(v) for k, v in tables.items()})
        except ConfigError:
            raise
        except Exception as e:
            log.error("extract", "failed", error_type=type(e).__name__, detail=str(e)[:300])
            return 1
    log.info("transform", "join.start")
    joined, assets = merge(tables)
    findings, scans, rejected = build_payloads(joined, assets, args.stale_days,
                                               tenable_assets=tables.get("tenable_assets"),
                                               scanner_tool=args.scanner_tool, scanner_scale=scale)
    log.info("transform", "derive.complete", findings=len(findings), assets=len(scans), rejected=len(rejected))
    now = datetime.now(timezone.utc)
    source_dates = {label: source_as_of(tables.get(label, [])) for label in ("findings", "assets")}
    if tables.get("tenable_assets") is not None:
        source_dates["tenable_assets"] = source_as_of(tables["tenable_assets"])
    records = build_records(
        findings, scans, now=now, finding_partitions=finding_partitions, asset_partitions=args.asset_partitions,
        closed_lookback_days=args.closed_lookback_days, max_source_age_days=args.max_source_age_days,
        max_record_bytes=args.max_record_bytes, rejected=len(rejected), source_dates=source_dates,
        auto_size=True)

    log.info("records", "built", records=len(records), output=os.path.join(args.output_dir, "records.json"))
    _dump(os.path.join(args.output_dir, "records.json"), records, indent=None)
    try:
        profile = build_profile(tables, joined, findings, scans)
        _dump(os.path.join(args.output_dir, "_profile.json"), profile)
        log.info("profile", "summary", **summary(profile))
    except Exception as e:
        log.warn("profile", "skipped", error_type=type(e).__name__)
    _dump(os.path.join(args.output_dir, "_rejected.json"), rejected)
    log.info("records", "summary", findings=len(findings), assets=len(scans), rejected=len(rejected), records=len(records),
             largest_record_mb=log.mb(max(size_of(r) for r in records)), total_mb=log.mb(sum(size_of(r) for r in records)))
    if rejected:
        log.warn("transform", "rejected.sample", count=len(rejected), sample=["%s:%s" % (r["resource"], r["reason"]) for r in rejected[:5]])
    partition_counts = {r["severity"]: r["partitionCount"] for r in records if r["recordType"] == "findingPartition"}
    log.info("records", "partitions", **partition_counts, assets=records[0]["assetPartitionCount"])

    # count what is actually submitted: an empty array makes every array test pass
    kept_findings, kept_assets = records[0]["findingCount"], records[0]["assetCount"]
    short = [n for n, have, need in (("findings", kept_findings, args.min_findings), ("assets", kept_assets, args.min_assets))
             if have < need]
    if short:
        (log.warn if args.dry_run else log.error)(
            "guard", "min_records.violated", short=short, findings=kept_findings, assets=kept_assets,
            min_findings=args.min_findings, min_assets=args.min_assets, pushed=False)
    if args.dry_run:
        return 0
    if short:
        return 2

    total = len(findings) + len(scans) + len(rejected)
    if total and len(rejected) / total > args.max_reject_ratio:
        log.error("guard", "reject_ratio.exceeded", ratio=len(rejected) / total, max_ratio=args.max_reject_ratio, pushed=False)
        return 2

    base_url = _env_str("DRATA_API_BASE", "https://public-api.drata.com")
    log.info("drata", "target", tenant="prod" if args.drata_prod else "sandbox", push_mode=push_mode, base_url=base_url,
             connection_id=os.environ["DRATA_CONNECTION_ID"], resource_id=os.environ["DRATA_RESOURCE_ID"])
    if args.local and push_mode == "session":
        log.warn("drata", "local_session_push.replaces_resource", data="synthetic")
    dc = DrataClient(base_url,
                     drata_api_key(args.drata_prod, args.workspace))
    if _schema_mismatch(dc, os.environ["DRATA_CONNECTION_ID"], os.environ["DRATA_RESOURCE_ID"], records):
        return 2
    session_id = "vipr-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    conn, res = os.environ["DRATA_CONNECTION_ID"], os.environ["DRATA_RESOURCE_ID"]
    if push_mode == "session":
        ok, failed, action = dc.replace_via_session(conn, res, records, session_id, cancel_foreign=args.cancel_open_sessions)
        if action == "unusable":
            log.warn("session", "replace.unusable", reason=failed[-1]["error"], fallback="upsert", old_records_removed=False)
            ok, failed = dc.upsert(conn, res, records)
            action = "upsert_fallback"
        outcome = (action if not any(f["error"].startswith("session %s failed" % action) for f in failed) else action + "_failed").replace(" ", "_")
        log.info("session", "replace.result", session_id=session_id, pushed=ok, failed=len(failed), outcome=outcome)
    else:
        ok, failed = dc.upsert(conn, res, records)
        log.info("drata", "upsert.result", pushed=ok, failed=len(failed))
    log.info("drata", "http.summary", responses={str(k): v for k, v in dc.http_counts.items()})
    if not failed:
        _verify(dc, conn, res, records)
    if dc.unverified:
        log.warn("drata", "bulk_response.unverified", count=dc.unverified)
    if failed:
        _dump(os.path.join(args.output_dir, "_failed.json"), failed)
        by_error = {}
        for f in failed:
            by_error.setdefault(f["error"], []).append(f["id"])
        log.error("drata", "records.failed", count=len(failed), distinct_errors=len(by_error), details=os.path.join(args.output_dir, "_failed.json"))
        for msg, ids in list(by_error.items())[:3]:
            log.error("drata", "records.failed.error", count=len(ids), example_id=ids[0], message=msg)
        if any("Schema validation failed" in m for m in by_error):
            log.error("drata", "schema.mismatch", cause="resource_schema_outdated",
                      remedy="edit the resource schema in Drata and paste schemas/vipr_unified.schema.json")
    return 1 if failed else 0


def _schema_mismatch(dc, conn, res, records):
    try:
        schema = dc.resource_schema(conn, res)
        if not isinstance(schema, dict):
            log.warn("schema", "read.unavailable", effect="validation_by_drata_on_upload")
            return False
        declared = schema.get("properties")
        required = [k for k in schema.get("required") or [] if isinstance(k, str)]
        missing = sorted({k for k in required for r in records if k not in r})
        closed = isinstance(declared, dict) and schema.get("additionalProperties") is False
        extra = sorted({k for r in records for k in r if k not in declared}) if closed else []
        if missing or extra:
            log.error("schema", "mismatch", required_not_sent=missing[:8] or "none", sent_not_in_schema=extra[:8] or "none",
                      pushed=False, remedy="edit the resource schema in Drata and paste schemas/vipr_unified.schema.json")
            return True
        _warn_undeclared_facts(declared, records)
    except Exception as e:
        log.warn("schema", "check.skipped", error_type=type(e).__name__)
    return False


def _warn_undeclared_facts(declared, records):
    if not isinstance(declared, dict):
        return
    facts = {k for r in records for k in r if k not in declared}
    for array in ("findings", "assets"):
        item_props = ((declared.get(array) or {}).get("items") or {}).get("properties")
        if isinstance(item_props, dict):
            keys = set()
            for r in records:
                for item in r.get(array) or []:
                    keys.update(item)
            facts |= {"%s[].%s" % (array, k) for k in keys if k not in item_props}
    if facts:
        log.warn("schema", "facts_missing", count=len(facts), facts=sorted(facts)[:12],
                 effect="custom tests cannot use these facts", remedy="paste schemas/vipr_unified.schema.json into the resource")


def _verify(dc, conn, res, records):
    log.info("verify", "start", sample_size=3, order="newest_first")
    box = {}

    def read():
        try:
            box["listed"] = dc.list_records(conn, res)
        except Exception as e:
            box["error"] = e

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    reader.join(45)
    if reader.is_alive():
        log.warn("verify", "timeout", seconds=45)
        return
    try:
        if "error" in box:
            raise box["error"]
        listed = box.get("listed")
        if listed is None:
            log.warn("verify", "read.unavailable", cause="no_response_or_missing_read_scope")
            return
        ids, total = listed
        ours = {r["id"] for r in records}
        seen = len(ours & set(ids))
        log.info("verify", "result", sampled=len(ids), resource_total=total, ours_present=seen, ours_sent=len(ours))
        legacy = [i for i in ids if i.startswith(("finding:", "asset:"))]
        if legacy:
            log.warn("verify", "legacy_records.present", sampled=len(legacy), example_id=legacy[0][:60],
                     remedy="vipr-drata --push-mode session")
        if not seen and (total is None or total > len(ids)):
            log.info("verify", "sample.inconclusive", sampled=len(ids), push_accepted=True)
        elif not seen:
            log.warn("verify", "records.not_visible", ours_sent=len(ours), check="DRATA_CONNECTION_ID,DRATA_RESOURCE_ID,DRATA_API_KEY")
    except Exception as e:
        log.warn("verify", "skipped", error_type=type(e).__name__)


def run():
    sys.exit(main())


if __name__ == "__main__":
    run()
