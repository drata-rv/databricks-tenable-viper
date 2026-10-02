"""CLI / python_wheel_task entry point. --env KEY=VALUE feeds os.environ (serverless has no env injection)."""
import argparse
import atexit
import json
import os
import sys


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


_apply_cli_env_overrides()

try:
    from dotenv import load_dotenv

    load_dotenv()  # never overrides already-set vars
except ImportError:
    pass

from .db.auth import drata_api_key, get_client_for_env  # noqa: E402
from .db.drata_client import DrataClient  # noqa: E402
from .etl.extract import extract_all, merge  # noqa: E402
from .transform import build_payloads  # noqa: E402


def _dump(path, data):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def main(argv=None):
    p = argparse.ArgumentParser(prog="vipr-drata")
    p.add_argument("--workspace", default=os.getenv("DATABRICKS_WORKSPACE", "test"), help="test|prod (Databricks source)")
    p.add_argument("--warehouse-id", default=os.getenv("DATABRICKS_WAREHOUSE_ID"))
    p.add_argument("--output-dir", default=os.getenv("OUTPUT_DIR", "output"))
    p.add_argument("--stale-days", type=int, default=int(os.getenv("SCAN_STALE_DAYS", "7")))
    p.add_argument("--drata-prod", action="store_true", default=os.getenv("DRATA_PROD", "false").lower() == "true",
                   help="push to Drata prod tenant (separate credentials, no sandbox fallback)")
    p.add_argument("--dry-run", action="store_true", help="extract+transform only, no push")
    p.add_argument("--env", action="append", help="KEY=VALUE applied to environment (job params)")
    args = p.parse_args(argv)
    if not args.warehouse_id:
        p.error("warehouse id required (--warehouse-id or DATABRICKS_WAREHOUSE_ID)")

    state = {}
    atexit.register(lambda: state and _dump(os.path.join(args.output_dir, "partial.json"), state)
                    if state.get("incomplete") else None)
    state["incomplete"] = True

    client = get_client_for_env(args.workspace)
    tables = extract_all(client, args.warehouse_id)
    joined, assets = merge(tables)
    findings, scans, rejected = build_payloads(joined, assets, args.stale_days)
    state.update(findings=findings, assets=scans, rejected=rejected)

    _dump(os.path.join(args.output_dir, "findings.json"), findings)
    _dump(os.path.join(args.output_dir, "asset_scan_coverage.json"), scans)
    _dump(os.path.join(args.output_dir, "_rejected.json"), rejected)
    print("findings=%d assets=%d rejected=%d" % (len(findings), len(scans), len(rejected)))

    if args.dry_run:
        state["incomplete"] = False
        return 0
    dc = DrataClient(
        os.getenv("DRATA_API_BASE", "https://public-api.drata.com"),
        drata_api_key(args.drata_prod),
        os.environ["DRATA_CONNECTION_ID"],
        os.getenv("DRATA_PUSH_PATH", "/public/v1/custom-connections/{connection_id}/resources/{resource}/records"),
    )
    failed_total = 0
    for resource, recs in (("vulnerability_findings", findings), ("asset_scan_coverage", scans)):
        ok, failed = dc.push_all(resource, recs)
        failed_total += len(failed)
        print("%s pushed=%d failed=%d" % (resource, ok, len(failed)))
        if failed:
            _dump(os.path.join(args.output_dir, "_failed_%s.json" % resource), failed)
    state["incomplete"] = False
    return 1 if failed_total else 0


if __name__ == "__main__":
    sys.exit(main())
