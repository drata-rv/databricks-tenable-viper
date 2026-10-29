import json
import pathlib
import sys
from datetime import datetime, timezone

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "src"))
import rules  # noqa: E402
from vipr_drata.batching import build_records  # noqa: E402

UI_ORDER = ["equal", "notEqual", "in", "notIn", "contains", "doesNotContain", "startsWith", "endsWith", "lessThan",
            "lessThanOrEqual", "greaterThan", "greaterThanOrEqual", "exist", "empty", "isBefore", "isAfter",
            "withinLastDays", "withinNextDays", "withinLastHours", "olderThanDays", "all", "any", "none", "notAll",
            "intersectsAny", "intersectsAll"]
RECORDS = (("scanSummary", "S"), ("findingPartition", "F"), ("assetPartition", "A"))


def fmt(node, depth=0):
    key = "all" if "all" in node else "any" if "any" in node else None
    if key is None:
        value = node.get("value")
        if isinstance(value, dict) and ("all" in value or "any" in value):
            head = json.dumps({k: v for k, v in node.items() if k != "value"}, separators=(",", ":"))
            return '%s,"value":%s}' % (head[:-1], fmt(value, depth))
        return json.dumps(node, separators=(",", ":"))
    pad = "  " * (depth + 1)
    body = ",\n".join(pad + fmt(c, depth + 1) for c in node[key])
    return '{"%s":[\n%s\n%s]}' % (key, body, "  " * depth)


def block(rule):
    return "```json\n%s\n```" % fmt(rule)


def type_label(prop):
    return " or ".join(sorted(t for t in rules.base_types(prop) if t != "null"))


def fact_tables(schema):
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    records = build_records([{"id": "f", "viprSeverity": "low", "open": True}], [{"id": "a"}], now=now,
                            source_dates={"findings": now, "assets": now})
    props = schema["properties"]
    where = {}
    for rtype, letter in RECORDS:
        for k in next(r for r in records if r["recordType"] == rtype):
            where[k] = where.get(k, "") + letter
    out = ["Records: S scanSummary, F findingPartition, A assetPartition.", "", "| Fact | Type | Records |", "|---|---|---|"]
    out += ["| `%s` | %s | %s |" % (k, type_label(props[k]), where[k]) for k in props if k in where]
    for arr in ("findings", "assets"):
        out += ["", "`%s[]` items (Advanced editor, nested rule):" % arr, "", "| Fact | Type |", "|---|---|"]
        out += ["| `%s` | %s |" % (k, type_label(v)) for k, v in props[arr]["items"]["properties"].items()]
    return "\n".join(out)


def operator_table():
    def ops(names):
        return ", ".join("`%s`" % o for o in UI_ORDER if o in names)
    return "\n".join([
        "| Field type | Operators |", "|---|---|",
        "| string | %s |" % ops(rules.STRING_OPS), "| number | %s |" % ops(rules.NUMBER_OPS),
        "| boolean | %s |" % ops(rules.BOOLEAN_OPS), "| array of objects | %s |" % ops(rules.ARRAY_OF_OBJECTS_OPS)])


def render():
    schema = json.load(open(HERE.parent / "schemas" / "vipr_unified.schema.json"))
    catalog = json.load(open(HERE / "catalog.json"))
    out = [(HERE / "intro.md").read_text().rstrip(), "", "## Facts", "", fact_tables(schema), "", "## Operators", "",
           operator_table(), "", (HERE / "operators.md").read_text().rstrip(), "", "## Tests", ""]
    for n, t in enumerate(catalog, 1):
        controls = "; ".join("%s %s" % (c["id"], c["name"]) for c in t["controls"])
        out += ["### %d. %s" % (n, t["name"]), "", "- Controls: %s" % controls, "- Editor: %s" % t["editor"],
                "- Description: %s" % t["description"]] + (["- Note: %s" % t["note"]] if t.get("note") else []) + ["", "Filtering criteria, Inclusion:", "", block(t["filter"]["evaluator"]), "",
                "Condition:", "", block(t["condition"]), ""]
    return "\n".join(out)


if __name__ == "__main__":
    (HERE / "README.md").write_text(render())
