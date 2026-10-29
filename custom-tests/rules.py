from datetime import datetime, timedelta, timezone

STRING_OPS = {"equal", "notEqual", "in", "notIn", "contains", "doesNotContain", "startsWith", "endsWith", "isBefore",
              "isAfter", "exist", "empty", "withinLastDays", "withinNextDays", "withinLastHours", "olderThanDays"}
NUMBER_OPS = {"equal", "notEqual", "lessThan", "lessThanOrEqual", "greaterThan", "greaterThanOrEqual", "in", "notIn",
              "isBefore", "isAfter", "exist", "withinLastDays", "withinNextDays", "withinLastHours", "olderThanDays"}
BOOLEAN_OPS = {"equal", "notEqual", "in", "notIn", "exist"}
NULL_OPS = {"equal", "notEqual", "exist"}
ARRAY_OF_OBJECTS_OPS = {"contains", "doesNotContain", "all", "any", "none", "notAll", "exist", "empty"}
ARRAY_OF_PRIMITIVES_OPS = {"contains", "doesNotContain", "intersectsAny", "intersectsAll", "exist", "empty"}
NESTED_OPS = {"all", "any", "none", "notAll"}
VALUE_TYPES = {
    "equal": {"string", "boolean", "number", "null"}, "notEqual": {"string", "boolean", "number", "null"},
    "contains": {"string", "boolean", "number", "null"}, "doesNotContain": {"string", "boolean", "number", "null"},
    "in": {"array"}, "notIn": {"array"}, "intersectsAny": {"array"}, "intersectsAll": {"array"},
    "lessThan": {"number"}, "lessThanOrEqual": {"number"}, "greaterThan": {"number"}, "greaterThanOrEqual": {"number"},
    "exist": {"boolean"}, "empty": {"boolean"}, "startsWith": {"string"}, "endsWith": {"string"},
    "isBefore": {"string", "number"}, "isAfter": {"string", "number"},
    "withinLastDays": {"number"}, "withinNextDays": {"number"}, "withinLastHours": {"number"}, "olderThanDays": {"number"},
}
LITERAL_OPS = {"equal", "notEqual", "contains", "doesNotContain"}
MAX_CONDITIONS = 7
MAX_LINES = 70


def base_types(prop):
    raw = prop.get("type")
    return {"number" if t == "integer" else t for t in (raw if isinstance(raw, list) else [raw])}


def operators_for(prop):
    types = base_types(prop)
    ops = set()
    if "string" in types:
        ops |= STRING_OPS
    if "number" in types:
        ops |= NUMBER_OPS
    if "boolean" in types:
        ops |= BOOLEAN_OPS
    if "null" in types:
        ops |= NULL_OPS
    if "array" in types:
        item_types = base_types(prop.get("items", {}))
        ops |= ARRAY_OF_OBJECTS_OPS if item_types == {"object"} else ARRAY_OF_PRIMITIVES_OPS
    return ops


def json_type(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    return "array" if isinstance(value, list) else "string" if isinstance(value, str) else "object"


def count_conditions(node):
    group = node.get("all") if "all" in node else node.get("any")
    return 1 if group is None else sum(count_conditions(c) for c in group)


def check(node, props):
    errors = []
    if ("all" in node) == ("any" in node):
        return ["group needs exactly one of all/any"]
    for item in node.get("all") or node.get("any"):
        if "all" in item or "any" in item:
            errors += check(item, props)
            continue
        fact, op = item.get("fact"), item.get("operator")
        if fact not in props:
            errors.append("unknown fact %r" % fact)
            continue
        prop = props[fact]
        if item.get("path") == "length":
            prop = {"type": "number"}
        elif "path" in item:
            errors.append("unsupported path %r" % item["path"])
        if op not in operators_for(prop):
            errors.append("operator %r not offered for %s" % (op, fact))
            continue
        value = item.get("value")
        if op in NESTED_OPS:
            items = props[fact].get("items", {})
            if "properties" not in items:
                errors.append("%s has no item properties" % fact)
                continue
            errors += check(value if ("all" in value or "any" in value) else {"all": [value]}, items["properties"])
        elif json_type(value) not in VALUE_TYPES[op] or (
                op in LITERAL_OPS and json_type(value) not in base_types(prop) | {"null"}):
            errors.append("value %r invalid for %s on %s" % (value, op, fact))
        elif op in ("in", "notIn") and not {json_type(v) for v in value} <= base_types(prop):
            errors.append("list items invalid for %s" % fact)
    return errors


def _eq(a, b):
    return isinstance(a, bool) == isinstance(b, bool) and a == b


def _date(value, now):
    if value == "now":
        return now
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(value / 1000, tz=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def _midnight(dt):
    return dt.replace(hour=0, minute=0, second=0, microsecond=0)


def _compare(op, fact, value, now):
    if op in ("isBefore", "isAfter"):
        a, b = _date(fact, now), _date(value, now)
        return a is not None and b is not None and (a < b if op == "isBefore" else a > b)
    if isinstance(fact, bool) or not isinstance(fact, (str, int, float)):
        return False
    dt = _date(fact, now)
    if dt is None:
        return False
    today = _midnight(now)
    if op == "withinLastDays":
        return today - timedelta(days=value) <= _midnight(dt) <= today
    if op == "withinNextDays":
        return today <= _midnight(dt) <= today + timedelta(days=value)
    if op == "withinLastHours":
        return now - timedelta(hours=value) <= dt <= now
    return _midnight(dt) < today - timedelta(days=value)


def _fact(obj, cond):
    value = obj.get(cond["fact"]) if isinstance(obj, dict) else None
    path = cond.get("path")
    if path:
        value = len(value) if path == "length" and isinstance(value, list) else (value or {}).get(path) if isinstance(value, dict) else None
    return value


def evaluate(rule, obj, now=None):
    now = now or datetime.now(timezone.utc)
    if "all" in rule:
        return all(evaluate(r, obj, now) for r in rule["all"])
    if "any" in rule:
        return any(evaluate(r, obj, now) for r in rule["any"])
    fact, op, value = _fact(obj, rule), rule["operator"], rule["value"]
    if op in NESTED_OPS:
        if not isinstance(fact, list):
            return False
        hits = [evaluate(value, item, now) for item in fact]
        return {"all": all(hits), "any": any(hits), "none": not any(hits), "notAll": not all(hits) and bool(hits)}[op]
    if isinstance(value, dict) and "fact" in value:
        value = _fact(obj, value)
    if op in ("equal", "notEqual"):
        return _eq(fact, value) == (op == "equal")
    if op == "exist":
        return (fact is not None) == value
    if op == "empty":
        return (fact is None or isinstance(fact, (bool, int, float)) or (isinstance(fact, (str, list, dict)) and not fact)) == value
    if op in ("in", "notIn"):
        return (fact in value) == (op == "in")
    if op in ("lessThan", "lessThanOrEqual", "greaterThan", "greaterThanOrEqual"):
        if isinstance(fact, bool) or not isinstance(fact, (int, float)):
            return False
        return {"lessThan": fact < value, "lessThanOrEqual": fact <= value, "greaterThan": fact > value,
                "greaterThanOrEqual": fact >= value}[op]
    if op in ("contains", "doesNotContain"):
        if not isinstance(fact, (str, list)):
            return False
        return (value in fact) == (op == "contains")
    if op in ("startsWith", "endsWith"):
        return isinstance(fact, str) and (fact.startswith(value) if op == "startsWith" else fact.endswith(value))
    return _compare(op, fact, value, now)


def offending_items(rule, record, array):
    cond = next(c for c in rule["all"] if c.get("fact") == array and c.get("operator") in ("all", "none"))
    wanted = cond["operator"] == "none"
    return [i for i in record.get(array) or [] if evaluate(cond["value"], i) == wanted]
