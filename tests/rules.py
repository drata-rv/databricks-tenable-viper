OPS = {
    "equal": lambda a, b: a == b, "equals": lambda a, b: a == b,
    "notEqual": lambda a, b: a != b,
    "exist": lambda a, b: (a is not None) == bool(b),
}


def _get(obj, cond):
    value = obj.get(cond["fact"]) if isinstance(obj, dict) else None
    for part in str(cond.get("path", "")).split(".") if cond.get("path") else []:
        value = value.get(part) if isinstance(value, dict) else None
    return value


def evaluate(rule, obj):
    if "all" in rule:
        return all(evaluate(r, obj) for r in rule["all"])
    if "any" in rule:
        return any(evaluate(r, obj) for r in rule["any"])
    fact = _get(obj, rule)
    if rule["operator"] == "all":
        return isinstance(fact, list) and all(evaluate(rule["value"], item) for item in fact)
    return OPS[rule["operator"]](fact, rule["value"])


def failing_items(rule, record, array):
    inner = next(c["value"] for c in rule["all"] if c["fact"] == array and c["operator"] == "all")
    return [i for i in record.get(array) or [] if not evaluate(inner, i)]
