DENIED = ("permission_denied", "does not have", "insufficient privilege", "not authorized", "forbidden")
MISSING = ("table_or_view_not_found", "schema_not_found", "catalog_not_found", "does not exist")


def classify(error):
    text = str(error).lower()
    if any(m in text for m in DENIED):
        return "denied"
    return "missing" if any(m in text for m in MISSING) else "error"
