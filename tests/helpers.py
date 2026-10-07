def flatten(records):
    out = {"summary": None, "findings": {}, "assets": {}, "batches": {"findingBatch": [], "assetBatch": []}}
    for r in records:
        if r["recordType"] == "summary":
            out["summary"] = r
        elif r["recordType"] == "findingBatch":
            out["batches"]["findingBatch"].append(r)
            out["findings"].update({i["id"]: i for i in r["findings"]})
        elif r["recordType"] == "assetBatch":
            out["batches"]["assetBatch"].append(r)
            out["assets"].update({i["id"]: i for i in r["assets"]})
    return out
