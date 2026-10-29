def flatten(records):
    out = {"summary": None, "findings": {}, "assets": {}, "partitions": {"findingPartition": [], "assetPartition": []}}
    for r in records:
        if r["recordType"] == "scanSummary":
            out["summary"] = r
        elif r["recordType"] == "findingPartition":
            out["partitions"]["findingPartition"].append(r)
            out["findings"].update({i["id"]: i for i in r["findings"]})
        elif r["recordType"] == "assetPartition":
            out["partitions"]["assetPartition"].append(r)
            out["assets"].update({i["id"]: i for i in r["assets"]})
    return out


def sent(call):
    import json
    return json.loads(call.kwargs["data"])
