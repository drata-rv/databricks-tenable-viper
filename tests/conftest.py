import os
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "custom-tests"))


@pytest.fixture(autouse=True)
def hermetic_env(monkeypatch):
    monkeypatch.setenv("VIPR_DRATA_NO_DOTENV", "1")
    for k in list(os.environ):
        if k.startswith(("DRATA_", "VIPR_FINDINGS", "VIPR_ASSETS", "TENABLE_", "DATABRICKS_", "SCAN_STALE",
                         "MAX_REJECT", "LOCAL_DATA", "OUTPUT_DIR", "ASSET_PARTITIONS", "FINDING_PARTITIONS",
                         "CLOSED_LOOKBACK", "MAX_SOURCE", "MAX_RECORD", "MIN_FINDINGS", "MIN_ASSETS", "LOCAL_ROWS",
                         "SCANNER_")):
            monkeypatch.delenv(k)
    monkeypatch.setenv("DRATA_API_BASE", "http://invalid.test")
    monkeypatch.setenv("DRATA_PUSH_MODE", "session")
