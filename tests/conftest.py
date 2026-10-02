import os

import pytest


@pytest.fixture(autouse=True)
def hermetic_env(monkeypatch):
    """No developer .env, no ambient DRATA_/VIPR_/TENABLE_/DATABRICKS_ config, no real HTTP target."""
    monkeypatch.setenv("VIPR_DRATA_NO_DOTENV", "1")
    for k in list(os.environ):
        if k.startswith(("DRATA_", "VIPR_FINDINGS", "VIPR_ASSETS", "TENABLE_", "DATABRICKS_", "SCAN_STALE",
                         "MAX_REJECT", "LOCAL_DATA", "OUTPUT_DIR")):
            monkeypatch.delenv(k)
    monkeypatch.setenv("DRATA_API_BASE", "http://invalid.test")
