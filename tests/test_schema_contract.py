import csv
import pathlib

import openpyxl
import pytest

from vipr_drata.etl.extract import TABLE_REGISTRY
from vipr_drata.etl.sample_data import write_sample_data

DOCS = pathlib.Path(__file__).parent.parent / "docs"
SOURCES = {
    "findings": ("Vipr Tables Describe.xlsx", "Findings"),
    "assets": ("Vipr Tables Describe.xlsx", "Assets"),
    "tenable_assets": ("Tenable Tables.xlsx", "Assets"),
}


def load_sheet(book, sheet):
    ws = openpyxl.load_workbook(DOCS / book)[sheet]
    rows = [r for r in ws.iter_rows(values_only=True) if any(c is not None for c in r)]
    cols = {}
    for name, dtype in rows[2:]:
        if str(name).startswith("#"):
            break
        cols[name] = dtype
    return rows[0][0], cols


@pytest.mark.parametrize("spec", TABLE_REGISTRY, ids=lambda s: s.label)
def test_registry_columns_exist_in_xlsx(spec):
    _, cols = load_sheet(*SOURCES[spec.label])
    assert not [c for c in spec.columns if c not in cols], "columns not in xlsx"
    assert "__date" in cols and "__hour" in cols
    assert "__raw" not in spec.columns


def test_env_example_table_names_match_xlsx():
    env = (pathlib.Path(__file__).parent.parent / ".env.example").read_text()
    for var, label in (("VIPR_FINDINGS_TABLE", "findings"), ("VIPR_ASSETS_TABLE", "assets")):
        table, _ = load_sheet(*SOURCES[label])
        assert "%s=%s" % (var, table) in env


def test_tenable_array_columns_are_arrays():
    _, cols = load_sheet(*SOURCES["tenable_assets"])
    for c in ("hostnames", "fqdns", "mac_addresses"):
        assert cols[c].startswith("array<")


def test_local_fixture_headers_are_subset_of_xlsx(tmp_path):
    write_sample_data(str(tmp_path))
    for label, (book, sheet) in SOURCES.items():
        _, cols = load_sheet(book, sheet)
        header = next(csv.reader(open(tmp_path / (label + ".csv"))))
        assert set(header) <= set(cols)
