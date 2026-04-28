from backend.database.db import compare_scans


def test_compare_scans_returns_none_for_missing_reports():
    assert compare_scans("missing-left", "missing-right") is None
