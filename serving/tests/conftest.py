"""Test isolation: point the watchlist at a per-session temp copy so tests
never mutate serving/data/watchlist.json."""

import json
import os
import shutil
from pathlib import Path

import pytest

REAL_WATCHLIST = Path(__file__).resolve().parents[1] / "data" / "watchlist.json"


@pytest.fixture(autouse=True)
def temp_watchlist(tmp_path, monkeypatch):
    tmp = tmp_path / "watchlist.json"
    if REAL_WATCHLIST.exists():
        shutil.copy(REAL_WATCHLIST, tmp)
    else:
        tmp.write_text(json.dumps({"entries": []}))
    monkeypatch.setenv("WATCHLIST_PATH", str(tmp))
    yield
