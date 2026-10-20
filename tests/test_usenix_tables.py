"""Prevent manuscript route/stratum tables from drifting from frozen C1 data."""

from __future__ import annotations

import csv
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "paper/venues/usenixsecurity27/official_pdf/main.tex"
DATA = ROOT / "paper/current/table_c1_route_strata.csv"
FIELDS = ("imported", "rejected", "semantic_pass", "degraded_visible", "degraded_silent", "not_evaluable")


def _expected(key: str) -> dict[str, tuple[int, ...]]:
    grouped: dict[str, Counter[str]] = defaultdict(Counter)
    with DATA.open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            for field in FIELDS:
                grouped[row[key]][field] += int(row[field])
    return {group: tuple(counts[field] for field in FIELDS) for group, counts in grouped.items()}


def _observed(pattern: str) -> dict[str, tuple[int, ...]]:
    text = SOURCE.read_text(encoding="utf-8")
    out = {}
    for match in re.finditer(pattern, text, flags=re.MULTILINE):
        cells = [cell.strip() for cell in match.group(2).split("&")]
        out[match.group(1)] = tuple(int(cell.replace(",", "")) for cell in cells[-6:])
    return out


def test_route_table_matches_frozen_matrix():
    assert _observed(r"^(R\d\d) & (.+?) \\\\$") == _expected("route_id")


def test_stratum_table_matches_frozen_matrix():
    assert _observed(r"^(F\d) [^&]+ & (.+?) \\\\$") == _expected("feature_stratum")
