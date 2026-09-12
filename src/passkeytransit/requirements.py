from __future__ import annotations

import json
import re
from pathlib import Path


def requirement_coverage(path: Path) -> dict[str, object]:
    data = json.loads(path.read_text(encoding="utf-8"))
    requirements = data["requirements"]
    ids = [item["id"] for item in requirements]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate requirement ids")
    levels: dict[str, int] = {}
    verification: dict[str, int] = {}
    tests_root = path.parent.parent / "tests"
    available_tests: set[str] = set()
    for test_file in tests_root.glob("test_*.py"):
        available_tests.update(
            re.findall(r"^def (test_[A-Za-z0-9_]+)\s*\(", test_file.read_text(encoding="utf-8"), re.MULTILINE)
        )
    referenced_tests: set[str] = set()
    for item in requirements:
        levels[item["level"]] = levels.get(item["level"], 0) + 1
        verification[item["verification"]] = verification.get(item["verification"], 0) + 1
        if item["verification"].startswith("automated") and not item["tests"]:
            raise ValueError(f"automated requirement without tests: {item['id']}")
        referenced_tests.update(item["tests"])
    missing_tests = referenced_tests - available_tests
    if missing_tests:
        raise ValueError(f"requirement matrix references missing tests: {sorted(missing_tests)}")
    return {
        "profile_id": data["profile_id"],
        "requirement_count": len(requirements),
        "levels": levels,
        "verification": verification,
        "referenced_test_count": len(referenced_tests),
        "valid": True,
    }
