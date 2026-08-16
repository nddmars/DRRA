#!/usr/bin/env python3
"""
DRRA-087 — Evidence-path gate for the traceability matrix.

Turns the capability→evidence traceability matrix (docs/CLAIM_TRACEABILITY.md)
from a document into an enforced control. It does NOT judge whether the evidence
is *sufficient* (that is human review); it enforces that every **Implemented**
claim points at real, plausibly-substantive artifacts, so a claim cannot silently
drift away from code.

Checks, for every row whose status starts with "Implemented":
  * the matrix file exists and contains the status-policy section;
  * all committed file paths cited in the Evidence cell exist (generated outputs
    under results/ are exempt — see GENERATED_PREFIXES);
  * the row does not simultaneously say Implemented and cite "future"/"planned"/
    "TODO" (a contradictory status);
  * each cited test file actually contains a test definition (a Python `def test`
    or a Rust `#[test]`), so an Implemented claim cannot cite an empty test file.

Exit non-zero on any violation.

Usage:
    python scripts/check_claim_integrity.py
"""

from __future__ import annotations

import os
import re
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MATRIX = os.path.join(REPO, "docs", "CLAIM_TRACEABILITY.md")

# file references like backend/services/foo.py, tests/bar.rs, lab/lab_manifest.json
PATH_RE = re.compile(r"[\w./-]+\.(?:py|rs|md|json|yaml|yml|toml)")

# Generated outputs are produced by running a generator; they are not committed,
# so a fresh checkout won't contain them. The generator SOURCE existing is the
# real evidence, so evidence paths under these prefixes are not required to exist.
GENERATED_PREFIXES = ("results/",)


def _read(path: str) -> str:
    try:
        return open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return ""


def main() -> int:
    if not os.path.exists(MATRIX):
        print(f"::error::traceability matrix missing: {MATRIX}")
        return 1

    text = open(MATRIX, encoding="utf-8").read()
    if "Status policy" not in text:
        print("::error::traceability matrix is missing its 'Status policy' section")
        return 1

    violations = 0
    implemented_rows = 0
    for line in text.splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 3:
            continue
        status, evidence = cells[1], cells[2]
        # only enforce rows whose status is Implemented (not Partial/Modeled/Future)
        if not status.lower().startswith("implemented"):
            continue
        implemented_rows += 1
        # contradictory status: Implemented but evidence talks about future work
        if re.search(r"\b(future|planned|TODO|not yet)\b", evidence, re.I):
            print(f"::error::row {cells[0]!r} is Implemented but cites future/planned work")
            violations += 1
        # only require committed source evidence, not generated outputs
        paths = [p for p in PATH_RE.findall(evidence)
                 if not p.startswith(GENERATED_PREFIXES)]
        if not paths:
            print(f"::error::Implemented row cites no committed evidence file: {cells[0]!r}")
            violations += 1
            continue
        for rel in paths:
            full = os.path.join(REPO, rel)
            if not os.path.exists(full):
                print(f"::error::Implemented row {cells[0]!r} cites missing file: {rel}")
                violations += 1
                continue
            # a cited test file must actually contain a test
            base = os.path.basename(rel)
            if rel.endswith(".py") and (base.startswith("test_") or "/tests/" in "/" + rel):
                if "def test" not in _read(full):
                    print(f"::error::row {cells[0]!r} cites test file with no test: {rel}")
                    violations += 1
            elif rel.endswith(".rs") and "test" in base and "#[test]" not in _read(full):
                print(f"::error::row {cells[0]!r} cites Rust test file with no #[test]: {rel}")
                violations += 1

    print(f"Checked {implemented_rows} Implemented rows; {violations} violation(s).")
    if violations:
        print("::error::evidence-path gate failed — see violations above")
        return 1
    print("Evidence-path gate passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
