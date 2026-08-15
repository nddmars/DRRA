#!/usr/bin/env python3
"""
DRRA-087 — Claim-integrity gate.

Turns the capability→evidence traceability matrix (docs/CLAIM_TRACEABILITY.md)
from a document into an enforced control: every capability marked **Implemented**
must cite evidence files that actually exist in the repository. A row that claims
"Implemented" while pointing at a missing file fails the build, so a measured
claim can never drift away from its supporting artifact.

Checks:
  * the matrix file exists and contains the status-policy section;
  * for every Implemented row, all file paths cited in its Evidence cell exist.

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
        paths = PATH_RE.findall(evidence)
        if not paths:
            print(f"::error::Implemented row cites no evidence file: {cells[0]!r}")
            violations += 1
            continue
        for rel in paths:
            if not os.path.exists(os.path.join(REPO, rel)):
                print(f"::error::Implemented row {cells[0]!r} cites missing file: {rel}")
                violations += 1

    print(f"Checked {implemented_rows} Implemented rows; {violations} violation(s).")
    if violations:
        print("::error::claim-integrity gate failed — see violations above")
        return 1
    print("Claim-integrity gate passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
