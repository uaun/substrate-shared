#!/usr/bin/env python3
"""tools/burn.py: burn a pseudonym-epoch (JT.12): --framework F --epoch E --pseudonym P --reason TEXT (JETSAM, The public log and the aggregation tools). It runs the `log-burn` verb of the
Jetsam package vendored in tools/jetsam/, byte-checked against tools/jetsam/VENDOR.json, from this repository's
root; arguments pass through. Python's standard library only."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools" / "jetsam"))
from jetsam.__main__ import main  # noqa: E402

sys.exit(main(["jetsam", "log-burn", *sys.argv[1:], "--root", str(ROOT)]))
