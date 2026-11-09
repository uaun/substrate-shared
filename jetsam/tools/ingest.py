#!/usr/bin/env python3
"""tools/ingest.py: inbox/ to log/, the only write path to log/: each packet validated against the enum file of its release, then the duplicate, the burn list and the cap; a refused file is kept under inbox/refused/ and counted (JETSAM, The public log and the aggregation tools). It runs the `log-ingest` verb of the
Jetsam package vendored in tools/jetsam/, byte-checked against tools/jetsam/VENDOR.json, from this repository's
root; arguments pass through. Python's standard library only."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools" / "jetsam"))
from jetsam.__main__ import main  # noqa: E402

sys.exit(main(["jetsam", "log-ingest", *sys.argv[1:], "--root", str(ROOT)]))
