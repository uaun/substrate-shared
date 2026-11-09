#!/usr/bin/env python3
"""tools/drop.py: the drop point, route 1 (Jetsam's J4; JT.11, the atlas's AT.644: necessary but untrusted, its
code public, no store, no log). It is hosted nowhere yet (AT.645). A host serves `application` from this file
with the environment the package's drop.py names (JETSAM_DROP_TOKEN, an identity that may commit to this
repository's main; JETSAM_DROP_LOG defaults to this folder, whose schema and enum mirrors it validates against).
Run directly it is a local test host on 127.0.0.1, for measurement only:

    python3 -I -B tools/drop.py [--port N]

It runs the Jetsam package vendored in tools/jetsam/, byte-checked against tools/jetsam/VENDOR.json. Python's
standard library only."""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools" / "jetsam"))
os.environ.setdefault("JETSAM_DROP_LOG", str(ROOT))
from jetsam.drop import application, serve  # noqa: E402,F401

if __name__ == "__main__":
    args = sys.argv[1:]
    serve(int(args[args.index("--port") + 1]) if "--port" in args[:-1] else 8737)
