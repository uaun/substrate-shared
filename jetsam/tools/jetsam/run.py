#!/usr/bin/env python3
"""The vendored jetsam tool's entry (J2): python3 -I -B <this folder>/run.py <verb> --root <house root>.
Copied into a recording house by `bin/jetsam.py vendor`, byte for byte, with the package beside it;
`-I` ignores PYTHONPATH, so this puts its own folder on the path. Standard library only."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from jetsam.__main__ import main  # noqa: E402

sys.exit(main(sys.argv))
