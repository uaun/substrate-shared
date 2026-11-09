#!/usr/bin/env python3
"""tools/guard.py BASE: the paths this branch changed since BASE that a pull request may not change (JT.8):
the log's log/, views/ and inbox/refused/, which only the automated ingest writes. CI runs it on every pull
request; exit 1 names each refused path. A pull request may add a packet under inbox/. Paths are read
relative to this log's folder in the repository (jetsam/ in uaun/substrate-shared); a path outside it is
not the log's concern. The one branch that creates the log, against a base that holds none, passes."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools" / "jetsam"))
from jetsam.__main__ import main  # noqa: E402

if len(sys.argv) != 2:
    print(__doc__)
    sys.exit(2)
git = ["git", "-C", str(ROOT)]
top = Path(subprocess.run(git + ["rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True).stdout.strip())
prefix = ROOT.resolve().relative_to(top.resolve()).as_posix()
prefix = "" if prefix == "." else prefix + "/"
changed = subprocess.run(git + ["diff", "--name-only", f"{sys.argv[1]}...HEAD"],
                         capture_output=True, text=True, check=True).stdout.split()
mine = [c[len(prefix):] for c in changed if c.startswith(prefix)]
print(f"guard: {len(changed)} path(s) changed since {sys.argv[1]}, {len(mine)} of them in the log's folder")
existed = subprocess.run(git + ["cat-file", "-e", f"{sys.argv[1]}:{prefix}log/LEDGER.jsonl"], capture_output=True).returncode == 0
if not existed:
    print(f"guard: {sys.argv[1]} holds no log yet, so this branch creates it; its empty log/ and generated views/ "
          "are the one change of theirs a pull request carries")
    sys.exit(0)
sys.exit(main(["jetsam", "log-guard", *mine, "--root", str(ROOT)]))
