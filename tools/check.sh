#!/usr/bin/env sh
# Repository check: unique ids in append-only logs, never-store .gitignore present.
set -eu
cd "$(dirname "$0")/.."
[ -f .gitignore ] || { echo "FAIL: .gitignore (never-store list) missing"; exit 1; }
python3 -I - <<'PY'
import glob, json, sys
bad = False
for path in sorted(glob.glob("ops/*.jsonl")):
    seen = set()
    for n, line in enumerate(open(path, encoding="utf-8"), 1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as e:
            print(f"FAIL: {path}:{n} not JSON ({e})"); bad = True; continue
        i = rec.get("id")
        if not i:
            print(f"FAIL: {path}:{n} has no id"); bad = True; continue
        if i in seen:
            print(f"FAIL: {path}:{n} duplicate id {i}"); bad = True
        seen.add(i)
    print(f"ok: {path} ({len(seen)} ids)")
sys.exit(1 if bad else 0)
PY
echo "check: green"
