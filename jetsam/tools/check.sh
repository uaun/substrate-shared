#!/usr/bin/env bash
# tools/check.sh: this repository's one check, run by CI on every commit and pull request.
#   the vendored Jetsam package against its manifest (tools/jetsam/VENDOR.json)
#   verify: every view rebuilt from log/ and diffed, the log's names, places and ledger, the schema
#   the tests (tests/, under pytest)
# A step that cannot run says NOT RUN, and tests that cannot run are not a pass.
set -u
cd "$(dirname "$0")/.."
rc=0
echo "== the vendored package"
python3 -I -B tools/jetsam/run.py vendor-check tools/jetsam || rc=1
echo "== verify"
python3 -I -B tools/verify.py || rc=1
echo "== the tests"
if python3 -c "import pytest" 2>/dev/null; then
  python3 -m pytest -q -p no:cacheprovider tests || rc=1
else
  echo "NOT RUN: pytest is not installed"; rc=1
fi
if [ $rc -eq 0 ]; then echo "log check: GREEN"; else echo "log check: RED"; fi
exit $rc
