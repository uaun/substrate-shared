"""The recorder call (J2, the atlas's TODO-194; JETSAM, the shape in one page, piece 2): what a
framework calls at the moment it names. A host imports this file or copies it into its own code;
it reads only the standard library and nothing else in this package, so calling it costs a host
no dependency. `reference/record.mjs` is the same call for a Node host.

    record(root, cls, **fields)     root: the house root, the folder that holds jetsam/

- It never raises, never blocks and never changes the outcome of what it watched (rule 6,
  "never load-bearing"): every failure is swallowed.
- While `cls` is not consented it writes nothing at all, not a directory and not a byte (rule 1's
  control: a house with every class off produces zero bytes). Consent is read from
  `jetsam/local/consent.json`; a consent given under another schema version counts as none,
  because a new version is asked again.
- It appends one line to `jetsam/local/events-<epoch>.jsonl`, the epoch being the UTC month.
- An event it cannot write is a counted absence: it appends `{"refused": "recorder"}` to
  `jetsam/local/refused-<epoch>.jsonl`, which the close counts in the packet's control block, and
  gives up silently when even that fails (the next disclosure then reads UNAVAILABLE).
- `fields` are the class's fields without its count (`n`, or `opened` for reach): the close counts
  identical events and buckets the counts. Ids are not checked here; an id the enum file does not
  hold is refused at the close and counted the same way, so this call stays a few lines in any
  language.
"""
from __future__ import annotations

import json
import os
import time

SCHEMA = "1.0"


def epoch() -> str:
    """The current epoch: the UTC month, YYYY-MM (JT.9)."""
    return time.strftime("%Y-%m", time.gmtime())


def consented(root, cls: str) -> bool:
    try:
        with open(os.path.join(os.fspath(root), "jetsam", "local", "consent.json"), encoding="utf-8") as f:
            c = json.load(f)
        return c.get("jetsam") == SCHEMA and cls in (c.get("classes") or {})
    except Exception:
        return False


def record(root, cls: str, **fields) -> None:
    try:
        if not consented(root, cls):
            return
        local = os.path.join(os.fspath(root), "jetsam", "local")
    except Exception:
        return
    e = epoch()
    try:
        line = json.dumps(dict(fields, **{"class": cls}), sort_keys=True, ensure_ascii=False)
        with open(os.path.join(local, f"events-{e}.jsonl"), "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        try:
            with open(os.path.join(local, f"refused-{e}.jsonl"), "a", encoding="utf-8") as f:
                f.write('{"refused":"recorder"}\n')
        except Exception:
            pass
