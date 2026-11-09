"""The three routes from a recording house's side (J4, the atlas's TODO-196; JETSAM, Surfaces). Standard
library only. Every route sends the outbox file's bytes and nothing else, and every send is the operator's
act: the close asks the question, `jetsam send` carries out the yes.

  route 1, drop   POST the bytes to the drop point the house's config names (`"drop": "<https URL>"`). None
                  is hosted yet (AT.645), so no house names one and the tool refuses this route by name. The
                  drop point sees the sender's address for that one request (JT.11, AT.644).
  route 2, push   the operator's own pull request: in a clean checkout of the log's repository (or a fork of
                  it), a branch `jetsam/<hash>` with ONE commit adding `jetsam/inbox/<hash>.json`, its author
                  and committer the name and address the operator chooses (a neutral default, never read from
                  git's config) and both dates the day at 00:00Z. The operator pushes it from the account
                  they choose and opens the pull request; GitHub shows that account as its author. Then
                  `jetsam send <hash> --receipt <pull request URL>` records it as sent.
  route 3, handoff  on a surface that cannot send: the packet travels in the handoff under jetsam/outbox/
                  and is sent from a machine with the tool, by route 1 or 2. `jetsam carry-check <zip>` reads
                  a handoff zip and refuses one that carries anything of jetsam/local/ or a packet whose bytes
                  are not canonical or not named by their hash.

Send-day jitter (JT.11's option, off unless the config says `"jitter": true` or the send says `--jitter`):
the first send of a packet picks a day uniformly from today to the month's end, kept in jetsam/local/, and
the packet is held until that day, so the moment of sending says less about when the house closed.

The sent-ledger (jetsam/sent.jsonl, travels): hash, day, route, receipt; never content. A packet the drop
point refuses is counted in jetsam/local/sends-refused.jsonl (hash, day, route, the checks' names) and stays
unsent, so `jetsam status` shows the count and the next send can carry it once the tool is fixed.
"""
from __future__ import annotations

import calendar
import datetime as dt
import json
import os
import secrets
import subprocess
import urllib.error
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

from . import canonical as core
from .house import House

OPERATOR_NAME = "jetsam operator"
OPERATOR_EMAIL = "operator@jetsam.invalid"
MESSAGE = "jetsam: one packet, {day}"
USER_AGENT = "jetsam"
NO_DROP = ("no drop point address is configured: none is hosted yet (the atlas's AT.645), so route 1 is off; "
           "route 2 (`jetsam send --route push --clone DIR`) or route 3 (the handoff) carries the packet")
HANDOFF = ("route handoff (route 3): the packet travels with the house in jetsam/outbox/; send it from a machine "
           "with the tool by route 2 (`jetsam send --route push --clone DIR`), or hand the house to a session that can")


def today() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")


def unsent(house: House, which: str | None = None) -> list[tuple[Path, bytes]]:
    sent = house.sent_hashes()
    out = []
    for p, _ in house.outbox_packets():
        if p.stem in sent or (which and not p.stem.startswith(which)):
            continue
        out.append((p, p.read_bytes()))
    return out


def append(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(row, sort_keys=True) + "\n")


def record_sent(house: House, h: str, day: str, route: str, receipt: str) -> None:
    append(house.sent_path, {"hash": h, "day": day, "route": route, "receipt": receipt})


def refused_path(house: House) -> Path:
    return house.local / "sends-refused.jsonl"


def record_refused(house: House, h: str, day: str, route: str, checks: list[str]) -> None:
    append(refused_path(house), {"hash": h, "day": day, "route": route, "checks": sorted(checks)})


def refused_sends(house: House) -> int:
    try:
        return sum(1 for l in refused_path(house).read_text(encoding="utf-8").splitlines() if l.strip())
    except OSError:
        return 0


# ------------------------------------------------------------------------------ send-day jitter

def hold_day(house: House, h: str, day: str) -> str:
    """The day this packet may first be sent: chosen once, uniformly from `day` to the month's end."""
    p = house.local / f"hold-{h[:16]}.json"
    try:
        return json.loads(p.read_text(encoding="utf-8"))["day"]
    except (OSError, ValueError, KeyError):
        pass
    d = dt.date.fromisoformat(day)
    last = calendar.monthrange(d.year, d.month)[1]
    pick = d.replace(day=d.day + secrets.randbelow(last - d.day + 1)).isoformat()
    house.local.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"day": pick}) + "\n", encoding="utf-8")
    return pick


# ------------------------------------------------------------------------------ route 1, the drop point

def send_drop(url: str, raw: bytes) -> tuple[str, object]:
    """('accepted', receipt) | ('refused', [checks]) | ('error', why). The request carries the bytes, a
    content type and a fixed user agent: no name, no house, no time."""
    req = urllib.request.Request(url, data=raw, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = json.loads(r.read() or b"{}")
            return "accepted", ("already in the log's inbox" if body.get("duplicate")
                                else f"accepted by the drop point, commit {str(body.get('commit', ''))[:12] or 'unnamed'}")
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read() or b"{}")
        except ValueError:
            body = {}
        if e.code == 422 and isinstance(body.get("refused"), list):
            return "refused", [str(c) for c in body["refused"]]
        return "error", f"HTTP {e.code}: {body.get('error', 'no reason given')}"
    except (urllib.error.URLError, OSError, ValueError) as e:
        return "error", f"unreachable ({type(e).__name__})"


# ------------------------------------------------------------------------------ route 2, own push

def git(clone: Path, *a, env=None) -> str:
    return subprocess.run(["git", "-C", str(clone), *a], capture_output=True, text=True, check=True,
                          env=env).stdout.strip()


def send_push(clone, raw: bytes, day: str, name: str | None = None, email: str | None = None) -> tuple[str, str]:
    """One commit on a new branch of the clone: the packet's file and the day. Returns (branch, commit)."""
    clone = Path(clone)
    if not (clone / "jetsam" / "inbox").is_dir():
        raise ValueError(f"{clone} is not a checkout of the log's repository (no jetsam/inbox/)")
    if git(clone, "status", "--porcelain"):
        raise ValueError(f"{clone} has uncommitted changes; route 2 commits only the packet")
    h = core.content_hash(raw)
    branch = f"jetsam/{h[:12]}"
    rel = f"jetsam/inbox/{h}.json"
    git(clone, "checkout", "-q", "-b", branch)
    (clone / rel).write_bytes(raw)
    git(clone, "add", rel)
    stamp = f"{day}T00:00:00Z"
    env = {k: x for k, x in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_AUTHOR_NAME=name or OPERATOR_NAME, GIT_AUTHOR_EMAIL=email or OPERATOR_EMAIL,
               GIT_COMMITTER_NAME=name or OPERATOR_NAME, GIT_COMMITTER_EMAIL=email or OPERATOR_EMAIL,
               GIT_AUTHOR_DATE=stamp, GIT_COMMITTER_DATE=stamp)
    git(clone, "-c", "commit.gpgsign=false", "commit", "-q", "--no-verify", "-m", MESSAGE.format(day=day), env=env)
    return branch, git(clone, "rev-parse", "HEAD")


# ------------------------------------------------------------------------------ route 3, the handoff

def carry_check(zip_path) -> tuple[int, list[str]]:
    """(packets carried, problems) for a handoff zip: nothing of jetsam/local/, and every outbox file's
    bytes canonical and named by their content hash. Only the bytes are ever sent, so a file's stored time
    in the zip never reaches the log."""
    n, problems = 0, []
    with zipfile.ZipFile(zip_path) as z:
        for name in z.namelist():
            parts = PurePosixPath(name).parts
            if "jetsam" not in parts:
                continue
            sub = parts[parts.index("jetsam") + 1:]
            if sub[:1] == ("local",):
                problems.append(f"carries {name}: jetsam/local/ never leaves the house")
            elif sub[:1] == ("outbox",) and name.endswith(".json"):
                raw = z.read(name)
                try:
                    canon = core.canonical(core.parse(raw))
                except Exception:
                    canon = None
                if canon != raw or PurePosixPath(name).name != core.content_hash(raw) + ".json":
                    problems.append(f"carries {name}: its bytes are not canonical or not named by their hash")
                else:
                    n += 1
    return n, problems
