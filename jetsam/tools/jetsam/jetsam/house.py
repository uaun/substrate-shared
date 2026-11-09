"""A recording house's Jetsam state (J2, the atlas's TODO-194; JETSAM, rules 1, 2 and 5, and
Surfaces). Everything lives under `jetsam/` at the house root:

  jetsam/config.json          travels with the house: the framework, its enum file, its release,
                              the classes this house offers and the route (written by the train)
  jetsam/outbox/<hash>.json   travels: one packet per framework per epoch, canonical bytes, named
                              by their content hash
  jetsam/sent.jsonl           travels, append-only: hash, day, route, receipt; content never
  jetsam/local/               never leaves: the house's never-store mirror and its packer exclude it
      consent.json            the classes the operator said yes to, and the schema asked under
      secret-<framework>      the pseudonym's 32-byte secret, only while the pseudonym is on (JT.2)
      events-<epoch>.jsonl    one line per event, written by the recorder call (record.py)
      refused-<epoch>.jsonl   one line per event the recorder could not take
      closes-<epoch>.jsonl    one line per close: the totals at that close and its own run time
      suggestion-<epoch>.json the epoch's one suggestion, scrubbed and confirmed (JT.3)

While every class is off nothing under jetsam/ is written by a close or a recorder call: not a
directory, not a byte.
"""
from __future__ import annotations

import json
import os
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from . import SCHEMA, enums as enumfiles
from . import record as recorder

ROUTES = ("handoff", "drop", "push")
SENDING = ("drop", "push")          # the routes that send; neither exists before J4 (TODO-196)
EPOCH_FILE = re.compile(r"^(events|refused|closes)-([0-9]{4}-[0-9]{2})\.jsonl$")


class HouseError(ValueError):
    """The house's config cannot be read, or names something that is not there."""


@dataclass
class House:
    root: Path
    framework: str
    enums_path: Path
    release: str
    offered: list[str]
    route: str
    surface: str
    digests_path: Path | None = None
    patterns_path: Path | None = None
    raw: dict = field(default_factory=dict)

    # ---------------------------------------------------------------- paths
    @property
    def dir(self) -> Path:
        return self.root / "jetsam"

    @property
    def local(self) -> Path:
        return self.dir / "local"

    @property
    def outbox(self) -> Path:
        return self.dir / "outbox"

    @property
    def sent_path(self) -> Path:
        return self.dir / "sent.jsonl"

    def epoch_file(self, kind: str, epoch: str) -> Path:
        return self.local / f"{kind}-{epoch}.jsonl"

    def secret_path(self) -> Path:
        return self.local / f"secret-{self.framework}"

    def suggestion_path(self, epoch: str) -> Path:
        return self.local / f"suggestion-{epoch}.json"

    # ---------------------------------------------------------------- consent
    def consent(self) -> dict:
        """{class: month consented} under the current schema; a consent given under another schema
        version is none at all (rule 1: a new version is asked again)."""
        try:
            c = json.loads((self.local / "consent.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        if c.get("jetsam") != SCHEMA or not isinstance(c.get("classes"), dict):
            return {}
        return {k: v for k, v in c["classes"].items() if k in self.offered}

    def stale_consent(self) -> bool:
        try:
            c = json.loads((self.local / "consent.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        return c.get("jetsam") != SCHEMA and bool(c.get("classes"))

    def write_consent(self, classes: dict) -> None:
        p = self.local / "consent.json"
        if not classes:
            if p.exists():
                p.unlink()
            return
        self.local.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"jetsam": SCHEMA, "classes": dict(sorted(classes.items()))}, indent=1) + "\n",
                     encoding="utf-8")

    def classes_on(self, schema: dict) -> list[str]:
        """The consented classes, in the schema's class order."""
        on = self.consent()
        return [c for c in schema["classes"] if c in on]

    # ---------------------------------------------------------------- the pseudonym's secret (JT.2)
    def secret(self) -> bytes | None:
        try:
            s = self.secret_path().read_bytes()
        except OSError:
            return None
        return s if len(s) == 32 else None

    def pseudonym_on(self) -> None:
        if self.secret() is not None:
            return
        self.local.mkdir(parents=True, exist_ok=True)
        p = self.secret_path()
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(secrets.token_bytes(32))

    def pseudonym_off(self) -> None:
        if self.secret_path().exists():
            self.secret_path().unlink()

    # ---------------------------------------------------------------- local detail
    def lines(self, kind: str, epoch: str) -> list[str]:
        try:
            return [l for l in self.epoch_file(kind, epoch).read_text(encoding="utf-8").splitlines() if l.strip()]
        except OSError:
            return []

    def epochs(self) -> list[str]:
        """Every epoch the local detail holds a file for, oldest first."""
        out = set()
        try:
            for p in self.local.iterdir():
                m = EPOCH_FILE.match(p.name)
                if m:
                    out.add(m.group(2))
                elif p.name.startswith("suggestion-") and p.name.endswith(".json"):
                    out.add(p.name[len("suggestion-"):-len(".json")])
        except OSError:
            pass
        return sorted(out)

    def writable(self) -> bool:
        """Whether a close could write its detail: jetsam/local/ exists and takes a file, or can be
        made. Probed only while a class is on, so an off house is never touched."""
        try:
            self.local.mkdir(parents=True, exist_ok=True)
            probe = self.local / ".probe"
            probe.write_bytes(b"")
            probe.unlink()
            return True
        except OSError:
            return False

    # ---------------------------------------------------------------- outbox and sent-ledger
    def outbox_packets(self) -> list[tuple[Path, dict]]:
        out = []
        try:
            files = sorted(self.outbox.glob("*.json"))
        except OSError:
            return out
        for p in files:
            try:
                out.append((p, json.loads(p.read_bytes().decode("utf-8"))))
            except (OSError, ValueError):
                out.append((p, {}))
        return out

    def sent(self) -> list[dict]:
        try:
            return [json.loads(l) for l in self.sent_path.read_text(encoding="utf-8").splitlines() if l.strip()]
        except (OSError, ValueError):
            return []

    def sent_hashes(self) -> set[str]:
        return {s.get("hash") for s in self.sent()}

    # ---------------------------------------------------------------- the recorder, for the CLI
    def record(self, cls: str, **fields) -> None:
        recorder.record(self.root, cls, **fields)

    def load_enums(self, digests: set[str] | None = None):
        return enumfiles.load(self.enums_path, digests)


def load(root, config: str = "jetsam/config.json") -> House:
    """The house at `root`, from its `jetsam/config.json`; raises HouseError naming what is wrong."""
    root = Path(root).resolve()
    p = root / config
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except OSError:
        raise HouseError(f"no Jetsam config at {config}: Jetsam is not installed in this house")
    except ValueError as e:
        raise HouseError(f"{config} is not JSON ({e})")
    need = ("jetsam", "framework", "enums", "release", "offered", "route")
    missing = [k for k in need if k not in raw]
    if missing:
        raise HouseError(f"{config} lacks {', '.join(missing)}")
    if raw["jetsam"] != SCHEMA:
        raise HouseError(f"{config} is written for schema {raw['jetsam']}, and this tool writes {SCHEMA}")
    if raw["route"] not in ROUTES:
        raise HouseError(f"{config}: the route {raw['route']!r} is not one of {', '.join(ROUTES)}")
    if not isinstance(raw["offered"], list) or not all(isinstance(c, str) for c in raw["offered"]):
        raise HouseError(f"{config}: `offered` is not a list of class names")
    opt = lambda k: (root / raw[k]) if raw.get(k) else None  # noqa: E731
    return House(root=root, framework=raw["framework"], enums_path=root / raw["enums"], release=raw["release"],
                 offered=list(raw["offered"]), route=raw["route"], surface=raw.get("surface", "other"),
                 digests_path=opt("digests"), patterns_path=opt("patterns"), raw=raw)
