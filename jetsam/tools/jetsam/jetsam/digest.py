"""The close (J2, the atlas's TODO-194): one epoch's local detail into one packet, written to the
outbox as canonical bytes named by their content hash (JETSAM, rule 2 and The packet).

`build(house, epoch)` reads `jetsam/local/` for the epoch and returns a Digest: the packet, its bytes
and name, and what was refused. Nothing in it can come from anywhere but an enum id, a closed list,
the release, the epoch and the house's own secret (rule 4): every distinct event is put through the
J1 validator inside a one-event packet before it joins, and one that fails is dropped and counted.

  - Identical events are counted and the count bucketed (`n`, or `opened` for reach), so the packet
    says how often, never when (the schema's order rule).
  - A funnel event's `steps` and a budget event's `wall` are filled from the enum file when the
    recorder left them out.
  - The once-per-packet classes: `surface` takes the epoch's most frequent declaration (ties go to
    the latest), `cost` its latest, `suggestion` the one `jetsam suggest` confirmed.
  - Refused, each counted in `control.refused`: the recorder's own failures, unreadable lines, a class
    the schema lacks or this house does not offer or the operator has not consented to, a count the
    recorder supplied itself, a suggestion recorded outside `jetsam suggest`, and any event the
    validator refuses (an unknown id, a value off its list, a field its class lacks).
  - No packet when every class is off, or when the epoch holds no close, no event and no refusal.

`close(house, now)` is what a host runs at every close: it builds and writes each closed epoch that
has no packet yet (and a named epoch on request, for a dry run), then appends the close's own line
(totals and its run time in milliseconds). It never raises and never fails a close: whatever goes
wrong is a line of its report.
"""
from __future__ import annotations

import collections
import json
import time
from dataclasses import dataclass, field

from . import SCHEMA, packet_bytes, packet_name, pseudonym
from . import attribution, scrub as scrubber, validate as v
from .house import SENDING, House

BUCKETS = ["1", "2", "3-4", "5-8", "9-16", "17-32", "33+"]
SEND_SENTENCE = ("This packet is published verbatim to a public log. It cannot be withdrawn from the "
                 "log's history, only removed from its views. Send it?")
NO_ROUTE = ("no send question: this house's route is handoff (route 3), so the packet travels with the house "
            "in jetsam/outbox/ and is sent from a machine with the tool (`jetsam send --route push --clone DIR`)")


def bucket(n: int) -> str:
    for b in BUCKETS[:-1]:
        lo, _, hi = b.partition("-")
        if n <= int(hi or lo):
            return b
    return BUCKETS[-1]


def count0(n: int) -> str:
    return "0" if n == 0 else bucket(n)


def count_field(spec: dict) -> str | None:
    f = spec["fields"]
    return "n" if "n" in f else ("opened" if "opened" in f else None)


def key(e: dict) -> str:
    return json.dumps(e, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


@dataclass
class Digest:
    epoch: str
    packet: dict | None = None
    raw: bytes | None = None
    name: str | None = None
    refused: collections.Counter = field(default_factory=collections.Counter)
    problems: list[str] = field(default_factory=list)


def context(house: House, schema: dict, enums, digests=None, patterns=None) -> v.Context:
    rel = set() if house.release == schema["release_dev"] else {house.release}
    return v.Context(schema, {house.framework: enums}, {house.framework: rel}, set(digests or ()), list(patterns or ()))


def extras(house: House):
    """The attribution digests and never-store content patterns the house's config names, for the
    scrubber and the text check; empty when it names none."""
    digests = attribution.load(house.digests_path) if house.digests_path and house.digests_path.is_file() else set()
    patterns = []
    if house.patterns_path and house.patterns_path.is_file():
        cfg = json.loads(house.patterns_path.read_text(encoding="utf-8"))
        patterns = (cfg.get("never_store") or {}).get("content") or cfg.get("content") or []
    return digests, patterns


def fill(e: dict, enums) -> dict:
    if e.get("class") == "funnel" and "steps" not in e and isinstance(e.get("funnel"), str):
        e = dict(e, steps=len(enums.steps(e["funnel"])))
    if e.get("class") == "budget" and "wall" not in e and isinstance(e.get("tool"), str):
        w = enums.wall(e["tool"])
        if w:
            e = dict(e, wall=w)
    return e


def build(house: House, epoch: str, schema: dict | None = None, enums=None, digests=None, patterns=None,
          known_pass: bool = True) -> Digest:
    schema = schema or v.load_schema()
    d = Digest(epoch)
    on = house.classes_on(schema)
    if not on:
        d.problems.append("every class is off: no packet")
        return d
    if enums is None:
        enums = house.load_enums()
    if digests is None or patterns is None:
        digests, patterns = extras(house)
    ctx = context(house, schema, enums, digests, patterns)
    lines = house.lines("events", epoch)
    if house.lines("refused", epoch):
        d.refused["recorder"] += len(house.lines("refused", epoch))

    groups: dict[str, list] = {}
    surfaces: list[dict] = []
    latest: dict[str, dict] = {}
    for line in lines:
        try:
            e = json.loads(line)
        except ValueError:
            d.refused["unreadable"] += 1
            continue
        if not isinstance(e, dict) or not isinstance(e.get("class"), str):
            d.refused["unreadable"] += 1
            continue
        cls = e["class"]
        spec = schema["classes"].get(cls)
        if spec is None or cls not in house.offered:
            d.refused["class not offered"] += 1
            continue
        if cls not in on:
            d.refused["class not consented"] += 1
            continue
        if spec.get("text"):
            d.refused["suggestion outside jetsam suggest"] += 1
            continue
        cf = count_field(spec)
        if cf and cf in e:
            d.refused["count given by the recorder"] += 1
            continue
        e = fill(e, enums)
        if spec.get("once"):
            if cls == "surface":
                surfaces.append(e)
            else:
                latest[cls] = e
            continue
        groups.setdefault(key(e), [e, 0])[1] += 1

    candidates: list[tuple[dict, int]] = []
    for e, n in groups.values():
        candidates.append((dict(e, **{count_field(schema["classes"][e["class"]]): bucket(n)}), n))
    if surfaces:
        tally = collections.Counter(key(s) for s in surfaces)
        top = max(tally.values())
        pick = next(s for s in reversed(surfaces) if tally[key(s)] == top)
        candidates.append((pick, len(surfaces)))
    for cls, e in latest.items():
        candidates.append((e, 1))

    text, scrubbed = None, 0
    if "suggestion" in on:
        try:
            s = json.loads(house.suggestion_path(epoch).read_text(encoding="utf-8"))
            candidates.append(({"class": "suggestion", "kind": s["kind"], "target": s["target"]}, 1))
            text, scrubbed = s["text"], int(s.get("removed", 0))
        except (OSError, ValueError, KeyError, TypeError):
            pass

    surface = next((e["surface"] for e, _ in candidates if e.get("class") == "surface"), None)
    if surface not in schema["lists"]["surface"]:
        surface = house.surface if house.surface in schema["lists"]["surface"] else "other"
    secret = house.secret()
    envelope = {"v": 1, "jetsam": SCHEMA, "framework": house.framework, "release": house.release,
                "surface": surface, "epoch": epoch, "pseudonym": pseudonym(secret, epoch) if secret else None}

    events = []
    for e, n in candidates:
        probe = dict(envelope, pseudonym=None, classes=[e["class"]], events=[e],
                     control={"known_pass": True, "refused": "0", "scrubbed": "0"},
                     text=text if e["class"] == "suggestion" else None)
        try:
            r = v.validate(packet_bytes(probe), ctx)
        except Exception as x:     # a value outside kernel-format's profile cannot be serialized at all
            d.refused[f"refused by the validator ({type(x).__name__})"] += n
            continue
        if r.ok:
            events.append(e)
        else:
            d.refused["refused by the validator (" + ", ".join(sorted(r.checks())) + ")"] += n
            if e["class"] == "suggestion":
                text = None

    if not events and not lines and not house.lines("closes", epoch) and not d.refused:
        d.problems.append(f"the epoch {epoch} holds no close, no event and no refusal: no packet")
        return d
    packet = dict(envelope, classes=on, events=sorted(events, key=lambda e: v.key(e)),
                  control={"known_pass": bool(known_pass), "refused": count0(sum(d.refused.values())),
                           "scrubbed": count0(scrubbed)},
                  text=text if any(e["class"] == "suggestion" for e in events) else None)
    raw = packet_bytes(packet)
    r = v.validate(raw, ctx, name=packet_name(raw))
    if not r.ok:
        d.problems.append("the packet failed the validator, so nothing was written: "
                          + "; ".join(f"{c}: {m}" for c, m in r.refusals))
        return d
    d.packet, d.raw, d.name = packet, raw, packet_name(raw)
    return d


def held(house: House, epoch: str) -> tuple[list, list]:
    """(unsent, sent) outbox packets of this house's framework for the epoch."""
    sent = house.sent_hashes()
    mine = [(p, j) for p, j in house.outbox_packets()
            if j.get("framework") == house.framework and j.get("epoch") == epoch]
    return [x for x in mine if x[0].stem not in sent], [x for x in mine if x[0].stem in sent]


def write(house: House, d: Digest) -> str:
    """Write the digest's packet, replacing an unsent packet of the same framework and epoch (one
    packet per framework per epoch, JT.9). Returns what happened, as a line."""
    unsent, sent = held(house, d.epoch)
    if sent or any(s.get("framework") == house.framework and s.get("epoch") == d.epoch for s in house.sent()):
        return f"{d.epoch}: already sent, so it is never built again (the sent-ledger holds it)"
    house.outbox.mkdir(parents=True, exist_ok=True)
    target = house.outbox / d.name
    for p, _ in unsent:
        if p != target:
            p.unlink()
    if target.exists():
        return f"{d.epoch}: {d.name[:12]}... unchanged ({len(d.raw)} bytes)"
    target.write_bytes(d.raw)
    return f"{d.epoch}: wrote {d.name[:12]}... ({len(d.raw)} bytes, {len(d.packet['events'])} event(s), refused {d.packet['control']['refused']})"


def close(house: House, now: str | None = None, epoch: str | None = None, known_pass: bool = True) -> list[str]:
    """The close's step (see the module's text). Never raises."""
    t0 = time.perf_counter()
    try:
        from .record import epoch as current
        now = now or current()
        schema = v.load_schema()
        on = house.classes_on(schema)
        if not on:
            return ["every class is off: nothing recorded, nothing written"]
        if not house.writable():
            return ["UNAVAILABLE (cannot write jetsam/local/): nothing recorded; the close proceeds"]
        enums = house.load_enums()
        digests, patterns = extras(house)
        out = []
        todo = [e for e in house.epochs() if e < now and not any(held(house, e))]
        if epoch and epoch not in todo:
            todo.append(epoch)
        for e in sorted(todo):
            d = build(house, e, schema, enums, digests, patterns, known_pass)
            out.append(write(house, d) if d.packet is not None else f"{e}: " + "; ".join(d.problems))
        ms = int((time.perf_counter() - t0) * 1000)
        line = {"events": len(house.lines("events", now)), "refused": len(house.lines("refused", now)), "ms": ms}
        with open(house.epoch_file("closes", now), "a", encoding="utf-8") as f:
            f.write(json.dumps(line, sort_keys=True) + "\n")
        out.append(f"close recorded for {now} ({ms} ms)")
        unsent = [p for p, _ in house.outbox_packets() if p.stem not in house.sent_hashes()]
        if unsent:
            out.append(card(house, unsent) if house.route in SENDING else NO_ROUTE)
        return out
    except Exception as x:
        return [f"UNAVAILABLE ({type(x).__name__}): nothing recorded; the close proceeds"]


def card(house: House, unsent) -> str:
    names = ", ".join(p.stem[:12] + "..." for p in unsent)
    return (f"send question, by the operator's widget (or as a text card): {len(unsent)} packet(s) in "
            f"jetsam/outbox/ ({names}), route {house.route}. `jetsam show` prints each as it will be "
            f"published. {SEND_SENTENCE}")


def measure(house: House, epoch: str) -> list[str]:
    """The dry epoch's figures (JETSAM, Measurement plan, before J2): closes, events and refused per
    close, the packet's bytes, and the close's own run time."""
    closes = []
    for l in house.lines("closes", epoch):
        try:
            closes.append(json.loads(l))
        except ValueError:
            pass
    n = len(closes)
    ev = len(house.lines("events", epoch))
    d = build(house, epoch)
    rf = sum(d.refused.values())
    unsent, sent = held(house, epoch)
    pk = (unsent or sent or [(None, None)])[0][0]
    per = (lambda x: f"{x / n:.2f} per close") if n else (lambda x: "UNMEASURED per close (no close recorded)")
    ms = [c.get("ms", 0) for c in closes]
    why = ", ".join(f"{k} {c}" for k, c in sorted(d.refused.items()))
    out = [f"epoch {epoch}, framework {house.framework}",
           f"closes: {n}",
           f"events recorded: {ev} ({per(ev)})",
           f"refused: {rf} ({per(rf)}){': ' + why if why else ''}",
           f"packet: {pk.stat().st_size} bytes ({pk.stem[:12]}...)" if pk else "packet: none yet (run the close with --epoch)",
           (f"close time: mean {sum(ms) / n:.0f} ms, max {max(ms)} ms (the close step's own run, as it timed itself)"
            if n else "close time: UNMEASURED (no close recorded)")]
    return out
