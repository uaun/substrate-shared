"""The package's command line (see jetsam/__init__.py for the verbs)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from . import attribution, canonical, enums as enumfiles, validate as v
from . import digest as dg, house as hs, scrub as scrubber, vendor as vd
from .record import epoch as current_epoch

HERE = Path(__file__).resolve().parent
FLAGS = {"--enums", "--releases", "--digests", "--patterns", "--root", "--epoch", "--kind", "--target",
         "--route", "--by", "--reason", "--framework", "--pseudonym", "--atlas", "--day"}
HOUSE_VERBS = ("status", "disclosure", "consent", "revoke", "pseudonym", "record", "show", "close", "send",
               "suggest", "measure")
LOG_VERBS = ("log-ingest", "log-aggregate", "log-verify", "log-tombstone", "log-burn", "log-guard", "log-correlate")
SUGGEST_SENTENCE = "this text is published verbatim and cannot be withdrawn from the log's history"
REVIEW = ("an identified proposal or patch goes through Substrate Review instead, which carries its author; "
          "Jetsam carries no name")


def arg(args: list, flag: str):
    return args[args.index(flag) + 1] if flag in args[:-1] else None


def positional(rest: list) -> list[str]:
    return [a for i, a in enumerate(rest) if not a.startswith("--") and (i == 0 or rest[i - 1] not in FLAGS)]


def context(args: list) -> v.Context:
    held = {}
    d = arg(args, "--enums")
    if d:
        for f in sorted(list(Path(d).glob("*.yaml")) + list(Path(d).glob("*.json"))):
            e = enumfiles.load(f)
            held[e.framework] = e
    rel = {}
    r = arg(args, "--releases")
    if r:
        rel = {k: set(x or []) for k, x in (enumfiles.parse_text(Path(r).read_text(encoding="utf-8")) or {}).items()}
    digests = attribution.load(arg(args, "--digests")) if arg(args, "--digests") else set()
    patterns = []
    if arg(args, "--patterns"):
        cfg = json.loads(Path(arg(args, "--patterns")).read_text(encoding="utf-8"))
        patterns = (cfg.get("never_store") or {}).get("content") or cfg.get("content") or []
    return v.Context(v.load_schema(), held, rel, digests, patterns)


def packets(paths: list[str]) -> list[Path]:
    out = []
    for p in paths:
        q = Path(p)
        out += sorted(q.glob("*.json")) if q.is_dir() else [q]
    return out


# ------------------------------------------------------------------------------ the house verbs

def drift() -> list[str]:
    root = vd.vendored_root(HERE)
    return vd.check(root) if root else []


def disclosure(root) -> str:
    """The boot's capabilities line, one of the three the jetsam-recorder contract fixes (rule 1)."""
    if drift():
        return "FEEDBACK: UNAVAILABLE (tool damaged)"
    try:
        h = hs.load(root)
    except hs.HouseError:
        return "FEEDBACK: UNAVAILABLE (not installed)"
    try:
        h.load_enums()
    except (OSError, enumfiles.EnumError):
        return "FEEDBACK: UNAVAILABLE (enum file damaged)"
    on = h.classes_on(v.load_schema())
    if not on:
        return "FEEDBACK: OFF"
    if not h.writable():
        return "FEEDBACK: UNAVAILABLE (cannot write)"
    return f"FEEDBACK: ON ({', '.join(on)}; route {h.route})"


def value(k: str, s: str):
    """A field's value from the command line: true, false and null are JSON's; every other value is a
    string, since every count is a bucket string ("0", "3-4"). `steps` is the one integer field, and the
    close fills it from the enum file when it is left out."""
    if s in ("true", "false"):
        return s == "true"
    if s == "null":
        return None
    return int(s) if k == "steps" and s.isdigit() else s


def strip_class(h: hs.House, cls: str) -> int:
    """Delete one class's local events, in every epoch; returns how many lines went."""
    gone = 0
    for e in h.epochs():
        p = h.epoch_file("events", e)
        keep, here = [], 0
        for l in h.lines("events", e):
            try:
                c = json.loads(l).get("class")
            except (ValueError, AttributeError):
                c = None
            if c == cls:
                here += 1
            else:
                keep.append(l)
        if here:
            p.write_text("".join(x + "\n" for x in keep), encoding="utf-8")
            gone += here
        if cls == "suggestion" and h.suggestion_path(e).exists():
            h.suggestion_path(e).unlink()
            gone += 1
    return gone


def house_main(verb: str, rest: list) -> int:
    root = arg(rest, "--root") or "."
    pos = positional(rest)
    if verb == "disclosure":
        print(disclosure(root))
        return 0
    if verb == "record":                 # the recorder call, for a host step that is not Python (CI, shell)
        if pos:
            try:
                fields = dict(p.split("=", 1) for p in pos[1:])
                hs.load(root).record(pos[0], **{k: value(k, x) for k, x in fields.items()})
            except Exception:
                pass
        return 0
    if verb == "close":                  # never fails a close: every problem is a line, and the exit is 0
        d = drift()
        if d:
            print("UNAVAILABLE (tool damaged: " + "; ".join(d) + "): nothing recorded; the close proceeds")
            return 0
        try:
            h = hs.load(root)
        except hs.HouseError as e:
            print(f"UNAVAILABLE ({e}): the close proceeds")
            return 0
        for line in dg.close(h, epoch=arg(rest, "--epoch")):
            print(line)
        return 0
    try:
        h = hs.load(root)
    except hs.HouseError as e:
        print(f"jetsam: {e}")
        return 2
    schema = v.load_schema()
    if verb == "status":
        print(disclosure(root))
        on = h.classes_on(schema)
        print(f"framework {h.framework}, release {h.release}, route {h.route}; enum file {h.enums_path.relative_to(h.root)}")
        print(f"offered: {', '.join(h.offered) or 'none'}; on: {', '.join(on) or 'none'}"
              + ("; a consent given under another schema version is void, asked again" if h.stale_consent() else ""))
        print(f"pseudonym: {'on (a secret in jetsam/local/, never exported)' if h.secret() else 'off: packets are unlinkable'}")
        for e in h.epochs():
            print(f"  {e}: {len(h.lines('events', e))} event line(s), {len(h.lines('refused', e))} refused, "
                  f"{len(h.lines('closes', e))} close(s)")
        sent = h.sent_hashes()
        for p, j in h.outbox_packets():
            print(f"  outbox {p.stem[:12]}... {j.get('epoch')} {p.stat().st_size} bytes{' (sent)' if p.stem in sent else ''}")
        vroot = vd.vendored_root(HERE)
        print("tool: " + (("vendored from " + json.loads((vroot / vd.MANIFEST).read_text())["commit"][:12]
                           + (", matches its manifest" if not drift() else ", DIFFERS: " + "; ".join(drift())))
                          if vroot else "run from the Jetsam house itself"))
        return 0
    if verb in ("consent", "revoke"):
        bad = [c for c in pos if c not in schema["classes"] or c not in h.offered]
        if bad or not pos:
            print(f"jetsam: {', '.join(bad) or 'no class named'}: not a class this house offers ({', '.join(h.offered)})")
            return 2
        on = h.consent()
        if verb == "consent":
            on.update({c: current_epoch() for c in pos})
            h.write_consent(on)
        else:
            for c in pos:
                on.pop(c, None)
                print(f"revoked {c}: {strip_class(h, c)} local line(s) deleted")
            sent = h.sent_hashes()
            for p, j in h.outbox_packets():
                if p.stem not in sent and set(pos) & set(j.get("classes") or []):
                    p.unlink()
                    print(f"deleted the unsent packet {p.stem[:12]}..., which carried a withdrawn class")
            h.write_consent(on)
        print(disclosure(root))
        return 0
    if verb == "pseudonym":
        what = pos[0] if pos else "status"
        if what == "on":
            h.pseudonym_on()
        elif what == "off":
            h.pseudonym_off()
        elif what != "status":
            print("jetsam pseudonym on|off|status")
            return 2
        print("pseudonym " + ("on: one house counts once per month, and the link dies at the month's end"
                              if h.secret() else "off: packets are unlinkable"))
        return 0
    if verb == "show":
        if arg(rest, "--epoch"):
            d = dg.build(h, arg(rest, "--epoch"), schema)
            if d.packet is None:
                print("; ".join(d.problems))
                return 1
            print(f"preview of {d.epoch}, not written: {len(d.raw)} bytes, content hash {d.name[:-5]}")
            print(json.dumps(d.packet, indent=1, ensure_ascii=False, sort_keys=True))
            return 0
        sent = h.sent_hashes()
        shown = 0
        for p, j in h.outbox_packets():
            if p.stem in sent:
                continue
            shown += 1
            print(f"packet {p.stem} ({p.stat().st_size} bytes), as it will be published; the file is its canonical bytes")
            print(json.dumps(j, indent=1, ensure_ascii=False, sort_keys=True))
        if not shown:
            print("nothing unsent in jetsam/outbox/; `jetsam show --epoch YYYY-MM` previews an epoch without writing it")
        return 0
    if verb == "send":
        print("NOT SENT: no route can send a packet yet; the drop point and own push arrive at J4 (the atlas's "
              "TODO-196). The packet stays in jetsam/outbox/, which travels with the house.")
        return 3
    if verb == "suggest":
        if "suggestion" not in h.consent():
            print(f"jetsam: the suggestion class is not on in this house, so nothing was recorded; {REVIEW}")
            return 1
        kind, target, text = arg(rest, "--kind"), arg(rest, "--target"), " ".join(pos)
        digests, patterns = dg.extras(h)
        s = scrubber.scrub(text, digests, patterns)
        print(f"as it will be published ({len(s.text)} of {scrubber.MAX_CHARS} characters; "
              f"{len(s.removed)} span(s) removed: {', '.join(s.removed) or 'none'}):")
        print(s.text)
        print(f"Before you confirm: {SUGGEST_SENTENCE}.")
        if s.too_long:
            print("too long: nothing recorded")
            return 1
        if "--confirm" not in rest:
            print("nothing recorded; run again with --confirm to record it")
            return 0
        h.local.mkdir(parents=True, exist_ok=True)
        p = h.suggestion_path(current_epoch())
        replaced = p.exists()
        p.write_text(json.dumps({"kind": kind, "target": target, "text": s.text, "removed": len(s.removed)},
                                ensure_ascii=False) + "\n", encoding="utf-8")
        print("recorded" + (", replacing this epoch's earlier suggestion (one per packet)" if replaced else ""))
        return 0
    if verb == "measure":
        for line in dg.measure(h, arg(rest, "--epoch") or current_epoch()):
            print(line)
        return 0
    return 2


def log_main(verb: str, rest: list) -> int:
    """The public log's verbs (J3), run from its root (--root, default the current folder)."""
    from . import log as lg
    root = arg(rest, "--root") or "."
    pos = positional(rest)
    if verb == "log-ingest":
        r = lg.ingest(root, day=arg(rest, "--day"), route=arg(rest, "--route") or "push")
        for h in r.ingested:
            print(f"ingested {h[:12]}...")
        for h, checks in r.refused:
            print(f"refused  {h[:12]}... by {', '.join(checks)}")
        print(f"ingest: {len(r.ingested)} ingested, {len(r.refused)} refused")
        return 0
    if verb == "log-aggregate":
        print(f"aggregate: {lg.aggregate(root)} view(s) written")
        return 0
    if verb == "log-verify":
        diffs = lg.verify(root)
        for d in diffs:
            print(f"RED  {d}")
        print("verify: every view reproduced from log/, the log intact" if not diffs else f"verify: {len(diffs)} difference(s)")
        return 0 if not diffs else 1
    try:
        if verb == "log-tombstone":
            lg.tombstone(root, pos[0], arg(rest, "--by") or "operator", arg(rest, "--reason") or "", arg(rest, "--day"))
            print(f"withdrawn {pos[0][:12]}...: it counts in no view from the next aggregate")
            return 0
        if verb == "log-burn":
            lg.burn(root, arg(rest, "--framework"), arg(rest, "--epoch"), arg(rest, "--pseudonym"),
                    arg(rest, "--reason") or "", arg(rest, "--day"))
            print("burned: refused at ingest and left out of every view")
            return 0
    except (ValueError, IndexError, TypeError) as e:
        print(f"jetsam {verb}: refused: {e}")
        return 1
    if verb == "log-guard":
        bad = lg.guard(pos)
        for p in bad:
            print(f"REFUSED  {p}: only the automated ingest writes here (JT.8)")
        return 1 if bad else 0
    if verb == "log-correlate":
        for line in lg.correlate(root, arg(rest, "--atlas") or "."):
            print(line)
        return 0
    return 2


def main(argv) -> int:
    args = argv[1:]
    verbs = ("validate", "enums", "canonical", "vendor", "vendor-check") + HOUSE_VERBS + LOG_VERBS
    if not args or args[0] not in verbs:
        print(__import__("jetsam").__doc__)
        return 2
    verb, rest = args[0], args[1:]
    paths = positional(rest)
    if verb in HOUSE_VERBS:
        return house_main(verb, rest)
    if verb in LOG_VERBS:
        return log_main(verb, rest)
    if verb == "vendor":
        if not paths or not (arg(rest, "--enums") or "--package-only" in rest):
            print("jetsam vendor DEST --enums FILE      (a recording house)\n"
                  "jetsam vendor DEST --package-only    (the public log, which mirrors enum files itself)")
            return 2
        try:
            m = vd.vendor(HERE.parents[1], paths[0], arg(rest, "--enums"))
        except (ValueError, OSError, enumfiles.EnumError) as e:
            print(f"jetsam vendor: refused: {e}")
            return 1
        print(f"vendored {len(m['files'])} file(s) from {m['commit'][:12]} into {paths[0]} "
              + (f"(framework {m['framework']})" if m["framework"] else "(package only)"))
        return 0
    if verb == "vendor-check":
        diffs = vd.check(paths[0] if paths else HERE.parent)
        print("vendored copy matches its manifest" if not diffs else "DIFFERS: " + "; ".join(diffs))
        return 0 if not diffs else 1
    if verb == "canonical":
        raw = Path(paths[0]).read_bytes()
        print(canonical.canonical(canonical.parse(raw)).decode("utf-8"))
        print(f"content hash {canonical.content_hash(canonical.canonical(canonical.parse(raw)))}")
        return 0
    if verb == "enums":
        digests = attribution.load(arg(rest, "--digests")) if arg(rest, "--digests") else None
        rc = 0
        for p in paths:
            try:
                e = enumfiles.load(Path(p), digests)
                print(f"{p}: {e.framework}, {e.status}, {e.count()} ids and steps, 0 findings"
                      + ("" if digests else " (no digest list given: the attribution windows were not read)"))
            except enumfiles.EnumError as x:
                rc = 1
                for f in x.findings:
                    print(f"REFUSED {p}: {f}")
        return rc
    ctx = context(rest)
    results = []
    for p in packets(paths):
        r = v.validate(p.read_bytes(), ctx, name=p.name)
        results.append(r)
        print(("ACCEPTED " if r.ok else "REFUSED  ") + p.name + ("" if r.ok else ": " + "; ".join(f"{c}: {d}" for c, d in r.refusals)))
    if "--count" in rest:
        t = v.tally(results)
        print(f"{len(results)} packet(s): {sum(r.ok for r in results)} accepted, {sum(not r.ok for r in results)} refused")
        for c, _ in v.CHECKS:
            if t[c]:
                print(f"  refused by {c}: {t[c]}")
    return 0 if all(r.ok for r in results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
