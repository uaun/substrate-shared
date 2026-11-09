"""The packet validator (J1; JETSAM, The packet, the six rules and the public log's ingest).

`validate(raw, ctx, name=None)` runs every check in CHECKS, in order, over a packet's bytes and
returns a Result: `ok`, and `refusals`, each a (check, detail) pair. `tally(results)` counts the
refusals by check, which is what the log's ingest publishes as its own refusals view (rule 6).

Each check owns one failure and reports only that one: a check that needs a value another check
owns (an id, a framework, a well-formed token) passes over it silently when it is not there, so a
packet broken in one way is refused by exactly one check. That is what lets the house's tests take
any one check away and watch its adversarial fixture pass, the proof that the check is
load-bearing (IR-5; TODO-193's negative control).

  json        the bytes are UTF-8 and one JSON object
  profile     kernel-format's JSON profile (core A3): integers only, no repeated key, ASCII keys,
              no lone surrogate
  canonical   the bytes are their own canonical serialization (sorted keys, no whitespace)
  name        a named packet's file name is its content hash and `.json` (core A2)
  envelope    exactly the schema's envelope fields
  version     `v` is 1 and `jetsam` is this schema's version
  framework   an enum file for the packet's framework is held
  release     a release id the framework's release list holds, or `dev`
  surface     a surface from the closed list
  epoch       a month, YYYY-MM, a real one (core A4, the month grain)
  pseudonym   null, or 64 lowercase hex
  classes     known classes, each once, in the schema's order
  consent     every event's class is among the packet's classes
  fields      each event is a mapping with its class and exactly the fields its class declares
  shape       every string outside `text` is a short lowercase token: no path, host or name can
              stand in a field
  ids         every id is in the enum file's list for its field; a step is one its funnel declares
  buckets     every count is a value from its list (the buckets, the zero-able control counts,
              P2's scales)
  values      every other closed-list value, boolean and release field
  steps       a funnel event's step total is the number of steps its funnel declares
  wall        a budget event's wall is the one its tool declares
  order       events sorted by their canonical bytes
  alike       no two events alike but for their count
  once        the one-per-packet classes (surface, suggestion, cost) appear at most once
  control     the control block holds exactly known_pass, refused and scrubbed, its counts from
              the zero-able list
  known-pass  the control block's known-pass field is true
  text        null unless the packet carries its suggestion; then at most 500 characters that
              the scrubber would not change
"""
from __future__ import annotations

import collections
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import canonical as core
from . import scrub as scrubber
from .enums import Enums

HERE = Path(__file__).resolve().parent
# The schema sits beside the package in a vendored copy (<dir>/jetsam/, <dir>/schema/) and two levels
# up in this house (src/jetsam/, schema/); the first that exists is read.
SCHEMA_PATH = next((p for p in (HERE.parent / "schema" / "1.0.json", HERE.parents[1] / "schema" / "1.0.json")
                    if p.is_file()), HERE.parents[1] / "schema" / "1.0.json")
TOKEN = re.compile(r"^[a-z0-9<][a-z0-9.+_<-]{0,63}$")
EPOCH = re.compile(r"^([0-9]{4})-(0[1-9]|1[0-2])$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def load_schema(path: Path = SCHEMA_PATH) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@dataclass
class Context:
    """What a check reads beyond the bytes: the schema, the enum files held (by framework), each
    framework's release list, and for the text check the attribution digests and the never-store
    content patterns."""
    schema: dict
    enums: dict[str, Enums]
    releases: dict[str, set[str]]
    digests: set[str] = field(default_factory=set)
    patterns: list[str] = field(default_factory=list)


@dataclass
class Result:
    ok: bool
    refusals: list[tuple[str, str]]

    def checks(self) -> set[str]:
        return {c for c, _ in self.refusals}


@dataclass
class Packet:
    raw: bytes
    name: str | None
    value: object = None          # the lenient parse, for every check after `json`


# ------------------------------------------------------------------ the checks, each one failure

def c_json(p: Packet, ctx: Context) -> list[str]:
    try:
        text = p.raw.decode("utf-8")
        v = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        return [f"not UTF-8 JSON ({type(e).__name__})"]
    if not isinstance(v, dict):
        return ["a packet is one JSON object"]
    return []


def c_profile(p: Packet, ctx: Context) -> list[str]:
    try:
        core.parse(p.raw)
    except core.ProfileError as e:
        return [str(e)]
    return []


def c_canonical(p: Packet, ctx: Context) -> list[str]:
    try:
        again = json.dumps(p.value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except (TypeError, ValueError):
        return []
    return [] if again == p.raw else ["the bytes are not their own canonical serialization (core A3)"]


def c_name(p: Packet, ctx: Context) -> list[str]:
    if p.name is None:
        return []
    want = core.content_hash(p.raw) + ".json"
    return [] if p.name == want else [f"the file is named {p.name}, its content hash names it {want[:12]}...json"]


def c_envelope(p: Packet, ctx: Context) -> list[str]:
    want, have = ctx.schema["envelope"], list(p.value)
    out = [f"the envelope lacks `{k}`" for k in want if k not in have]
    out += [f"`{k}` is not an envelope field" for k in have if k not in want]
    return out


def c_version(p: Packet, ctx: Context) -> list[str]:
    out = []
    v = p.value.get("v")
    if "v" in p.value and (type(v) is not int or v != ctx.schema["v"]):
        out.append(f"`v` is {v!r}, not {ctx.schema['v']}")
    if "jetsam" in p.value and p.value.get("jetsam") != ctx.schema["jetsam"]:
        out.append(f"`jetsam` is {p.value.get('jetsam')!r}, not this schema's {ctx.schema['jetsam']!r}")
    return out


def held(p: Packet, ctx: Context) -> Enums | None:
    fw = p.value.get("framework")
    return ctx.enums.get(fw) if isinstance(fw, str) else None


def c_framework(p: Packet, ctx: Context) -> list[str]:
    if "framework" not in p.value:
        return []
    return [] if held(p, ctx) else [f"no enum file is held for the framework {p.value.get('framework')!r}"]


def c_release(p: Packet, ctx: Context) -> list[str]:
    if "release" not in p.value or not held(p, ctx):
        return []
    r = p.value.get("release")
    if r == ctx.schema["release_dev"] or r in ctx.releases.get(p.value["framework"], set()):
        return []
    return [f"the release {r!r} is not on the framework's release list, which the log holds"]


def c_surface(p: Packet, ctx: Context) -> list[str]:
    if "surface" not in p.value:
        return []
    return [] if p.value["surface"] in ctx.schema["lists"]["surface"] else [f"the surface {p.value['surface']!r} is not on the list"]


def c_epoch(p: Packet, ctx: Context) -> list[str]:
    if "epoch" not in p.value:
        return []
    e = p.value["epoch"]
    return [] if isinstance(e, str) and EPOCH.match(e) else [f"the epoch {e!r} is not a month, YYYY-MM"]


def c_pseudonym(p: Packet, ctx: Context) -> list[str]:
    if "pseudonym" not in p.value:
        return []
    s = p.value["pseudonym"]
    return [] if s is None or (isinstance(s, str) and HEX64.match(s)) else ["the pseudonym is neither null nor 64 lowercase hex"]


def events(p: Packet) -> list:
    ev = p.value.get("events")
    return ev if isinstance(ev, list) else []


def c_classes(p: Packet, ctx: Context) -> list[str]:
    if "classes" not in p.value:
        return []
    cl, order = p.value["classes"], list(ctx.schema["classes"])
    if not isinstance(cl, list) or not all(isinstance(c, str) for c in cl):
        return ["`classes` is not a list of class names"]
    out = [f"the class {c!r} is not in schema {ctx.schema['jetsam']}" for c in cl if c not in order]
    known = [c for c in cl if c in order]
    if len(set(known)) != len(known):
        out.append("a class is listed twice")
    elif known != sorted(known, key=order.index):
        out.append("the classes are not in the schema's order")
    if "events" in p.value and not isinstance(p.value["events"], list):
        out.append("`events` is not a list")
    return out


def c_consent(p: Packet, ctx: Context) -> list[str]:
    cl = p.value.get("classes") if isinstance(p.value.get("classes"), list) else []
    return [f"an event of the class {e.get('class')!r}, which the packet's classes do not consent to"
            for e in events(p) if isinstance(e, dict) and e.get("class") in ctx.schema["classes"] and e.get("class") not in cl]


def spec(ctx: Context, e) -> dict | None:
    return ctx.schema["classes"].get(e.get("class")) if isinstance(e, dict) else None


def c_fields(p: Packet, ctx: Context) -> list[str]:
    out = []
    for i, e in enumerate(events(p)):
        s = spec(ctx, e)
        if s is None:
            out.append(f"event {i} is not a mapping with a known `class`")
            continue
        want = set(s["fields"]) | {"class"}
        out += [f"event {i} ({e['class']}) lacks `{k}`" for k in sorted(want - set(e))]
        out += [f"event {i} ({e['class']}): `{k}` is not a field of its class" for k in sorted(set(e) - want)]
        for f, kind in s["fields"].items():
            if f in e and not json_type(kind, e[f]):
                out.append(f"event {i} ({e['class']}): `{f}` is not of the JSON type its kind takes")
    return out


def json_type(kind: str, v) -> bool:
    """The JSON type a field's kind takes; membership is the later checks' to judge. A number with a
    fraction passes here: whether it is an integer is the profile's to say (core A3)."""
    if kind == "boolean":
        return type(v) is bool
    if kind == "integer":
        return isinstance(v, (int, float)) and not isinstance(v, bool)
    nullable = kind.endswith("|null") or kind.startswith("step")
    return isinstance(v, str) or (v is None and nullable)


def strings(value, path="$"):
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from strings(v, f"{path}[{i}]")
    elif isinstance(value, dict):
        for k, v in value.items():
            if path == "$" and k == "text":
                continue
            yield from strings(v, f"{path}.{k}")


def token(v) -> bool:
    return isinstance(v, str) and bool(TOKEN.match(v))


def c_shape(p: Packet, ctx: Context) -> list[str]:
    return [f"{where} is not a short lowercase token" for where, v in strings(p.value) if not TOKEN.match(v)]


def typed(p: Packet, ctx: Context):
    """(index, event, field, kind, value) for every declared field an event carries."""
    for i, e in enumerate(events(p)):
        s = spec(ctx, e)
        if s is None:
            continue
        for f, kind in s["fields"].items():
            if f in e:
                yield i, e, f, kind, e[f]


def c_ids(p: Packet, ctx: Context) -> list[str]:
    en = held(p, ctx)
    if en is None:
        return []
    out = []
    for i, e, f, kind, v in typed(p, ctx):
        if v is None and kind.endswith("|null"):
            continue
        if kind.startswith("id:"):
            lists = kind[3:].removesuffix("|null").split(",")
            if token(v) and not any(v in en.ids(n) for n in lists):
                out.append(f"event {i} ({e['class']}): `{f}` names an id the enum file's {'/'.join(lists)} do not hold")
        elif kind.startswith("step"):
            fn = e.get("funnel")
            if not token(fn) or fn not in en.ids("funnels"):
                continue
            declared = en.steps(fn)
            if v is None and declared:
                out.append(f"event {i} (funnel {fn}): `last_step` is null, and the funnel declares steps")
            elif v is not None and token(v) and v not in declared:
                out.append(f"event {i} (funnel {fn}): `last_step` names no step the funnel declares")
        elif kind == "attached":
            lst = {"funnel": "funnels", "refusal": "gates", "red": "checks"}.get(e.get("attached"))
            if lst and token(v) and v not in en.ids(lst):
                out.append(f"event {i} (pain): `target` names no id in the enum file's {lst}")
    return out


SCALES = ("bucket", "count0", "tokens", "minutes")


def c_buckets(p: Packet, ctx: Context) -> list[str]:
    out = []
    for i, e, f, kind, v in typed(p, ctx):
        if kind.startswith("list:") and kind[5:] in SCALES and token(v) and v not in ctx.schema["lists"][kind[5:]]:
            out.append(f"event {i} ({e['class']}): `{f}` is {v!r}, outside the {kind[5:]} list")
    return out


def c_values(p: Packet, ctx: Context) -> list[str]:
    out = []
    rel = ctx.releases.get(p.value.get("framework"), set()) if held(p, ctx) else None
    for i, e, f, kind, v in typed(p, ctx):
        if kind.startswith("list:") and kind[5:] not in SCALES:
            if token(v) and v not in ctx.schema["lists"][kind[5:]]:
                out.append(f"event {i} ({e['class']}): `{f}` is not on the {kind[5:]} list")
        elif kind == "release" and rel is not None and token(v) and v not in rel:
            out.append(f"event {i} ({e['class']}): `{f}` is not a release the framework's list holds")
    return out


def c_steps(p: Packet, ctx: Context) -> list[str]:
    en = held(p, ctx)
    if en is None:
        return []
    out = []
    for i, e, f, kind, v in typed(p, ctx):
        if kind == "integer":
            fn = e.get("funnel")
            if not token(fn) or fn not in en.ids("funnels"):
                continue
            if isinstance(v, (int, float)) and not isinstance(v, bool) and v != len(en.steps(fn)):
                out.append(f"event {i} (funnel {fn}): `steps` is {v!r}; the funnel declares {len(en.steps(fn))}")
    return out


def c_wall(p: Packet, ctx: Context) -> list[str]:
    en = held(p, ctx)
    if en is None:
        return []
    out = []
    for i, e, f, kind, v in typed(p, ctx):
        if kind == "wall":
            t = e.get("tool")
            if token(t) and t in en.ids("tools") and v != en.wall(t):
                out.append(f"event {i} (budget {t}): `wall` is {v!r}; the tool declares {en.wall(t)!r}")
    return out


def key(e) -> bytes:
    return json.dumps(e, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def c_order(p: Packet, ctx: Context) -> list[str]:
    ev = [e for e in events(p) if isinstance(e, dict)]
    try:
        ks = [key(e) for e in ev]
    except (TypeError, ValueError):
        return []
    return [] if ks == sorted(ks) else ["the events are not sorted by their canonical bytes"]


def c_alike(p: Packet, ctx: Context) -> list[str]:
    seen = collections.Counter()
    for e in events(p):
        if isinstance(e, dict):
            try:
                seen[key({k: v for k, v in e.items() if k not in ("n", "opened")})] += 1
            except (TypeError, ValueError):
                pass
    n = sum(c - 1 for c in seen.values() if c > 1)
    return [f"{n} event(s) alike but for their count: one event carries the sum"] if n else []


def c_once(p: Packet, ctx: Context) -> list[str]:
    c = collections.Counter(e.get("class") for e in events(p) if isinstance(e, dict))
    return [f"the class {k!r} appears {c[k]} times; it appears at most once"
            for k, s in ctx.schema["classes"].items() if s.get("once") and c[k] > 1]


def c_control(p: Packet, ctx: Context) -> list[str]:
    if "control" not in p.value:
        return []
    c = p.value["control"]
    if not isinstance(c, dict):
        return ["the control block is not a mapping"]
    want = ctx.schema["control"]
    out = [f"the control block lacks `{k}`" for k in want if k not in c]
    out += [f"`{k}` is not a control field" for k in c if k not in want]
    for k in ("refused", "scrubbed"):
        if k in c and c[k] not in ctx.schema["lists"]["count0"]:
            out.append(f"the control block's `{k}` is not a zero-able count")
    if "known_pass" in c and type(c["known_pass"]) is not bool:
        out.append("the control block's `known_pass` is not true or false")
    return out


def c_known_pass(p: Packet, ctx: Context) -> list[str]:
    c = p.value.get("control")
    if isinstance(c, dict) and c.get("known_pass") is False:
        return ["the control block's known-pass field is false: the house's recorder failed its own known pass"]
    return []


def c_text(p: Packet, ctx: Context) -> list[str]:
    if "text" not in p.value:
        return []
    t = p.value["text"]
    texted = [e for e in events(p) if isinstance(e, dict) and (spec(ctx, e) or {}).get("text")]
    if t is None:
        return [f"the {texted[0]['class']} event carries no text"] if texted else []
    if not texted:
        return ["`text` is set, and the packet carries no suggestion"]
    if not isinstance(t, str):
        return ["`text` is not a string"]
    if len(t) > ctx.schema["text"]["max_chars"]:
        return [f"`text` is {len(t)} characters, over {ctx.schema['text']['max_chars']}"]
    s = scrubber.scrub(t, ctx.digests, ctx.patterns)
    return [f"the scrubber would still remove {len(s.removed)} span(s) ({', '.join(sorted(set(s.removed)))})"] if s.changed else []


CHECKS = [
    ("json", c_json), ("profile", c_profile), ("canonical", c_canonical), ("name", c_name),
    ("envelope", c_envelope), ("version", c_version), ("framework", c_framework), ("release", c_release),
    ("surface", c_surface), ("epoch", c_epoch), ("pseudonym", c_pseudonym), ("classes", c_classes),
    ("consent", c_consent), ("fields", c_fields), ("shape", c_shape), ("ids", c_ids), ("buckets", c_buckets),
    ("values", c_values), ("steps", c_steps), ("wall", c_wall), ("order", c_order), ("alike", c_alike),
    ("once", c_once), ("control", c_control), ("known-pass", c_known_pass), ("text", c_text),
]


def validate(raw: bytes, ctx: Context, name: str | None = None, checks=None) -> Result:
    """Run every check (or the `checks` given, for the house's sabotage tests) over the bytes."""
    checks = CHECKS if checks is None else checks
    p = Packet(bytes(raw), name)
    refusals: list[tuple[str, str]] = []
    try:
        p.value = json.loads(p.raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        p.value = None
    for cname, fn in checks:
        if cname != "json" and not isinstance(p.value, dict):
            continue          # bytes that are not one JSON object are the json check's alone
        refusals += [(cname, d) for d in fn(p, ctx)]
    return Result(not refusals, refusals)


def tally(results) -> collections.Counter:
    """Refusals counted by check, the ingest's refusals view."""
    c = collections.Counter()
    for r in results:
        for check in sorted(r.checks()):
            c[check] += 1
    return c
