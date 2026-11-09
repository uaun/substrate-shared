"""A framework's enum file: the moments it can name, each an id with a one-line public description
(JETSAM, The packet: value kind 1). A framework ships its file in its release as `jetsam/enums.yaml`;
the log mirrors it at `enums/<framework>/<release>/enums.yaml`; this house's fixtures hold the
first two, J0's census of the soul and the Membrane, ratified on the operator's word (JT.17).

  load(path_or_text) -> Enums      raises EnumError naming every rule broken
  Enums.ids(list_name) -> set      funnels, gates, checks, tools, documents, categories
  Enums.steps(funnel) -> list      a funnel's declared step ids, in order
  Enums.wall(tool) -> str          a tool's declared wall

The rules are J0's (its `validate.py`): an id is a short lowercase token of letters and digits
joined by dots or dashes, at most 48 characters, unique in its list; a description is one line of
at most 140 characters with no path separator, no at-sign, no URL, no file extension and no
capital letter; a tool declares a wall from the schema's list; no entry keeps a `source` line,
which is for review only and never ships. With a digest list, every id and description is also
held against the attribution list, one to four words at a time.

An enum file is a YAML document, and its JSON form is the same document (YAML 1.2 reads JSON).
With PyYAML installed either form loads; without it, as in a host whose tools use the standard
library only, the JSON form loads and a YAML-only file is refused by name. `bin/jetsam.py vendor`
writes a host's file in its JSON form for that reason.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from . import attribution


def parse_text(text: str):
    """The document in an enum file's text: YAML when PyYAML is installed, else JSON."""
    try:
        import yaml
    except ImportError:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            raise EnumError(["the enum file is not in its JSON form, and PyYAML is not installed to read YAML"])
    return yaml.safe_load(text)

FORMAT = 1
ID = re.compile(r"^[a-z0-9]+([.-][a-z0-9]+)*$")
BAD = [(re.compile(r"[/\\]"), "a path separator"), (re.compile(r"@"), "an at-sign"),
       (re.compile(r"https?:|://|www\."), "a URL"),
       (re.compile(r"\.(py|md|ts|mjs|js|json|ya?ml|sh|txt|html|zip|enc)\b", re.I), "a file extension"),
       (re.compile(r"[A-Z]"), "a capital letter (a possible proper name)")]
LISTS = ("funnels", "gates", "checks", "tools", "documents", "categories")
TOP = {"enums", "framework", "status", "ratified", "measured_at", "counts", "excluded_by_category", *LISTS}
ENTRY = {"id", "description", "steps", "wall", "scope"}
STEP = {"id", "description"}
WALLS = ("line", "ceiling", "coupling")
SCOPES = ("mechanism", "house")
STATUS = ("draft", "ratified")


class EnumError(ValueError):
    def __init__(self, findings: list[str]):
        super().__init__("; ".join(findings))
        self.findings = findings


@dataclass
class Enums:
    framework: str
    status: str
    doc: dict

    def ids(self, name: str) -> set[str]:
        return {e["id"] for e in self.doc.get(name) or []}

    def entry(self, name: str, id_: str) -> dict | None:
        return next((e for e in self.doc.get(name) or [] if e["id"] == id_), None)

    def steps(self, funnel: str) -> list[str]:
        e = self.entry("funnels", funnel) or {}
        return [s["id"] for s in e.get("steps") or []]

    def wall(self, tool: str) -> str | None:
        return (self.entry("tools", tool) or {}).get("wall")

    def count(self) -> int:
        return sum(len(self.doc.get(n) or []) + sum(len(e.get("steps") or []) for e in self.doc.get(n) or [])
                   for n in LISTS)


def _description(where: str, d, digests, out: list[str]) -> None:
    if not isinstance(d, str) or not d or "\n" in d or len(d) > 140:
        out.append(f"{where}: the description is not one line of 1 to 140 characters")
        return
    for rx, why in BAD:
        if rx.search(d):
            out.append(f"{where}: the description carries {why}")


def _id(where: str, i, out: list[str]) -> bool:
    if not isinstance(i, str) or not ID.match(i) or len(i) > 48:
        out.append(f"{where}: the id is not a short lowercase token joined by dots or dashes")
        return False
    return True


def check(doc, digests: set[str] | None = None) -> list[str]:
    """Every rule an enum file breaks, as findings that name ids, never a matched word."""
    out: list[str] = []
    if not isinstance(doc, dict):
        return ["the enum file is not a mapping"]
    for k in sorted(set(doc) - TOP):
        out.append(f"the top-level key `{k}` is not part of an enum file")
    if doc.get("enums") != FORMAT:
        out.append(f"`enums` is not {FORMAT}, the enum file format this package reads")
    fw = doc.get("framework")
    if not isinstance(fw, str) or not ID.match(fw or ""):
        out.append("`framework` is not a registry slug")
    if doc.get("status") not in STATUS:
        out.append(f"`status` is not one of {', '.join(STATUS)}")
    if doc.get("status") == "ratified" and not doc.get("ratified"):
        out.append("a ratified file names the ruling that ratified it (`ratified`)")
    for name in LISTS:
        items = doc.get(name)
        if items is None:
            continue
        if not isinstance(items, list):
            out.append(f"`{name}` is not a list")
            continue
        seen = set()
        for n, e in enumerate(items):
            where = f"{name}[{n}]"
            if not isinstance(e, dict):
                out.append(f"{where}: not a mapping")
                continue
            for k in sorted(set(e) - ENTRY):
                out.append(f"{where} {e.get('id')}: the key `{k}` is not part of an entry"
                           + (" (a source line is for review only and never ships)" if k == "source" else ""))
            if _id(where, e.get("id"), out):
                if e["id"] in seen:
                    out.append(f"{where}: the id `{e['id']}` appears twice in `{name}`")
                seen.add(e["id"])
                where = f"{name} {e['id']}"
            _description(where, e.get("description"), digests, out)
            if digests and attribution.matches(f"{e.get('id', '')} {e.get('description', '')}", digests):
                out.append(f"{where}: matches a digest on the attribution list")
            if name == "tools" and e.get("wall") not in WALLS:
                out.append(f"{where}: a tool declares a wall, one of {', '.join(WALLS)}")
            if name != "tools" and "wall" in e:
                out.append(f"{where}: only a tool declares a wall")
            if "scope" in e and e["scope"] not in SCOPES:
                out.append(f"{where}: `scope` is not one of {', '.join(SCOPES)}")
            if "steps" in e:
                if name != "funnels" or not isinstance(e["steps"], list):
                    out.append(f"{where}: only a funnel declares steps, as a list")
                    continue
                sseen = set()
                for m, s in enumerate(e["steps"]):
                    sw = f"{where} step {m}"
                    if not isinstance(s, dict):
                        out.append(f"{sw}: not a mapping")
                        continue
                    for k in sorted(set(s) - STEP):
                        out.append(f"{sw}: the key `{k}` is not part of a step")
                    if _id(sw, s.get("id"), out):
                        if s["id"] in sseen:
                            out.append(f"{sw}: the step id `{s['id']}` appears twice")
                        sseen.add(s["id"])
                        sw = f"{where} step {s['id']}"
                    _description(sw, s.get("description"), digests, out)
                    if digests and attribution.matches(f"{s.get('id', '')} {s.get('description', '')}", digests):
                        out.append(f"{sw}: matches a digest on the attribution list")
    return out


def load(source, digests: set[str] | None = None) -> Enums:
    """An enum file from a path or its text; raises EnumError with every finding."""
    text = Path(source).read_text(encoding="utf-8") if isinstance(source, Path) or (
        isinstance(source, str) and "\n" not in source and Path(source).is_file()) else source
    doc = parse_text(text)
    findings = check(doc, digests)
    if findings:
        raise EnumError(findings)
    return Enums(doc["framework"], doc["status"], doc)
