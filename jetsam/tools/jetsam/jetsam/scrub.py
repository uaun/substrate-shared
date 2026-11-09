"""The scrubber for the one free field (JT.3; JETSAM, The packet): the suggestion's text, at most 500
characters, scrubbed in the house before the operator sees it, then shown as it will be published
and confirmed. The schema is the first layer (nothing else in a packet can hold a string that is
not a listed id); the scrubber is the second.

`scrub(text, digests, patterns)` replaces each span below with `[removed]` and returns the text
with the reason for every span it took out, in order. The validator refuses a packet whose text
the scrubber would still change, so a scrubbed text passes and an unscrubbed one cannot.

Each reason is one rule, and each rule is tested red once:
  url        a URL, or a name starting www.
  email      an address of the form a@b.c
  path       anything with a / or \\ between word characters, a home path (~), or a file name
             with a known extension
  host       a dotted name whose last label is two or more letters (hosts, domains)
  hex        a run of 16 or more hex digits (a pseudonym, a hash, a key, an id)
  number     seven or more digits, separators allowed between them (phones, accounts, ids)
  pattern    a match of one of the never-store content patterns the caller passes (the atlas's
             charter/never-store.yaml `content`: credentials and the like)
  name       one to four words whose digest is on the attribution list the caller passes
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import attribution

MAX_CHARS = 500
MARK = "[removed]"

RULES = [
    ("url", re.compile(r"(?i)\b(?:https?|ftp|file)://\S+|\bwww\.\S+")),
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")),
    ("path", re.compile(r"(?:~|\.{1,2})?(?:[\w.-]+)?(?:[/\\][\w.-]+)+[/\\]?|~[/\\]?|\b[\w-]+\.(?:py|md|ts|mjs|js|json|ya?ml|sh|txt|html|zip|enc|toml|cfg|ini|env|log|csv|db|sqlite|pem|key)\b", re.I)),
    ("host", re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}\b")),
    ("hex", re.compile(r"\b[0-9A-Fa-f]{16,}\b")),
    ("number", re.compile(r"\+?\d(?:[\s().-]?\d){6,}")),
]


@dataclass
class Scrubbed:
    text: str
    removed: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.removed)

    @property
    def too_long(self) -> bool:
        return len(self.text) > MAX_CHARS


def _replace(text: str, rx: re.Pattern, reason: str, removed: list[str]) -> str:
    def sub(m):
        if m.group(0) == MARK or not m.group(0).strip():
            return m.group(0)
        removed.append(reason)
        return MARK
    return rx.sub(sub, text)


def scrub(text: str, digests: set[str] | None = None, patterns: list[str] | None = None) -> Scrubbed:
    removed: list[str] = []
    out = text
    for reason, rx in RULES:
        out = _replace(out, rx, reason, removed)
    for p in patterns or []:
        out = _replace(out, re.compile(p), "pattern", removed)
    if digests:
        out = _names(out, digests, removed)
    return Scrubbed(out, removed)


def _names(text: str, digests: set[str], removed: list[str]) -> str:
    """Replace each word window whose digest is on the list, by its character span."""
    spans = [(m.start(), m.end()) for m in attribution.WORD.finditer(text.lower())]
    hit = set()
    for i, k in attribution.matches(text, digests):
        hit.update(range(i, i + k))
    if not hit:
        return text
    out, last, run = [], 0, None
    for j, (a, b) in enumerate(spans):
        if j in hit:
            if run is None:
                run = [a, b]
            else:
                run[1] = b
        elif run is not None:
            out += [text[last:run[0]], MARK]
            removed.append("name")
            last, run = run[1], None
    if run is not None:
        out += [text[last:run[0]], MARK]
        removed.append("name")
        last = run[1]
    out.append(text[last:])
    return "".join(out)
