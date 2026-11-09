"""The attribution check by digest: no name the atlas's list holds may appear in an enum file or in
the one free field (JETSAM, rule 4 and the register wall).

The atlas's `charter/attribution.digests` holds one SHA-256 per line, each the digest of a
lowercased name of one to four words joined by single spaces; the names never appear anywhere,
only their digests. A text matches when any window of one to four consecutive lowercase words
(letters and digits) hashes to a digest on the list, the same windowing as the atlas's tool and
J0's validator. A finding names what matched by position, never the word.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

WORD = re.compile(r"[a-z0-9]+")
EMPTY = hashlib.sha256(b"").hexdigest()


def load(path) -> set[str]:
    """The digests in a list file, comments and blanks left out; the empty digest never counts."""
    out = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if re.fullmatch(r"[0-9a-f]{64}", line):
            out.add(line)
    return out - {EMPTY}


def parse(text: str) -> set[str]:
    out = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if re.fullmatch(r"[0-9a-f]{64}", line):
            out.add(line)
    return out - {EMPTY}


def windows(text: str) -> list[tuple[int, int]]:
    """Every (start word, word count) window of one to four words whose digest is on no list yet:
    the positions a caller hashes."""
    n = len(WORD.findall(text.lower()))
    return [(i, k) for i in range(n) for k in range(1, 5) if i + k <= n]


def matches(text: str, digests: set[str]) -> list[tuple[int, int]]:
    """The (start word, word count) windows of `text` that hash to a digest on the list."""
    if not digests:
        return []
    words = WORD.findall(text.lower())
    out = []
    for i in range(len(words)):
        for k in range(1, 5):
            if i + k <= len(words) and hashlib.sha256(" ".join(words[i:i + k]).encode()).hexdigest() in digests:
                out.append((i, k))
    return out
