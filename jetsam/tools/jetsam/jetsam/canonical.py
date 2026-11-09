"""Canonical bytes, content hashes and salted commitments, by the atlas's kernel-format core v1
(frameworks/kernel/engineering/docs/specs/KERNEL-FORMAT, Part A), which Jetsam defines no
encoding of its own beside (JETSAM, The packet).

- `parse(raw)`: the bytes as JSON under the core's profile (A3): UTF-8, one object, no repeated
  key, ASCII keys, no lone surrogate, integers only from 0 to 2^53 - 1, no float, no NaN.
  Raises ProfileError naming the first rule broken.
- `canonical(value)`: RFC 8785 bytes for a value inside the profile, checked first.
- `is_canonical(raw)`: parsing and serializing again gives the same bytes (A3's definition).
- `content_hash(raw)`: SHA-256 over the bytes exactly as stored, full lowercase hex (A2).
- `commitment(tag, salt, data)`: SHA-256 over the tag, 0x00, the 32-byte salt and the bytes (A8).

Checked against the Kernel house's vectors (`tests/fixtures/kernel-format-v1.json`, read from
uaun/substrate-kernel at 5cdae89): every entry's canonical bytes and hash, the staged record,
the commitment, and the core-level negatives (a float, a boolean for an integer, members out of
order) refused.
"""
from __future__ import annotations

import hashlib
import json
import re

MAX_INT = 2 ** 53 - 1
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TAG = re.compile(r"^[a-z0-9-]+(/[a-z0-9-]+)*/v[0-9]+$")


class ProfileError(ValueError):
    """The bytes or the value break kernel-format's JSON profile (core A3)."""


def _no_float(text: str):
    raise ProfileError(f"a number with a fraction or an exponent ({text}) is not an integer (A3, rule 1)")


def _no_constant(text: str):
    raise ProfileError(f"{text} is not a JSON value the profile admits (A3, rule 1)")


def _object(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ProfileError(f"the key {k!r} is repeated in one object (A3, rule 2)")
        out[k] = v
    return out


def check(value, where: str = "$") -> None:
    """Every value inside the profile: objects with ASCII keys, arrays, strings of Unicode scalar
    values, integers from 0 to 2^53 - 1, true, false and null."""
    if value is None or value is True or value is False:
        return
    if isinstance(value, int):
        if not 0 <= value <= MAX_INT:
            raise ProfileError(f"{where}: the integer {value} is outside 0 to 2^53 - 1 (A3, rule 1)")
        return
    if isinstance(value, float):
        raise ProfileError(f"{where}: {value!r} is a float, not an integer (A3, rule 1)")
    if isinstance(value, str):
        for ch in value:
            if 0xD800 <= ord(ch) <= 0xDFFF:
                raise ProfileError(f"{where}: a lone surrogate (A3, rule 3)")
        return
    if isinstance(value, list):
        for i, v in enumerate(value):
            check(v, f"{where}[{i}]")
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str) or not k.isascii():
                raise ProfileError(f"{where}: the key {k!r} is not ASCII (A3, rule 2)")
            check(v, f"{where}.{k}")
        return
    raise ProfileError(f"{where}: a {type(value).__name__} is not a JSON value")


def parse(raw: bytes):
    """The value of `raw` under the profile; raises ProfileError."""
    if not isinstance(raw, (bytes, bytearray)):
        raise ProfileError("a record is bytes")
    try:
        text = bytes(raw).decode("utf-8")
    except UnicodeDecodeError:
        raise ProfileError("the bytes are not UTF-8")
    if text.startswith("﻿"):
        raise ProfileError("a byte order mark is not part of canonical JSON")
    try:
        value = json.loads(text, object_pairs_hook=_object, parse_float=_no_float, parse_constant=_no_constant)
    except ProfileError:
        raise
    except json.JSONDecodeError as e:
        raise ProfileError(f"not JSON ({e.msg} at character {e.pos})")
    check(value)
    return value


def canonical(value) -> bytes:
    """RFC 8785 bytes of a value inside the profile. Under the profile (integers only, ASCII keys)
    Python's sorted, separator-tight, non-ASCII-preserving dump is RFC 8785 exactly (core A3,
    the informative note); the profile is checked first, because the dump checks nothing."""
    check(value)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True,
                      allow_nan=False).encode("utf-8")


def is_canonical(raw: bytes) -> bool:
    try:
        return canonical(parse(raw)) == bytes(raw)
    except ProfileError:
        return False


def content_hash(raw: bytes) -> str:
    """The content hash: SHA-256 over the bytes exactly as stored, in full (A2)."""
    return hashlib.sha256(bytes(raw)).hexdigest()


def commitment(tag: str, salt: bytes, data: bytes) -> str:
    """A salted commitment (A8): SHA-256 over the tag, one 0x00 byte, a 32-byte salt and the bytes."""
    if not TAG.match(tag):
        raise ValueError(f"{tag!r} is not a domain tag of the form <owner>/<record>/v<n> (A5)")
    if len(salt) != 32:
        raise ValueError("a salt is 32 bytes (A2)")
    return hashlib.sha256(tag.encode("ascii") + b"\x00" + bytes(salt) + bytes(data)).hexdigest()
