"""Vendoring the jetsam tool into a recording house (J2, the operator's ruling of 2026-11-08 that each
house carries this house's tool at a pinned commit, byte-checked, and writes only its own recorder
call). One implementation, so two hosts cannot drift apart; a house changes it only by vendoring
again from a newer commit.

  vendor(src_root, dest, enums_file)   copy the package, the schema, the reference recorder for Node,
                                       the entry script and the host's enum file (in its JSON form) into
                                       `dest`, and write `dest/VENDOR.json`: the source commit and the
                                       SHA-256 of every file
  vendor(src_root, dest, None)         the same without an enum file, for the public log (J3), which
                                       mirrors every framework's enum files under its own enums/
  check(dest) -> list[str]             every difference between `dest` and its manifest: a changed,
                                       missing or extra file; empty when it matches

The layout a host receives:

  <dest>/run.py                 python3 -I -B <dest>/run.py <verb> --root <house root>
  <dest>/jetsam/*.py            this package, byte for byte
  <dest>/schema/1.0.json        the packet schema
  <dest>/record.mjs             the recorder call for a Node host
  <dest>/enums/<framework>.json the host's enum file, ratified (JT.17), in its JSON form
  <dest>/VENDOR.json            the manifest

The source must be a clean checkout of this house: a file the commit does not hold could not be
traced, so vendoring from a dirty tree is refused.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from . import enums as enumfiles

MANIFEST = "VENDOR.json"
SOURCE = "uaun/substrate-jetsam"
TRACKED = ("src/jetsam", "schema", "reference", "fixtures/enums")


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def files(dest: Path) -> list[str]:
    out = []
    for p in sorted(dest.rglob("*")):
        if p.is_file() and p.name != MANIFEST and "__pycache__" not in p.parts:
            out.append(p.relative_to(dest).as_posix())
    return out


def commit_of(src_root: Path) -> str:
    def git(*a):
        return subprocess.run(["git", "-C", str(src_root), *a], capture_output=True, text=True, check=True).stdout
    try:
        dirty = git("status", "--porcelain", "--", *TRACKED).strip()
        head = git("rev-parse", "HEAD").strip()
    except (OSError, subprocess.CalledProcessError) as e:
        raise ValueError(f"the source is not a git checkout of {SOURCE} ({e})")
    if dirty:
        raise ValueError("the source tree has changes its commit does not hold, so nothing is vendored:\n" + dirty)
    return head


def vendor(src_root, dest, enums_file=None) -> dict:
    src_root, dest = Path(src_root).resolve(), Path(dest).resolve()
    commit = commit_of(src_root)
    e = None
    if enums_file is not None:
        enums_file = Path(enums_file).resolve()
        e = enumfiles.load(enums_file)
        if e.status != "ratified":
            raise ValueError(f"{enums_file.name} is {e.status}; a house ships only a ratified enum file (JT.17)")
    if dest.exists():
        shutil.rmtree(dest)
    (dest / "jetsam").mkdir(parents=True)
    for p in sorted((src_root / "src" / "jetsam").glob("*.py")):
        shutil.copyfile(p, dest / "jetsam" / p.name)
    (dest / "schema").mkdir()
    shutil.copyfile(src_root / "schema" / "1.0.json", dest / "schema" / "1.0.json")
    shutil.copyfile(src_root / "reference" / "record.mjs", dest / "record.mjs")
    shutil.copyfile(src_root / "reference" / "run.py", dest / "run.py")
    if e is not None:
        (dest / "enums").mkdir()
        (dest / "enums" / f"{e.framework}.json").write_text(json.dumps(e.doc, indent=1, ensure_ascii=False) + "\n",
                                                          encoding="utf-8")
    manifest = {"vendored_from": SOURCE, "commit": commit, "framework": e.framework if e else None,
                "enums_from": (enums_file.relative_to(src_root).as_posix() if enums_file.is_relative_to(src_root)
                               else enums_file.name) if e else None,
                "files": {rel: sha256(dest / rel) for rel in files(dest)}}
    (dest / MANIFEST).write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def check(dest) -> list[str]:
    dest = Path(dest)
    try:
        manifest = json.loads((dest / MANIFEST).read_text(encoding="utf-8"))
        want = manifest["files"]
    except (OSError, ValueError, KeyError):
        return [f"{MANIFEST} is missing or unreadable"]
    out = []
    have = files(dest)
    for rel, h in sorted(want.items()):
        p = dest / rel
        if not p.is_file():
            out.append(f"missing: {rel}")
        elif sha256(p) != h:
            out.append(f"changed: {rel}")
    out += [f"extra: {rel}" for rel in have if rel not in want]
    return out


def vendored_root(package_dir: Path) -> Path | None:
    """The vendored copy's root when the package runs from one (a VENDOR.json beside it), else None."""
    d = package_dir.parent
    return d if (d / MANIFEST).is_file() else None
