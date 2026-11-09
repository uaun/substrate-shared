"""This repository's own tests, run by tools/check.sh in CI. The Jetsam package's own suite, in its house,
tests each mechanism; these prove the repository is wired to it: the committed views verify, the tools run
the whole path on a copy of the repository, the guard refuses what only the ingest and the drop point write,
the drop point refuses what the ingest would and commits nothing without an identity, and the mirrors and the
schema load. ROOT is the log's folder (jetsam/ in uaun/substrate-shared)."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools" / "jetsam"))

import jetsam  # noqa: E402
from jetsam import enums as enumfiles, validate as v  # noqa: E402


def tool(root: Path, name: str, *args: str):
    return subprocess.run([sys.executable, "-I", "-B", str(root / "tools" / f"{name}.py"), *args],
                          capture_output=True, text=True)


def copy_repo(tmp_path: Path) -> Path:
    dest = tmp_path / "repo"
    shutil.copytree(ROOT, dest, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
    return dest


def red_packet(epoch="2026-11", secret=b"\x01" * 32) -> bytes:
    p = {"v": 1, "jetsam": "1.0", "framework": "soul", "release": "dev", "surface": "claude-code", "epoch": epoch,
         "pseudonym": jetsam.pseudonym(secret, epoch), "classes": ["red"],
         "events": [{"class": "red", "check": "auto-15", "state": "red", "n": "1"}],
         "control": {"known_pass": True, "refused": "0", "scrubbed": "0"}, "text": None}
    return jetsam.packet_bytes(p)


def test_the_committed_views_verify():
    r = tool(ROOT, "verify")
    assert r.returncode == 0, r.stdout + r.stderr


def test_the_whole_path_on_a_copy(tmp_path):
    repo = copy_repo(tmp_path)
    raw = red_packet()
    (repo / "inbox" / jetsam.packet_name(raw)).write_bytes(raw)
    bad = raw.replace(b"auto-15", b"auto-99")
    (repo / "inbox" / jetsam.packet_name(bad)).write_bytes(bad)
    r = tool(repo, "ingest", "--day", "2026-11-09")
    assert "ingest: 1 ingested, 1 refused" in r.stdout, r.stdout + r.stderr
    assert tool(repo, "verify").returncode == 1          # the views are stale until aggregate runs
    assert tool(repo, "aggregate").returncode == 0
    r = tool(repo, "verify")
    assert r.returncode == 0, r.stdout
    assert (repo / "log" / "soul" / "2026-11" / jetsam.packet_name(raw)).read_bytes() == raw
    assert "| ids | 1 |" in (repo / "views" / "REFUSALS.md").read_text()
    assert "suppressed (5)" in (repo / "views" / "soul" / "dev" / "red.md").read_text()


def test_the_guard_refuses_what_only_the_ingest_writes(tmp_path):
    repo = copy_repo(tmp_path)
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    subprocess.run(git + ["add", "-A"], check=True)
    subprocess.run(git + ["commit", "-q", "-m", "base"], check=True)
    raw = red_packet()
    (repo / "inbox" / jetsam.packet_name(raw)).write_bytes(raw)
    subprocess.run(git + ["add", "-A"], check=True)
    subprocess.run(git + ["commit", "-q", "-m", "a packet"], check=True)
    assert tool(repo, "guard", "HEAD~1").returncode == 0           # a packet under inbox/ is what a pull request adds
    with open(repo / "log" / "LEDGER.jsonl", "a") as f:
        f.write("{}\n")
    subprocess.run(git + ["commit", "-q", "-am", "a hand-made ledger line"], check=True)
    r = tool(repo, "guard", "HEAD~2")
    assert r.returncode == 1 and "REFUSED  log/LEDGER.jsonl" in r.stdout


def test_the_guard_passes_the_branch_that_creates_the_log(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    (repo / "LICENSE").write_text("x")
    subprocess.run(git + ["add", "-A"], check=True)
    subprocess.run(git + ["commit", "-q", "-m", "base"], check=True)
    shutil.copytree(ROOT, repo / "jetsam", ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
    subprocess.run(git + ["add", "-A"], check=True)
    subprocess.run(git + ["commit", "-q", "-m", "the log"], check=True)
    r = tool(repo / "jetsam", "guard", "HEAD~1")
    assert r.returncode == 0 and "creates it" in r.stdout, r.stdout + r.stderr
    with open(repo / "jetsam" / "log" / "LEDGER.jsonl", "a") as f:
        f.write("{}\n")
    subprocess.run(git + ["commit", "-q", "-am", "a hand-made ledger line"], check=True)
    r = tool(repo / "jetsam", "guard", "HEAD~1")
    assert r.returncode == 1 and "REFUSED  log/LEDGER.jsonl" in r.stdout


def test_the_mirrors_and_the_schema():
    assert json.loads((ROOT / "schema" / "1.0.json").read_text()) == v.load_schema()
    for f in sorted((ROOT / "enums").glob("*/*/enums.yaml")):
        e = enumfiles.load(f)
        assert e.status == "ratified" and e.framework == f.parts[-3], f


def test_a_packet_in_the_drop_folder_is_ingested_as_route_1(tmp_path):
    repo = copy_repo(tmp_path)
    raw = red_packet()
    (repo / "inbox" / "drop").mkdir()          # the drop point's first commit makes the folder
    (repo / "inbox" / "drop" / jetsam.packet_name(raw)).write_bytes(raw)
    r = tool(repo, "ingest", "--day", "2026-11-09")
    assert "ingest: 1 ingested, 0 refused" in r.stdout, r.stdout + r.stderr
    row = json.loads((repo / "log" / "LEDGER.jsonl").read_text().splitlines()[-1])
    assert row["route"] == "drop" and list((repo / "inbox" / "drop").iterdir()) == []


def test_the_guard_refuses_a_pull_request_into_the_drop_folder(tmp_path):
    repo = copy_repo(tmp_path)
    git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    subprocess.run(git + ["add", "-A"], check=True)
    subprocess.run(git + ["commit", "-q", "-m", "base"], check=True)
    raw = red_packet()
    (repo / "inbox" / "drop").mkdir()
    (repo / "inbox" / "drop" / jetsam.packet_name(raw)).write_bytes(raw)
    subprocess.run(git + ["add", "-A"], check=True)
    subprocess.run(git + ["commit", "-q", "-m", "a packet claiming route 1"], check=True)
    r = tool(repo, "guard", "HEAD~1")
    assert r.returncode == 1 and "only the drop point, route 1 (JT.11) writes here" in r.stdout, r.stdout


def test_the_drop_point_refuses_what_the_ingest_would_and_commits_nothing_without_an_identity():
    import io
    import os
    from wsgiref.util import setup_testing_defaults
    sys.path.insert(0, str(ROOT / "tools"))
    old = os.environ.pop("JETSAM_DROP_TOKEN", None)
    try:
        import drop  # tools/drop.py
        def call(raw):
            env, out = {}, {}
            setup_testing_defaults(env)
            env.update(REQUEST_METHOD="POST", CONTENT_LENGTH=str(len(raw)), **{"wsgi.input": io.BytesIO(raw)})
            body = b"".join(drop.application(env, lambda s, h: out.setdefault("status", s)))
            return out["status"], json.loads(body)
        status, body = call(red_packet().replace(b"auto-15", b"auto-99"))
        assert status.startswith("422") and body["refused"] == ["ids"]
        status, body = call(red_packet())
        assert status.startswith("503") and "identity" in body["error"]
    finally:
        if old is not None:
            os.environ["JETSAM_DROP_TOKEN"] = old
