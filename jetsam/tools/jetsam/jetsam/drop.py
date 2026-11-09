"""The drop point, route 1 (J4, the atlas's TODO-196; JETSAM, Surfaces and the threat model). Standard library
only. JT.11 (AT.644): necessary but untrusted. Its code is public (it is vendored into the public log's folder),
it keeps no store, writes no log, and is named as the one place a sender's identity exists: the network address
and the moment of a request, for that request's life. It is hosted nowhere yet (AT.645): no house may name a
drop point address until the operator names a host and its commit identity, so route 1 stays off and routes 2
and 3 carry the packets.

What it does with one request, and nothing else:

  POST a packet's canonical bytes  the J1 validator against the log folder it is deployed from (that folder's
                                   schema and enum mirrors, the same context the ingest uses); a refusal answers
                                   422 with the names of the checks, never their detail, and writes nothing; an
                                   accepted packet becomes ONE commit adding `<prefix>inbox/drop/<hash>.json` to
                                   the log's branch, its message, author and committer dated to the day and no
                                   finer, under the drop point's fixed name; 201 with the content hash
  GET                              a short text naming this code and its rules
  anything else                    405

The commit is asked of GitHub's contents API with the host's token (JETSAM_DROP_TOKEN), so the commit object
carries the file and the day. GitHub keeps its own record of the push (the token's identity and the push time);
that is the host's residual, declared in JETSAM, and the sender's address never reaches it.

Statelessness is a rule the tests hold: the module keeps no mutable state between requests (every global is a
constant), the request handler opens no file for writing, and the local server prints nothing. A rejected push
(409, the branch moved) is retried; a file already in the inbox (the same bytes sent twice) is answered as
accepted, since the bytes are the packet.

Configuration, read from the environment at each request:

  JETSAM_DROP_LOG     the log's folder in a checkout of uaun/substrate-shared (its jetsam/ folder)
  JETSAM_DROP_REPO    owner/name of the log's repository (default uaun/substrate-shared)
  JETSAM_DROP_PREFIX  the log folder's path inside that repository (default jetsam/)
  JETSAM_DROP_BRANCH  the branch the commit lands on (default main)
  JETSAM_DROP_API     the GitHub API root (default https://api.github.com)
  JETSAM_DROP_TOKEN   a token whose identity may commit to that branch; absent, every accepted packet is
                      answered 503 and nothing is committed

  python3 -I -B -m jetsam drop-serve [--port N]   a local test host on 127.0.0.1, for measurement only
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import os
import urllib.error
import urllib.request

from . import canonical as core
from . import validate as v

MAX_BYTES = 65536
NAME = "jetsam drop point"
EMAIL = "drop@jetsam.invalid"
MESSAGE = "jetsam: one packet, {day}"
USER_AGENT = "jetsam-drop"
RETRIES = 3
ABOUT = ("Substrate Jetsam's drop point (route 1). Public code, no store, no log (JT.11, AT.644). POST a "
         "packet's canonical bytes; an accepted packet becomes one commit adding the file to the public log's "
         "inbox, dated to the day.\n")


def day_of(now: dt.datetime | None = None) -> str:
    return (now or dt.datetime.now(dt.timezone.utc)).strftime("%Y-%m-%d")


def checks_for(raw: bytes, log_root) -> list[str]:
    """The names of the checks that refuse these bytes (empty: accepted), the ingest's own context."""
    from .log import Log  # the log's context: its schema and its enum mirrors, nothing else
    if len(raw) > MAX_BYTES:
        return ["size"]
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        value = None
    fw = value.get("framework") if isinstance(value, dict) else None
    rel = value.get("release") if isinstance(value, dict) else None
    name = core.content_hash(raw) + ".json"
    return sorted(v.validate(raw, Log(log_root).context(fw, rel), name=name).checks())


def commit_request(raw: bytes, day: str, branch: str) -> dict:
    """The whole body of the contents API request: the file, the branch, and the day in three places."""
    who = {"name": NAME, "email": EMAIL, "date": f"{day}T00:00:00Z"}
    return {"message": MESSAGE.format(day=day), "content": base64.b64encode(raw).decode("ascii"),
            "branch": branch, "author": who, "committer": dict(who)}


def put(api: str, repo: str, path: str, body: dict, token: str) -> tuple[int, dict]:
    req = urllib.request.Request(f"{api.rstrip('/')}/repos/{repo}/contents/{path}", method="PUT",
                                 data=json.dumps(body, sort_keys=True).encode("utf-8"),
                                 headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                                          "Content-Type": "application/json", "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {}


def handle(method: str, raw: bytes, env) -> tuple[int, dict | str]:
    """One request, start to end: nothing read before it, nothing kept after it."""
    if method == "GET":
        return 200, ABOUT
    if method != "POST":
        return 405, {"error": "POST a packet"}
    log_root = env.get("JETSAM_DROP_LOG")
    if not log_root:
        return 503, {"error": "no log folder is configured"}
    checks = checks_for(raw, log_root)
    if checks:
        return 422, {"refused": checks}
    h = core.content_hash(raw)
    token = env.get("JETSAM_DROP_TOKEN")
    if not token:
        return 503, {"error": "no commit identity is configured"}
    prefix = env.get("JETSAM_DROP_PREFIX", "jetsam/")
    path = f"{prefix}inbox/drop/{h}.json"
    body = commit_request(raw, day_of(), env.get("JETSAM_DROP_BRANCH", "main"))
    status = 0
    for _ in range(RETRIES):
        status, reply = put(env.get("JETSAM_DROP_API", "https://api.github.com"),
                            env.get("JETSAM_DROP_REPO", "uaun/substrate-shared"), path, body, token)
        if status in (200, 201):
            return 201, {"accepted": h, "commit": str((reply.get("commit") or {}).get("sha", ""))}
        if status == 422:      # the path exists: these bytes are already in the inbox
            return 200, {"accepted": h, "duplicate": True}
        if status != 409:      # 409: the branch moved under the request; ask again
            break
    return 502, {"error": f"the log refused the commit ({status})"}


def application(environ, start_response):
    """The WSGI entry a host serves. The sender's address is in `environ` and is never read."""
    try:
        n = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        n = 0
    raw = environ["wsgi.input"].read(min(n, MAX_BYTES + 1)) if n > 0 else b""
    try:
        status, body = handle(environ.get("REQUEST_METHOD", "GET"), raw, os.environ)
    except Exception:  # never a traceback, which could echo the packet
        status, body = 500, {"error": "the drop point failed; nothing was committed"}
    text = body if isinstance(body, str) else json.dumps(body, sort_keys=True) + "\n"
    reason = {200: "OK", 201: "Created", 405: "Method Not Allowed", 422: "Unprocessable Entity",
              500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable"}[status]
    ctype = "text/plain; charset=utf-8" if isinstance(body, str) else "application/json"
    start_response(f"{status} {reason}", [("Content-Type", ctype)])
    return [text.encode("utf-8")]


def serve(port: int = 8737) -> None:
    """A local test host for measurement: 127.0.0.1 only, and its request log silenced."""
    from wsgiref.simple_server import WSGIRequestHandler, make_server

    class Quiet(WSGIRequestHandler):
        def log_message(self, *a):  # the stock handler prints each request's address and time
            pass

    with make_server("127.0.0.1", port, application, handler_class=Quiet) as httpd:
        httpd.serve_forever()
