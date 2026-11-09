"""Substrate Jetsam's package: the schema package (J1, the atlas's TODO-193) and the jetsam tool a
recording house carries (J2, TODO-194). Standard library only; PyYAML, when installed, also reads an
enum file's YAML form. No model dependency.

The schema package: the packet schema 1.0, the enum files, the validator, the scrubber, and
canonical bytes and hashes by the atlas's kernel-format core v1.

  jetsam validate PACKET... --enums DIR --releases FILE [--digests FILE] [--patterns FILE] [--count]
  jetsam enums FILE... [--digests FILE]
  jetsam canonical FILE

The tool, run in a recording house (--root, default the current folder; its jetsam/config.json):

  jetsam disclosure           the boot's line: FEEDBACK: OFF | ON (classes; route R) | UNAVAILABLE (why)
  jetsam status               the line, the classes offered and on, the pseudonym, the epochs, the outbox
  jetsam consent CLASS...     the operator's yes, one class at a time (rule 1)
  jetsam revoke CLASS...      withdraw it: its local lines and every unsent packet carrying it deleted
  jetsam pseudonym on|off     the optional per-epoch pseudonym (JT.2); off by default
  jetsam record CLASS k=v...  the recorder call, for a host step that is not Python or Node
  jetsam close [--epoch E]    at every close: digest each closed epoch into the outbox; never fails
  jetsam show [--epoch E]     each unsent packet as it will be published, or a preview of an epoch
  jetsam send [HASH] [--route drop|push] [--clone DIR] [--name N --email E] [--jitter]
                              the send act (J4, TODO-196): route 1 POSTs to the drop point the config
                              names (none hosted yet, AT.645); route 2 commits the file, dated to the day,
                              on a branch of a clean checkout of the log's repository for the operator's
                              own pull request; route 3, the handoff, names those two
  jetsam send HASH --receipt TEXT      record a route-2 packet as sent once its pull request is open
  jetsam carry-check ZIP      route 3: a handoff zip carries the packet and nothing of jetsam/local/
  jetsam suggest --kind K --target T TEXT [--confirm]   the one free field, scrubbed (JT.3)
  jetsam measure [--epoch E]  the dry epoch's figures: closes, events and refused per close, bytes, time

The public log's verbs (J3), run in the jetsam/ folder of uaun/substrate-shared (log.py says what each does):

  jetsam log-ingest [--route push|drop|handoff]   inbox/ to log/, refusals kept and counted
  jetsam log-aggregate                             views/ from log/ and schema/ alone
  jetsam log-verify                                rebuild the views and diff; red on any difference
  jetsam log-tombstone HASH --by operator|burn --reason TEXT   withdraw a packet from every view (JT.6)
  jetsam log-burn --framework F --epoch E --pseudonym P --reason TEXT   burn a pseudonym-epoch (JT.12)
  jetsam log-guard PATH...                         refuse a pull request's paths under log/, views/ or inbox/drop/ (JT.8)
  jetsam log-correlate --atlas DIR                 releases beside the atlas's alignment ledger

  jetsam drop-serve [--port N]   the drop point (route 1, drop.py) on a local test host, for measurement;
                                 a host serves `jetsam.drop:application`

  jetsam vendor DEST --enums FILE     copy the tool into a recording house, with its manifest
  jetsam vendor DEST --package-only   the same without an enum file, for the public log (J3)
  jetsam vendor-check [DEST]          compare a vendored copy with its manifest

Here `jetsam` is `python3 -I -B bin/jetsam.py` in this house and `python3 -I -B <dir>/run.py` in a
house that vendored the tool. The recorder call itself is record.py (and reference/record.mjs for
Node): a host calls it at each event.
"""
from __future__ import annotations

from . import canonical as _core

SCHEMA = "1.0"
PSEUDONYM_TAG = "jetsam/pseudonym/v1"


def pseudonym(secret: bytes, epoch: str) -> str:
    """The per-epoch pseudonym (JT.2): kernel-format's salted commitment (core A8) with the house's
    32-byte secret for one framework as the salt and the epoch's UTF-8 bytes as the data. Two epochs,
    or two frameworks' secrets, give unrelated values; the secret never leaves jetsam/local/."""
    return _core.commitment(PSEUDONYM_TAG, secret, epoch.encode("utf-8"))


def packet_bytes(packet: dict) -> bytes:
    """A packet's bytes as it is written to the outbox: its canonical serialization."""
    return _core.canonical(packet)


def packet_name(raw: bytes) -> str:
    """A packet's file name: its full content hash and `.json` (core A2)."""
    return _core.content_hash(raw) + ".json"
