# ops

Append-only logs for this repository. Add lines; never rewrite, reorder or delete; never reuse an id.

- `branches.jsonl`: the creation log. One line per branch a Claude session creates here (`by: claude-session`), so the pruning rule can tell Claude's branches from the operator's. A branch absent from this log is the operator's and is never pruned.

Schema is provisional: align it with the atlas's `tools/branch.sh` format when a session with atlas access next touches this repository.

`tools/check.sh` verifies that every id in `ops/*.jsonl` is unique and that the never-store `.gitignore` is present.
