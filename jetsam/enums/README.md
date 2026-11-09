# Enum files

`enums/<framework>/<release>/enums.yaml` is the enum file a framework shipped in that release, mirrored here so
the ingest can check every id in a packet against it, and a reader can see what each id means. Release `dev`
is what a house on an unreleased commit sends (JT.5). Each file is in its JSON form, which YAML also reads, so
the tools read it with Python's standard library.

| framework | release | mirrored from | ratified |
| --- | --- | --- | --- |
| soul | dev | `uaun/substrate-jetsam` `fixtures/enums/soul.yaml` | JT.17 (AT.556), as public text |
| membrane | dev | `uaun/substrate-jetsam` `fixtures/enums/membrane.yaml` | JT.17 (AT.556), as public text |

A change to a description is a new ratification, never an edit in place; it arrives here by pull request (JT.8).
