// The recorder call for a Node host (J2, the atlas's TODO-194): the same call as the package's
// src/jetsam/record.py, line for line, for a framework whose tools run on Node (the Membrane's
// engine in Adaptive UX's house). Node's standard library only.
//
//   record(root, cls, fields)    root: the house root, the folder that holds jetsam/
//
// It never throws and never changes what it watched. While `cls` is not consented it writes
// nothing at all. It appends one line to jetsam/local/events-<epoch>.jsonl (the epoch is the UTC
// month); an event it cannot write is counted as {"refused":"recorder"} in
// jetsam/local/refused-<epoch>.jsonl, and it gives up silently when even that fails. `fields` are
// the class's fields without its count (`n`, or `opened` for reach); ids are checked at the close,
// which refuses an unknown one and counts it in the packet's control block.
import { appendFileSync, readFileSync } from "node:fs";
import { join } from "node:path";

export const SCHEMA = "1.0";

export function epoch(now = new Date()) {
  return now.toISOString().slice(0, 7);
}

export function consented(root, cls) {
  try {
    const c = JSON.parse(readFileSync(join(root, "jetsam", "local", "consent.json"), "utf8"));
    return c.jetsam === SCHEMA && !!c.classes && Object.prototype.hasOwnProperty.call(c.classes, cls);
  } catch {
    return false;
  }
}

export function record(root, cls, fields = {}) {
  let local;
  try {
    if (!consented(root, cls)) return;
    local = join(root, "jetsam", "local");
  } catch {
    return;
  }
  const e = epoch();
  try {
    const event = { ...fields, class: cls };
    const line = JSON.stringify(Object.fromEntries(Object.keys(event).sort().map((k) => [k, event[k]])));
    appendFileSync(join(local, `events-${e}.jsonl`), line + "\n", "utf8");
  } catch {
    try {
      appendFileSync(join(local, `refused-${e}.jsonl`), '{"refused":"recorder"}\n', "utf8");
    } catch {
      // a counted absence is the best this call can do; the next disclosure reads UNAVAILABLE
    }
  }
}
