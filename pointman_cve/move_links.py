"""One-off for the switchover, taken out in the next version: the records' old links (`pointman://thread/<n>`) as
`pointman://channel/<n>`, for the threads named, which kept their number as channels. Nothing else in a record changes."""

from __future__ import annotations

import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from .impacts import Impact
from .store import READERS, Store

PLAIN = re.compile(r"pointman://thread/(\d+)(?![\w-]|/?\?)")                                  # no ?query after it
OLD = re.compile(r"(?:pointman|messageboard)://thread/[\w/?=&%-]*|(?<!\w)thr_\d+")            # every old form


def move(store: Store, threads: set[str], write: bool) -> dict:
    """Counts, and with `write` a new version of each record whose links move. `left`: every old link still in a
    record, in any form; `refused`: the records left as they were because the new text doesn't pass their check."""
    def one(path: str):
        text = store.get(path) or ""
        new = PLAIN.sub(lambda m: f"pointman://channel/{m[1]}" if m[1] in threads else m[0], text)
        moved, why = [m[1] for m in PLAIN.finditer(text) if m[1] in threads], ""
        if moved:
            try:
                Impact.from_toml(new).check()
            except (ValueError, TypeError, AttributeError) as e:
                new, moved, why = text, [], str(e)
        if moved and write:
            store.put(path, new)
        return path, moved, OLD.findall(new), why

    with ThreadPoolExecutor(max_workers=READERS) as pool:       # each read and written in one go, a few at a time
        done = list(pool.map(one, [f["path"] for f in store.list("impacts/")]))
    return {"records": len(done), "changed": sum(1 for _, moved, _, _ in done if moved), "written": write,
            "moved": {t: 0 for t in sorted(threads, key=int)} | Counter(t for _, moved, _, _ in done for t in moved),
            "left": [{"record": path, "links": links} for path, _, links, _ in done if links],
            "refused": [{"record": path, "why": why} for path, _, _, why in done if why]}


def said(got: dict) -> str:
    lines = [f"{got['records']} records: {sum(got['moved'].values())} links in {got['changed']} "
             + ("moved" if got["written"] else "to move (nothing written: write=true does)")
             + " (" + ", ".join(f"{t}: {n}" for t, n in got["moved"].items()) + ")."]
    lines += [f"- Left in {x['record']}: {', '.join(x['links'])}" for x in got["left"]]
    lines += [f"- Not written, {x['record']}: {x['why']}" for x in got["refused"]]
    return "\n".join(lines if got["left"] else [*lines, "No other old link."])
