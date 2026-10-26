"""What a project's pinned versions mean for its records: the advisories that hit them (from OSV, one each under
all its ids), a record opened for each new one, and what's reopened, gone and still open. The node's side of a
scan (settings, folders, the event) is the command's, in __main__."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from .feeds import Advisory, Feeds, merge_aliases
from .impacts import Impact
from .repos import Read
from .store import Book

OPEN = ("investigating", "affected")
SHOWN = 12                # hits a project's lines in a scan's text list

Found = list[tuple[list[str], Advisory | None, list[tuple[str, str, str]]]]


def look_up(feeds: Feeds, ids: list[str], log: Callable = print) -> dict[str, Advisory | None]:
    """Each advisory's details, a few at a time; one that can't be had is listed by its id alone."""
    def one(aid: str) -> Advisory | None:
        try:
            return feeds.advisory(aid)
        except ValueError as e:
            log(f"couldn't look up {aid}: {e}")
            return None
    with ThreadPoolExecutor(8) as pool:
        return dict(zip(ids, pool.map(one, ids), strict=True))


def advisories(feeds: Feeds, where: dict[tuple, list[str]], limit: int | None = None,
               log: Callable = print) -> Found:
    """The advisories that hit these pinned versions, one each under all its ids: (its ids, the CVE first; its
    details, when they could be had; the (ecosystem, name, version) it hits). Only the first `limit` are looked
    up. A ValueError when OSV can't be asked."""
    hits = feeds.affecting(sorted(where)) if where else {}
    by_advisory: dict[str, list[tuple]] = {}
    for key, ids in hits.items():
        for i in ids:
            by_advisory.setdefault(i, []).append(key)
    details = look_up(feeds, list(by_advisory)[:limit], log)
    by_advisory = merge_aliases(by_advisory, details)
    return [((details[aid].ids() if details.get(aid) else [aid]), details.get(aid), keys)
            for aid, keys in sorted(by_advisory.items())]


def severity_of(a: Advisory | None) -> str:
    return a.severity if a and a.severity in ("critical", "high", "medium", "low") else "unknown"


def fixed_for(a: Advisory | None, package: str) -> str:
    return next((p["fixed"] for p in (a.packages if a else []) if p["name"] == package and p.get("fixed")), "")


def opened(project: str, ids: list[str], a: Advisory | None, where: list[dict], by: str) -> Impact:
    """A new hit's record, investigating, as /cve add opens one."""
    return Impact(advisory=ids, project=project.upper(), title=(a.summary[:200] if a else ""),
                  severity=severity_of(a), found_by=by, where=where)


def hit(advisory: str, ecosystem: str, package: str, version: str, severity: str, fixed: str) -> dict:
    return {"advisory": advisory, "package": package, "version": version, "ecosystem": ecosystem,
            "severity": severity, "fixed": fixed}


def scan(key: str, repo: str, got: Read, found: Found, book: Book, by: str) -> dict:
    """One project's scan from what its ref pins (`got`) and the advisories that hit it (`found`): a record opened
    for each advisory not recorded before (`new`, a line a version it hits), the fixed ones hit again
    (`reopened`), and open records from this repo that nothing hits any more (`gone`). Records are only opened
    here: what reopened and gone do to them is decided elsewhere."""
    records = book.all(key)
    by_id = {i.upper(): r for r in records for i in r.advisory}
    new, reopened, made, hit_ids = [], [], [], set()
    for ids, a, keys in found:
        hit_ids |= {i.upper() for i in ids}
        rows = [hit(ids[0], e, n, v, severity_of(a), fixed_for(a, n)) for e, n, v in keys]
        record = next((by_id[i.upper()] for i in ids if i.upper() in by_id), None)
        if record is None:
            imp = opened(key, ids, a, [{"repo": got.name, "file": f, "package": n, "version": v, "ecosystem": e,
                                        "fixed_version": fixed_for(a, n)}
                                       for e, n, v in keys for f in got.where[(e, n, v)][:3]], by)
            book.save(imp)
            records.append(imp)
            made.append(imp.advisory[0])
            new += rows
        elif record.status == "fixed":
            reopened += rows
    gone = []
    for r in records:
        mine = [w for w in r.where if w.get("repo") == got.name and w.get("package")]
        if r.status in OPEN and mine and not hit_ids & {i.upper() for i in r.advisory}:
            gone += [hit(r.advisory[0], str(w.get("ecosystem") or ""), str(w["package"]), str(w.get("version") or ""),
                         r.severity, str(w.get("fixed_version") or "")) for w in mine]
    return {"project": key, "repo": repo, "ref": got.ref, "commit": got.commit, "new": new, "reopened": reopened,
            "gone": gone, "open": sum(1 for r in records if r.status in OPEN), "note": got.note,
            "files": len(got.files), "opened": made}


def totals(found: list[dict]) -> dict:
    """The scan's counts over the projects it could read, and how many it couldn't (`failed`: those with an error)."""
    read = [f for f in found if "error" not in f]
    out = {k: sum(len(f[k]) for f in read) for k in ("new", "reopened", "gone")}
    out["open"] = sum({f["project"]: f["open"] for f in read}.values())      # a key with two repos counts once
    out["failed"] = len(found) - len(read)
    return out


def text(found: list[dict], all_: dict) -> str:
    lines = [f"Scanned {', '.join(f['project'] for f in found)}: {all_['new']} new, {all_['reopened']} reopened, "
             f"{all_['gone']} gone, {all_['open']} open" + (f", {all_['failed']} failed." if all_["failed"] else ".")]
    for f in found:
        if "error" in f:
            lines.append(f"\n**{f['project']}** couldn't be scanned: {f['error']}.")
            continue
        at = f" at {f['ref']} ({f['commit'][:8]})" if f["commit"] else ""
        note = f" {f['note'][0].upper()}{f['note'][1:]}." if f["note"] else ""
        lines.append(f"\n**{f['project']}**{at}, {f['files']} lockfiles: {len(f['new'])} new, "
                     f"{len(f['reopened'])} reopened, {len(f['gone'])} gone, {f['open']} open.{note}")
        rows = [(kind, h) for kind in ("new", "reopened", "gone") for h in f[kind]]
        lines += [f"- {kind}: **{h['advisory']}** ({h['severity']}) {h['ecosystem']} {h['package']} {h['version']}"
                  + (f", fixed in {h['fixed']}" if h["fixed"] else "") for kind, h in rows[:SHOWN]]
        if len(rows) > SHOWN:
            lines.append(f"- …and {len(rows) - SHOWN} more.")
        if f["opened"]:
            lines.append(f"Opened {len(f['opened'])} records in {f['project']} as investigating.")
    return "\n".join(lines)
