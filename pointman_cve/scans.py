"""What a project's pinned versions mean for its records: the advisories that hit them (from OSV, one each under
all its ids), a record opened for each new one, and what's reopened, gone and still open, fix-first: known
exploited (CISA's KEV), then the likeliest to be (FIRST's EPSS), then severity. The node's side of a scan
(settings, folders, the event) is the command's, in __main__."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from . import versions
from .feeds import Advisory, Feeds, merge_aliases
from .impacts import Impact, now
from .repos import Read
from .store import Book

OPEN = ("investigating", "affected")
SHOWN = 12                # hits a project's lines in a scan's text list
RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
EPSS_CREDIT = "EPSS scores: FIRST, https://www.first.org/epss"

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


def signal(feeds: Feeds, found: Found) -> str:
    """KEV and EPSS on each advisory found, by its CVE id; "" or why they couldn't be had (they're left None).
    KEV and EPSS know only CVEs: an advisory without one is not in KEV, and has no EPSS."""
    details = [a for _, a, _ in found if a]
    kev, epss, why = feeds.exploited([a.cve for a in details if a.cve])
    for a in details:
        cve = (a.cve or "").upper()
        a.kev = None if kev is None else cve in kev
        a.kev_added = (kev or {}).get(cve, "")
        a.epss = epss.get(cve)
    return why


def first(kev: bool | None, epss: float | None, severity: str, score: float | None = None) -> tuple:
    """Fix-first order's key: known exploited, then EPSS, then severity, then CVSS. EPSS counts by whole percentage
    points: 0.05% against 0.03% is noise, and severity decides between them."""
    return (0 if kev else 1, -round(epss or 0.0, 2), RANK.get(severity, 4), -(score or 0.0))


def fix_first(records: list[Impact], feeds: Feeds) -> tuple[list[Impact], dict[str, tuple], str]:
    """Open records first, fix-first, then the rest, newest first; each open one's (kev, epss) by its path, and why
    they couldn't be had."""
    open_ = [r for r in records if r.status in OPEN]
    cve = {r.path: next((i.upper() for i in r.advisory if i.upper().startswith("CVE-")), "") for r in open_}
    kev, epss, why = feeds.exploited(list(cve.values()))
    signals = {path: (None if kev is None else c in kev, epss.get(c)) for path, c in cve.items()}
    open_.sort(key=lambda r: (first(*signals[r.path], r.severity), r.advisory[0]))
    rest = sorted((r for r in records if r.status not in OPEN), key=lambda r: r.found, reverse=True)
    return open_ + rest, signals, why


def flags(kev: bool | None, epss: float | None) -> str:
    return (", known exploited" if kev else "") + (f", EPSS {percent(epss)}" if epss is not None else "")


def percent(epss: float) -> str:
    """An EPSS score as people read it: 42%, 0.3%, <0.1%."""
    return f"{epss:.0%}" if epss >= 0.1 else f"{epss:.1%}" if epss >= 0.001 else "<0.1%"


def severity_of(a: Advisory | None) -> str:
    return a.severity if a and a.severity in ("critical", "high", "medium", "low") else "unknown"


def fixed_for(a: Advisory | None, package: str, version: str = "") -> str:
    """The lowest version that fixes this package at this version: the fix of the range it's in, not the
    advisory's first (undici 7.30.0 is fixed in 7.30.1, not 6.29.1). "" when none is named."""
    entries = [p for p in (a.packages if a else []) if p["name"] == package]
    if version and any(p.get("ranges") or p.get("versions") for p in entries):
        return versions.fixed_above(entries, version)
    return next((p["fixed"] for p in entries if p.get("fixed")), "")      # GitHub's: one fix a package


def opened(project: str, ids: list[str], a: Advisory | None, where: list[dict], by: str) -> Impact:
    """A new hit's record, investigating, as /cve add opens one."""
    return Impact(advisory=ids, project=project.upper(), title=(a.summary[:200] if a else ""),
                  severity=severity_of(a), found_by=by, where=where)


def hit(advisory: str, ecosystem: str, package: str, version: str, severity: str, fixed: str,
        a: Advisory | None = None) -> dict:
    """A line of a scan's answer: the advisory, where it hits, and its exploitation signals (None: not known)."""
    return {"advisory": advisory, "package": package, "version": version, "ecosystem": ecosystem,
            "severity": severity, "fixed": fixed, "kev": a.kev if a else None, "epss": a.epss if a else None,
            "cvss": a.score if a else None}


def scan(key: str, repo: str, got: Read, found: Found, book: Book, by: str) -> dict:
    """One project's scan from what its ref pins (`got`) and the advisories that hit it (`found`). Agents mark
    records; scans check them:
    - `new`: a record opened, investigating, for each advisory not recorded before (a line a version it hits);
    - `still`: records marked fixed whose version is still at the ref (the fix isn't there yet), left as they are;
    - `confirmed`: records marked fixed whose versions have all gone from this repo: confirmed for this repo, once,
      with the scan, ref, commit and time (a record is confirmed once every repo it was found in is);
    - `reopened`: records confirmed for this repo whose version is back: affected again, with a note;
    A record found here too, under an advisory recorded from another repo, gains this repo's places.
    - `gone`: open records from this repo that nothing hits any more, left open for an agent to mark fixed."""
    records = book.all(key)
    by_id = {i.upper(): r for r in records for i in r.advisory}
    new, reopened, still, made, hit_ids = [], [], [], [], set()
    for ids, a, keys in found:
        hit_ids |= {i.upper() for i in ids}
        rows = [hit(ids[0], e, n, v, severity_of(a), fixed_for(a, n, v), a) for e, n, v in keys]
        record = next((by_id[i.upper()] for i in ids if i.upper() in by_id), None)
        if record is None:
            imp = opened(key, ids, a, [{"repo": got.name, "file": f, "package": n, "version": v, "ecosystem": e,
                                        "fixed_version": fixed_for(a, n, v)}
                                       for e, n, v in keys for f in got.where[(e, n, v)][:3]], by)
            imp.log(by, "found at " + (f"{got.ref} ({got.commit[:8]})" if got.commit else "its files"))
            book.save(imp)
            records.append(imp)
            made.append(imp.advisory[0])
            new += rows
            continue
        if got.name not in record.repos and record.repos:     # one advisory, another repo: one record, both places
            record.where += [{"repo": got.name, "file": f, "package": n, "version": v, "ecosystem": e,
                              "fixed_version": fixed_for(a, n, v)} for e, n, v in keys for f in got.where[(e, n, v)][:3]]
            record.log(by, f"found in {got.name} too")
            book.save(record)
        if record.status == "fixed" and got.name in record.confirmed:
            was = record.confirmed[got.name]
            record.status, record.fixed, record.confirmed = "affected", "", {}
            why = (", ".join(f"{h['package']} {h['version']}" for h in rows)
                   + f" is back (confirmed gone at {was.get('ref') or 'its files'} {str(was.get('commit'))[:8]})")
            record.notes.append(f"{now()[:10]}: reopened by {by}: {why}")
            record.log(by, f"reopened: {why}", was="fixed")
            book.save(record)
            reopened += rows
        elif record.status == "fixed":
            still += rows
    for listed in (new, reopened, still):
        listed.sort(key=lambda h: (first(h["kev"], h["epss"], h["severity"], h["cvss"]), h["advisory"]))
    gone, confirmed = [], []
    for r in records:
        mine = [w for w in r.where if w.get("repo") == got.name and w.get("package")]
        if not mine or hit_ids & {i.upper() for i in r.advisory}:
            continue
        if r.status in OPEN:
            gone += [hit(r.advisory[0], str(w.get("ecosystem") or ""), str(w["package"]), str(w.get("version") or ""),
                         r.severity, str(w.get("fixed_version") or "")) for w in mine]
        elif r.status == "fixed" and got.name not in r.confirmed:
            r.confirmed[got.name] = {"by": by, "ref": got.ref, "commit": got.commit, "at": now()}
            r.log(by, f"confirmed in {got.name}: the version has gone at "
                  + (f"{got.ref} ({got.commit[:8]})" if got.commit else "its files"))
            book.save(r)
            confirmed.append(r.advisory[0])
    return {"project": key, "repo": repo, "ref": got.ref, "commit": got.commit, "new": new, "reopened": reopened,
            "still": still, "confirmed": confirmed, "gone": gone, "open": sum(1 for r in records if r.status in OPEN),
            "note": got.note, "plan": plan(found, records, got.where), "skipped": len(got.skipped),
            "files": len(got.files), "opened": made}


def plan(found: Found, records: list[Impact], where: dict[tuple, list[str]]) -> list[dict]:
    """The upgrades that fix what a ref is hit by: a line a pinned (ecosystem, package, version), going `to` the
    lowest version past every advisory on it, the ones that leaves behind (`fixes`, checked against each one's
    ranges) and the ones it doesn't (`unfixed`: no fix named, or not known). Advisories recorded as
    not_affected are left out. Most fixes first, then those with a known-exploited one."""
    skip = {i.upper() for r in records if r.status == "not_affected" for i in r.advisory}
    lines: dict[tuple, dict] = {}
    for ids, a, keys in found:
        if skip & {i.upper() for i in ids}:
            continue
        for e, n, v in keys:
            line = lines.setdefault((e, n, v), {"ecosystem": e, "package": n, "from": v, "to": "", "fixes": 0,
                                                "advisories": [], "unfixed": [], "kev": False,
                                                "files": list(where.get((e, n, v), []))})
            line["advisories"].append((ids[0], a))
            line["kev"] = line["kev"] or bool(a and a.kev)
    for (e, n, v), line in lines.items():
        line["to"] = versions.highest([fixed_for(a, n, v) for _, a in line["advisories"]])
        done = [aid for aid, a in line["advisories"] if line["to"] and a
                and not versions.affected([p for p in a.packages if p["name"] == n], line["to"])]
        line["unfixed"] = [aid for aid, _ in line["advisories"] if aid not in done]
        line["advisories"], line["fixes"] = [aid for aid, _ in line["advisories"]], len(done)
    return sorted(lines.values(), key=lambda x: (-x["fixes"], not x["kev"], x["ecosystem"], x["package"],
                                                 versions.key(x["from"])))


def plan_text(lines: list[dict], shown: int = SHOWN) -> list[str]:
    """A plan in a few lines: its sum, an upgrade a line, and what no upgrade fixes yet."""
    if not lines:
        return []
    all_ids = {i for x in lines for i in x["advisories"]}
    stuck = {i for x in lines for i in x["unfixed"]}
    ups = [x for x in lines if x["to"] and x["fixes"]]
    n, total = len(ups), len(all_ids)
    out = [f"Upgrade plan: {n} upgrade{'s fix' if n != 1 else ' fixes'} {len(all_ids - stuck)} of {total} "
           f"advisor{'ies' if total != 1 else 'y'}."]
    out += [f"- {x['ecosystem']} {x['package']} {x['from']} → {x['to']}: fixes {x['fixes']}"
            + (", one known exploited" if x["kev"] else "")
            + (f" ({len(x['unfixed'])} not)" if x["unfixed"] else "") for x in ups[:shown]]
    if len(ups) > shown:
        out.append(f"- …and {len(ups) - shown} more.")
    if stuck:
        out.append(f"No fix named yet for {len(stuck)}: " + ", ".join(sorted(stuck)[:8])
                   + (", …" if len(stuck) > 8 else "") + ".")
    return out


def totals(found: list[dict]) -> dict:
    """The scan's counts over the projects it could read, and how many it couldn't (`failed`: those with an error)."""
    read = [f for f in found if "error" not in f]
    out = {k: sum(len(f[k]) for f in read) for k in ("new", "reopened", "gone", "still", "confirmed")}
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
        skipped = f" ({f['skipped']} skipped: test data, or the skip setting)" if f.get("skipped") else ""
        lines.append(f"\n**{f['project']}**{at}, {f['files']} lockfiles{skipped}: {len(f['new'])} new, "
                     f"{len(f['reopened'])} reopened, {len(f['gone'])} gone, {f['open']} open.{note}")
        rows = [(kind, h) for kind in ("new", "reopened", "still there", "gone") for h in f[kind.split()[0]]]
        lines += [f"- {kind}: **{h['advisory']}** ({h['severity']}"
                  + (f" {h['cvss']}" if h.get("cvss") is not None else "") + flags(h.get("kev"), h.get("epss"))
                  + f") {h['ecosystem']} {h['package']} {h['version']}"
                  + (f", fixed in {h['fixed']}" if h["fixed"] else "") for kind, h in rows[:SHOWN]]
        if len(rows) > SHOWN:
            lines.append(f"- …and {len(rows) - SHOWN} more.")
        if f["confirmed"]:
            lines.append(f"Confirmed fixed (the version has gone): {', '.join(f['confirmed'])}.")
        if f["still"]:
            lines.append("Marked fixed but still there (the fix isn't at this ref yet): "
                         + ", ".join(sorted({h["advisory"] for h in f["still"]})) + ".")
        if f["gone"]:
            lines.append("Gone from this ref but still open: mark each fixed with its PR, commit or release.")
        lines += plan_text(f.get("plan") or [], shown=5)
        if f["opened"]:
            lines.append(f"Opened {len(f['opened'])} records in {f['project']} as investigating.")
    if any(h.get("epss") is not None for f in found for k in ("new", "reopened") for h in f.get(k, [])):
        lines.append(f"\n{EPSS_CREDIT}")
    return "\n".join(lines)
