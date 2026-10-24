"""The CVE tracker's process: `python -m pointman_cve`, started and spoken to by the node.

- `/cve recent [ecosystem] [days]`: advisories published lately, newest first, in a pane.
- `/cve check [folder] [project]`: which advisories hit the versions a folder's lockfiles pin; with a
  project, an impact is opened for each one not yet recorded.
- `/cve add <advisory> <project>`, `/cve set <advisory> <project> …`: our record of one that touched a project,
  with its status, where it hit, and the PRs, threads and tasks that dealt with it.
- `/cve show <advisory>`, `/cve impacts [project]`: what we know, in a pane too.
- Once a day (the `check_hours` setting), the `folders` setting is checked, and anything new is posted in
  the `thread` setting's thread.
"""

from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pointman_extension_types as types
from pointman_extension import Extension, Refused
from pointman_extension_types import Block, Chart, Empty, Layout, PaneContent, PaneOpenResponse, Text, Tone

from . import lockfiles
from .feeds import GITHUB_ECOSYSTEM, OSV_ECOSYSTEM, Advisory, Feeds, merge_aliases
from .impacts import JUSTIFICATIONS, STATUSES, Impact, now, thread_link
from .store import Book, store_for

SHOWN = 12                          # advisories a command's text lists
LISTED = 30                         # impacts cve.impacts' text lists

ext = Extension()
feeds = Feeds()
lock = threading.Lock()


def book() -> Book:
    return Book(store_for(lambda message: ext.request(message, timeout=30)))


def machine() -> str:
    return str(ext.node.get("machine") or "this machine")


def one_line(a: Advisory) -> str:
    pkgs = ", ".join(f"{p['ecosystem']} {p['name']}" for p in a.packages[:2]) or "no package named"
    fixed = next((p["fixed"] for p in a.packages if p.get("fixed")), "")
    kind = " · malware" if a.kind == "malware" else ""
    return (f"- **{a.ids()[0]}** ({a.severity}{kind}) {pkgs}: {a.summary[:120]}"
            + (f" · fixed in {fixed}" if fixed else "") + (f" · {a.url}" if a.url else ""))


def ecosystem_of(given) -> str | None:
    e = str(given or ext.settings.get("ecosystem") or "").strip().lower()
    if e in ("", "all"):
        return None
    e = GITHUB_ECOSYSTEM.get(e, e)
    if e not in OSV_ECOSYSTEM:
        raise Refused(f"ecosystem is one of {', '.join(['all', *OSV_ECOSYSTEM])}")
    return e


def split(value) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return [v.strip() for v in str(value).split(",") if v.strip()]


# ------------------------------------------------------------------ commands


@ext.command("cve.recent")
def recent(job):
    eco = ecosystem_of(job.params.get("ecosystem"))
    days = max(1, min(int(job.params.get("days") or 7), 90))
    found = feeds.recent(eco, days, limit=50)
    where = eco or "every ecosystem"
    if not found:
        return {"text": f"No advisories published in {where} in the last {days} days."}
    lines = [one_line(a) for a in found[:SHOWN]]
    more = f"\n…and {len(found) - SHOWN} more in the pane." if len(found) > SHOWN else ""
    return {"text": f"{len(found)} advisories published in {where} in the last {days} days, newest first:\n"
                    + "\n".join(lines) + more,
            "pane": {"open": "cve", "target": {"view": "recent", "ecosystem": eco or "all", "days": days}}}


def scan(folders: list[str]) -> tuple[list[Path], dict[tuple, list[str]], dict[tuple, list[str]]]:
    """Lockfiles under the folders, what each pins, and which pinned versions have advisories (OSV ids)."""
    files, where = [], {}
    for f in folders:
        root = ext.allowed(f)
        for lf in lockfiles.find(root):
            files.append(lf)
            for key in lockfiles.pinned(lf):
                where.setdefault(key, []).append(str(lf))
    hits = feeds.affecting(sorted(where)) if where else {}
    return files, where, hits


LOOK_UP = 40      # advisories a check looks up; the rest are listed by id


def look_up(ids: list[str]) -> dict[str, Advisory | None]:
    """Each advisory's details, a few at a time; one that can't be had is listed by its id alone."""
    def one(aid: str) -> Advisory | None:
        try:
            return feeds.advisory(aid)
        except ValueError as e:
            ext.log(f"couldn't look up {aid}: {e}")
            return None
    with ThreadPoolExecutor(8) as pool:
        return dict(zip(ids, pool.map(one, ids), strict=True))


def check_folders(folders: list[str], project: str | None, by: str = "") -> dict:
    files, where, hits = scan(folders)
    if not files:
        return {"text": f"No lockfiles under {', '.join(folders)} on {machine()}.", "found": [], "opened": []}
    by_advisory: dict[str, list[tuple]] = {}
    for key, ids in hits.items():
        for i in ids:
            by_advisory.setdefault(i, []).append(key)
    details = look_up(list(by_advisory)[:LOOK_UP])
    by_advisory = merge_aliases(by_advisory, details)
    found, opened, lines = [], [], []
    b = book() if project else None
    for aid, keys in sorted(by_advisory.items()):
        a = details.get(aid)
        ids = a.ids() if a else [aid]
        pkgs = "; ".join(f"{e} {n} {v}" for e, n, v in keys)
        lines.append(f"- **{ids[0]}** ({a.severity if a else 'unknown'}) {pkgs}"
                     + (f": {a.summary[:100]}" if a else ""))
        found.append({"advisory": ids, "packages": [list(k) for k in keys]})
        if b is not None and not any(b.load(project, i) for i in ids):
            imp = Impact(advisory=ids, project=project.upper(), title=(a.summary[:200] if a else ""),
                         severity=a.severity if a and a.severity in ("critical", "high", "medium", "low") else "unknown",
                         found_by=by or f"cve check on {machine()}",
                         where=[{"file": f, "package": n, "version": v, "ecosystem": e,
                                 "fixed_version": next((p["fixed"] for p in (a.packages if a else [])
                                                        if p["name"] == n and p.get("fixed")), "")}
                                for e, n, v in keys for f in where[(e, n, v)][:3]])
            b.save(imp)
            opened.append(imp.path)
    head = (f"{len(files)} lockfiles, {len(where)} pinned versions on {machine()}: "
            + (f"{len(by_advisory)} advisories hit them." if by_advisory else "no advisory hits them."))
    tail = f"\nOpened {len(opened)} impacts in {project.upper()} as investigating." if opened else ""
    return {"text": head + ("\n" + "\n".join(lines) if lines else "") + tail, "found": found, "opened": opened}


@ext.command("cve.check")
def check(job):
    folder = str(job.params.get("folder") or "").strip()
    folders = [folder] if folder else split(ext.settings.get("folders"))
    if not folders:
        raise Refused("which folder? /cve check ~/Documents/project, or set this machine's folders setting")
    project = str(job.params.get("project") or "").strip() or None
    got = check_folders(folders, project)
    if got["opened"]:
        got["pane"] = {"open": "cve", "target": {"view": "impacts", "project": project.upper()}}
    return got


@ext.command("cve.add")
def add(job):
    """Record one advisory, or several that one fix covers (`advisory` a list, or comma-separated), for a project."""
    p = job.params
    advisories, project = split(p.get("advisory")), str(p.get("project") or "").strip().upper()
    if not advisories or not project:
        raise Refused("/cve add <advisory> <project>: CVE-2026-1234 MB")
    b = book()
    if len(advisories) == 1:
        if b.load(project, advisories[0]):
            raise Refused(f"{advisories[0]} is already recorded for {project}: change it with /cve set")
        imp, version = add_one(b, advisories[0], project, p)
        return {"text": f"Recorded {advisories[0]} for {project} as {imp.status} ({imp.path}, version {version}).",
                "impact": imp.path, "version": version,
                "pane": {"open": "cve", "target": {"view": "impacts", "project": project}}}
    done, had = [], []
    for advisory in advisories:
        if b.load(project, advisory):
            had.append(advisory)
            continue
        imp, _ = add_one(b, advisory, project, p)
        done.append(imp.path)
    status = str(p.get("status") or "investigating")
    text = f"Recorded {len(done)} advisories for {project} as {status}."
    if had:
        text += f" Already recorded (change them with /cve set): {', '.join(had)}."
    return {"text": text, "impacts": done, "already": had,
            "pane": {"open": "cve", "target": {"view": "impacts", "project": project}}}


def add_one(b: Book, advisory: str, project: str, p: dict) -> tuple[Impact, int]:
    try:
        a = feeds.advisory(advisory)
    except ValueError:
        a = None                     # offline, or rate-limited: the record still goes in with what was given
    ids = a.ids() if a else []
    imp = Impact(advisory=[advisory] + [i for i in ids if i.upper() != advisory.upper()], project=project, title=str(p.get("title") or (a.summary[:200] if a else "")),
                 status=str(p.get("status") or "investigating"), justification=str(p.get("justification") or ""),
                 severity=str(p.get("severity") or (a.severity if a and a.severity in
                                                     ("critical", "high", "medium", "low") else "unknown")),
                 found_by=str(p.get("by") or ""))
    apply(imp, p)
    return imp, b.save(imp)


@ext.command("cve.set")
def set_(job):
    """Change one recorded advisory, or several (`advisory` a list, or comma-separated), in a project."""
    p = job.params
    advisories, project = split(p.get("advisory")), str(p.get("project") or "").strip().upper()
    if not advisories:
        raise Refused("/cve set <advisory> <project> status=…: CVE-2026-1234 MB")
    b = book()
    changed, missing = [], []
    for advisory in advisories:
        imp = b.load(project, advisory)
        if imp is None:
            if len(advisories) == 1:
                raise Refused(f"{advisory} isn't recorded for {project}: add it with /cve add {advisory} {project}")
            missing.append(advisory)
            continue
        for key in ("status", "justification", "severity", "title"):
            if p.get(key):
                setattr(imp, key, str(p[key]))
        apply(imp, p)
        changed.append((advisory, imp, b.save(imp)))
    if len(advisories) == 1:
        advisory, imp, version = changed[0]
        return {"text": f"{advisory} in {project} is {imp.status} (version {version} of {imp.path}).",
                "impact": imp.path, "version": version}
    text = f"Changed {len(changed)} advisories in {project}."
    if missing:
        text += f" Not recorded (add them with /cve add): {', '.join(missing)}."
    return {"text": text, "impacts": [i.path for _, i, _ in changed], "missing": missing}


def apply(imp: Impact, p: dict) -> None:
    """Links and notes add to what's there; fixed_in, and the time it was fixed."""
    for key, attr in (("pr", "prs"), ("task", "tasks")):
        for v in split(p.get(key)):
            if v not in getattr(imp, attr):
                getattr(imp, attr).append(v)
    for t in split(p.get("thread")):
        link = thread_link(t)
        if link not in imp.threads:
            imp.threads.append(link)
    if p.get("fixed_in"):
        imp.fixed_in = str(p["fixed_in"])
    if imp.status == "fixed" and not imp.fixed:
        imp.fixed = now()
    if p.get("note"):
        imp.notes.append(f"{now()[:10]}: {str(p['note']).strip()}")
    if p.get("package"):
        w = {"package": str(p["package"]), "version": str(p.get("version") or ""),
             "fixed_version": str(p.get("fixed_version") or ""), "file": str(p.get("file") or ""),
             "repo": str(p.get("repo") or "")}
        if w not in imp.where:
            imp.where.append(w)


@ext.command("cve.show")
def show(job):
    advisory = str(job.params.get("advisory") or "").strip()
    if not advisory:
        raise Refused("/cve show <advisory>: CVE-2026-1234 or GHSA-…")
    try:
        a = feeds.advisory(advisory)
    except ValueError as e:
        a, why = None, str(e)
    else:
        why = "no advisory has that id"
    try:
        impacts, kept = book().for_advisory(a.ids() if a else [advisory]), ""
    except RuntimeError as e:        # a node without the extension's files yet: the advisory alone
        impacts, kept = [], f"\n\nOur records aren't readable here: {e}."
    head = one_line(a) if a else f"{advisory}: {why}."
    ours = "\n".join(f"- {i.project}: {i.status}" + (f" ({i.justification})" if i.justification else "")
                     + (f", fixed in {i.fixed_in}" if i.fixed_in else "")
                     + (f" · PRs: {', '.join(i.prs)}" if i.prs else "") for i in impacts)
    return {"text": head + (kept or ("\n\nOur record:\n" + ours if ours else "\n\nNot recorded for any project.")),
            "impacts": [i.path for i in impacts]}


@ext.command("cve.impacts")
def impacts_cmd(job):
    project = str(job.params.get("project") or "").strip().upper() or None
    status = str(job.params.get("status") or "").strip() or None
    if status and status not in STATUSES:
        raise Refused(f"status is one of {', '.join(STATUSES)}")
    found = [i for i in book().all(project) if not status or i.status == status]
    if not found:
        return {"text": "No impacts recorded" + (f" for {project}" if project else "") + "."}
    lines = [f"- **{i.advisory[0]}** {i.project}: {i.status}" + (f", fixed in {i.fixed_in}" if i.fixed_in else "")
             for i in sorted(found, key=lambda i: i.found, reverse=True)[:LISTED]]
    more = f"\n…and {len(found) - LISTED} more in the pane." if len(found) > LISTED else ""
    return {"text": f"{len(found)} impacts:\n" + "\n".join(lines) + more,
            "pane": {"open": "cve", "target": {"view": "impacts", **({"project": project} if project else {})}}}


# ------------------------------------------------------------------ the pane


def heading(name: str, text: str, subtitle: str) -> Block:
    return Block(name=name, text=Text(markdown=text, heading=Text.Heading(subtitle=subtitle)))


def table(name: str, columns: list[str], rows: list[tuple[str, list]]) -> Block:
    """A table whose rows are (id, cells)."""
    return Block(name=name, chart=Chart(type=Chart.Type.TYPE_TABLE, data=Chart.Data(
        columns=columns, rows=[cells for _, cells in rows], row_ids=[rid for rid, _ in rows])))


def stat(name: str, label: str, value: int, tone: Tone) -> Block:
    return Block(name=name, chart=Chart(type=Chart.Type.TYPE_STAT, title=label, tone=tone,
                                        data=Chart.Data(columns=["value"], rows=[[value]])))


def empty(name: str, title: str, note: str) -> Block:
    return Block(name=name, empty=Empty(title=title, note=note))


def recent_blocks(eco: str | None, days: int) -> list[Block]:
    found = feeds.recent(eco, days, limit=50)
    rows = [(a.id or str(n), [a.ids()[0], ", ".join(p["name"] for p in a.packages[:2]) or "-",
                              a.severity + (" · malware" if a.kind == "malware" else ""), a.published[:10]])
            for n, a in enumerate(found)]
    return [heading("h", f"Advisories, last {days} days", eco or "every ecosystem"),
            table("t", ["Advisory", "Package", "Severity", "Published"], rows)
            if rows else empty("t", "Nothing new", "No advisories in that time.")]


def impact_blocks(project: str | None) -> list[Block]:
    found = sorted(book().all(project), key=lambda i: i.found, reverse=True)
    counts = {s: sum(1 for i in found if i.status == s) for s in STATUSES}
    tones = {"investigating": Tone.TONE_WARN, "affected": Tone.TONE_BAD, "not_affected": Tone.TONE_NEUTRAL,
             "fixed": Tone.TONE_GOOD}
    stats = [stat(f"s{s}", s.replace("_", " ").capitalize(), counts[s], tones[s]) for s in STATUSES]
    rows = [(i.path, [i.advisory[0], i.project, i.status.replace("_", " "), i.fixed_in or "-",
                      (i.prs[0].rsplit("/", 2)[-2] + "/" + i.prs[0].rsplit("/", 1)[-1]) if i.prs else "-"])
            for i in found]
    return [heading("h", "Our impacts", project or "every project"),
            Block(name="st", layout=Layout(stack=Layout.Stack(children=stats, horizontal=True))),
            table("t", ["Advisory", "Project", "Status", "Fixed in", "PR"], rows)
            if rows else empty("t", "Nothing recorded yet", "/cve add <advisory> <project> records one.")]


@ext.pane("cve")
def open_pane(pane):
    t = pane.target or {}
    view = t.get("view") or "recent"
    try:
        if view == "impacts":
            blocks = impact_blocks(t.get("project"))
            title = "CVE impacts"
        else:
            blocks = recent_blocks(ecosystem_of(t.get("ecosystem")), int(t.get("days") or 7))
            title = "Recent advisories"
    except (ValueError, RuntimeError) as e:
        blocks, title = [empty("e", "Couldn't load it", str(e))], "CVE tracker"

    @pane.on_input
    def tapped(event):
        raise Refused("the CVE pane is read-only: change a record with /cve set")

    return PaneOpenResponse(title=title, content=PaneContent(blocks=blocks))


# ------------------------------------------------------------------ the daily check


def state_file() -> Path:
    return Path(str(ext.node.get("state_dir") or ".")) / "check.json"


def daily() -> None:
    folders = split(ext.settings.get("folders"))
    hours = float(ext.settings.get("check_hours") or 24)
    if not folders or hours <= 0:
        return
    f = state_file()
    try:
        state = json.loads(f.read_text())
    except (OSError, ValueError):
        state = {}
    if time.time() - float(state.get("at") or 0) < hours * 3600:
        return
    project = str(ext.settings.get("project") or "").strip() or None
    try:
        got = check_folders(folders, project)
    except (ValueError, RuntimeError, PermissionError) as e:
        ext.log(f"daily check: {e}")
        return
    seen = set(state.get("seen") or [])
    new = [x for x in got["found"] if x["advisory"][0] not in seen]
    state = {"at": time.time(), "seen": sorted(seen | {x["advisory"][0] for x in got["found"]})}
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(state))
    ext.event("cve.status", {"checked": now(), "advisories": len(got["found"]), "new": len(new)})
    thread = int(ext.settings.get("thread") or 0)
    if new and thread:
        ids = ", ".join(x["advisory"][0] for x in new[:10])
        ext.request(types.BoardPostRequest(thread=types.ThreadId(value=f"thr_{thread}"),
                                           text=f"New advisories hit {machine()}'s lockfiles: {ids}.\n\n"
                                                + got["text"][:3500]))


ext.every(600, daily, lane="check")

if __name__ == "__main__":
    ext.run()
