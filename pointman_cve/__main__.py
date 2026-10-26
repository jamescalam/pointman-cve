"""The CVE tracker's process: `python -m pointman_cve`, started and spoken to by the node.

- `/cve recent [ecosystem] [days]`: advisories published lately, newest first, in a pane.
- `/cve scan [project]`: every project in the `projects` setting (or the one named), its lockfiles read from git
  at its ref: an impact is opened for each new hit, and the answer says what's new, reopened, gone and open.
- `/cve check <folder> [project]`: which advisories hit the versions a folder's lockfiles pin, as they are on disk;
  with a project, an impact is opened for each one not yet recorded.
- `/cve add <advisory> <project>`, `/cve set <advisory> <project> …`: our record of one that touched a project,
  with its status, where it hit, and the PRs, threads and tasks that dealt with it.
- `/cve show <advisory>`, `/cve impacts [project]`: what we know, in a pane too.

Nothing runs on its own: a scan is asked for, by a person or a workflow that follows `cve.scanned`.
"""

from __future__ import annotations

import threading

from pointman_extension import Extension, Refused, Retry
from pointman_extension_types import Block, Chart, Empty, Layout, PaneContent, PaneOpenResponse, Text, Tone

from . import lockfiles, repos, scans
from .feeds import GITHUB_ECOSYSTEM, OSV_ECOSYSTEM, Advisory, Feeds
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


LOOK_UP = 40      # advisories a check looks up; the rest are listed by id


def check_folder(folder: str, project: str | None) -> dict:
    root = ext.allowed(folder)
    files, where = lockfiles.find(root), {}
    for lf in files:
        for key in lockfiles.pinned(lf):
            where.setdefault(key, []).append(str(lf))
    if not files:
        return {"text": f"No lockfiles under {folder} on {machine()}.", "found": [], "opened": []}
    hits = scans.advisories(feeds, where, LOOK_UP, ext.log)
    found, made, lines = [], [], []
    b = book() if project else None
    for ids, a, keys in hits:
        pkgs = "; ".join(f"{e} {n} {v}" for e, n, v in keys)
        lines.append(f"- **{ids[0]}** ({a.severity if a else 'unknown'}) {pkgs}"
                     + (f": {a.summary[:100]}" if a else ""))
        found.append({"advisory": ids, "packages": [list(k) for k in keys]})
        if b is not None and not any(b.load(project, i) for i in ids):
            imp = scans.opened(project, ids, a, [{"file": f, "package": n, "version": v, "ecosystem": e,
                                                  "fixed_version": scans.fixed_for(a, n)}
                                                 for e, n, v in keys for f in where[(e, n, v)][:3]],
                               f"cve check on {machine()}")
            b.save(imp)
            made.append(imp.path)
    head = (f"{len(files)} lockfiles, {len(where)} pinned versions on {machine()}: "
            + (f"{len(hits)} advisories hit them." if hits else "no advisory hits them."))
    tail = f"\nOpened {len(made)} impacts in {project.upper()} as investigating." if made else ""
    return {"text": head + ("\n" + "\n".join(lines) if lines else "") + tail, "found": found, "opened": made}


@ext.command("cve.check")
def check(job):
    folder = str(job.params.get("folder") or "").strip()
    if not folder:
        raise Refused("which folder? /cve check ~/Documents/project (/cve scan reads the projects setting's repos)")
    project = str(job.params.get("project") or "").strip() or None
    got = check_folder(folder, project)
    if got["opened"]:
        got["pane"] = {"open": "cve", "target": {"view": "impacts", "project": project.upper()}}
    return got


def scan_project(p: repos.Project, b: Book) -> dict:
    """One project, read from git at its ref (fetched first), or its folder as files when it isn't in git."""
    try:
        folder = ext.allowed(p.repo)
    except PermissionError as e:
        raise Refused(f"{p.key}: {e}") from None
    if not folder.is_dir():
        raise Refused(f"{p.key}: {p.repo} isn't a folder on {machine()}")
    try:
        got = repos.read(p, folder)
    except (ValueError, repos.GitFailed) as e:
        raise Refused(f"{p.key}: {e}") from None
    try:
        found = scans.advisories(feeds, got.where, log=ext.log)
    except ValueError as e:          # OSV wasn't answering: no answer isn't taken to mean every record has gone
        raise Retry(f"{p.key}: {e}") from None
    by = f"cve scan on {machine()}" + (f" at {got.ref} ({got.commit[:8]})" if got.commit else "")
    return scans.scan(p.key, p.repo, got, found, b, by)


@ext.command("cve.scan")
def scan(job):
    """Every project in the projects setting, or the one named: its lockfiles at its ref, against OSV."""
    try:
        projects = repos.from_settings(ext.settings.get("projects") or [])
    except ValueError as e:
        raise Refused(f"the projects setting: {e}") from None
    if not projects:
        raise Refused("no projects to scan: add them to the projects setting, each a key (MB), a repo under "
                      "~/Documents and a ref (origin/main); /cve check reads one folder")
    named = str(job.params.get("project") or "").strip().upper()
    if named and not any(p.key == named for p in projects):
        raise Refused(f"{named} isn't in the projects setting ({', '.join(dict.fromkeys(p.key for p in projects))})")
    projects = [p for p in projects if not named or p.key == named]
    b = book()
    found = []
    for n, p in enumerate(projects):
        job.progress(n / len(projects), f"{p.key} at {p.ref}")
        found.append(scan_project(p, b))
    all_ = scans.totals(found)
    text = scans.text(found, all_)
    for f in found:
        del f["files"], f["opened"]
    ext.event("cve.scanned", {"scanned": now(), **all_,
                              "projects": [{"project": f["project"], "ref": f["ref"], "commit": f["commit"],
                                            **{k: len(f[k]) for k in ("new", "reopened", "gone")}, "open": f["open"]}
                                           for f in found]})
    return {"projects": found, **all_, "text": text}


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


if __name__ == "__main__":
    ext.run()
