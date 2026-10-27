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

import json
import threading
import time
from collections import Counter
from pathlib import Path

from pointman_extension import Extension, Refused, Retry
from pointman_extension_types import (Block, Chart, Empty, Input, Layout, List, PaneContent, PaneOpenResponse, Text,
                                      Tone)

from . import lockfiles, report, repos, scans, vex
from .feeds import GITHUB_ECOSYSTEM, OSV_ECOSYSTEM, Advisory, Feeds
from .impacts import JUSTIFICATIONS, STATUSES, Impact, now, slug, thread_link
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
    skipped: list = []
    files, where = lockfiles.find(root, skipped_out=skipped), {}
    for lf in files:
        for key in lockfiles.pinned(lf):
            where.setdefault(key, []).append(str(lf))
    if not files:
        return {"text": f"No lockfiles under {folder} on {machine()}"
                        + (f" but test data ({len(skipped)} skipped)." if skipped else "."),
                "found": [], "opened": [], "skipped": len(skipped)}
    hits = scans.advisories(feeds, where, LOOK_UP, ext.log)
    why = scans.signal(feeds, hits)
    hits.sort(key=lambda h: (scans.first(h[1].kev if h[1] else None, h[1].epss if h[1] else None,
                                         scans.severity_of(h[1]), h[1].score if h[1] else None), h[0][0]))
    found, made, lines = [], [], []
    b = book() if project else None
    for ids, a, keys in hits:
        pkgs = "; ".join(f"{e} {n} {v}" for e, n, v in keys)
        lines.append(f"- **{ids[0]}** ({a.severity if a else 'unknown'}{scans.flags(a.kev, a.epss) if a else ''}) {pkgs}"
                     + (f": {a.summary[:100]}" if a else ""))
        found.append({"advisory": ids, "packages": [list(k) for k in keys], "kev": a.kev if a else None,
                      "epss": a.epss if a else None, "cvss": a.score if a else None})
        if b is not None and not any(b.load(project, i) for i in ids):
            imp = scans.opened(project, ids, a, [{"file": f, "package": n, "version": v, "ecosystem": e,
                                                  "fixed_version": scans.fixed_for(a, n, v)}
                                                 for e, n, v in keys for f in where[(e, n, v)][:3]],
                               f"cve check on {machine()}")
            imp.log(imp.found_by, f"found in {folder}")
            b.save(imp)
            made.append(imp.path)
    head = (f"{len(files)} lockfiles" + (f" ({len(skipped)} skipped as test data)" if skipped else "")
            + f", {len(where)} pinned versions on {machine()}: "
            + (f"{len(hits)} advisories hit them." if hits else "no advisory hits them."))
    tail = f"\nOpened {len(made)} impacts in {project.upper()} as investigating." if made else ""
    if why:
        tail += f"\nKnown-exploited and EPSS couldn't be had ({why}): in severity order."
    if any(f["epss"] is not None for f in found):
        tail += f"\n{scans.EPSS_CREDIT}"
    return {"text": head + ("\n" + "\n".join(lines) if lines else "") + tail, "found": found, "opened": made,
            "skipped": len(skipped)}


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


def read_project(p: repos.Project) -> repos.Read | str:
    """One project, read from git at its ref (fetched first), or its folder as files when it isn't in git; or
    why it couldn't be read (not allowed, not there, a ref or git that fails)."""
    try:
        folder = ext.allowed(p.repo)
        if not folder.is_dir():
            raise ValueError(f"{p.repo} isn't a folder on {machine()}")
        return repos.read(p, folder)
    except (OSError, ValueError, repos.GitFailed) as e:
        return str(e)


def found_at(p: repos.Project, got: repos.Read) -> scans.Found:
    """The advisories that hit what a project pins, with their KEV and EPSS."""
    try:
        found = scans.advisories(feeds, got.where, log=ext.log)
    except ValueError as e:          # OSV wasn't answering: no answer isn't taken to mean every record has gone
        raise Retry(f"{p.key}: {e}") from None
    why = scans.signal(feeds, found)
    if why:                          # KEV and EPSS add to the scan: without them it goes on, in severity order
        got.note = "; ".join(x for x in (got.note, f"known-exploited and EPSS couldn't be had ({why})") if x)
    return found


def last_scan(project: str, repo: str) -> str:
    """Where a project's repo's last scan is kept, beside the records: what the pane shows of it."""
    return f"scans/{project.lower()}/{slug(repo)}.json"


def scan_project(p: repos.Project, b: Book) -> dict:
    """One project's scan; one that can't be read answers its `error`, and the scan goes on."""
    got = read_project(p)
    if isinstance(got, str):
        return {"project": p.key, "repo": p.repo, "ref": p.ref, "error": got}
    found = found_at(p, got)
    by = f"cve scan on {machine()}" + (f" at {got.ref} ({got.commit[:8]})" if got.commit else "")
    done = scans.scan(p.key, p.repo, got, found, b, by)
    b.store.put(last_scan(p.key, p.repo), json.dumps({
        "project": p.key, "repo": p.repo, "ref": got.ref, "commit": got.commit, "scanned": now(), "open": done["open"],
        "skipped": done["skipped"],
        **{k: len(done[k]) for k in ("new", "reopened", "gone", "still", "confirmed")}, "plan": done["plan"]}, indent=1))
    return done


@ext.command("cve.plan")
def plan(job):
    """A project's upgrade plan at its refs: the fewest upgrades that fix the most. It reads; it records nothing."""
    key = str(job.params.get("project") or "").strip().upper()
    try:
        projects = [p for p in repos.from_settings(ext.settings.get("projects") or []) if p.key == key]
    except ValueError as e:
        raise Refused(f"the projects setting: {e}") from None
    if not key or not projects:
        raise Refused("which project? /cve plan <key>, one in the projects setting" + (f" ({key} isn't)" if key else ""))
    records = book().all(key)
    lines, notes, read = [], [], 0
    for p in projects:
        got = read_project(p)
        if isinstance(got, str):
            notes.append(f"{p.repo} couldn't be read: {got}")
            continue
        read += 1
        for line in scans.plan(found_at(p, got), records, got.where):
            lines.append({**line, "repo": p.repo, "ref": got.ref, "commit": got.commit})
        if got.note:
            notes.append(f"{p.repo}: {got.note}")
    if not read:
        raise Refused("; ".join(notes))
    lines.sort(key=lambda x: (-x["fixes"], not x["kev"], x["ecosystem"], x["package"]))
    stuck = sorted({i for x in lines for i in x["unfixed"]})
    head = scans.plan_text(lines) or [f"Nothing to upgrade in {key}: no advisory hits what its refs pin."]
    return {"project": key, "plan": lines, "upgrades": sum(1 for x in lines if x["to"] and x["fixes"]),
            "fixes": len({i for x in lines for i in x["advisories"]} - set(stuck)), "unfixed": stuck,
            "text": "\n".join([f"**{key}**: " + head[0], *head[1:], *notes])}


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
    if all("error" in f for f in found):
        raise Refused("no project could be scanned: " + "; ".join(f"{f['project']}: {f['error']}" for f in found))
    all_ = scans.totals(found)
    text = scans.text(found, all_)
    for f in found:
        f.pop("files", None)
        f.pop("opened", None)
    ext.event("cve.scanned", {"scanned": now(), **all_, "projects": [
        {"project": f["project"], "ref": f["ref"], "error": f["error"]} if "error" in f else
        {"project": f["project"], "ref": f["ref"], "commit": f["commit"],
         **{k: len(f[k]) for k in ("new", "reopened", "gone", "still", "confirmed")}, "open": f["open"]} for f in found]})
    return {"projects": found, **all_, "text": text}


def caller(job) -> tuple[str, bool]:
    """Who's making a change, and whether that's only what the caller said: the node's word for who asked, once its
    request carries it (MB-672), and then the `by` param is ignored; until then, the `by` the caller gives."""
    asked = getattr(job.request, "asked_by", None)
    if asked:
        return str(getattr(asked, "value", asked)), False
    return str(job.params.get("by") or "").strip(), True


def says_why(p: dict) -> None:
    """not_affected says why, as VEX does: one of its justifications, and a note in our words."""
    if str(p.get("status") or "") != "not_affected":
        return
    j = str(p.get("justification") or "")
    if j not in JUSTIFICATIONS:
        raise Refused(f"not_affected needs VEX's justification, one of {', '.join(JUSTIFICATIONS)}"
                      + (f" (not {j})" if j else "") + ", and a note saying why")
    if not str(p.get("note") or "").strip():
        raise Refused(f"not_affected needs a note saying why it's {j} here: note=…")


def given(p: dict) -> list[str]:
    """The evidence a change brings: its PRs, commits and the release it names."""
    return [*split(p.get("pr")), *split(p.get("commit"))] + ([f"fixed in {p['fixed_in']}"] if p.get("fixed_in") else [])


def evidence(p: dict) -> None:
    """Marking a record fixed takes its evidence: a PR, a commit or the release that fixed it. A scan then checks it."""
    if str(p.get("status") or "") == "fixed" and not (split(p.get("pr")) or split(p.get("commit")) or p.get("fixed_in")):
        raise Refused("fixed needs its evidence: pr=<link>, commit=<link> or fixed_in=<release>. The next scan "
                      "confirms it once the version has gone, or says it's still there")


@ext.command("cve.add")
def add(job):
    """Record one advisory, or several that one fix covers (`advisory` a list, or comma-separated), for a project."""
    p = job.params
    advisories, project = split(p.get("advisory")), str(p.get("project") or "").strip().upper()
    if not advisories or not project:
        raise Refused("/cve add <advisory> <project>: CVE-2026-1234 MB")
    evidence(p)
    says_why(p)
    who, said = caller(job)
    p = {**p, "by": who, "_said": said}
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
    imp.log(str(p.get("by") or ""), str(p.get("note") or "").strip() or "recorded", given(p), said=bool(p.get("_said")))
    return imp, b.save(imp)


@ext.command("cve.set")
def set_(job):
    """Change one recorded advisory, or several (`advisory` a list, or comma-separated), in a project."""
    p = job.params
    advisories, project = split(p.get("advisory")), str(p.get("project") or "").strip().upper()
    if not advisories:
        raise Refused("/cve set <advisory> <project> status=…: CVE-2026-1234 MB")
    b = book()
    loaded = [(advisory, b.load(project, advisory)) for advisory in advisories]
    if len(advisories) == 1 and loaded[0][1] is None:
        raise Refused(f"{advisories[0]} isn't recorded for {project}: add it with /cve add {advisories[0]} {project}")
    evidence(p)                      # before anything is written: one without its evidence or its why changes none
    says_why(p)
    who, said = caller(job)
    changed, missing = [], []
    for advisory, imp in loaded:
        if imp is None:
            missing.append(advisory)
            continue
        was = imp.status
        for key in ("status", "justification", "severity", "title"):
            if p.get(key):
                setattr(imp, key, str(p[key]))
        if imp.status != "not_affected":
            imp.justification = ""
        apply(imp, p)
        imp.log(who, str(p.get("note") or "").strip(), given(p), was, said)
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
    """Links and notes add to what's there; fixed_in, and the time it was fixed. A commit is kept with the PRs, as
    its link. A record that isn't fixed any more loses its fixed time and its confirmation."""
    for key, attr in (("pr", "prs"), ("commit", "prs"), ("task", "tasks")):
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
    if imp.status != "fixed":
        imp.fixed, imp.confirmed = "", {}
    if p.get("note"):
        imp.notes.append(f"{now()[:10]}: {str(p['note']).strip()}")
    if p.get("package"):
        w = {"package": str(p["package"]), "version": str(p.get("version") or ""),
             "fixed_version": str(p.get("fixed_version") or ""), "file": str(p.get("file") or ""),
             "repo": str(p.get("repo") or "")}
        if w not in imp.where:
            imp.where.append(w)


def history(i: Impact, shown: int = 10) -> str:
    """A record's history, newest last: when, who, from and to, why, evidence. A record from before 0.8.0 starts
    with when it was found."""
    lines = [] if i.history else [f"{i.found[:10]} {i.found_by or 'someone'}: found"]
    for h in i.history[-shown:]:
        step = f"{h.get('was')} → {h.get('status')}" if h.get("was") else str(h.get("status"))
        who = h.get("by") or (f"{h['by_said']} (said)" if h.get("by_said") else "someone (not said)")
        lines.append(f"{str(h.get('at'))[:10]} {who}: {step}"
                     + (f" ({h['justification']})" if h.get("justification") else "")
                     + (f", {h['why']}" if h.get("why") else "")
                     + (f" · {', '.join(h['evidence'])}" if h.get("evidence") else ""))
    more = [f"…{len(i.history) - shown} earlier"] if len(i.history) > shown else []
    return "".join(f"\n  - {x}" for x in more + lines)


def confirmation(i: Impact) -> str:
    """Whether scans have checked a fixed record: confirmed at each repo's ref, in some of its repos, or not yet."""
    if i.status != "fixed":
        return ""
    if not i.confirmed:
        return ", not confirmed by a scan yet"
    at = "; ".join(f"{repo} at {c.get('ref') or 'its files'}" + (f" ({str(c.get('commit'))[:8]})" if c.get("commit") else "")
                   + f" on {str(c.get('at'))[:10]}" for repo, c in sorted(i.confirmed.items()))
    left = sorted(i.repos - set(i.confirmed))
    return f", confirmed in {at}" + (f"; not yet in {', '.join(left)}" if left else "")


@ext.command("cve.vex")
def vex_cmd(job):
    """A project's records as an OpenVEX document, posted as a file with the answer."""
    project = str(job.params.get("project") or "").strip().upper()
    if not project:
        raise Refused("which project? /cve vex <key>: MB")
    records = book().all(project)
    if not records:
        raise Refused(f"nothing is recorded for {project}, so there's nothing to say yet")
    tool = f"pointman-cve {ext.manifest.get('extension', {}).get('version', '')}".strip()
    doc = vex.document(project, records, str(job.params.get("author") or "").strip() or "pointman-cve", tool, now())
    path = Path(job.work) / f"openvex-{project.lower()}-{now()[:10]}.json"
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    job.output(path, kind="document", meta={"title": f"OpenVEX: {project}", "file": path.stem})
    counts = Counter(s["status"] for s in doc["statements"])
    said = ", ".join(f"{n} {status.replace('_', ' ')}" for status, n in sorted(counts.items()))
    return {"text": f"OpenVEX for {project}: {len(doc['statements'])} statements ({said}), posted as {path.name}.",
            "file": path.name, "id": doc["@id"], "statements": len(doc["statements"]), "counts": dict(counts)}


@ext.command("cve.report")
def report_cmd(job):
    """Every open record a PR fixes, by project and PR, as a page posted with the answer: for whoever reviews and
    merges the PRs. It reads the records; it changes nothing."""
    keys = [k.upper() for k in split(job.params.get("project"))]
    b = book()
    records = [r for k in keys for r in b.all(k)] if keys else b.all()
    if not any(r.status in scans.OPEN for r in records):
        raise Refused("nothing is open" + (f" in {', '.join(keys)}" if keys else "") + ", so there's nothing to report")
    _, signals, why = scans.fix_first(records, feeds)
    data = report.build(records, signals, now(), keys or None)
    page = report.html(data, signals, str(job.params.get("title") or "").strip())
    path = Path(job.work) / f"cve-report-{now()[:10]}.html"
    path.write_text(page, encoding="utf-8")
    job.output(path, kind="document", meta={"title": "CVE fix report", "file": path.stem})
    note = f"\nKnown-exploited and EPSS couldn't be had ({why})." if why else ""
    return {"text": report.text(data) + f"\nPosted as {path.name}." + note, "file": path.name,
            **{k: data[k] for k in ("prs", "open", "fixed_by_prs", "kev", "without_pr")},
            "projects": [{k: v for k, v in p.items() if not k.startswith("_")} for p in data["projects"]]}


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
                     + (f", fixed in {i.fixed_in}" if i.fixed_in else "") + confirmation(i) + history(i)
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
    ordered, signals, why = scans.fix_first(found, feeds)     # open ones first, fix-first; then newest first
    lines = [f"- **{i.advisory[0]}** {i.project}: {i.status}" + scans.flags(*signals.get(i.path, (None, None)))
             + (f", fixed in {i.fixed_in}" if i.fixed_in else "") + confirmation(i) for i in ordered[:LISTED]]
    note = f"Known-exploited and EPSS couldn't be had ({why}): open ones are in severity order.\n" if why else ""
    more = f"\n…and {len(found) - LISTED} more in the pane." if len(found) > LISTED else ""
    credit = f"\n{scans.EPSS_CREDIT}" if any(e is not None for _, e in signals.values()) else ""
    return {"text": f"{len(found)} impacts:\n" + note + "\n".join(lines) + more + credit,
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


def rows(name: str, items: list[List.Item], *, tap: bool = True, limit: int | None = None) -> Block:
    return Block(name=name, list=List(style=List.Style.STYLE_ROWS, items=items, tap=tap, limit=limit))


def buttons(name: str, *pairs: tuple[str, str]) -> Block:
    return Block(name=name, input=Input(actions=Input.Actions(buttons=[Input.Actions.Button(id=i, title=t)
                                                                        for i, t in pairs])))


def when(at: str) -> str:
    """An ISO time as a phone reads it: 26 Oct 22:10."""
    try:
        return time.strftime("%-d %b %H:%M", time.strptime(str(at)[:16], "%Y-%m-%dT%H:%M"))
    except ValueError:
        return str(at)[:16]


def cve_of(r: Impact) -> str:
    return next((i.upper() for i in r.advisory if i.upper().startswith("CVE-")), "")


def last_scans(project: str) -> list[dict]:
    """Each of a project's repos' last scan, as the scan kept it for the pane."""
    store, out = book().store, []
    for f in store.list(f"scans/{project.lower()}/"):
        try:
            out.append(json.loads(store.get(f["path"]) or ""))
        except ValueError:
            continue
    return out


def picker_blocks() -> tuple[str, list[Block]]:
    """Where the pane opens: every project, with what's open and when it was last scanned."""
    records = book().all()
    try:
        keys = [p.key for p in repos.from_settings(ext.settings.get("projects") or [])]
    except ValueError:
        keys = []
    keys = list(dict.fromkeys([*keys, *sorted({r.project for r in records})]))
    if not keys:
        return "CVE tracker", [heading("h", "CVE tracker", "No projects yet"),
                               empty("projects", "No projects yet", "Add them to the projects setting, then /cve scan."),
                               buttons("nav", ("recent", "Recent advisories"))]
    kev, _, _ = feeds.exploited([cve_of(r) for r in records if r.status in scans.OPEN])
    items = []
    for k in keys:
        open_ = [r for r in records if r.project == k and r.status in scans.OPEN]
        exploited = sum(1 for r in open_ if kev and cve_of(r) in kev)
        last = max((str(x.get("scanned") or "") for x in last_scans(k)), default="")
        said = [f"{len(open_)} open", f"{exploited} known exploited" if exploited else "",
                f"scanned {when(last)}" if last else "not scanned yet"]
        items.append(List.Item(id=k, title=k, subtitle=" · ".join(x for x in said if x), badge="KEV" if exploited else None,
                               tone=Tone.TONE_BAD if exploited else Tone.TONE_WARN if open_ else Tone.TONE_GOOD))
    return "CVE tracker", [heading("h", "CVE tracker", f"{len(keys)} project{'s' if len(keys) != 1 else ''}"),
                           rows("projects", items), buttons("nav", ("recent", "Recent advisories"))]


def record_row(r: Impact, kev: bool | None, epss: float | None) -> List.Item:
    pkgs = sorted({f"{w['package']} {w.get('version') or ''}".strip() for w in r.where if w.get("package")})
    status = r.status.replace("_", " ") + (f" ({r.justification.replace('_', ' ')})" if r.justification else "")
    said = [status, r.severity if r.severity != "unknown" else "", "known exploited" if kev else "",
            f"EPSS {scans.percent(epss)}" if epss is not None else "", ", ".join(pkgs[:2]) + ("…" if len(pkgs) > 2 else "")]
    tone = Tone.TONE_BAD if kev or r.status == "affected" else Tone.TONE_WARN if r.status in scans.OPEN \
        else Tone.TONE_GOOD if r.status == "fixed" else Tone.TONE_NEUTRAL
    return List.Item(id=r.path, title=r.advisory[0], subtitle=" · ".join(x for x in said if x),
                     badge="KEV" if kev else None, tone=tone)


def project_blocks(key: str) -> tuple[str, list[Block]]:
    """A project: its counts, its open records fix-first, its upgrade plan and its last scans, then its closed ones."""
    ordered, signals, why = scans.fix_first(book().all(key), feeds)
    counts = {s: sum(1 for i in ordered if i.status == s) for s in STATUSES}
    tones = {"investigating": Tone.TONE_WARN, "affected": Tone.TONE_BAD, "not_affected": Tone.TONE_NEUTRAL,
             "fixed": Tone.TONE_GOOD}
    open_ = [record_row(r, *signals.get(r.path, (None, None))) for r in ordered if r.status in scans.OPEN]
    closed = [record_row(r, None, None) for r in ordered if r.status not in scans.OPEN]
    kept = last_scans(key)
    plan = [List.Item(id=f"{x['ecosystem']}:{x['package']}:{x['from']}:{n}", title=f"{x['package']} {x['from']} → {x['to']}",
                      subtitle=" · ".join(y for y in [f"fixes {x['fixes']}", "known exploited" if x.get("kev") else "",
                                                       ", ".join(x.get("files") or []), str(last.get("repo") or "")] if y),
                      tone=Tone.TONE_BAD if x.get("kev") else Tone.TONE_WARN)
            for n, last in enumerate(kept) for x in last.get("plan") or [] if x.get("to") and x.get("fixes")]
    scanned = [List.Item(id=str(last.get("repo")), title=str(last.get("repo")),
                         subtitle=" · ".join([f"{last.get('ref')} ({str(last.get('commit'))[:8]})" if last.get("commit")
                                              else "its files", f"scanned {when(str(last.get('scanned')))}",
                                              f"{last.get('new', 0)} new, {last.get('gone', 0)} gone, {last.get('open', 0)} open"]))
               for last in kept]
    latest = max((str(x.get("scanned") or "") for x in kept), default="")
    blocks = [heading("h", key, f"last scanned {when(latest)}" if latest else "not scanned yet"),
              buttons("nav", ("projects", "All projects")),
              Block(name="st", layout=Layout(stack=Layout.Stack(
                  children=[stat(f"s{s}", s.replace("_", " ").capitalize(), counts[s], tones[s]) for s in STATUSES],
                  horizontal=True))),
              heading("oh", "Open, fix first", why and f"Known-exploited and EPSS couldn't be had: {why}" or
                      "known exploited, then EPSS, then severity"),
              rows("open", open_) if open_ else empty("open", "Nothing open", "No record is investigating or affected."),
              heading("ph", "Upgrade plan", "from each repo's last scan"),
              rows("plan", plan, tap=False) if plan else empty("plan", "Nothing to upgrade",
                                                                "No fix is named for what's open, or no scan yet."),
              heading("sh", "Last scans", f"{len(kept)} repo{'s' if len(kept) != 1 else ''}"),
              rows("scans", scanned, tap=False) if scanned else empty("scans", "Not scanned yet", f"/cve scan {key}")]
    if closed:
        blocks += [heading("ch", "Closed", "fixed or not affected"), rows("closed", closed, limit=10)]
    return f"CVE · {key}", blocks


def record_blocks(path: str) -> tuple[str, list[Block]]:
    """One record: what it is, where it hit, its evidence, and its history, newest first."""
    text = book().store.get(path) if path.startswith("impacts/") else None
    if not text:
        raise Refused(f"there's no record at {path}")
    r = Impact.from_toml(text)
    status = r.status.replace("_", " ") + (f" ({r.justification.replace('_', ' ')})" if r.justification else "")
    about = [r.title, f"Also known as {', '.join(r.advisory[1:])}." if r.advisory[1:] else "",
             f"Severity: {r.severity}." if r.severity != "unknown" else "",
             f"Found {when(r.found)}" + (f" by {r.found_by}" if r.found_by else "") + ".",
             f"Fixed in {r.fixed_in}." if r.fixed_in else "", confirmation(r).removeprefix(", ").capitalize()]
    where = [List.Item(id=f"w{n}", title=f"{w.get('package')} {w.get('version') or ''}".strip()
                       + (f" → {w['fixed_version']}" if w.get("fixed_version") else ""),
                       subtitle=" · ".join(str(x) for x in (w.get("repo"), w.get("file")) if x))
             for n, w in enumerate(r.where) if w.get("package")]
    evidence = ([List.Item(id=f"pr{n}", title=link.rsplit("/", 2)[-2] + "/" + link.rsplit("/", 1)[-1], subtitle=link, link=link)
                 for n, link in enumerate(r.prs)]
                + [List.Item(id=f"t{n}", title=f"Thread {t.rsplit('/', 1)[-1]}", link=t) for n, t in enumerate(r.threads)]
                + [List.Item(id=f"k{n}", title=t, link=f"pointman://item/{t}") for n, t in enumerate(r.tasks)])
    history = [List.Item(id=f"h{n}", title=(f"{h['was'].replace('_', ' ')} → " if h.get("was") else "")
                         + str(h.get("status", "")).replace("_", " ")
                         + (f" ({h['justification'].replace('_', ' ')})" if h.get("justification") else ""),
                         subtitle=" · ".join(str(x) for x in [h.get("by") or (f"{h['by_said']} (said)" if h.get("by_said")
                                                                            else "someone (not said)"),
                                                              when(str(h.get("at"))), h.get("why"),
                                                              ", ".join(h.get("evidence") or [])] if x))
               for n, h in reversed(list(enumerate(r.history)))]
    blocks = [heading("h", r.advisory[0], f"{r.project} · {status}"),
              buttons("nav", (f"project:{r.project}", f"Back to {r.project}"), ("projects", "All projects")),
              Block(name="about", text=Text(markdown="\n\n".join(x for x in about if x))),
              heading("wh", "Where it hit", f"{len(where)} place{'s' if len(where) != 1 else ''}"),
              rows("where", where, tap=False) if where else empty("where", "No place named", "It was recorded by hand."),
              heading("eh", "Evidence", "PRs, threads and tasks"),
              rows("evidence", evidence, tap=False) if evidence else empty("evidence", "None yet",
                                                                           "fixed needs a PR, commit or release."),
              heading("hh", "History", "newest first"),
              rows("history", history, tap=False) if history else empty("history", "Before 0.8.0",
                                                                         "Changes are kept from 0.8.0 on.")]
    return r.advisory[0], blocks


def view(target: dict) -> tuple[str, list[Block]]:
    """What a target shows: the picker, a project, a record, or recent advisories."""
    v = str(target.get("view") or "projects")
    if v == "recent":
        return "Recent advisories", recent_blocks(ecosystem_of(target.get("ecosystem")), int(target.get("days") or 7))
    if v == "record" and target.get("path"):
        return record_blocks(str(target["path"]))
    if v in ("impacts", "project") and target.get("project"):
        return project_blocks(str(target["project"]).upper())
    return picker_blocks()


@ext.pane("cve")
def open_pane(pane):
    try:
        title, blocks = view(pane.target or {})
    except (ValueError, RuntimeError) as e:
        title, blocks = "CVE tracker", [empty("e", "Couldn't load it", str(e))]

    @pane.on_input
    def tapped(event):
        """Taps move between the views: a project, a record, back. Records change with /cve set."""
        f = event.fields or {}
        block, value = f.get("block"), str(f.get("value") or f.get("item") or "")
        if event.kind != "tap" or not value:
            raise Refused("the CVE pane only shows records: change one with /cve set")
        if block == "projects":
            target = {"view": "project", "project": value}
        elif block in ("open", "closed"):
            target = {"view": "record", "path": value}
        elif block == "nav" and value in ("projects", "recent"):
            target = {"view": value}
        elif block == "nav" and value.startswith("project:"):
            target = {"view": "project", "project": value.removeprefix("project:")}
        else:
            raise Refused("the CVE pane only shows records: change one with /cve set")
        title, blocks = view(target)
        pane.set_title(title)
        pane.show(blocks)

    return PaneOpenResponse(title=title, content=PaneContent(blocks=blocks))


if __name__ == "__main__":
    ext.run()
