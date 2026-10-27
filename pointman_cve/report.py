"""The fix report: every open record that a PR fixes, grouped by project and PR, as one HTML page for the person who
reviews and merges them (a Spacesheep page's shape: the answer first, four numbers, a section a project, the detail
folded, and what wasn't checked last). It reads the records; it changes nothing.
"""

from __future__ import annotations

import re
from html import escape

from .impacts import Impact
from .scans import OPEN, RANK, percent

PACKAGES_SHOWN = 2          # a PR's packages named in its table row; the rest are "+N more"


def osv(advisory: str) -> str:
    return f"https://osv.dev/vulnerability/{advisory}"


def pr_name(link: str) -> str:
    """A PR's link as people say it: owner/repo#12 (a commit's: owner/repo@abc1234)."""
    m = re.match(r"https://github\.com/([^/]+/[^/]+)/pull/(\d+)", link)
    if m:
        return f"{m[1]}#{m[2]}"
    m = re.match(r"https://github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7})", link)
    return f"{m[1]}@{m[2]}" if m else link


def upgrades(r: Impact) -> list[str]:
    """Its packages as `name from → to`, as the scan found them."""
    out = []
    for w in r.where:
        if w.get("package"):
            to = w.get("fixed_version") or ""
            out.append(f"{w['package']} {w.get('version') or ''}".strip() + (f" → {to}" if to else ""))
    return list(dict.fromkeys(out))


def pr_link(link: str) -> str:
    """A PR as a link, only when it's an https:// one (records come from agents): anything else as plain text."""
    name = escape(pr_name(link))
    return f'<a href="{escape(link)}">{name}</a>' if link.startswith("https://") else name


def worst(records: list[Impact]) -> str:
    return min((r.severity for r in records), key=lambda s: RANK.get(s, 9), default="unknown")


def build(records: list[Impact], signals: dict[str, tuple], when: str, projects: list[str] | None = None) -> dict:
    """The report's data: each project's open records, those with a PR grouped by it (a record with two PRs is under
    both), and those without one. `signals` is each record's (known exploited, EPSS) by its path."""
    open_ = [r for r in records if r.status in OPEN and (not projects or r.project in projects)]
    keys = projects or sorted({r.project for r in open_})
    out = []
    for key in keys:
        mine = sorted((r for r in open_ if r.project == key), key=lambda r: rank(r, signals))
        by_pr: dict[str, list[Impact]] = {}
        for r in mine:
            for link in r.prs:
                by_pr.setdefault(link, []).append(r)
        prs = sorted(by_pr.items(), key=lambda kv: (-sum(1 for r in kv[1] if signals.get(r.path, (None,))[0]),
                                                   RANK.get(worst(kv[1]), 9), -len(kv[1]), kv[0]))
        out.append({"project": key, "open": len(mine),
                    "prs": [{"pr": link, "advisories": [r.advisory[0] for r in rs]} for link, rs in prs],
                    "fixed_by_prs": sum(1 for r in mine if r.prs),
                    "without_pr": [r.advisory[0] for r in mine if not r.prs],
                    "_records": mine, "_by_pr": prs})
    covered = [r for p in out for r in p["_records"] if r.prs]
    return {"when": when, "projects": out,
            "prs": len({link for p in out for link, _ in p["_by_pr"]}),
            "open": sum(p["open"] for p in out), "fixed_by_prs": len(covered),
            "kev": sum(1 for r in covered if signals.get(r.path, (None,))[0]),
            "without_pr": sum(len(p["without_pr"]) for p in out)}


def rank(r: Impact, signals: dict[str, tuple]) -> tuple:
    kev, epss = signals.get(r.path, (None, None))
    return (not kev, -(epss or 0.0), RANK.get(r.severity, 9), r.advisory[0])


def flags(r: Impact, signals: dict[str, tuple]) -> str:
    kev, epss = signals.get(r.path, (None, None))
    return ", ".join(x for x in [r.severity if r.severity != "unknown" else "",
                                 "known exploited" if kev else "",
                                 f"EPSS {percent(epss)}" if epss is not None else ""] if x)


def text(data: dict) -> str:
    lines = [f"Fix report, {data['when'][:16].replace('T', ' ')} UTC: {data['prs']} PRs fix {data['fixed_by_prs']} "
             f"of {data['open']} open advisories ({data['kev']} known exploited); {data['without_pr']} have no PR yet."]
    for p in data["projects"]:
        lines.append(f"- {p['project']}: {len(p['prs'])} PRs fix {p['fixed_by_prs']} of {p['open']} open")
    return "\n".join(lines)


def html(data: dict, signals: dict[str, tuple], title: str = "") -> str:
    """The page, self-contained."""
    names = ", ".join(p["project"] for p in data["projects"]) or "no projects"
    title = title or f"Security fixes ready for review: {data['prs']} pull requests"
    lead = (f"{data['prs']} pull requests fix {data['fixed_by_prs']} of the {data['open']} open advisories in "
            f"{escape(names)}. Review and merge each one; the next scan marks its advisories fixed.")
    if data["kev"]:
        lead += f" {data['kev']} are known to be exploited, so their PRs come first."
    kpis = [(data["prs"], "", "Pull requests to review"),
            (data["fixed_by_prs"], f"of {data['open']}", "Open advisories they fix"),
            (data["kev"], "", "Known exploited among them"),
            (data["without_pr"], "", "Open with no PR yet")]
    parts = [HEAD.replace("{title}", escape(title)), "<main>\n<header>",
             f'<p class="kicker">Security · fixes for review · <time datetime="{escape(data["when"])}">'
             f'{escape(data["when"][:16].replace("T", " "))} UTC</time></p>',
             f"<h1>{escape(title)}</h1>", f'<p class="lead">{lead}</p>', '<div class="kpis">']
    parts += [f'<div class="kpi"><div class="v">{v}' + (f" <small>{escape(s)}</small>" if s else "")
              + f'</div><div class="l">{escape(label)}</div></div>' for v, s, label in kpis]
    parts += ["</div>", "</header>"]
    for p in data["projects"]:
        parts += project_section(p, signals)
    parts += ['<section>', "<h2>After you merge, the next scan confirms each fix</h2>",
              "<p>Nothing is marked fixed until its PR is merged and a scan finds the old version gone.</p>",
              '<ol class="steps">',
              "<li><b>Review and merge</b><span>Each PR above, in its repo.</span></li>",
              "<li><b>Next scan</b><span>Finds the old versions gone at main.</span></li>",
              "<li><b>Marked fixed</b><span>Each advisory, with its PR as evidence.</span></li>",
              "</ol>", "</section>",
              '<section>', "<h2>Not checked</h2>", '<ul class="plain">',
              "<li>Each PR's own checks: see them on GitHub.</li>",
              f"<li>Changes since the records were read, at {escape(data['when'][:16].replace('T', ' '))} UTC.</li>",
              "<li>Whether each project reaches the vulnerable code: every open advisory is treated as affecting it.</li>",
              "</ul>", "</section>",
              '<details class="sources"><summary>Sources</summary><ul class="plain">',
              '<li>Advisories: <a href="https://osv.dev">OSV.dev</a> and the GitHub advisory database.</li>',
              '<li>Known exploited: <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA KEV</a>.</li>',
              '<li>EPSS scores: <a href="https://www.first.org/epss">FIRST</a>.</li>',
              "</ul></details>", "</main>", "</body>", "</html>"]
    return "\n".join(parts) + "\n"


def project_section(p: dict, signals: dict[str, tuple]) -> list[str]:
    key, by_pr = p["project"], p["_by_pr"]
    out = ["<section>", f"<h2>{escape(key)}: {len(by_pr)} PRs fix {p['fixed_by_prs']} of {p['open']} open</h2>"]
    if not by_pr:
        out += ["<p>No PR yet for any of its open advisories.</p>"]
    else:
        out += ["<p>Known exploited first, then the most severe. Each row is one PR to review.</p>",
                '<div class="scroll-x">', "<table>",
                "<thead><tr><th>Pull request</th><th>Fixes</th><th>Worst</th><th>Exploited</th><th>Upgrades</th></tr></thead>",
                "<tbody>"]
        for link, rs in by_pr:
            kev = sum(1 for r in rs if signals.get(r.path, (None,))[0])
            ups = list(dict.fromkeys(u for r in rs for u in upgrades(r)))
            shown = ", ".join(ups[:PACKAGES_SHOWN]) + (f" +{len(ups) - PACKAGES_SHOWN} more" if len(ups) > PACKAGES_SHOWN else "")
            out.append(f'<tr><th scope="row">{pr_link(link)}</th>'
                       f'<td class="num">{len(rs)}</td><td>{escape(worst(rs))}</td>'
                       + (f'<td class="down">{kev} known</td>' if kev else "<td>none</td>")
                       + f"<td>{escape(shown)}</td></tr>")
        out += ["</tbody>", "</table>", "</div>",
                f'<details class="all-notes"><summary>Every advisory {escape(key)}\'s PRs fix</summary>']
        for link, rs in by_pr:
            out.append(f'<p>{pr_link(link)}</p><ul class="plain">')
            out += [f'<li><a href="{escape(osv(r.advisory[0]))}">{escape(r.advisory[0])}</a> {escape(flags(r, signals))}'
                    f" · {escape(', '.join(upgrades(r)[:2]))}</li>" for r in rs]
            out.append("</ul>")
        out.append("</details>")
    left = [r for r in p["_records"] if not r.prs]
    if left:
        out += [f"<h3>{len(left)} open with no PR yet</h3>", '<ul class="plain">']
        out += [f'<li><a href="{escape(osv(r.advisory[0]))}">{escape(r.advisory[0])}</a> {escape(flags(r, signals))}'
                f" · {escape(', '.join(upgrades(r)[:2]) or 'no package named')}"
                + ("" if any(w.get("fixed_version") for w in r.where) else " · no fixed version yet") + "</li>"
                for r in left]
        out.append("</ul>")
    out.append("</section>")
    return out


HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root{--bg:#fff;--ink:#1b1b22;--ink2:#46464f;--muted:#6a6a73;--line:#e3e3e8;--acc:#2563eb;--acc-soft:#e6efff;
--link:#1c5cab;--bad:#fbe3e1;--bad-ink:#a3261a}
@media (prefers-color-scheme: dark){:root{--bg:#121317;--ink:#e8e9ee;--ink2:#c2c4cc;--muted:#9a9ca6;--line:#2c2e36;
--acc:#7aa7ff;--acc-soft:#1f2a44;--link:#8db4ff;--bad:#3a1d1b;--bad-ink:#f19a8f}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:17px/1.6 ui-sans-serif,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
main{max-width:980px;margin:0 auto;padding:0 32px 80px}
header{padding:40px 0 4px}
.kicker{font-size:14px;letter-spacing:.04em;text-transform:uppercase;color:var(--muted);margin:0 0 8px}
h1{font-size:40px;line-height:1.15;margin:0 0 12px;letter-spacing:-.01em}
h2{font-size:27px;line-height:1.25;margin:52px 0 8px}
h3{font-size:19px;margin:28px 0 6px}
p{margin:0 0 12px}
.lead{font-size:20px;color:var(--ink2);max-width:760px}
a{color:var(--link)}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:20px 0 8px}
.kpi{border:1px solid var(--line);border-radius:8px;padding:14px 16px}
.kpi .v{font-size:30px;font-weight:700;line-height:1.1}
.kpi .v small{font-size:17px;font-weight:500;color:var(--muted)}
.kpi .l{font-size:14px;color:var(--ink2);margin-top:4px}
.scroll-x{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:15px}
th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
thead th{font-size:13px;letter-spacing:.04em;text-transform:uppercase;color:var(--muted);font-weight:650}
td.num{text-align:right;font-variant-numeric:tabular-nums}
td.down{background:var(--bad);color:var(--bad-ink);font-weight:650}
ol.steps{list-style:none;padding:0;margin:12px 0;display:grid;gap:10px;counter-reset:s}
ol.steps li{display:grid;grid-template-columns:34px 170px 1fr;gap:12px;align-items:baseline;border:1px solid var(--line);border-radius:8px;padding:10px 14px;counter-increment:s}
ol.steps li::before{content:counter(s);display:grid;place-items:center;width:26px;height:26px;border-radius:50%;background:var(--acc-soft);color:var(--acc);font-weight:700}
ol.steps b{font-weight:650}
.all-notes{margin-top:10px;font-size:15px}
.all-notes summary,.sources summary{cursor:pointer;min-height:44px;display:flex;align-items:center}
summary::before{content:"\\25B8";width:1.2em;color:var(--muted)}
details[open]>summary::before{content:"\\25BE"}
ul.plain{padding-left:20px;margin:6px 0}
ul.plain li{margin:4px 0}
.sources{margin-top:52px;font-size:15px;color:var(--ink2)}
.sources summary{font-weight:650;color:var(--ink)}
@media (max-width:640px){main{padding:0 18px 60px}h1{font-size:30px}h2{font-size:23px;margin-top:40px}
.lead{font-size:18px}.kpis{grid-template-columns:repeat(2,1fr)}ol.steps li{grid-template-columns:34px 1fr}
ol.steps li span{grid-column:2}}
</style>
</head>
<body>"""
