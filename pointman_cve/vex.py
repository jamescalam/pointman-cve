"""A project's records as an OpenVEX document (https://github.com/openvex/spec, v0.2.0): one statement a record,
saying what the advisory means for each repo it was found in. The statuses and justifications are VEX's
already; investigating is VEX's under_investigation.

- **vulnerability:** the advisory, its other ids as aliases.
- **products:** each repo it was found in (owner/repo as a GitHub purl, a folder as a urn), with the packages it
  hits as subcomponents, by purl; a record that names no repo is about the project itself.
- **status**, with a not_affected one's justification and its note (impact_statement), an affected one's
  action (the upgrade to take: action_statement, which VEX requires), and the latest why (status_notes).
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse

from .impacts import Impact

CONTEXT = "https://openvex.dev/ns/v0.2.0"
STATUS = {"investigating": "under_investigation", "affected": "affected", "not_affected": "not_affected",
          "fixed": "fixed"}
PURL = {"rust": "cargo", "pip": "pypi", "npm": "npm", "go": "golang", "rubygems": "gem", "composer": "composer",
        "actions": "github", "maven": "maven", "nuget": "nuget"}


def purl(ecosystem: str, name: str, version: str) -> str:
    """A package's purl: pkg:cargo/rustls@0.23.45, pkg:npm/%40scope/pkg@1.0.0, pkg:pypi/pyyaml@6.0.3."""
    kind = PURL.get(ecosystem, "generic")
    if kind == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()
    if kind == "maven":
        name = name.replace(":", "/")
    parts = [urllib.parse.quote(p, safe="") for p in name.split("/")]
    out = f"pkg:{kind}/" + "/".join(parts)
    return out + (f"@{urllib.parse.quote(version, safe='.-_~')}" if version else "")


def product_id(repo: str, project: str) -> str:
    """A repo as VEX's product: owner/repo as a GitHub purl, anything else (a folder) as a urn of the project."""
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo or ""):
        return f"pkg:github/{repo}"
    tail = urllib.parse.quote((repo or "").strip("~/"), safe="/")
    return f"urn:pointman:cve:{project.lower()}" + (f":{tail}" if tail else "")


def products(r: Impact) -> list[dict]:
    """Each repo the record was found in, with the package versions it hits there."""
    by_repo: dict[str, list[str]] = {}
    for w in r.where:
        if not w.get("package"):
            continue
        ids = by_repo.setdefault(product_id(str(w.get("repo") or ""), r.project), [])
        p = purl(str(w.get("ecosystem") or ""), str(w["package"]), str(w.get("version") or ""))
        if p not in ids:
            ids.append(p)
    if not by_repo:
        return [{"@id": product_id("", r.project)}]
    return [{"@id": pid, **({"subcomponents": [{"@id": p, "identifiers": {"purl": p}} for p in subs]} if subs else {})}
            for pid, subs in sorted(by_repo.items())]


def latest(r: Impact, key: str) -> str:
    return next((str(h[key]) for h in reversed(r.history) if h.get(key)), "")


def action(r: Impact) -> str:
    """What to do about an affected record: the upgrades its places name, or that no fix is named yet."""
    ups = sorted({f"{w['package']} {w.get('version')} to {w['fixed_version']}" for w in r.where
                  if w.get("package") and w.get("fixed_version")})
    return ("Upgrade " + "; ".join(ups) + ".") if ups else "No fixed version is named yet: the record stays open."


def statement(r: Impact) -> dict:
    out: dict = {"vulnerability": {"name": r.advisory[0], **({"aliases": list(dict.fromkeys(r.advisory[1:]))}
                                                              if r.advisory[1:] else {})},
                 "timestamp": latest(r, "at") or r.found, "products": products(r), "status": STATUS[r.status]}
    why = latest(r, "why") or (r.notes[-1] if r.notes else "")
    if r.status == "not_affected":
        out["justification"] = r.justification
        if why:
            out["impact_statement"] = why
    elif r.status == "affected":
        out["action_statement"] = action(r)
    notes = why if r.status in ("investigating", "affected") else ""
    if r.status == "fixed":                               # with its evidence: the PRs and the release
        notes = "; ".join(x for x in (why, ", ".join([*r.prs] + ([f"fixed in {r.fixed_in}"] if r.fixed_in else []))) if x)
    if notes:
        out["status_notes"] = notes
    return out


def document(project: str, records: list[Impact], author: str, tooling: str, timestamp: str) -> dict:
    """The OpenVEX document: its @id the hash of what it says, as vexctl names one."""
    statements = [statement(r) for r in sorted(records, key=lambda r: r.advisory[0])]
    digest = hashlib.sha256(json.dumps(statements, sort_keys=True).encode()).hexdigest()
    return {"@context": CONTEXT, "@id": f"https://openvex.dev/docs/public/vex-{digest}", "author": author,
            "timestamp": timestamp, "version": 1, "tooling": tooling, "statements": statements}
