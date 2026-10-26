"""Impacts: our record of an advisory that touched one of our projects. One file each, in the extension's
own files in the workspace (`impacts/<PROJECT>/<ADVISORY>.toml`), so every machine and app sees the same
record, and every change is a new version of it.

A status is one of VEX's: investigating, affected, not_affected (with one of VEX's justifications) or fixed. Every
change keeps a line of its history: when, by whom, the status it left and took, why, and its evidence.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from datetime import datetime, timezone

STATUSES = ("investigating", "affected", "not_affected", "fixed")
JUSTIFICATIONS = ("component_not_present", "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path",
                  "vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist")   # VEX's
WAS = {"not_present": "component_not_present", "not_reachable": "vulnerable_code_not_in_execute_path",
       "not_in_execute_path": "vulnerable_code_not_in_execute_path", "inline_mitigations": "inline_mitigations_already_exist",
       "protected": "vulnerable_code_cannot_be_controlled_by_adversary"}    # before 0.8.0: read as VEX's names
SEVERITIES = ("critical", "high", "medium", "low", "unknown")
PROJECT = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,15}$")


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def slug(advisory: str) -> str:
    """An advisory id as a file name, lowercased: extension files are paths of a-z 0-9 . _ - / (the record keeps
    the id as written)."""
    a = re.sub(r"[^a-z0-9._-]+", "-", advisory.strip().lower()).strip("-.")
    if not a:
        raise ValueError("an advisory id: CVE-…, GHSA-…, or a short name for one without")
    return a[:80]


def path_of(project: str, advisory: str) -> str:
    return f"impacts/{project.lower()}/{slug(advisory)}.toml"


@dataclass
class Impact:
    advisory: list[str]
    project: str
    title: str = ""
    status: str = "investigating"
    justification: str = ""
    severity: str = "unknown"
    found: str = field(default_factory=now)
    found_by: str = ""
    fixed: str = ""
    fixed_in: str = ""
    prs: list[str] = field(default_factory=list)
    threads: list[str] = field(default_factory=list)
    tasks: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    where: list[dict] = field(default_factory=list)   # {repo, file, package, version, fixed_version}
    confirmed: dict = field(default_factory=dict)     # fixed, and gone at a repo's ref: {repo: {by, ref, commit, at}}
    history: list[dict] = field(default_factory=list)  # each change: {at, by or by_said, status, was, why, evidence, …}

    def log(self, by: str, why: str = "", evidence: list[str] | None = None, was: str = "", said: bool = False) -> None:
        """A line of history for a change just made: when, who, the status taken (and the one left), why, evidence.
        `said`: who it was is only what the caller said (`by_said`), not what the node knows (`by`)."""
        entry = {"at": now(), "by_said" if said else "by": by, "status": self.status}
        if was and was != self.status:
            entry["was"] = was
        if self.status == "not_affected" and self.justification:
            entry["justification"] = self.justification
        if why:
            entry["why"] = why
        if evidence:
            entry["evidence"] = list(evidence)
        self.history.append(entry)

    @property
    def repos(self) -> set[str]:
        """The repos it was found in."""
        return {str(w["repo"]) for w in self.where if w.get("repo")}

    @property
    def confirmed_everywhere(self) -> bool:
        """Fixed, and a scan has found its version gone in every repo it was found in."""
        return bool(self.repos) and self.repos <= set(self.confirmed)

    @property
    def path(self) -> str:
        return path_of(self.project, self.advisory[0])

    def check(self) -> None:
        if not self.advisory or not self.advisory[0].strip():
            raise ValueError("an impact names its advisory")
        if not PROJECT.match(self.project):
            raise ValueError(f"project is a project's key, such as MB, not {self.project!r}")
        if self.status not in STATUSES:
            raise ValueError(f"status is one of {', '.join(STATUSES)}, not {self.status!r}")
        if self.justification and self.justification not in JUSTIFICATIONS:
            raise ValueError(f"justification is one of {', '.join(JUSTIFICATIONS)}")
        if self.status == "not_affected" and not self.justification:
            raise ValueError(f"not_affected says why: justification is one of {', '.join(JUSTIFICATIONS)}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"severity is one of {', '.join(SEVERITIES)}")
        for link in self.prs:
            if not link.startswith("https://"):
                raise ValueError(f"a PR is its https:// link, not {link!r}")
        for t in self.threads:
            if not (t.startswith("pointman://thread/") or t.isdigit()):
                raise ValueError(f"a thread is pointman://thread/<n> or its number, not {t!r}")

    def to_toml(self) -> str:
        lines = []
        for key in ("advisory", "title", "project", "status", "justification", "severity", "found", "found_by",
                    "fixed", "fixed_in", "prs", "threads", "tasks", "notes"):
            lines.append(f"{key} = {value(getattr(self, key))}")
        for repo, c in self.confirmed.items():
            lines += ["", f"[confirmed.{value(repo)}]"] + [f"{k} = {value(v)}" for k, v in c.items() if v not in (None, "")]
        for w in self.where:
            lines += ["", "[[where]]"] + [f"{k} = {value(v)}" for k, v in w.items() if v not in (None, "")]
        for h in self.history:
            lines += ["", "[[history]]"] + [f"{k} = {value(v)}" for k, v in h.items() if v not in (None, "", [])]
        return "\n".join(lines) + "\n"

    @classmethod
    def from_toml(cls, text: str) -> Impact:
        d = tomllib.loads(text)
        names = set(cls.__dataclass_fields__)
        kept = {k: v for k, v in d.items() if k in names}
        if isinstance(kept.get("advisory"), str):
            kept["advisory"] = [kept["advisory"]]
        if kept.get("justification") in WAS:
            kept["justification"] = WAS[kept["justification"]]
        return cls(**kept)


def value(v) -> str:
    """A TOML value: a string or a list of them."""
    if isinstance(v, list):
        return "[" + ", ".join(value(x) for x in v) + "]"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\t", "\\t")
    return f'"{s}"'


def thread_link(t: str) -> str:
    t = t.strip()
    return f"pointman://thread/{t}" if t.isdigit() else t
