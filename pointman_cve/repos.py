"""The projects a scan reads (the `projects` setting): each a Pointman project's key, a repo on this machine and a
ref. A repo's lockfiles are read from git at the ref, after a fetch (`git show <commit>:<path>`), never from its
working tree, so an old or dirty checkout can't change what a scan finds. A folder that isn't in git is read as
files, and the scan says so."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from . import lockfiles
from .impacts import PROJECT

REF = "origin/main"
FETCH_FOR = 120          # seconds a fetch may take
GIT_FOR = 30             # and any other git command
REF_OK = re.compile(r"[A-Za-z0-9._/@{}^~-]{1,200}")
PR = re.compile(r"https://github\.com/[\w.-]+/[\w.-]+/pull/\d+")
GH_FOR = 20              # seconds `gh pr view` may take
GH_AT = ("/opt/homebrew/bin/gh", "/usr/local/bin/gh")      # where gh is when a node's PATH is launchd's short one


class GitFailed(Exception):
    pass


@dataclass
class Project:
    key: str                  # MB
    repo: str                 # as set: ~/Documents/message-board
    ref: str = REF
    skip: tuple[str, ...] = ()       # more paths that aren't the project's (globs, or folders), beside test data
    include: tuple[str, ...] = ()    # paths to read anyway
    name: str = ""                   # what people call it (Spark), for a scan's digest; its key if left out


@dataclass
class Read:
    """What a project's lockfiles pin, (ecosystem, name, version) → the lockfiles that pin it (paths in the repo)."""
    where: dict[tuple[str, str, str], list[str]] = field(default_factory=dict)
    files: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)   # lockfiles that aren't the project's: test data, `skip`
    name: str = ""            # the repo in its records: owner/repo, or ~/… for a folder without a remote
    ref: str = ""             # the ref read, and its commit: both empty for a folder read as files
    commit: str = ""
    note: str = ""            # what didn't go as asked: read as files, or the fetch failed


def from_settings(value) -> list[Project]:
    """The `projects` setting, checked: a ValueError says which one is wrong and how."""
    if not isinstance(value, list):
        raise ValueError("the projects setting is a list of {key, repo, ref}")
    out = []
    for n, p in enumerate(value, 1):
        if not isinstance(p, dict):
            raise ValueError(f"projects #{n} is {{key, repo, ref}}, not {p!r}")
        key, repo, ref = (str(p.get(k) or "").strip() for k in ("key", "repo", "ref"))
        if not PROJECT.match(key):
            raise ValueError(f"projects #{n}: key is a project's key, such as MB, not {key!r}")
        if not repo:
            raise ValueError(f"projects #{n} ({key}): repo is its folder under ~/Documents")
        ref = ref or REF
        if ref.startswith("-") or not REF_OK.fullmatch(ref):
            raise ValueError(f"projects #{n} ({key}): ref is a branch, tag or commit (origin/main), not {ref!r}")
        paths = {}
        for k in ("skip", "include"):
            given = p.get(k) or []
            if not isinstance(given, list) or not all(isinstance(x, str) for x in given):
                raise ValueError(f"projects #{n} ({key}): {k} is a list of paths in the repo (tests/data, *.lock)")
            paths[k] = tuple(x.strip() for x in given if x.strip())
        name = str(p.get("name") or "").strip()[:60]
        out.append(Project(key.upper(), repo, ref, **paths, name=name))
    return out


def pr_states(links: list[str]) -> dict[str, str]:
    """Each GitHub PR's state (OPEN, MERGED or CLOSED), as this machine's own `gh` sign-in reads it, a few at a time.
    One it can't say (no gh, not signed in, offline, not a PR link) is left out: a scan then goes by whether its
    advisories are still at the ref. It reads; it changes nothing. CVE_OFFLINE=1 asks nothing."""
    links = [x for x in dict.fromkeys(links) if PR.fullmatch(x)]
    gh = shutil.which("gh") or next((x for x in GH_AT if os.access(x, os.X_OK)), None)
    if not links or not gh or os.environ.get("CVE_OFFLINE") == "1":
        return {}

    def one(link: str) -> str | None:
        try:
            r = subprocess.run([gh, "pr", "view", link, "--json", "state"], capture_output=True, timeout=GH_FOR,
                               stdin=subprocess.DEVNULL, env={**os.environ, "GH_PROMPT_DISABLED": "1"})
            state = json.loads(r.stdout).get("state") if r.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired, ValueError, AttributeError):
            return None
        return state if state in ("OPEN", "MERGED", "CLOSED") else None

    with ThreadPoolExecutor(6) as pool:
        return {link: s for link, s in zip(links, pool.map(one, links), strict=True) if s}


def git(folder: Path, *args: str, timeout: float = GIT_FOR) -> str:
    """A git command's output in folder; GitFailed with git's last line of complaint. It never asks for a password."""
    try:
        r = subprocess.run(["git", "-C", str(folder), *args], capture_output=True, timeout=timeout,
                           stdin=subprocess.DEVNULL, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    except FileNotFoundError:
        raise GitFailed("git isn't installed on this machine") from None
    except subprocess.TimeoutExpired:
        raise GitFailed(f"git {args[0]} took more than {timeout:.0f} s") from None
    if r.returncode != 0:
        said = r.stderr.decode("utf-8", "replace").strip().splitlines()
        raise GitFailed(said[-1].removeprefix("fatal: ") if said else f"git {args[0]} failed")
    return r.stdout.decode("utf-8", "surrogateescape")


def home_path(folder: Path) -> str:
    """A folder as ~/… when it's under the home folder, so machines' records name it alike."""
    try:
        return "~/" + str(folder.relative_to(Path.home()))
    except ValueError:
        return str(folder)


def repo_name(url: str) -> str:
    """owner/repo from a remote's URL: git@github.com:pointman-ai/pointman.git, https://github.com/…"""
    parts = [p for p in re.split(r"[/:]", url.strip().removesuffix("/").removesuffix(".git")) if p]
    return "/".join(parts[-2:]) if len(parts) >= 2 else ""


def read(p: Project, folder: Path) -> Read:
    """The project's lockfiles at its ref, fetched first; a folder that isn't in git, as files."""
    try:
        prefix = git(folder, "rev-parse", "--show-prefix").strip()
    except GitFailed as e:
        why = "it isn't a git repo" if "not a git repository" in str(e) else str(e)
        return read_folder(folder, f"read as files, not from git: {why}", p.skip, p.include)
    remotes = git(folder, "remote").split()
    remote = p.ref.split("/", 1)[0] if p.ref.split("/", 1)[0] in remotes else ""
    note = ""
    if remotes:
        try:
            git(folder, "fetch", "--quiet", *([remote] if remote else []), timeout=FETCH_FOR)
        except GitFailed as e:
            note = f"couldn't fetch ({e}): read {p.ref} as last fetched"
    try:
        commit = git(folder, "rev-parse", "--verify", "--quiet", f"{p.ref}^{{commit}}").strip()
    except GitFailed:
        raise ValueError(f"{p.ref} isn't a branch, tag or commit in {p.repo}") from None
    try:
        url = git(folder, "remote", "get-url", remote or (remotes[0] if remotes else "origin")).strip()
    except GitFailed:
        url = ""
    got = Read(name=repo_name(url) or home_path(folder), ref=p.ref, commit=commit, note=note)
    for entry in git(folder, "ls-tree", "-r", "-z", "--full-name", commit).split("\0"):
        if not entry:
            continue
        meta, path = entry.split("\t", 1)
        mode, kind, _ = meta.split(" ", 2)
        said = lockfiles.verdict(path.removeprefix(prefix), p.skip, p.include) if kind == "blob" and mode != "120000" else ""
        if said == "skipped":
            got.skipped.append(path)
        if said != "read":
            continue
        got.files.append(path)
        for key in lockfiles.parse(path, git(folder, "show", f"{commit}:{path}")):
            got.where.setdefault(key, []).append(path)
    return got


def read_folder(folder: Path, note: str, skip=(), include=()) -> Read:
    got = Read(name=home_path(folder), note=note)
    skipped: list[Path] = []
    for lf in lockfiles.find(folder, skip, include, skipped):
        path = str(lf.relative_to(folder))
        got.files.append(path)
        for key in lockfiles.pinned(lf):
            got.where.setdefault(key, []).append(path)
    got.skipped = [str(x.relative_to(folder)) for x in skipped]
    return got
