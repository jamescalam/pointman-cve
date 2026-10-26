"""The projects a scan reads (the `projects` setting): each a Pointman project's key, a repo on this machine and a
ref. A repo's lockfiles are read from git at the ref, after a fetch (`git show <commit>:<path>`), never from its
working tree, so an old or dirty checkout can't change what a scan finds. A folder that isn't in git is read as
files, and the scan says so."""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from . import lockfiles
from .impacts import PROJECT

REF = "origin/main"
FETCH_FOR = 120          # seconds a fetch may take
GIT_FOR = 30             # and any other git command
REF_OK = re.compile(r"[A-Za-z0-9._/@{}^~-]{1,200}")


class GitFailed(Exception):
    pass


@dataclass
class Project:
    key: str                  # MB
    repo: str                 # as set: ~/Documents/message-board
    ref: str = REF


@dataclass
class Read:
    """What a project's lockfiles pin, (ecosystem, name, version) → the lockfiles that pin it (paths in the repo)."""
    where: dict[tuple[str, str, str], list[str]] = field(default_factory=dict)
    files: list[str] = field(default_factory=list)
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
        out.append(Project(key.upper(), repo, ref))
    return out


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
        return read_folder(folder, f"read as files, not from git: {why}")
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
        if kind != "blob" or mode == "120000" or not lockfiles.wanted(path.removeprefix(prefix)):
            continue
        got.files.append(path)
        for key in lockfiles.parse(path, git(folder, "show", f"{commit}:{path}")):
            got.where.setdefault(key, []).append(path)
    return got


def read_folder(folder: Path, note: str) -> Read:
    got = Read(name=home_path(folder), note=note)
    for lf in lockfiles.find(folder):
        path = str(lf.relative_to(folder))
        got.files.append(path)
        for key in lockfiles.pinned(lf):
            got.where.setdefault(key, []).append(path)
    return got
