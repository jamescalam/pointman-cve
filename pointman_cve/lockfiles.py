"""The package versions a project's lockfiles pin, by ecosystem (GitHub's names): Cargo.lock (rust), uv.lock,
poetry.lock and requirements*.txt (pip), go.sum (go), package-lock.json, pnpm-lock.yaml and yarn.lock (npm),
Gemfile.lock (rubygems), composer.lock (composer), and the actions a repo's own workflows use (actions). Only
packages from a registry: a path, a git checkout, a workspace or the project itself has no advisories. The same
files count in a folder and in a git tree."""

from __future__ import annotations

import fnmatch
import json
import os
import re
import tomllib
import urllib.parse
from pathlib import Path

NAMES = ("Cargo.lock", "uv.lock", "poetry.lock", "go.sum", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
         "Gemfile.lock", "composer.lock")
SKIP = {".git", "node_modules", "target", ".venv", "venv", "__pycache__", "dist", "build", ".cache"}   # never walked
NOT_OURS = {"tests", "test", "fixtures", "testdata", "examples", "vendor"}   # a project's test data, others' code
DEPTH = 4
WORKFLOWS = (".github", "workflows")       # only the repo's own, at its root: where GitHub runs them from

PINNED = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([0-9][^\s;,\\#]*)")   # name[extra]==1.2
GEM = re.compile(r"    ([^\s(]+) \(([^)]+)\)")                    # a spec in a GEM section, 4 spaces in
YARN_FIELD = re.compile(r'  (version|resolved) "?([^"\s]+)"?\s*$')
BERRY = re.compile(r'^  resolution: "(@?[^@"]+)@npm:([^"]+)"', re.M)
USES = re.compile(r"""^\s*(?:-\s*)?uses:\s*["']?([^"'\s#]+)["']?\s*(?:#\s*(\S+))?""")
SHA = re.compile(r"[0-9a-f]{40}")
TAG = re.compile(r"v?\d")
PNPM5 = re.compile(r"(@?[^@/]+(?:/[^@/]+)?)/(\d[^/_]*)(?:_.*)?")     # @scope/name/1.2.3_peer@1


def skipped(folder: str) -> bool:
    return folder in SKIP or folder.startswith(".")


def kind(path: str) -> str | None:
    """Which lockfile a path is, by its name: one of NAMES, `requirements.txt` (requirements*.txt, or any .txt in a
    `requirements` folder), `workflow` (a .yml in .github/workflows), or None."""
    parts = path.replace(os.sep, "/").split("/")
    name = parts[-1]
    if name in NAMES:
        return name
    if name.endswith(".txt") and (name.startswith("requirements") or parts[-2:-1] == ["requirements"]):
        return "requirements.txt"
    if tuple(parts[-3:-1]) == WORKFLOWS and name.endswith((".yml", ".yaml")):
        return "workflow"
    return None


def matches(path: str, patterns) -> bool:
    """Whether a path is one a pattern names: a glob (`legacy/*/Cargo.lock`), or a folder or file (`docs/site`)."""
    return any(fnmatch.fnmatchcase(path, p) or path == p.strip("/") or path.startswith(p.strip("/") + "/")
               for p in patterns if p.strip("/"))


def verdict(path: str, skip=(), include=()) -> str:
    """What becomes of a path in a tree (`node/Cargo.lock`): "read"; "skipped", a lockfile that isn't the project's
    own (under a tests, test, fixtures, testdata, examples or vendor folder at any depth, or one `skip` names),
    unless `include` names it; or "" when it's no lockfile of ours (or too deep, or in a build folder)."""
    *folders, _ = path.split("/")
    k = kind(path)
    if k == "workflow":
        return "read" if tuple(folders) == WORKFLOWS else ""
    if k is None or len(folders) > DEPTH or any(skipped(f) for f in folders):
        return ""
    if matches(path, include):
        return "read"
    if any(f.lower() in NOT_OURS for f in folders) or matches(path, skip):
        return "skipped"
    return "read"


def wanted(path: str, skip=(), include=()) -> bool:
    """Whether a path in a tree is a lockfile find() would read in a folder."""
    return verdict(path, skip, include) == "read"


def find(root: Path, skip=(), include=(), skipped_out: list | None = None) -> list[Path]:
    """The lockfiles under root, at most DEPTH folders down, and its own workflows, but not build and dependency
    folders, and not test data (verdict); those it skips go in skipped_out."""
    root = Path(root)
    out: list[Path] = sorted(p for p in root.joinpath(*WORKFLOWS).glob("*") if p.is_file() and wanted(
        "/".join([*WORKFLOWS, p.name])))
    base = len(root.parts)
    for d, dirs, files in os.walk(root):
        dirs[:] = sorted(x for x in dirs if not skipped(x))
        if len(Path(d).parts) - base >= DEPTH:
            dirs[:] = []
        for f in sorted(files):
            said = verdict(str((Path(d) / f).relative_to(root)).replace(os.sep, "/"), skip, include)
            if said == "read":
                out.append(Path(d) / f)
            elif said == "skipped" and skipped_out is not None:
                skipped_out.append(Path(d) / f)
    return out


def pinned(path: Path) -> list[tuple[str, str, str]]:
    """(ecosystem, name, version) for each registry package the lockfile pins."""
    return parse(str(path), path.read_text(encoding="utf-8", errors="replace"))


def parse(path: str, text: str) -> list[tuple[str, str, str]]:
    """pinned() of a lockfile's text, by its path (its name, and its folders for requirements and workflows)."""
    name = kind(path)
    out: set[tuple[str, str, str]] = set()
    if name == "Cargo.lock":
        for p in tomllib.loads(text).get("package", []):
            if str(p.get("source", "")).startswith("registry+"):
                out.add(("rust", p["name"], p["version"]))
    elif name in ("uv.lock", "poetry.lock"):
        for p in tomllib.loads(text).get("package", []):
            src = p.get("source") or {}
            if name == "uv.lock" and not (isinstance(src, dict) and "registry" in src):
                continue
            if p.get("name") and p.get("version"):
                out.add(("pip", p["name"], p["version"]))
    elif name == "go.sum":
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                version = parts[1].removesuffix("/go.mod").removesuffix("+incompatible")
                out.add(("go", parts[0], version))
    elif name == "package-lock.json":
        for key, p in (json.loads(text).get("packages") or {}).items():
            if key.startswith("node_modules/") and isinstance(p, dict) and p.get("version") and not p.get("link"):
                out.add(("npm", key.rsplit("node_modules/", 1)[1], p["version"]))
    elif name == "pnpm-lock.yaml":
        out |= pnpm(text)
    elif name == "yarn.lock":
        out |= yarn(text)
    elif name == "requirements.txt":
        for line in text.splitlines():
            m = PINNED.match(line.strip())
            if m and "*" not in m[2]:
                out.add(("pip", re.sub(r"[-_.]+", "-", m[1]).lower(), m[2]))
    elif name == "Gemfile.lock":
        section = ""
        for line in text.splitlines():
            if line[:1].strip():
                section = line.strip()
            elif section == "GEM" and (m := GEM.fullmatch(line)):
                out.add(("rubygems", m[1], m[2].split("-", 1)[0]))      # 1.17.1-arm64-darwin: a platform's build
    elif name == "composer.lock":
        d = json.loads(text)
        for p in (d.get("packages") or []) + (d.get("packages-dev") or []):
            version = str(p.get("version") or "")
            if p.get("name") and TAG.match(version) and (p.get("dist") or {}).get("type") != "path":
                out.add(("composer", p["name"], version))
    elif name == "workflow":
        out |= actions(text)
    return sorted(out)


def pnpm(text: str) -> set[tuple[str, str, str]]:
    """Each `packages:` key, in every document of the file: `name@1.2.3` (v9), `/name@1.2.3(peer@1)` (v6), or
    `/name/1.2.3_peer@1` (v5). A version that isn't a number is a link, file or tarball."""
    out, section = set(), ""
    for line in text.splitlines():
        if line[:1].strip():
            section = line.rstrip()[:-1] if line.rstrip().endswith(":") else ""
            continue
        if section != "packages" or not re.match(r"  \S", line) or not line.rstrip().endswith(":"):
            continue
        key = line.strip()[:-1].strip("'\"").lstrip("/").split("(", 1)[0]
        if m := PNPM5.fullmatch(key):
            name, version = m[1], m[2]
        else:
            at = key.rfind("@")
            name, version = (key[:at], key[at + 1:]) if at > 0 else ("", "")
        if name and version[:1].isdigit():
            out.add(("npm", name, version))
    return out


def yarn(text: str) -> set[tuple[str, str, str]]:
    """Yarn 2+ (Berry): each `npm:` resolution. Yarn 1: each entry's version, named by its registry URL (an alias
    such as string-width-cjs is its real package's); one resolved anywhere else is a git or file dependency."""
    if "\n__metadata:" in text or text.startswith("__metadata:"):
        return {("npm", m[1], m[2].split("::", 1)[0]) for m in BERRY.finditer(text)}
    out = set()
    for entry in re.split(r"\n(?=[^\s#])", text):
        head, *lines = entry.splitlines()
        if not head.rstrip().endswith(":") or head.startswith("#"):
            continue
        fields = {m[1]: m[2] for line in lines if (m := YARN_FIELD.match(line))}
        version, resolved = fields.get("version", ""), fields.get("resolved")
        if resolved is not None:
            if "/-/" not in resolved:
                continue
            name = urllib.parse.unquote(urllib.parse.urlsplit(resolved).path.split("/-/", 1)[0].lstrip("/"))
        else:
            first = head.split(",", 1)[0].strip().strip('"')
            if ":" in first[:-1]:                    # npm:, file:, link:, git: … aren't the registry's name
                continue
            name = first[:first.rfind("@")] if first.rfind("@") > 0 else ""
        if name and version[:1].isdigit():
            out.add(("npm", name, version))
    return out


def actions(text: str) -> set[tuple[str, str, str]]:
    """Each `uses: owner/repo[/path]@ref` with a version tag (v4, v4.1.0), as its owner/repo. A commit pin counts by
    the tag in its comment (`@3d3c42e… # v7.0.1`); a branch, a local action or a docker image doesn't count."""
    out = set()
    for line in text.splitlines():
        m = USES.match(line)
        if not m or m[1].startswith(("./", "docker://")) or "@" not in m[1]:
            continue
        target, _, ref = m[1].rpartition("@")
        parts = target.split("/")
        version = (m[2] or "") if SHA.fullmatch(ref) else ref
        if len(parts) >= 2 and all(parts[:2]) and TAG.match(version):
            out.add(("actions", "/".join(parts[:2]), version))
    return out
