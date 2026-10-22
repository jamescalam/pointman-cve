"""The package versions a folder's lockfiles pin, by ecosystem (GitHub's names): Cargo.lock (rust), uv.lock and
poetry.lock (pip), go.sum (go) and package-lock.json (npm). Only packages from a registry: a path, a git
checkout or the project itself has no advisories."""

from __future__ import annotations

import json
import os
import tomllib
from pathlib import Path

SKIP = {".git", "node_modules", "target", ".venv", "venv", "vendor", "__pycache__", "dist", "build", ".cache"}
DEPTH = 4


def find(root: Path) -> list[Path]:
    """The lockfiles under root, at most DEPTH folders down, skipping build and dependency folders."""
    out: list[Path] = []
    root = Path(root)
    base = len(root.parts)
    for d, dirs, files in os.walk(root):
        dirs[:] = sorted(x for x in dirs if x not in SKIP and not x.startswith("."))
        if len(Path(d).parts) - base >= DEPTH:
            dirs[:] = []
        for f in sorted(files):
            if f in ("Cargo.lock", "uv.lock", "poetry.lock", "go.sum", "package-lock.json"):
                out.append(Path(d) / f)
    return out


def pinned(path: Path) -> list[tuple[str, str, str]]:
    """(ecosystem, name, version) for each registry package the lockfile pins."""
    name = path.name
    text = path.read_text(encoding="utf-8", errors="replace")
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
    return sorted(out)
