"""Our impacts, kept as the extension's own files in the workspace through its node (`files.put`, `files.list`,
`files.get`: Pointman's EXT-62, as their typed messages). Every machine with the extension reads the same files,
and every change is a new version.

CVE_FILES_DIR (tests only) keeps them in a folder instead, a version a file.
"""

from __future__ import annotations

import os
import re
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .impacts import Impact, path_of

NEEDS_NODE = ("this node can't keep an extension's files yet (files.put, list and get): it needs the "
              "Pointman release that brings them")


# a call core or the node dropped (core slow, the stream reconnecting): asked again, after these waits (seconds)
DROPPED = ("didn't answer", "timed out", "timeout", "lost", "connection reset", "unavailable")
AGAIN_AFTER = (1.0, 3.0)
READERS = 6                 # records read at once: each read is a round trip to core


def dropped(why: str) -> bool:
    why = why.lower()
    return any(d in why for d in DROPPED)


# a path as the node and core take one: relative, at most 200 characters of a-z 0-9 . _ - /, with no ..
PATH = re.compile(r"[a-z0-9._/-]{1,200}")


def path_ok(path: str) -> bool:
    return bool(PATH.fullmatch(path)) and not path.startswith("/") and ".." not in path


class Store:
    """The node's files, asked with the SDK's request messages (pointman_extension_types, which only the node's SDK
    has: imported when one is made, so the rest of this module runs without it)."""

    def __init__(self, request: Callable):
        import pointman_extension_types as types
        self.types = types
        self.request = request

    def _call(self, message):
        for wait in (*AGAIN_AFTER, None):
            try:
                return self.request(message)
            except RuntimeError as e:
                if "no method" in str(e) or "unknown method" in str(e):
                    raise RuntimeError(NEEDS_NODE) from None
                if wait is None or not dropped(str(e)):
                    raise
                time.sleep(wait)

    def put(self, path: str, text: str) -> int:
        return self._call(self.types.FilesPutRequest(path=path, text=text)).version

    def list(self, prefix: str) -> list[dict]:
        return [{"path": f.path, "version": f.version}
                for f in self._call(self.types.FilesListRequest(prefix=prefix)).files]

    def get(self, path: str) -> str | None:
        try:
            got = self._call(self.types.FilesGetRequest(path=path)).file
        except RuntimeError as e:
            if "no file" in str(e):
                return None
            raise
        return got.text if got else None


class DirStore(Store):
    """A folder for tests: `<path>@<version>` files, the newest version read back."""

    def __init__(self, root: str | Path):
        self.root = Path(root)

    def _versions(self, path: str) -> list[Path]:
        d = (self.root / path).parent
        if not d.is_dir():
            return []
        name = Path(path).name
        found = [p for p in d.iterdir() if p.name.startswith(name + "@")]
        return sorted(found, key=lambda p: int(p.name.rsplit("@", 1)[1]))

    def put(self, path: str, text: str) -> int:
        if not path_ok(path):                       # refused as the node refuses it
            raise RuntimeError("path: relative, at most 200 characters of a-z 0-9 . _ - /, with no ..")
        version = len(self._versions(path)) + 1
        target = self.root / f"{path}@{version}"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        return version

    def list(self, prefix: str) -> list[dict]:
        out = {}
        for p in self.root.rglob("*@*"):
            rel = str(p.relative_to(self.root)).rsplit("@", 1)[0]
            if rel.startswith(prefix):
                out[rel] = max(out.get(rel, 0), int(p.name.rsplit("@", 1)[1]))
        return [{"path": k, "version": v} for k, v in sorted(out.items())]

    def get(self, path: str) -> str | None:
        versions = self._versions(path)
        return versions[-1].read_text(encoding="utf-8") if versions else None


def store_for(request: Callable) -> Store:
    folder = os.environ.get("CVE_FILES_DIR")
    return DirStore(folder) if folder else Store(request)


class Book:
    """Every impact we've recorded."""

    def __init__(self, store: Store):
        self.store = store

    def load(self, project: str, advisory: str) -> Impact | None:
        text = self.store.get(path_of(project, advisory))
        return Impact.from_toml(text) if text else None

    def save(self, impact: Impact) -> int:
        impact.check()
        return self.store.put(impact.path, impact.to_toml())

    def all(self, project: str | None = None) -> list[Impact]:
        """Every record, or a project's: read a few at a time, in the order they're listed."""
        prefix = f"impacts/{project.lower()}/" if project else "impacts/"
        paths = [f["path"] for f in self.store.list(prefix)]
        with ThreadPoolExecutor(max_workers=READERS) as pool:
            texts = list(pool.map(self.store.get, paths))
        out = []
        for text in texts:
            if text:
                try:
                    out.append(Impact.from_toml(text))
                except (ValueError, TypeError):
                    continue
        return out

    def for_advisory(self, ids: list[str]) -> list[Impact]:
        wanted = {i.upper() for i in ids}
        return [i for i in self.all() if wanted & {a.upper() for a in i.advisory}]
