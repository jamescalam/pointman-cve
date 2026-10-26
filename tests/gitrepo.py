"""A project's git repo for the scan tests: an origin, and a checkout of it that's behind and dirty.

- `v1` (a tag, and origin/main as the checkout last fetched it): node/Cargo.lock pins rustls-webpki 0.103.15, which
  the stand-in OSV says has an advisory.
- origin/main, pushed after the checkout was made: rustls-webpki 0.103.16, which hasn't.
- The checkout's working tree: Cargo.lock edited to 0.103.99 and an uncommitted uv.lock, neither of which a scan
  may read.
"""

import os
import shutil
import subprocess
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
QUIET = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "t",
         "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}


def git(folder: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(folder), *args], check=True, capture_output=True, text=True,
                          env={**os.environ, **QUIET}).stdout.strip()


def cargo_lock(version: str) -> str:
    return (FIXTURES / "Cargo.lock").read_text().replace('version = "0.103.15"', f'version = "{version}"')


class Repo:
    def __init__(self, root: Path):
        root.mkdir(parents=True, exist_ok=True)
        self.origin, self.writer, self.checkout = root / "origin.git", root / "writer", root / "checkout"
        subprocess.run(["git", "init", "--quiet", "--bare", "-b", "main", str(self.origin)], check=True,
                       env={**os.environ, **QUIET})
        subprocess.run(["git", "clone", "--quiet", str(self.origin), str(self.writer)], check=True,
                       capture_output=True, env={**os.environ, **QUIET})
        git(self.writer, "checkout", "--quiet", "-b", "main")
        self.v1 = self.commit({"node/Cargo.lock": cargo_lock("0.103.15"), "README.md": "app\n"}, "v1")
        git(self.writer, "tag", "v1")
        git(self.writer, "push", "--quiet", "origin", "main", "v1")
        subprocess.run(["git", "clone", "--quiet", str(self.origin), str(self.checkout)], check=True,
                       capture_output=True, env={**os.environ, **QUIET})
        self.v2 = self.commit({"node/Cargo.lock": cargo_lock("0.103.16")}, "rustls-webpki 0.103.16")
        git(self.writer, "push", "--quiet", "origin", "main")
        (self.checkout / "node" / "Cargo.lock").write_text(cargo_lock("0.103.99"))
        shutil.copy(FIXTURES / "uv.lock", self.checkout / "uv.lock")

    def commit(self, files: dict[str, str], message: str) -> str:
        for path, text in files.items():
            (self.writer / path).parent.mkdir(parents=True, exist_ok=True)
            (self.writer / path).write_text(text)
        git(self.writer, "add", "-A")
        git(self.writer, "commit", "--quiet", "-m", message)
        return git(self.writer, "rev-parse", "HEAD")
