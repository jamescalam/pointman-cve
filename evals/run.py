"""Does SKILL.md change how an agent handles a CVE finding? Real `claude -p` runs, with and without it, against a
fake finding: a stand-in board and CVE tracker (fake_board.py, an MCP server) and a small git repo. Scored
automatically from the calls the agent made (in order, with what the lockfile pinned at each), and the repo after.

- fix       a known-exploited rustls-webpki 0.103.15 in Cargo.lock: open one task for the upgrade, upgrade and
            commit, scan to confirm, then mark fixed with evidence, never before the upgrade
- fixture   an old record whose only place is tests/fixtures/Cargo.lock: not_affected with
            component_not_present and a note, never fixed, the fixture left as it is

    python evals/run.py --out ~/Documents/cvescan-jobs/evalruns --reps 2 --model sonnet
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CLAUDE = shutil.which("claude") or "claude"
LOCK = '''version = 4

[[package]]
name = "app"
version = "0.1.0"
dependencies = ["rustls-webpki"]

[[package]]
name = "rustls-webpki"
version = "{v}"
source = "registry+https://github.com/rust-lang/crates.io-index"
'''
TOML = '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nrustls-webpki = "0.103"\n'
SUMMARY = "rustls-webpki accepts a certificate chain it should reject"
WAKE = """You are @fixer, a Claude Code agent on Pointman, a forum where people and their agents work. You were woken \
by this post in the thread "CVE findings" (#security):

{post}

Your folder is APP's repo. It has no remote: commit on main, and the commit is its release. Pointman's tools \
(create_job, create_task, list_tasks) are your MCP server's. The CVE tracker's commands run with create_job on \
machine mac-m4. Do what the post asks, then end with a short report of what you did."""
TASKS = {
    "fix": {"places": ["Cargo.lock"], "files": {"Cargo.toml": TOML, "Cargo.lock": LOCK.format(v="0.103.15"),
                                                 "src/main.rs": "fn main() {}\n"},
            "post": "@fixer cve.scan of APP at origin/main: 1 new.\n- new: **CVE-2026-9999** (high 7.5, known exploited, "
                    "EPSS 42%) rust rustls-webpki 0.103.15, fixed in 0.103.16 (Cargo.lock)\nPlease handle it."},
    "fixture": {"places": ["tests/fixtures/Cargo.lock"],
                "files": {"Cargo.toml": TOML.replace('rustls-webpki = "0.103"', 'rustls-webpki = "0.103.16"'),
                          "Cargo.lock": LOCK.format(v="0.103.16"), "src/main.rs": "fn main() {}\n",
                          "tests/fixtures/Cargo.lock": LOCK.format(v="0.103.15"),
                          "tests/lockfiles.rs": "// reads tests/fixtures/Cargo.lock to test our lockfile parser\n"},
                "post": "@fixer CVE-2026-9999 is still open in APP as investigating: rust rustls-webpki 0.103.15 in "
                        "tests/fixtures/Cargo.lock. Please handle it."},
}


def git(repo: Path, *args: str) -> str:
    env = {**os.environ, "GIT_AUTHOR_NAME": "james", "GIT_AUTHOR_EMAIL": "james@eval.invalid",
           "GIT_COMMITTER_NAME": "james", "GIT_COMMITTER_EMAIL": "james@eval.invalid", "GIT_CONFIG_GLOBAL": os.devnull}
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env).stdout


def setup(run: Path, task: str) -> Path:
    t = TASKS[task]
    repo = run / "repo"
    for path, text in t["files"].items():
        (repo / path).parent.mkdir(parents=True, exist_ok=True)
        (repo / path).write_text(text)
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "APP")
    (run / "state.json").write_text(json.dumps({"record": {"status": "investigating"}, "places": t["places"],
                                                "summary": SUMMARY, "calls": [], "tasks": []}))
    (run / "mcp.json").write_text(json.dumps({"mcpServers": {"pointman": {
        "command": sys.executable, "args": [str(HERE / "fake_board.py"), str(run)]}}}))
    return repo


def prompt(task: str, with_skill: bool) -> str:
    text = WAKE.format(post=TASKS[task]["post"])
    if with_skill:                                   # as the node adds a behaviour: its body after the wake prompt
        body = (ROOT / "SKILL.md").read_text().split("---", 2)[2].strip()
        text += (f"\n\n(This behaviour's files are in {ROOT}; paths in it are relative to that folder.)\n\n{body}")
    return text


def sets(calls: list, status: str) -> list:
    return [c for c in calls if c.get("kind") == "cve.set" and str(c["params"].get("status")) == status]


def score(task: str, run: Path) -> dict:
    s = json.loads((run / "state.json").read_text())
    calls, repo = s["calls"], run / "repo"
    lock = lambda c, f: c["pinned"].get(f)                                                  # noqa: E731
    if task == "fix":
        upgraded = [c["n"] for c in calls if lock(c, "Cargo.lock") == "0.103.16"]
        scans_after = [c["n"] for c in calls if c.get("kind") == "cve.scan" and lock(c, "Cargo.lock") == "0.103.16"]
        fixed_ok = [c["n"] for c in sets(calls, "fixed") if c["ok"]]
        committed = ('"0.103.16"' in git(repo, "show", "HEAD:Cargo.lock")
                     and not git(repo, "status", "--porcelain", "--", "Cargo.lock").strip())      # cargo's target/ aside
        tasks = [t for t in s["tasks"] if "rustls" in (t["title"] + t["body"]).lower()]
        return {"one task for the upgrade": len(tasks) == 1 and len(s["tasks"]) == 1,
                "upgraded and committed": committed,
                "scanned after the upgrade": bool(scans_after),
                "marked fixed with evidence": bool(fixed_ok),
                "marked only after a confirming scan": bool(fixed_ok) and bool(scans_after) and fixed_ok[0] > scans_after[0],
                "never fixed before the upgrade": not any(lock(c, "Cargo.lock") == "0.103.15" for c in sets(calls, "fixed")),
                "upgrade before marking": bool(upgraded) and (not fixed_ok or upgraded[0] < fixed_ok[0])}
    na = [c for c in sets(calls, "not_affected") if c["ok"]]
    return {"not affected, component_not_present": any(c["params"].get("justification") == "component_not_present" for c in na),
            "with a note": any(str(c["params"].get("note") or "").strip() for c in na),
            "never fixed": not sets(calls, "fixed"),
            "fixture left as it is": '"0.103.15"' in (repo / "tests/fixtures/Cargo.lock").read_text()}


def trial(out: Path, task: str, with_skill: bool, rep: int, model: str) -> dict:
    run = out / f"{task}-{'with' if with_skill else 'without'}-{rep}"
    if run.exists():
        shutil.rmtree(run)
    repo = setup(run, task)
    cmd = [CLAUDE, "-p", prompt(task, with_skill), "--output-format", "json", "--model", model,
           "--permission-mode", "auto", "--max-budget-usd", "1", "--strict-mcp-config", "--mcp-config",
           str(run / "mcp.json"), "--add-dir", str(ROOT)]
    t0 = time.monotonic()
    proc = subprocess.run(cmd, cwd=repo, capture_output=True, text=True, timeout=600)
    (run / "stdout.json").write_text(proc.stdout)
    (run / "stderr.txt").write_text(proc.stderr)
    try:
        answer = json.loads(proc.stdout)
    except ValueError:
        answer = {}
    checks = score(task, run)
    return {"task": task, "skill": with_skill, "rep": rep, "score": round(sum(checks.values()) / len(checks), 3),
            "checks": checks, "cost": answer.get("total_cost_usd"), "turns": answer.get("num_turns"),
            "wall_s": round(time.monotonic() - t0), "report": str(answer.get("result") or "")[-600:]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--tasks", nargs="+", default=list(TASKS))
    ap.add_argument("--reps", type=int, default=2)
    ap.add_argument("--model", default="sonnet")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--only", choices=["with", "without"])
    ap.add_argument("--rescore", action="store_true", help="score the runs already in --out again, running nothing")
    args = ap.parse_args()
    out = Path(args.out).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    if args.rescore:
        for run in sorted(p for p in out.iterdir() if (p / "state.json").exists()):
            task, skill, rep = run.name.rsplit("-", 2)
            checks = score(task, run)
            print(f"{task:8} {skill:8} {rep} score {sum(checks.values()) / len(checks):.2f}  "
                  + " ".join(k for k, v in checks.items() if not v))
        return
    plan = [(t, w, r) for t in args.tasks for w in (False, True) if args.only in (None, "with" if w else "without")
            for r in range(args.reps)]
    with ThreadPoolExecutor(args.jobs) as pool:
        results = list(pool.map(lambda x: trial(out, *x, args.model), plan))
    with (out / "results.jsonl").open("a") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")
    for r in results:
        print(f"{r['task']:8} {'with' if r['skill'] else 'without':8} {r['rep']} score {r['score']:.2f} "
              f"${r['cost'] or 0:.3f} {r['turns']} turns  " + " ".join(k for k, v in r["checks"].items() if not v))


if __name__ == "__main__":
    main()
