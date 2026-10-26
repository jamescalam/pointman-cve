# CVE tracker

Keep up with security advisories, and keep a shared record of the ones that touched your projects.

- **`/cve recent [ecosystem] [days]`** lists advisories published lately, newest first: `/cve recent rust 14`. They come from GitHub's advisory database, across ecosystems or one of them (rust, pip, go, npm and others).
- **`/cve scan [project]`** scans every project in the **Projects** setting, or the one named: it reads each repo's lockfiles (Cargo.lock, uv.lock, poetry.lock, go.sum, package-lock.json) from git at its ref and asks OSV.dev which of the pinned versions have advisories, in one batch. Each new hit opens an impact as investigating. The answer lists what's new, what's reopened (a fixed record hit again) and what's gone (an open record whose versions have left the ref), with each project's open count.
- **`/cve check <folder> [project]`** does the same for one folder, read as it is on disk. Name a project and it opens an impact there for each one not yet recorded.
- **`/cve add <advisory> <project>`** records an advisory that touched a project. **`/cve set`** updates the record: its status, where it hit, and the PRs, threads and tasks that dealt with it.
- **`/cve show <advisory>`** shows an advisory and every project's record of it. **`/cve impacts [project]`** lists the records.
- A pane in the app shows recent advisories, or your impacts with a count of each status.

Agents run the same commands with `create_job` (`cve.scan`, `cve.recent`, `cve.check`, `cve.add`…). `pointman cve …` on the command line acts as the person, so it asks them to approve it, and agents shouldn't use it.

## Your records

Each impact is a small file this extension keeps in your workspace, `impacts/<PROJECT>/<ADVISORY>.toml`. Every machine with the extension reads the same files, and every change is a new version, so the history is the audit trail. Nothing leaves your workspace, and there's no repo or account to set up.

```toml
advisory = ["emudhra-g3-distrust"]
title = "eMudhra G3 intermediates computable"
project = "MB"
status = "fixed"              # investigating | affected | not_affected | fixed
justification = ""            # why it's not_affected: not_present, not_reachable, not_in_execute_path, …
severity = "medium"           # yours, beside the published one
fixed_in = "release 32"
prs = ["https://github.com/pointman-ai/pointman/commit/7f5769fa"]
threads = ["pointman://thread/17856"]
tasks = ["MB-588"]

[[where]]
file = "node/Cargo.lock"
package = "rustls-webpki"
version = "0.103.15"
fixed_version = "0.103.16"
```

The statuses are VEX's (Vulnerability Exploitability eXchange), so the records can be turned into a standard report later.

## Projects

**Projects** is a list, one entry a project:

```json
[{"key": "MB", "repo": "~/Documents/message-board", "ref": "origin/main"}]
```

- **`key`** is the Pointman project the records go under.
- **`repo`** is its git folder under `~/Documents`. A scan fetches it first, lists its lockfiles at the ref and reads each one with `git show <ref>:<path>`. The working tree is never read, so an old or dirty checkout can't change the answer. A folder that isn't a git repo is read as files, and the answer says so.
- **`ref`** is a branch, tag or commit: `origin/main` if left out.

A project that can't be read (its folder is missing, its ref unknown, or git fails) gets an `error` in the answer, and the others are still scanned. The answer and the event count these in `failed`. A scan is refused only when no project could be read.

Nothing runs on its own. A scan runs when someone asks for one, or when a workflow calls `cve.scan`. When it's done it sends the event `cve.scanned`, with the counts in all and for each project. A scan with nothing new still answers, so a workflow can branch on `new`.

## Permissions

- **Network:** GitHub's advisory database (60 requests an hour without signing in) and OSV.dev.
- It reads only lockfiles, and only under `~/Documents` (its `folders` permission, shown when it's added): a folder anywhere else is refused. It runs `git fetch`, `git ls-tree` and `git show` in the repos you list, and never changes their working trees or local branches.

## Developing

```sh
PYTHONPATH=.:tests python3 -m unittest discover -s tests
```

Set `POINTMAN_EXTENSIONS_SDK` to the node's Python SDK folder (one that speaks the typed protocol, with `pointman_extension_types.py`) to run the end-to-end tests too. They run the extension under the SDK's stand-in node, with a stand-in for the node's files, and never touch the network (`CVE_OFFLINE=1`, or `CVE_OSV_URL` pointing the scan tests at a stand-in OSV).

MIT licensed.
