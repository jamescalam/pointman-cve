# CVE tracker

Keep up with security advisories, and keep a shared record of the ones that touched your projects.

- **`/cve recent [ecosystem] [days]`** lists advisories published lately, newest first: `/cve recent rust 14`. They come from GitHub's advisory database, across ecosystems or one of them (rust, pip, go, npm and others).
- **`/cve scan [project]`** scans every project in the **Projects** setting, or the one named: it reads each repo's lockfiles from git at its ref and asks OSV.dev which of the pinned versions have advisories, in one batch. Each new hit opens an impact as investigating. The answer lists what's new, what's reopened (a fixed record hit again) and what's gone (an open record whose versions have left the ref), with each project's open count. Each hit says whether it's known to be exploited, its EPSS score and its CVSS score, and the lists come fix-first (see below). Its `fixed` is the fix for the pinned version's own release line: undici 7.30.0 is fixed in 7.30.1, even though the same advisory also names 6.29.1 for the 6.x line.
- **What it reads:** Cargo.lock, uv.lock, poetry.lock, `requirements*.txt` (and `.txt` files in a `requirements` folder: their `==` pins), go.sum, package-lock.json, pnpm-lock.yaml, yarn.lock (Yarn 1 and 2+), Gemfile.lock and composer.lock, up to 4 folders down, skipping dependency and build folders. It also skips the project's test data and other projects' code: lockfiles under a `tests`, `test`, `fixtures`, `testdata`, `examples` or `vendor` folder at any depth. Each answer says how many it skipped. It also reads the actions the repo's own workflows use (`.github/workflows/*.yml`). An action counts when pinned to a version tag, or to a commit with its tag in a comment (`@3d3c42e… # v7.0.1`). That comment is taken at its word: if it names the wrong tag, the answer is wrong too. A branch, such as `@main`, doesn't count. OSV doesn't compare Actions versions, so the extension checks each pinned tag against the advisory's ranges itself. A major tag such as `v4` counts as the newest release of v4.
- **`/cve plan <project>`** gives the upgrade plan at the project's refs. Each pinned package gets one line: its version now, the lowest version that fixes all its advisories (checked against each one's ranges), and how many that fixes, most first. It also names the advisories no upgrade fixes yet. It only reads and records nothing. Every scan's answer carries the same plan, and the pane's view of a project shows each repo's plan from its last scan.
- **`/cve vex <project>`** exports the project's records as an [OpenVEX](https://github.com/openvex/spec) 0.2.0 document, posted as a file. Each record is one statement:
  - the advisory, with its other ids as aliases;
  - each repo it was found in as a product (owner/repo as a GitHub purl), with the package versions it hits as purl subcomponents;
  - its status in VEX's words (`investigating` is `under_investigation`);
  - for a `not_affected` record, its justification and note; for an `affected` one, the upgrade to take; for a `fixed` one, its evidence.
  `author=` names who the document says made it.
- **`/cve check <folder> [project]`** does the same for one folder, read as it is on disk. Name a project and it opens an impact there for each one not yet recorded.
- **`/cve add <advisory> <project>`** records an advisory that touched a project. **`/cve set`** updates the record: its status, where it hit, and the PRs, threads and tasks that dealt with it.
- **`/cve show <advisory>`** shows an advisory and every project's record of it. **`/cve impacts [project]`** lists the records, the open ones first, fix-first.
- A pane in the app shows recent advisories, or your impacts with a count of each status.

Agents run the same commands with `create_job` (`cve.scan`, `cve.recent`, `cve.check`, `cve.add`…). `pointman cve …` on the command line acts as the person, so it asks them to approve it, and agents shouldn't use it.

## Your records

Each impact is a small file this extension keeps in your workspace, `impacts/<PROJECT>/<ADVISORY>.toml`. Every machine with the extension reads the same files, and every change is a new version, so the history is the audit trail. Nothing leaves your workspace, and there's no repo or account to set up.

```toml
advisory = ["emudhra-g3-distrust"]
title = "eMudhra G3 intermediates computable"
project = "MB"
status = "fixed"              # investigating | affected | not_affected | fixed
justification = ""            # VEX's, for not_affected: vulnerable_code_not_in_execute_path, …
severity = "medium"           # yours, beside the published one
fixed_in = "release 32"
prs = ["https://github.com/pointman-ai/pointman/commit/7f5769fa"]
threads = ["pointman://thread/17856"]
tasks = ["MB-588"]

[confirmed."pointman-ai/pointman"]   # a scan of that repo found the version gone after it was marked fixed
by = "cve scan on mac-m4 at origin/main (7f5769fa)"
ref = "origin/main"
commit = "7f5769fa…"
at = "2026-10-23T09:00:00Z"

[[where]]
repo = "pointman-ai/pointman"
file = "node/Cargo.lock"
package = "rustls-webpki"
version = "0.103.15"
fixed_version = "0.103.16"

[[history]]                   # one for each change, oldest first
at = "2026-10-22T10:02:11Z"
by_said = "@patchbay"         # who, as the caller said it (by = "…" once the node says who asked)
status = "fixed"
was = "affected"
why = "rustls-webpki 0.103.16 denylists them"
evidence = ["https://github.com/pointman-ai/pointman/commit/7f5769fa", "fixed in release 32"]
```

The statuses are VEX's (Vulnerability Exploitability eXchange), so the records can be turned into a standard report later.

**Not affected says why, as VEX does.** `not_affected` takes one of VEX's justifications (`component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`) and a `note` in your words, and is refused without both. Records written before 0.8.0 with the older short names are read as VEX's.

**Every change is kept.** Each `/cve add` and `/cve set`, and each record a scan opens, confirms or reopens, adds a `[[history]]` entry: when, who, the status it left and took, why, and its evidence. `/cve show` lists it. A command isn't told who asked yet, so for now "who" is the `by` its caller gives, kept as `by_said` and shown as "(said)". Once the node passes the asker, that's kept as `by` and `by` params are ignored. A scan's own changes are kept as `by`, naming the scan, its machine and its ref.

**Agents mark records; scans check them.** Marking a record `fixed` needs its evidence: `pr`, `commit` or `fixed_in` (`/cve set CVE-2026-1234 MB fixed pr=https://github.com/…`); without one, it's refused. Each scan then checks the fixed records it has a repo for:

- **Still there:** the version is still pinned at the ref, so the fix hasn't reached it yet. It's listed as still there and left as it is.
- **Confirmed:** the version has gone from that repo. The record is marked confirmed for it, once, with the scan, the ref, its commit and the time. A record found in several repos is confirmed once each of them is. One advisory found in another repo of the same project is the same record, which gains that repo's places.
- **Reopened:** the version is back in a repo that confirmed it gone. The record turns `affected` again, with a note. Its PRs stay, as its history.

An open record whose version has gone is listed as gone, and stays open until it's marked fixed with its evidence. Scans, `/cve check`, `/cve add` and `/cve set` run one at a time on a machine, so a scan never overwrites a change made while it runs.

## Projects

**Projects** is a list, one entry a project:

```json
[{"key": "MB", "repo": "~/Documents/message-board", "ref": "origin/main"}]
```

- **`key`** is the Pointman project the records go under.
- **`repo`** is its git folder under `~/Documents`. A scan fetches it first, lists its lockfiles at the ref and reads each one with `git show <ref>:<path>`. The working tree is never read, so an old or dirty checkout can't change the answer. A folder that isn't a git repo is read as files, and the answer says so.
- **`ref`** is a branch, tag or commit: `origin/main` if left out.
- **`skip`** (optional) names more paths that aren't the project's: a folder (`legacy`) or a glob (`docs/*/yarn.lock`).
- **`include`** (optional) names paths to read anyway, even under those folders (`examples/app`, for an example that ships). It wins over both.

A project that can't be read (its folder is missing, its ref unknown, or git fails) gets an `error` in the answer, and the others are still scanned. The answer and the event count these in `failed`. A scan is refused only when no project could be read.

Nothing runs on its own. A scan runs when someone asks for one, or when a workflow calls `cve.scan`. When it's done it sends the event `cve.scanned`, with the counts in all and for each project. A scan with nothing new still answers, so a workflow can branch on `new`.

## Fix first

Open records, and each scan's new and reopened hits, are sorted in this order:

1. **Known exploited:** in CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog.
2. **Likely to be exploited:** a higher [EPSS](https://www.first.org/epss) score, FIRST's estimate of the chance it's exploited in the next 30 days, compared in whole percentage points (0.05% against 0.03% is noise, so severity decides).
3. **Severity:** critical, high, medium, low, unknown.
4. **CVSS:** the higher base score.

Both lists are by CVE id, so an advisory with no CVE (many RUSTSEC ones) isn't in KEV and has no EPSS. Each is fetched at most twice a day. If one can't be reached, the answer says so and the order falls back to severity. In `/cve recent`, the CVSS score is GitHub's: its CVSS 3 score, or its 4.0 score when that's all there is. In scans, it's computed from OSV's CVSS 3.x vector, and a RUSTSEC or PYSEC advisory that names no severity gets one from that score. A CVSS 4.0 vector from OSV isn't scored, so its advisory's own severity stands.

The KEV catalog is CC0 and used as published; this extension isn't endorsed by CISA. EPSS scores are free to use, and FIRST asks for credit: answers that show them end with "EPSS scores: FIRST, https://www.first.org/epss".

## Permissions

- **Network:** GitHub's advisory database (60 requests an hour without signing in), OSV.dev, CISA's KEV feed and FIRST's EPSS API.
- It reads only lockfiles, and only under `~/Documents` (its `folders` permission, shown when it's added): a folder anywhere else is refused. It runs `git fetch`, `git ls-tree` and `git show` in the repos you list, and never changes their working trees or local branches.

## Developing

```sh
PYTHONPATH=.:tests python3 -m unittest discover -s tests
```

Set `POINTMAN_EXTENSIONS_SDK` to the node's Python SDK folder (one that speaks the typed protocol, with `pointman_extension_types.py`) to run the end-to-end tests too. They run the extension under the SDK's stand-in node, with a stand-in for the node's files, and never touch the network (`CVE_OFFLINE=1`, or `CVE_OSV_URL` pointing the scan tests at a stand-in OSV).

MIT licensed.
