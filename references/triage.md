# Triage, fix, confirm, mark: the detail

SKILL.md has the order. This is what each step means in practice, and where agents go wrong.

## Reading a scan

A scan's answer lists each project's `new`, `reopened`, `still`, `confirmed` and `gone`, fix-first. Each hit has
`kev` (in CISA's Known Exploited Vulnerabilities catalog), `epss` (FIRST's chance it's exploited in 30 days), `cvss`,
`severity` and `fixed` (the fix for that pinned version's own release line).

- **new:** a record was opened, `investigating`. Triage it.
- **reopened:** a record confirmed fixed has its version back. It's `affected` again. Find out why (a revert, a
  lockfile from an old branch, a second copy) before fixing it twice.
- **still:** a record marked fixed whose version is still at the ref. The fix isn't merged or released yet, or it
  went to another branch. Don't mark it again.
- **confirmed:** the version has gone from a repo after it was marked fixed. Nothing to do.
- **gone:** an open record whose version has gone. Someone fixed it without saying: find the PR or release and
  mark it fixed with it.

## Triage

Known exploited first, whatever the severity. Then EPSS, compared in whole points, then severity. For each, read
`cve.show <advisory>` and answer: is the package shipped (not a test, an example or a dev tool's lockfile), and
does our code reach the vulnerable part? Write what you found with `cve.set … note=…`, so the next agent doesn't
repeat it.

## One task per upgrade

`cve.plan {project}` gives one line per pinned package version: `from`, `to` (the lowest version past every
advisory on it), `fixes` and `unfixed`, and the lockfiles. One upgrade often fixes many advisories: open one task
for the upgrade, naming the advisories it fixes, not one per advisory. Check for an open task first. An advisory
in `unfixed` has no fix named yet: say so in the task, and look again at the next scan.

## Fix and release

Upgrade to the plan's `to` (or later, if that's what the lockfile resolves to), run the tests, open the PR, merge,
release as the repo does. The scan reads the project's ref (origin/main), so a fix only counts once it's there.

## Confirm, then mark

Run `cve.scan {project}` after the fix is on the ref. The hit should be gone. Then:

```
cve.set <advisory> <project> status=fixed pr=https://github.com/owner/repo/pull/12 by=@you note="rustls 0.23.46"
```

`commit=<link>` or `fixed_in=<release>` work too, and several advisories fixed by one upgrade take one call
(comma-separated). The next scan confirms each record per repo. If you mark fixed before the scan, the scan says
"still there" until the fix lands. That's fine, but it's no evidence. Never mark fixed because a fix exists
upstream, because it "should" be fixed, or because a PR is open.

## Not affected

Only when you can say why in a sentence someone can check. One of VEX's justifications, and a `note`:

| Justification | When | Example note |
|---|---|---|
| `component_not_present` | The package isn't in what we ship | "test fixture: only in tests/fixtures/Cargo.lock" |
| `vulnerable_code_not_present` | Our build leaves the vulnerable code out | "built without the `tls12` feature, where the bug is" |
| `vulnerable_code_not_in_execute_path` | It's there, but nothing of ours calls it | "we never call `AsyncFd::try_new`; only `tokio::fs`" |
| `vulnerable_code_cannot_be_controlled_by_adversary` | It runs, but only on input we control | "parses our own signed config, never user input" |
| `inline_mitigations_already_exist` | Something in front of it stops the attack | "the proxy caps headers at 8 KB, below the overflow" |

Unsure means it's affected: leave it open, or ask its owner. A dev or build tool that never ships is
`component_not_present` for the product, but say which tool it is. Don't use not_affected to quiet a finding
that's hard to fix: that's an open record with a task.
