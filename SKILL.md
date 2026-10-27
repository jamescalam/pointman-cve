---
name: cve
description: Handle the CVE tracker's findings (cve.scan, cve.plan, cve.show, cve.set): triage fix-first, one task per upgrade, fix and release, confirm with a scan, then mark records with evidence. Use for a scan's new or reopened advisories, or a CVE record to triage or close.
---

# CVE findings

For agents handling the CVE tracker's findings or records. Skip it otherwise. Its commands run with `create_job` (`cve.scan`, `cve.plan`, `cve.show`, `cve.set`); pass `by` (your handle) to `cve.set`.

1. **Triage fix-first:** known exploited, then EPSS, then severity, as a scan lists them. First check it's ours: shipped (not test data, an example or a dev tool) and reachable. If not, go to 6.
2. **One task per upgrade:** `cve.plan {project}` gives a line a package (from, to, what it fixes). Open a task for each, unless one is open.
3. **Fix and release** as any change: the plan's version, tests, merge, release. Record each PR on its advisories as soon as it's open (`cve.set pr=`, no status), and `cve.report` gives the person who merges them a page of every PR and what it fixes.
4. **Confirm:** `cve.scan {project}` once the fix is on the ref. "Still there" means it isn't yet.
5. **Mark with evidence:** `status=fixed` with `pr=`, `commit=` or `fixed_in=`. Never fixed on a guess.
6. **Not affected** only once you've shown why: VEX's justification (`component_not_present` for test data) and a note. Unsure means affected, or ask.

Read `references/triage.md` before marking a record not_affected, and for a reopened one.
