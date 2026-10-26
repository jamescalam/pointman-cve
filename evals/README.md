# Evals

Does `SKILL.md` change how an agent handles a CVE finding? `run.py` runs real `claude -p` sessions with and
without it, against a fake finding: `fake_board.py` stands in for the board and the CVE tracker as an MCP server
(`create_job` runs `cve.scan`, `cve.plan`, `cve.show`, `cve.set` against one record and the repo's real lockfile,
with the real extension's refusals), and each run gets a small git repo. The skill goes after the wake prompt, as
the node adds a behaviour. Scoring is automatic: the calls the agent made, in order and with what the lockfile
pinned at each, and the repo after.

| Task | The finding | Right is |
|---|---|---|
| `fix` | rustls-webpki 0.103.15 in `Cargo.lock`, known exploited, fixed in 0.103.16 | one task for the upgrade; the upgrade committed; a scan after it; marked fixed with evidence, after that scan; never fixed before the upgrade |
| `fixture` | an old record whose only place is `tests/fixtures/Cargo.lock` | not_affected, `component_not_present`, with a note; never fixed; the fixture left as it is |

```bash
python evals/run.py --out ~/Documents/cvescan-jobs/evalruns/r1 --reps 3 --model sonnet
python evals/run.py --out ~/Documents/cvescan-jobs/evalruns/r1 --rescore     # score them again, running nothing
```

## Round c1 (2026-10-27, Sonnet, 6 runs each)

| Task | Without | With the first text | With 0.12.0's |
|---|---|---|---|
| `fix`, fully right | 3/6 (mean 0.64) | 6/6 | 6/6 |
| `fixture`, fully right | 4/6 (mean 0.79) | 5/6 (mean 0.83) | 6/6 |
| Cost per run | $0.08–0.09 | $0.09 | $0.08–0.10 |

- **Without it**, three of six `fix` runs upgraded the lockfile and stopped. They opened no task, ran no scan and
  didn't touch the record. Two of six `fixture` runs went wrong: one bumped the test data and marked the record
  fixed, and one chose `vulnerable_code_not_in_execute_path` for a file that's never built.
- **The first text** missed one `fixture` run: it went straight to the plan, opened a task and "fixed" the
  fixture, because its first step only gave the order. 0.12.0's first step asks whether the finding is ours
  (shipped, not test data, an example or a dev tool) before anything else, and step 6 names
  `component_not_present` for test data. Both tasks then went 6/6, the `fixture` ones in fewer turns (7–8, not 9–11).
- Six runs a cell is small, both tasks were written knowing the guidance, and the fake tracker is simpler than
  the real one: read these as a check that the guidance does what it says, not as a measure of how much.
