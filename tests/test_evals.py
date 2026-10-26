"""The eval's own parts, with no agent run: its fake tracker answers as the extension does, and its scores give
the right sequence full marks and the failures seen in round c1 none."""

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evals"))
import fake_board  # noqa: E402
import run  # noqa: E402

LOCK = "tests/fixtures/Cargo.lock"


class EvalTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)

    def task(self, name: str, n: int = 0) -> Path:
        r = self.dir / f"{name}-{n}"
        run.setup(r, name)
        fake_board.RUN, fake_board.STATE = r, r / "state.json"
        return r

    def job(self, kind: str, **params) -> tuple[str, bool]:
        return fake_board.call("create_job", {"kind": kind, "params": {"extension": params}})

    def test_the_right_fix_scores_full_and_a_guess_doesn_t(self):
        r = self.task("fix")
        self.assertIn("Refused: fixed needs its evidence", self.job("cve.set", advisory="CVE-2026-9999", status="fixed")[0])
        fake_board.call("create_task", {"project": "APP", "title": "Upgrade rustls-webpki to 0.103.16"})
        (r / "repo" / "Cargo.lock").write_text(run.LOCK.format(v="0.103.16"))
        run.git(r / "repo", "commit", "-qam", "upgrade")
        self.assertIn("Gone from this ref but still open", self.job("cve.scan", project="APP")[0])
        self.assertEqual(self.job("cve.set", advisory="CVE-2026-9999", status="fixed", commit="abc")[1], False)
        checks = run.score("fix", r)
        self.assertEqual([k for k, v in checks.items() if not v], ["never fixed before the upgrade"])   # the guess

    def test_stopping_at_the_upgrade_scores_low(self):
        r = self.task("fix")
        (r / "repo" / "Cargo.lock").write_text(run.LOCK.format(v="0.103.16"))
        run.git(r / "repo", "commit", "-qam", "upgrade")
        (r / "repo" / "target").mkdir()                                     # cargo's, untracked: not held against it
        checks = run.score("fix", r)
        self.assertTrue(checks["upgraded and committed"])
        self.assertEqual(sum(checks.values()), 2)

    def test_a_fixture_is_not_affected_and_fixing_it_fails(self):
        r = self.task("fixture")
        self.assertIn("needs VEX's justification", self.job("cve.set", status="not_affected", justification="not_reachable")[0])
        self.job("cve.set", status="not_affected", justification="component_not_present", note="test fixture")
        self.assertEqual(run.score("fixture", r), dict.fromkeys(run.score("fixture", r), True))
        r = self.task("fixture", 1)
        (r / "repo" / LOCK).write_text(run.LOCK.format(v="0.103.16"))
        self.job("cve.set", status="fixed", commit="abc")
        self.assertEqual(sum(run.score("fixture", r).values()), 0)

    def test_the_skill_goes_after_the_wake_prompt(self):
        with_it, without = run.prompt("fix", True), run.prompt("fix", False)
        self.assertTrue(with_it.startswith(without))
        self.assertIn("First check it's ours", with_it)
        self.assertNotIn("name: cve", with_it)                              # the body, not its frontmatter
        self.assertEqual(json.loads((self.task("fix") / "mcp.json").read_text())["mcpServers"]["pointman"]["args"][0],
                         str(run.HERE / "fake_board.py"))
