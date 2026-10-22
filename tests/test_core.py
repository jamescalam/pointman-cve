import json
import shutil
import tempfile
import unittest
from pathlib import Path

from pointman_cve import lockfiles
from pointman_cve.feeds import Feeds, from_github, from_osv
from pointman_cve.impacts import Impact, path_of, slug
from pointman_cve.store import Book, DirStore

FIXTURES = Path(__file__).parent / "fixtures"


class ImpactTests(unittest.TestCase):
    def emudhra(self) -> Impact:
        return Impact(advisory=["emudhra-g3-distrust"], project="MB", title="eMudhra G3 intermediates computable",
                      status="fixed", severity="medium", fixed_in="release 32",
                      prs=["https://github.com/pointman-ai/pointman/commit/7f5769fa"],
                      threads=["pointman://thread/17856"], tasks=["MB-588", "MB-589"],
                      notes=['2026-10-22: rustls-webpki "0.103.16" denylists them'],
                      where=[{"repo": "pointman-ai/pointman", "file": "node/Cargo.lock", "package": "rustls-webpki",
                              "version": "0.103.15", "fixed_version": "0.103.16"}])

    def test_a_record_round_trips_through_its_file(self):
        imp = self.emudhra()
        imp.check()
        text = imp.to_toml()
        self.assertIn('status = "fixed"', text)
        self.assertIn("[[where]]", text)
        self.assertEqual(Impact.from_toml(text), imp)
        self.assertEqual(imp.path, "impacts/MB/emudhra-g3-distrust.toml")

    def test_paths_from_advisory_ids(self):
        self.assertEqual(path_of("mb", "cve-2026-1234"), "impacts/MB/CVE-2026-1234.toml")
        self.assertEqual(slug("GHSA-cw65-gx24-rc82"), "GHSA-cw65-gx24-rc82")
        self.assertEqual(slug("../../etc/passwd"), "etc-passwd")
        with self.assertRaises(ValueError):
            slug("///")

    def test_checks(self):
        for change, says in [({"status": "done"}, "status"), ({"project": "my project"}, "project"),
                             ({"status": "not_affected"}, "says why"), ({"prs": ["#42"]}, "https"),
                             ({"threads": ["general"]}, "thread"), ({"severity": "huge"}, "severity")]:
            imp = self.emudhra()
            for k, v in change.items():
                setattr(imp, k, v)
            with self.assertRaises(ValueError) as e:
                imp.check()
            self.assertIn(says, str(e.exception))
        ok = self.emudhra()
        ok.status, ok.justification = "not_affected", "not_reachable"
        ok.check()


class LockfileTests(unittest.TestCase):
    def test_registry_packages_only(self):
        self.assertEqual(lockfiles.pinned(FIXTURES / "Cargo.lock"), [("rust", "rustls-webpki", "0.103.15")])
        self.assertEqual(lockfiles.pinned(FIXTURES / "uv.lock"), [("pip", "litellm", "1.107.0")])
        self.assertEqual(lockfiles.pinned(FIXTURES / "go.sum"),
                         [("go", "github.com/a/b", "v1.2.3"), ("go", "golang.org/x/net", "v0.17.0")])
        self.assertEqual(lockfiles.pinned(FIXTURES / "package-lock.json"),
                         [("npm", "@scope/pkg", "1.0.0"), ("npm", "lodash", "4.17.20")])

    def test_finding_them_skips_dependency_folders(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "node").mkdir()
            shutil.copy(FIXTURES / "Cargo.lock", root / "node")
            (root / "node_modules" / "x").mkdir(parents=True)
            shutil.copy(FIXTURES / "package-lock.json", root / "node_modules" / "x")
            (root / "a" / "b" / "c" / "d" / "e").mkdir(parents=True)
            shutil.copy(FIXTURES / "uv.lock", root / "a" / "b" / "c" / "d" / "e")
            self.assertEqual([p.relative_to(root) for p in lockfiles.find(root)], [Path("node/Cargo.lock")])


GITHUB_ADVISORY = {"ghsa_id": "GHSA-cw65-gx24-rc82", "cve_id": "CVE-2026-113716", "type": "reviewed",
                   "summary": "virtualenv: builtin creation follows linked environment directories",
                   "severity": "medium", "published_at": "2026-10-21T21:35:56Z",
                   "html_url": "https://github.com/advisories/GHSA-cw65-gx24-rc82", "cvss": {"score": 5.5},
                   "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "virtualenv"},
                                        "vulnerable_version_range": "< 20.36.0", "first_patched_version": "20.36.0"}]}
OSV_VULN = {"id": "GHSA-xxxx-yyyy-zzzz", "aliases": ["CVE-2026-9999"], "summary": "rustls-webpki trusts a bad CA",
            "published": "2026-10-21T00:00:00Z", "database_specific": {"severity": "MODERATE"},
            "affected": [{"package": {"ecosystem": "crates.io", "name": "rustls-webpki"},
                          "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.103.16"}]}]}]}


class FeedTests(unittest.TestCase):
    def test_advisories_from_either_source(self):
        a = from_github(GITHUB_ADVISORY)
        self.assertEqual(a.ids(), ["CVE-2026-113716", "GHSA-cw65-gx24-rc82"])
        self.assertEqual((a.severity, a.score, a.packages[0]["fixed"]), ("medium", 5.5, "20.36.0"))
        o = from_osv(OSV_VULN)
        self.assertEqual(o.ids(), ["CVE-2026-9999", "GHSA-xxxx-yyyy-zzzz"])
        self.assertEqual((o.severity, o.packages[0]["ecosystem"], o.packages[0]["fixed"]), ("medium", "rust", "0.103.16"))

    def test_recent_asks_once_and_caches(self):
        calls = []

        def fetch(url, body):
            calls.append(url)
            return [GITHUB_ADVISORY]
        f = Feeds(fetch)
        self.assertEqual([a.id for a in f.recent("pip", 7)], ["GHSA-cw65-gx24-rc82"])
        f.recent("pip", 7)
        self.assertEqual(len(calls), 1)
        self.assertIn("ecosystem=pip", calls[0])
        self.assertIn("published=%3E%3D", calls[0])

    def test_pinned_versions_in_one_batch(self):
        seen = {}

        def fetch(url, body):
            seen["url"], seen["body"] = url, json.loads(body)
            return {"results": [{"vulns": [{"id": "GHSA-xxxx-yyyy-zzzz"}]}, {}]}
        got = Feeds(fetch).affecting([("rust", "rustls-webpki", "0.103.15"), ("pip", "requests", "2.32.0")])
        self.assertEqual(got, {("rust", "rustls-webpki", "0.103.15"): ["GHSA-xxxx-yyyy-zzzz"]})
        self.assertTrue(seen["url"].endswith("/querybatch"))
        self.assertEqual(seen["body"]["queries"][0]["package"], {"ecosystem": "crates.io", "name": "rustls-webpki"})
        self.assertEqual(seen["body"]["queries"][1]["package"]["ecosystem"], "PyPI")

    def test_an_unknown_advisory_is_none(self):
        def fetch(url, body):
            raise ValueError("api.osv.dev answered 404")
        self.assertIsNone(Feeds(fetch).advisory("CVE-2099-0001"))


class BookTests(unittest.TestCase):
    def test_each_change_is_a_new_version_and_every_record_reads_back(self):
        with tempfile.TemporaryDirectory() as d:
            b = Book(DirStore(d))
            imp = Impact(advisory=["CVE-2026-1", "GHSA-a"], project="MB")
            self.assertEqual(b.save(imp), 1)
            imp.status = "fixed"
            self.assertEqual(b.save(imp), 2)
            b.save(Impact(advisory=["CVE-2026-2"], project="PFE"))
            self.assertEqual(b.load("mb", "CVE-2026-1").status, "fixed")
            self.assertEqual(sorted(i.project for i in b.all()), ["MB", "PFE"])
            self.assertEqual([i.project for i in b.all("pfe")], ["PFE"])
            self.assertEqual([i.advisory[0] for i in b.for_advisory(["ghsa-a"])], ["CVE-2026-1"])
            self.assertIsNone(b.load("MB", "CVE-2026-404"))


if __name__ == "__main__":
    unittest.main()
