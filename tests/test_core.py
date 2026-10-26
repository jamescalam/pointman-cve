import json
import shutil
import tempfile
import tomllib
import unittest
from pathlib import Path

from gitrepo import Repo, git
from pointman_cve import lockfiles, repos, scans
from pointman_cve.feeds import Feeds, from_github, from_osv, merge_aliases
from pointman_cve.impacts import Impact, path_of, slug
from pointman_cve.store import Book, DirStore, path_ok

ROOT = Path(__file__).resolve().parents[1]
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
        self.assertEqual(imp.path, "impacts/mb/emudhra-g3-distrust.toml")

    def test_paths_from_advisory_ids(self):
        self.assertEqual(path_of("MB", "CVE-2026-1234"), "impacts/mb/cve-2026-1234.toml")
        self.assertEqual(slug("GHSA-cw65-gx24-rc82"), "ghsa-cw65-gx24-rc82")
        self.assertEqual(slug("../../etc/passwd"), "etc-passwd")
        with self.assertRaises(ValueError):
            slug("///")
        for project, advisory in [("MB", "CVE-2026-1234"), ("pfe", "GHSA-AbCd-1234-zz99"), ("X", "eMudhra G3 distrust")]:
            self.assertTrue(path_ok(path_of(project, advisory)), path_of(project, advisory))   # the node takes it

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

    def test_a_tree_s_paths_count_as_a_folder_s_do(self):
        for path, wanted in [("Cargo.lock", True), ("node/Cargo.lock", True), ("a/b/c/d/uv.lock", True),
                             ("a/b/c/d/e/uv.lock", False), ("node_modules/x/package-lock.json", False),
                             (".github/x/go.sum", False), ("node/Cargo.toml", False)]:
            self.assertEqual(lockfiles.wanted(path), wanted, path)


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

    def test_any_advisory_comes_from_osv(self):
        asked = []

        def fetch(url, body):
            asked.append(url)
            return OSV_VULN
        self.assertEqual(Feeds(fetch).advisory("ghsa-xxxx-yyyy-zzzz").cve, "CVE-2026-9999")
        self.assertEqual(asked, ["https://api.osv.dev/v1/vulns/GHSA-xxxx-yyyy-zzzz"])

    def test_one_entry_an_advisory_under_its_other_ids(self):
        rust = ("rust", "rustls-webpki", "0.103.15")
        got = merge_aliases({"GHSA-xxxx-yyyy-zzzz": [rust], "CVE-2026-9999": [rust], "RUSTSEC-2026-1": [rust]},
                            {"GHSA-xxxx-yyyy-zzzz": from_osv(OSV_VULN), "CVE-2026-9999": None, "RUSTSEC-2026-1": None})
        self.assertEqual(got, {"GHSA-xxxx-yyyy-zzzz": [rust], "RUSTSEC-2026-1": [rust]})

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



class OSV:
    """A stand-in OSV: rustls-webpki 0.103.15 has OSV_VULN (GHSA-xxxx-yyyy-zzzz, CVE-2026-9999); nothing else has
    any. `asked` keeps every (ecosystem, name, version) it was asked about."""

    def __init__(self):
        self.asked: list[tuple[str, str, str]] = []

    def fetch(self, url, body):
        if url.endswith("/querybatch"):
            queries = json.loads(body)["queries"]
            self.asked += [(q["package"]["ecosystem"], q["package"]["name"], q["version"]) for q in queries]
            return {"results": [{"vulns": [{"id": "GHSA-xxxx-yyyy-zzzz"}]}
                                if (q["package"]["name"], q["version"]) == ("rustls-webpki", "0.103.15") else {}
                                for q in queries]}
        if url.endswith("/vulns/GHSA-xxxx-yyyy-zzzz"):
            return OSV_VULN
        raise ValueError("api.osv.dev answered 404")


class RepoTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name).resolve()

    def test_settings_name_a_key_a_repo_and_a_ref(self):
        got = repos.from_settings([{"key": "mb", "repo": "~/Documents/message-board"},
                                   {"key": "PFE", "repo": "~/Documents/pfe", "ref": "v1.2"}])
        self.assertEqual(got, [repos.Project("MB", "~/Documents/message-board", "origin/main"),
                               repos.Project("PFE", "~/Documents/pfe", "v1.2")])
        for value, says in [({"key": "MB"}, "a list"), ([{"key": "my project", "repo": "x"}], "key"),
                            ([{"key": "MB"}], "repo"), ([{"key": "MB", "repo": "x", "ref": "--upload-pack=x"}], "ref"),
                            ([{"key": "MB", "repo": "x", "ref": "main branch"}], "ref"), (["MB"], "{key, repo, ref}")]:
            with self.assertRaises(ValueError) as e:
                repos.from_settings(value)
            self.assertIn(says, str(e.exception))

    def test_lockfiles_are_read_at_the_ref_never_the_working_tree(self):
        r = Repo(self.dir / "app")
        got = repos.read(repos.Project("MB", str(r.checkout), "v1"), r.checkout)
        self.assertEqual((got.ref, got.commit, got.files, got.note), ("v1", r.v1, ["node/Cargo.lock"], ""))
        self.assertEqual(got.where, {("rust", "rustls-webpki", "0.103.15"): ["node/Cargo.lock"]})
        self.assertEqual(got.name, "app/origin")                                    # its remote's last two parts

        got = repos.read(repos.Project("MB", str(r.checkout)), r.checkout)          # origin/main, fetched first
        self.assertEqual((got.ref, got.commit), ("origin/main", r.v2))
        self.assertEqual(got.where, {("rust", "rustls-webpki", "0.103.16"): ["node/Cargo.lock"]})
        self.assertEqual(git(r.checkout, "rev-parse", "HEAD"), r.v1)                 # the checkout left as it was
        self.assertIn("M node/Cargo.lock", git(r.checkout, "status", "--short"))

    def test_a_folder_inside_the_repo_reads_only_its_part(self):
        r = Repo(self.dir / "app")
        r.commit({"web/package-lock.json": (FIXTURES / "package-lock.json").read_text()}, "web")
        git(r.writer, "push", "--quiet", "origin", "main")
        (r.checkout / "web").mkdir()                                                 # as the checkout has it
        got = repos.read(repos.Project("MB", str(r.checkout / "web")), r.checkout / "web")
        self.assertEqual(got.files, ["web/package-lock.json"])                       # named as in the repo

    def test_without_its_remote_it_reads_the_ref_as_last_fetched_and_says_so(self):
        r = Repo(self.dir / "app")
        shutil.rmtree(r.origin)
        got = repos.read(repos.Project("MB", str(r.checkout)), r.checkout)
        self.assertEqual(got.commit, r.v1)
        self.assertIn("couldn't fetch", got.note)
        self.assertIn("read origin/main as last fetched", got.note)

    def test_a_ref_it_doesn_t_have_is_refused(self):
        r = Repo(self.dir / "app")
        with self.assertRaises(ValueError) as e:
            repos.read(repos.Project("MB", str(r.checkout), "origin/nope"), r.checkout)
        self.assertIn("origin/nope isn't a branch, tag or commit", str(e.exception))

    def test_a_folder_that_isn_t_in_git_is_read_as_files_and_says_so(self):
        (self.dir / "plain" / "node").mkdir(parents=True)
        shutil.copy(FIXTURES / "Cargo.lock", self.dir / "plain" / "node")
        got = repos.read(repos.Project("MB", str(self.dir / "plain")), self.dir / "plain")
        self.assertEqual((got.ref, got.commit, got.files), ("", "", ["node/Cargo.lock"]))
        self.assertEqual(got.note, "read as files, not from git: it isn't a git repo")

    def test_a_repo_is_named_by_its_remote(self):
        for url in ("git@github.com:pointman-ai/pointman.git", "https://github.com/pointman-ai/pointman",
                    "https://github.com/pointman-ai/pointman.git/", "ssh://git@github.com/pointman-ai/pointman.git"):
            self.assertEqual(repos.repo_name(url), "pointman-ai/pointman", url)


class ScanTests(unittest.TestCase):
    """A project at two refs of a fake git repo, against a stand-in OSV: a hit at v1, gone at origin/main."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name).resolve()
        self.repo = Repo(self.dir / "app")
        self.osv = OSV()
        self.feeds = Feeds(self.osv.fetch)
        self.book = Book(DirStore(self.dir / "files"))

    def scan(self, ref: str) -> dict:
        p = repos.Project("MB", str(self.repo.checkout), ref)
        got = repos.read(p, self.repo.checkout)
        return scans.scan(p.key, p.repo, got, scans.advisories(self.feeds, got.where), self.book, "a test")

    def test_a_hit_at_one_ref_opens_a_record_and_is_gone_at_the_other(self):
        at_v1 = self.scan("v1")
        hit = {"advisory": "CVE-2026-9999", "package": "rustls-webpki", "version": "0.103.15", "ecosystem": "rust",
               "severity": "medium", "fixed": "0.103.16"}
        self.assertEqual((at_v1["new"], at_v1["reopened"], at_v1["gone"], at_v1["open"]), ([hit], [], [], 1))
        self.assertEqual((at_v1["ref"], at_v1["commit"], at_v1["opened"]), ("v1", self.repo.v1, ["CVE-2026-9999"]))
        imp = self.book.load("MB", "CVE-2026-9999")
        self.assertEqual((imp.status, imp.advisory, imp.found_by), ("investigating", ["CVE-2026-9999", "GHSA-xxxx-yyyy-zzzz"], "a test"))
        self.assertEqual(imp.where, [{"repo": imp.where[0]["repo"], "file": "node/Cargo.lock", "package": "rustls-webpki",
                                      "version": "0.103.15", "ecosystem": "rust", "fixed_version": "0.103.16"}])
        self.assertEqual(imp.where[0]["repo"], "app/origin")

        again = self.scan("v1")                                      # seen before: not new, and no second record
        self.assertEqual((again["new"], again["open"]), ([], 1))
        self.assertEqual(len(self.book.all("MB")), 1)

        at_main = self.scan("origin/main")
        self.assertEqual((at_main["new"], at_main["reopened"], at_main["open"]), ([], [], 1))
        self.assertEqual(at_main["gone"], [hit])
        self.assertEqual(at_main["commit"], self.repo.v2)
        self.assertEqual(self.book.load("MB", "CVE-2026-9999").status, "investigating")   # gone changes nothing yet

        self.assertNotIn(("crates.io", "rustls-webpki", "0.103.99"), self.osv.asked)     # the working tree's
        self.assertNotIn("litellm", {n for _, n, _ in self.osv.asked})

    def test_a_fixed_record_hit_again_is_reopened(self):
        self.scan("v1")
        imp = self.book.load("MB", "CVE-2026-9999")
        imp.status = "fixed"
        self.book.save(imp)
        got = self.scan("v1")
        self.assertEqual((got["new"], got["gone"], got["open"]), ([], [], 0))
        self.assertEqual([(h["advisory"], h["version"]) for h in got["reopened"]], [("CVE-2026-9999", "0.103.15")])
        self.assertEqual(self.scan("origin/main")["gone"], [])        # a fixed record isn't open: not gone either

    def test_a_record_kept_under_another_id_isn_t_new(self):
        self.book.save(Impact(advisory=["GHSA-xxxx-yyyy-zzzz"], project="MB", status="affected"))
        got = self.scan("v1")
        self.assertEqual((got["new"], got["open"]), ([], 1))
        self.assertEqual(self.scan("origin/main")["gone"], [])          # no `where` from this repo: not judged

    def test_the_text_says_it_all_in_a_few_lines(self):
        found = [self.scan("v1")]
        text = scans.text(found, scans.totals(found))
        self.assertEqual(text.splitlines()[0], "Scanned MB: 1 new, 0 reopened, 0 gone, 1 open.")
        self.assertIn(f"**MB** at v1 ({self.repo.v1[:8]}), 1 lockfiles: 1 new, 0 reopened, 0 gone, 1 open.", text)
        self.assertIn("- new: **CVE-2026-9999** (medium) rust rustls-webpki 0.103.15, fixed in 0.103.16", text)
        self.assertTrue(text.endswith("Opened 1 records in MB as investigating."), text)

    def test_a_project_that_couldn_t_be_read_counts_as_failed(self):
        bad = {"project": "PFE", "repo": "~/Documents/pfe", "ref": "origin/nope",
               "error": "origin/nope isn't a branch, tag or commit in ~/Documents/pfe"}
        found = [self.scan("v1"), bad]
        all_ = scans.totals(found)
        self.assertEqual(all_, {"new": 1, "reopened": 0, "gone": 0, "open": 1, "failed": 1})
        text = scans.text(found, all_)
        self.assertEqual(text.splitlines()[0], "Scanned MB, PFE: 1 new, 0 reopened, 0 gone, 1 open, 1 failed.")
        self.assertIn("\n**PFE** couldn't be scanned: origin/nope isn't a branch, tag or commit in ~/Documents/pfe.",
                      text)

    def test_osv_not_answering_fails_the_scan(self):
        def down(url, body):
            raise ValueError("couldn't reach api.osv.dev")
        got = repos.read(repos.Project("MB", str(self.repo.checkout), "v1"), self.repo.checkout)
        with self.assertRaises(ValueError):
            scans.advisories(Feeds(down), got.where)


class ManifestTests(unittest.TestCase):
    def test_scans_run_only_on_command(self):
        m = tomllib.loads((ROOT / "extension.toml").read_text())
        self.assertEqual(sorted(m["settings"]["properties"]), ["ecosystem", "projects"])
        item = m["settings"]["properties"]["projects"]["items"]
        self.assertEqual((sorted(item["properties"]), item["required"]), (["key", "ref", "repo"], ["key", "repo"]))
        scan = next(c for c in m["commands"] if c["kind"] == "cve.scan")
        self.assertEqual((scan["slash"], list(scan["params"]["properties"])), ("scan", ["project"]))
        self.assertEqual([e["name"] for e in m["events"]], ["cve.scanned"])
        self.assertNotIn("post", m["permissions"])


if __name__ == "__main__":
    unittest.main()
