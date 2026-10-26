import json
import shutil
import tempfile
import tomllib
import unittest
from pathlib import Path

from gitrepo import Repo, git
from pointman_cve import cvss, feeds, lockfiles, repos, scans, versions
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
                             (".github/x/go.sum", False), ("node/Cargo.toml", False), ("web/pnpm-lock.yaml", True),
                             ("requirements.txt", True), ("requirements-dev.txt", True), ("requirements/base.txt", True),
                             ("docs/notes.txt", False), (".github/workflows/ci.yml", True),
                             (".github/workflows/release.yaml", True), ("sub/.github/workflows/ci.yml", False),
                             (".github/workflows/README.md", False)]:
            self.assertEqual(lockfiles.wanted(path), wanted, path)

    def test_the_newer_kinds_from_real_files(self):
        """Each from a public project's own lockfile, trimmed (tests/fixtures/SOURCES.md)."""
        self.assertEqual(lockfiles.pinned(FIXTURES / "pnpm-lock.yaml"),      # vuejs/core: pnpm itself in its own document
                         [("npm", "@babel/code-frame", "8.0.0"), ("npm", "@pnpm/exe.darwin-arm64", "12.11.2"),
                          ("npm", "@pnpm/exe.linux-x64", "12.11.2"), ("npm", "acorn", "8.16.0"),
                          ("npm", "acorn-jsx", "5.3.2"), ("npm", "pnpm", "12.11.2")])
        self.assertEqual(lockfiles.pinned(FIXTURES / "yarn.lock"),           # facebook/react: string-width-cjs is string-width
                         [("npm", "@ampproject/remapping", "2.3.0"), ("npm", "accepts", "1.3.7"),
                          ("npm", "accepts", "1.3.8"), ("npm", "string-width", "4.2.3")])
        self.assertEqual(lockfiles.pinned(FIXTURES / "berry" / "yarn.lock"),  # yarnpkg/berry: no patch, no workspace
                         [("npm", "@actions/core", "1.2.6"), ("npm", "esbuild-wasm", "0.23.0"), ("npm", "resolve", "1.9.0")])
        self.assertEqual(lockfiles.pinned(FIXTURES / "requirements" / "main.txt"),    # pypi/warehouse: extras dropped
                         [("pip", "alembic", "1.20.0"), ("pip", "celery", "5.6.3"), ("pip", "google-auth", "2.56.3"),
                          ("pip", "pyyaml", "6.0.3")])
        self.assertEqual(lockfiles.pinned(FIXTURES / "Gemfile.lock"),        # rails/rails: not rails itself, one ffi
                         [("rubygems", "addressable", "2.8.7"), ("rubygems", "ffi", "1.17.1"),
                          ("rubygems", "ffi-compiler", "1.3.2")])
        self.assertEqual(lockfiles.pinned(FIXTURES / "composer.lock"),       # composer/composer: dev packages too
                         [("composer", "composer/ca-bundle", "1.6.0"), ("composer", "phpstan/phpstan", "1.12.33"),
                          ("composer", "seld/jsonlint", "1.12.1")])
        self.assertEqual(lockfiles.parse(".github/workflows/ci.yml", (FIXTURES / "workflows" / "ci.yml").read_text()),
                         [("actions", "actions/checkout", "v7.0.1"), ("actions", "astral-sh/setup-uv", "v10.3.0")])

    def test_what_the_real_files_didn_t_show(self):
        cases = [
            ("pnpm-lock.yaml", "lockfileVersion: '6.0'\n\npackages:\n\n  /lodash@4.17.20:\n    resolution: {}\n\n"
             "  /@babel/core@7.24.0(supports-color@8.1.1):\n    resolution: {}\n\n  /local@file:../local:\n"
             "    resolution: {directory: ../local, type: directory}\n",
             [("npm", "@babel/core", "7.24.0"), ("npm", "lodash", "4.17.20")]),
            ("pnpm-lock.yaml", "lockfileVersion: 5.4\n\npackages:\n\n  /lodash/4.17.20:\n    resolution: {}\n\n"
             "  /@babel/core/7.24.0_supports-color@8.1.1:\n    resolution: {}\n",
             [("npm", "@babel/core", "7.24.0"), ("npm", "lodash", "4.17.20")]),
            ("yarn.lock", '"y@git+https://github.com/x/y.git":\n  version "1.0.0"\n  resolved "git+https://github.com/x/y.git#abc"\n\n'
             'local@file:../local:\n  version "0.0.1"\n\nleft-pad@^1.3.0:\n  version "1.3.0"\n',
             [("npm", "left-pad", "1.3.0")]),
            ("requirements.txt", "Django==4.2.1 ; python_version >= '3.8'\nrequests>=2.0\n-r base.txt\n-e .\n"
             "foo @ https://example.com/foo.whl\nZope.Interface==6.0\nbar==1.*\n# baz==1.0\n",
             [("pip", "django", "4.2.1"), ("pip", "zope-interface", "6.0")]),
            ("Gemfile.lock", "GIT\n  remote: https://github.com/x/y.git\n  revision: abc\n  specs:\n    y (0.1.0)\n\n"
             "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.8)\n      base64\n",
             [("rubygems", "rack", "2.2.8")]),
            ("composer.lock", json.dumps({"packages": [{"name": "a/b", "version": "dev-main"},
                                                       {"name": "c/d", "version": "1.0.0", "dist": {"type": "path"}},
                                                       {"name": "symfony/http-kernel", "version": "v4.4.0"}]}),
             [("composer", "symfony/http-kernel", "v4.4.0")]),
            (".github/workflows/x.yml", "    - uses: actions/checkout@v4\n      uses: 'actions/setup-node@v4.0.2'\n"
             "    - uses: ./local-action\n    - uses: docker://alpine:3\n    uses: org/repo/.github/workflows/x.yml@v1.2\n"
             "    - uses: some/action@main\n    - uses: other/action@0123456789abcdef0123456789abcdef01234567\n"
             "    - uses: third/action@0123456789abcdef0123456789abcdef01234567 # v2.1.0\n",
             [("actions", "actions/checkout", "v4"), ("actions", "actions/setup-node", "v4.0.2"),
              ("actions", "org/repo", "v1.2"), ("actions", "third/action", "v2.1.0")]),
        ]
        for path, text, pins in cases:
            self.assertEqual(lockfiles.parse(path, text), pins, text[:40])

    def test_a_folder_s_workflows_and_requirements_are_found(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / ".github" / "workflows").mkdir(parents=True)
            shutil.copy(FIXTURES / "workflows" / "ci.yml", root / ".github" / "workflows")
            (root / ".github" / "ISSUE_TEMPLATE.md").write_text("x")
            (root / "requirements").mkdir()
            shutil.copy(FIXTURES / "requirements" / "main.txt", root / "requirements")
            (root / "web").mkdir()
            shutil.copy(FIXTURES / "yarn.lock", root / "web")
            self.assertEqual([str(p.relative_to(root)) for p in lockfiles.find(root)],
                             [".github/workflows/ci.yml", "requirements/main.txt", "web/yarn.lock"])


GITHUB_ADVISORY = {"ghsa_id": "GHSA-cw65-gx24-rc82", "cve_id": "CVE-2026-113716", "type": "reviewed",
                   "summary": "virtualenv: builtin creation follows linked environment directories",
                   "severity": "medium", "published_at": "2026-10-21T21:35:56Z",
                   "html_url": "https://github.com/advisories/GHSA-cw65-gx24-rc82", "cvss": {"score": 5.5},
                   "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "virtualenv"},
                                        "vulnerable_version_range": "< 20.36.0", "first_patched_version": "20.36.0"}]}
OSV_VULN = {"id": "GHSA-xxxx-yyyy-zzzz", "aliases": ["CVE-2026-9999"], "summary": "rustls-webpki trusts a bad CA",
            "published": "2026-10-21T00:00:00Z", "database_specific": {"severity": "MODERATE"},
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"}],
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

    def test_github_s_score_for_a_4_0_only_advisory(self):
        """A real one: GitHub scores CVSS 4.0 itself, in cvss_severities; the older cvss field is empty."""
        a = from_github(json.loads((FIXTURES / "github" / "GHSA-xmj3-9gf7-h52w.json").read_text()))
        self.assertEqual((a.severity, a.score, a.cvss[:8]), ("low", 1.0, "CVSS:4.0"))
        both = {"cvss_severities": {"cvss_v3": {"vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                                "score": 7.5}, "cvss_v4": {"vector_string": "CVSS:4.0/x", "score": 8.7}}}
        self.assertEqual(from_github(both).score, 7.5)                          # CVSS 3 first, as OSV's is
        self.assertEqual(from_github({"cvss_severities": {"cvss_v3": {"score": 0, "vector_string": None}}}).score, None)

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

    def test_actions_are_checked_against_ranges_here(self):
        """OSV doesn't compare GitHub Actions versions: asked by name alone, and the tag checked here."""
        vulns = {"GHSA-mcph-m25j-8j63": [{"introduced": "0"}, {"fixed": "41"}],
                 "GHSA-mrrh-fwg8-r2c3": [{"introduced": "0"}, {"fixed": "46.0.1"}],
                 "GHSA-last": [{"introduced": "1.0.0"}, {"last_affected": "1.2.0"}]}
        asked = []

        def fetch(url, body):
            asked.append(url)
            if url.endswith("/querybatch"):
                queries = json.loads(body)["queries"]
                if queries[0]["package"]["ecosystem"] == "GitHub Actions":
                    self.assertTrue(all("version" not in q for q in queries), queries)
                    by_name = {"tj-actions/changed-files": ["GHSA-mcph-m25j-8j63", "GHSA-mrrh-fwg8-r2c3"],
                               "some/action": ["GHSA-last", "GHSA-list"]}
                    return {"results": [{"vulns": [{"id": i} for i in by_name.get(q["package"]["name"], [])]}
                                        for q in queries]}
                self.assertEqual(queries, [{"package": {"ecosystem": "npm", "name": "lodash"}, "version": "4.17.20"}])
                return {"results": [{}]}
            vid = url.rsplit("/", 1)[1]
            name = "some/action" if vid in ("GHSA-last", "GHSA-list") else "tj-actions/changed-files"
            if vid == "GHSA-list":
                return {"id": vid, "affected": [{"package": {"ecosystem": "GitHub Actions", "name": name},
                                                 "versions": ["v3.0.0"]}]}
            return {"id": vid, "affected": [{"package": {"ecosystem": "GitHub Actions", "name": name},
                                             "ranges": [{"type": "ECOSYSTEM", "events": vulns[vid]}]}]}
        tj = "tj-actions/changed-files"
        pins = [("actions", tj, v) for v in ("v35", "v41.0.0", "v46.0.0", "v46.0.1", "v46")]
        pins += [("actions", "some/action", v) for v in ("v1.2.0", "v1.2.1", "3.0.0")] + [("npm", "lodash", "4.17.20")]
        got = Feeds(fetch).affecting(pins)
        self.assertEqual(got, {("actions", tj, "v35"): ["GHSA-mcph-m25j-8j63", "GHSA-mrrh-fwg8-r2c3"],
                               ("actions", tj, "v41.0.0"): ["GHSA-mrrh-fwg8-r2c3"],
                               ("actions", tj, "v46.0.0"): ["GHSA-mrrh-fwg8-r2c3"],     # v46 is its newest: fixed
                               ("actions", "some/action", "v1.2.0"): ["GHSA-last"],
                               ("actions", "some/action", "3.0.0"): ["GHSA-list"]})
        self.assertEqual(len([u for u in asked if "/vulns/" in u]), 4)                  # each advisory once

    def test_osv_s_cvss_vector_gives_the_score_and_a_missing_severity(self):
        self.assertEqual((from_osv(OSV_VULN).score, from_osv(OSV_VULN).cvss[:8]), (4.8, "CVSS:3.1"))
        rustsec = {"id": "RUSTSEC-2026-0001", "database_specific": {"license": "CC0-1.0"},
                   "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]}
        self.assertEqual((from_osv(rustsec).severity, from_osv(rustsec).score), ("high", 7.5))   # was unknown
        v4 = {"id": "GHSA-xmj3-9gf7-h52w", "database_specific": {"severity": "LOW"},
              "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:A/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N"}]}
        self.assertEqual((from_osv(v4).severity, from_osv(v4).score, from_osv(v4).cvss[:8]), ("low", None, "CVSS:4.0"))
        self.assertEqual(from_osv({"id": "RUSTSEC-2026-0386"}).severity, "unknown")      # nothing to go on

    def test_kev_and_epss_by_cve_a_page_at_a_time_cached_and_backed_off(self):
        asked = []
        cves = [f"CVE-2026-{n:04}" for n in range(150)]

        def fetch(url, body):
            asked.append(url)
            if url == feeds.KEV:
                return {"vulnerabilities": [{"cveID": "CVE-2026-0007", "dateAdded": "2026-10-01"}, {"cveID": "CVE-1999-1"}]}
            asked_for = url.split("cve=", 1)[1].split(",")
            return {"data": [{"cve": c, "epss": "0.5", "percentile": "0.9"} for c in asked_for if c.endswith("7")]}
        f = Feeds(fetch)
        kev, epss, why = f.exploited(cves + ["GHSA-not-a-cve", "cve-2026-0007"])
        self.assertEqual((kev, why), ({"CVE-2026-0007": "2026-10-01"}, ""))
        self.assertEqual(sorted(epss), [c for c in cves if c.endswith("7")])
        self.assertEqual([u.startswith(feeds.EPSS) for u in asked], [False, True, True])     # 150 CVEs: two pages
        self.assertTrue(all(len(u.split("cve=")[1]) < 2000 for u in asked[1:]))
        f.exploited(cves)
        self.assertEqual(len(asked), 3)                                                     # kept for the day

        def down(url, body):
            asked.append(url)
            raise ValueError("couldn't reach www.cisa.gov")
        g = Feeds(down)
        self.assertEqual(g.exploited(["CVE-2026-0001"])[0], None)
        n = len(asked)
        self.assertIn("couldn't reach", g.exploited(["CVE-2026-0001"])[2])
        self.assertEqual(len(asked), n)                                                     # not asked again yet

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
    any. `asked` keeps every (ecosystem, name, version) it was asked about. It stands in for CISA's KEV list and
    FIRST's EPSS too: CVE-2026-9999 is known exploited, with an EPSS of 0.42."""

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
        if url == feeds.KEV or url.endswith("/kev.json"):
            return {"vulnerabilities": [{"cveID": "CVE-2026-9999", "dateAdded": "2026-10-22"}]}
        if url.startswith(feeds.EPSS) or "/epss?" in url:
            return {"data": [{"cve": "CVE-2026-9999", "epss": "0.42000", "percentile": "0.97"}]
                            if "CVE-2026-9999" in url else []}
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

    def test_the_newer_kinds_are_read_at_the_ref_too(self):
        r = Repo(self.dir / "app")
        r.commit({".github/workflows/ci.yml": (FIXTURES / "workflows" / "ci.yml").read_text(),
                  "web/pnpm-lock.yaml": (FIXTURES / "pnpm-lock.yaml").read_text(),
                  "requirements/main.txt": (FIXTURES / "requirements" / "main.txt").read_text()}, "more kinds")
        git(r.writer, "push", "--quiet", "origin", "main")
        got = repos.read(repos.Project("MB", str(r.checkout)), r.checkout)
        self.assertEqual(got.files, [".github/workflows/ci.yml", "node/Cargo.lock", "requirements/main.txt",
                                     "web/pnpm-lock.yaml"])
        self.assertEqual(got.where[("actions", "actions/checkout", "v7.0.1")], [".github/workflows/ci.yml"])
        self.assertEqual(got.where[("pip", "celery", "5.6.3")], ["requirements/main.txt"])
        self.assertEqual(got.where[("npm", "pnpm", "12.11.2")], ["web/pnpm-lock.yaml"])

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
        found = scans.advisories(self.feeds, got.where)
        scans.signal(self.feeds, found)
        return scans.scan(p.key, p.repo, got, found, self.book, "a test")

    def test_a_hit_at_one_ref_opens_a_record_and_is_gone_at_the_other(self):
        at_v1 = self.scan("v1")
        hit = {"advisory": "CVE-2026-9999", "package": "rustls-webpki", "version": "0.103.15", "ecosystem": "rust",
               "severity": "medium", "fixed": "0.103.16", "kev": True, "epss": 0.42, "cvss": 4.8}
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
        self.assertEqual(at_main["gone"], [{**hit, "kev": None, "epss": None, "cvss": None}])   # not looked up
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
        self.assertIn("- new: **CVE-2026-9999** (medium 4.8, known exploited, EPSS 42%) rust rustls-webpki 0.103.15, "
                      "fixed in 0.103.16", text)
        self.assertTrue(text.endswith("Opened 1 records in MB as investigating.\n\n"
                                      "EPSS scores: FIRST, https://www.first.org/epss"), text)

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


class FixFirstTests(unittest.TestCase):
    def test_cvss_3_scores_match_github_s(self):
        """66 real vectors with the scores GitHub's advisory database gives them (tests/fixtures/SOURCES.md)."""
        rows = [line.split("\t") for line in (FIXTURES / "cvss3.tsv").read_text().splitlines()]
        self.assertEqual(len(rows), 66)
        self.assertEqual([(v, cvss.score(v)) for v, _ in rows], [(v, float(s)) for v, s in rows])
        self.assertEqual(cvss.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)       # Log4Shell
        for vector in ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "AV:N/AC:L", "CVSS:3.1/AV:X"):
            self.assertIsNone(cvss.score(vector), vector)
        self.assertEqual([cvss.severity(x) for x in (9.0, 8.9, 7.0, 4.0, 3.9, 0.0, None)],
                         ["critical", "high", "high", "medium", "low", "unknown", "unknown"])

    def test_open_records_known_exploited_first_then_epss_then_severity(self):
        def fetch(url, body):
            if url == feeds.KEV:
                return {"vulnerabilities": [{"cveID": "CVE-2026-0003", "dateAdded": "2026-10-01"}]}
            return {"data": [{"cve": "CVE-2026-0002", "epss": "0.6"}, {"cve": "CVE-2026-0004", "epss": "0.01"}]}
        records = [Impact(advisory=["CVE-2026-0001"], project="MB", status="affected", severity="critical"),
                   Impact(advisory=["CVE-2026-0002"], project="MB", status="investigating", severity="low"),
                   Impact(advisory=["GHSA-a", "CVE-2026-0003"], project="MB", status="affected", severity="medium"),
                   Impact(advisory=["CVE-2026-0004"], project="MB", status="affected", severity="high"),
                   Impact(advisory=["RUSTSEC-2026-0005"], project="MB", status="investigating", severity="unknown"),
                   Impact(advisory=["CVE-2026-0006"], project="MB", status="fixed", severity="critical")]
        ordered, signals, why = scans.fix_first(records, Feeds(fetch))
        self.assertEqual([r.advisory[0] for r in ordered],
                         ["GHSA-a", "CVE-2026-0002", "CVE-2026-0004", "CVE-2026-0001", "RUSTSEC-2026-0005",
                          "CVE-2026-0006"])
        self.assertEqual((signals[records[2].path], signals[records[1].path], why), ((True, None), (False, 0.6), ""))
        self.assertNotIn(records[5].path, signals)                       # a fixed record isn't looked up

        def down(url, body):
            raise ValueError("offline")
        self.assertLess(scans.first(None, 0.0003, "high", 7.5), scans.first(None, 0.0009, "medium", 5.3))   # noise
        self.assertLess(scans.first(None, 0.04, "low"), scans.first(None, 0.0009, "critical"))           # not noise
        self.assertEqual([scans.percent(x) for x in (0.42, 0.1, 0.0344, 0.00344, 0.0004)],
                         ["42%", "10%", "3.4%", "0.3%", "<0.1%"])

        ordered, signals, why = scans.fix_first(records, Feeds(down))   # severity order, and it says why
        self.assertEqual([r.advisory[0] for r in ordered][:4], ["CVE-2026-0001", "CVE-2026-0004", "GHSA-a", "CVE-2026-0002"])
        self.assertIn("offline", why)
        self.assertEqual(signals[records[0].path], (None, None))


def osv_fixture(vid: str):
    return from_osv(json.loads((FIXTURES / "osv" / f"{vid}.json").read_text()))


def synthetic(vid: str, package: str, *events: list[dict]):
    return from_osv({"id": vid, "affected": [{"package": {"ecosystem": "npm", "name": package},
                                              "ranges": [{"type": "SEMVER", "events": list(e)} for e in events]}]})


class PlanTests(unittest.TestCase):
    def test_versions_sort_as_versions_do(self):
        ordered = ["0.0.0-0", "0.1", "1.0.dev0", "1.0a1", "1.0-beta", "1.0rc1", "1.0.0-rc.2", "1.0", "1.0.post1",
                   "1.0.1", "v1.9", "1.10", "2.0.0-next.5", "2.0.0"]
        for a, b in zip(ordered, ordered[1:]):
            self.assertTrue(versions.less(a, b) and not versions.less(b, a), (a, b))
        self.assertEqual(versions.key("v4.4.0"), versions.key("4.4.0.0"))
        for a, b in [("2.0.0-1", "2.0.0"), ("1.0.0-0.3.7", "1.0.0"), ("7.0.0-0", "7.0.0"),       # semver: digits
                     ("1.0.0-1", "1.0.0-alpha"), ("1.0.0-0.3.7", "1.0.0-alpha"), ("6.99.0", "7.0.0-0"),
                     ("v0.0.0-20210101000000-abcdef", "v0.0.0")]:                            # Go's pseudo-version
            self.assertTrue(versions.less(a, b) and not versions.less(b, a), (a, b))

    def test_the_fix_is_the_one_for_the_pinned_version_s_line(self):
        """Real advisories: undici's has a range a release line; 7.30.0 is fixed in 7.30.1, not 6.29.1."""
        undici, tokio = osv_fixture("GHSA-xjj6-f33q-929c"), osv_fixture("RUSTSEC-2026-0386")
        self.assertEqual([scans.fixed_for(undici, "undici", v) for v in ("6.25.0", "7.30.0", "8.1.0")],
                         ["6.29.1", "7.30.1", "8.12.2"])
        self.assertEqual([scans.fixed_for(tokio, "tokio", v) for v in ("1.50.0", "1.53.2")], ["1.51.6", "1.53.3"])
        self.assertFalse(versions.affected([p for p in tokio.packages if p["name"] == "tokio"], "1.53.3"))
        open_ended = synthetic("GHSA-open", "x", [{"introduced": "1.0.0"}, {"last_affected": "1.4.0"}])
        self.assertEqual(scans.fixed_for(open_ended, "x", "1.2.0"), "")       # no fix named

    def test_a_plan_takes_each_package_past_every_advisory_on_it(self):
        undici = ("npm", "undici", "7.30.0")
        later = synthetic("GHSA-later", "undici", [{"introduced": "7.0.0"}, {"fixed": "7.31.0"}])
        back = synthetic("GHSA-back", "undici", [{"introduced": "7.0.0"}, {"fixed": "7.30.1"},
                                                 {"introduced": "7.31.0"}, {"fixed": "7.32.0"}])
        none = synthetic("GHSA-none", "undici", [{"introduced": "7.0.0"}, {"last_affected": "7.40.0"}])
        tokio = ("rust", "tokio", "1.53.2")
        found = [(["GHSA-xjj6-f33q-929c"], osv_fixture("GHSA-xjj6-f33q-929c"), [undici]),
                 (["GHSA-later"], later, [undici]), (["GHSA-back"], back, [undici]), (["GHSA-none"], none, [undici]),
                 (["RUSTSEC-2026-0386"], osv_fixture("RUSTSEC-2026-0386"), [tokio]),
                 (["GHSA-ours"], later, [("npm", "left-pad", "1.3.0")])]
        records = [Impact(advisory=["GHSA-ours"], project="MB", status="not_affected", justification="not_reachable")]
        where = {undici: ["web/package-lock.json"], tokio: ["node/Cargo.lock"]}
        lines = scans.plan(found, records, where)
        self.assertEqual([(x["package"], x["from"], x["to"], x["fixes"], x["unfixed"]) for x in lines],
                         [("undici", "7.30.0", "7.31.0", 2, ["GHSA-back", "GHSA-none"]),   # 7.31.0 is back in one
                          ("tokio", "1.53.2", "1.53.3", 1, [])])
        self.assertEqual(lines[0]["files"], ["web/package-lock.json"])
        self.assertEqual(scans.plan_text(lines), [
            "Upgrade plan: 2 upgrades fix 3 of 5 advisories.",
            "- npm undici 7.30.0 → 7.31.0: fixes 2 (2 not)",
            "- rust tokio 1.53.2 → 1.53.3: fixes 1",
            "No fix named yet for 2: GHSA-back, GHSA-none."])


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
