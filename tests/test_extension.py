"""The extension's process as the node runs it, under the SDK's stand-in node, with a stand-in for the node's own
files (files.put, files.list, files.get) and no network (CVE_OFFLINE). Skipped where $POINTMAN_EXTENSIONS_SDK
doesn't name the node's Python SDK (one with pointman_extension_types, the typed protocol)."""

import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from gitrepo import Repo
from pointman_cve.store import path_ok
from test_core import OSV

ROOT = Path(__file__).resolve().parents[1]
SDK = os.environ.get("POINTMAN_EXTENSIONS_SDK")
if SDK:
    sys.path.insert(0, SDK)
try:
    import pointman_extension_types as types
    from pointman_extension_testing import ExtensionFailed, InputRefused, StandInNode
except ImportError:
    StandInNode = None


class Files:
    """The node's files for one extension, as it keeps them: each path's versions, the newest last."""

    def __init__(self):
        self.versions: dict[str, list[str]] = {}

    def methods(self) -> dict:
        return {"files.put": self.put, "files.list": self.list, "files.get": self.get}

    def put(self, req):
        if not path_ok(req.path):
            raise ValueError("path: relative, at most 200 characters of a-z 0-9 . _ - /, with no ..")
        texts = self.versions.setdefault(req.path, [])
        if not texts or texts[-1] != req.text:          # the same text as the newest is no new version
            texts.append(req.text)
        return types.FilesPutResponse(path=req.path, version=len(texts))

    def list(self, req):
        return types.FilesListResponse(files=[types.OwnFile(path=p, version=len(v))
                                              for p, v in sorted(self.versions.items()) if p.startswith(req.prefix)])

    def get(self, req):
        texts = self.versions.get(req.path)
        if not texts:
            raise ValueError(f"no file {req.path}")
        return types.FilesGetResponse(file=types.OwnFile(path=req.path, version=len(texts), text=texts[-1]))


@unittest.skipUnless(StandInNode, "needs the node's Python SDK ($POINTMAN_EXTENSIONS_SDK)")
class ExtensionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name).resolve()
        (self.dir / "app" / "node").mkdir(parents=True)
        shutil.copy(ROOT / "tests" / "fixtures" / "Cargo.lock", self.dir / "app" / "node")
        self.files = Files()
        self.node = self.start()

    def start(self, settings=None, methods=None, env=None):
        """The extension under a stand-in node (with these settings, or its files' stand-in left out)."""
        node = StandInNode(ROOT, settings=settings, methods=self.files.methods() if methods is None else methods,
                           env=env or {"CVE_OFFLINE": "1"}, roots=[self.dir / "app"], machine="mac-test",
                           state_dir=self.dir / "node")
        node.start()
        self.addCleanup(node.stop)
        return node

    def run_command(self, kind, params):
        return self.node.run(kind, params).result

    def refused(self, kind, params) -> str:
        with self.assertRaises(ExtensionFailed) as e:
            self.node.run(kind, params)
        return str(e.exception)

    def test_it_speaks_the_typed_protocol(self):
        self.assertEqual(self.node.info.protocol, types.Protocol.PROTOCOL_TYPED)
        self.assertEqual(self.node.info.id, "cve")

    def test_record_update_and_list_an_impact(self):
        got = self.run_command("cve.add", {"advisory": "CVE-2026-1234", "project": "mb", "package": "rustls-webpki",
                                           "version": "0.103.15", "thread": "17856", "note": "found in the sweep"})
        self.assertEqual(got["impact"], "impacts/mb/cve-2026-1234.toml")
        self.assertEqual(got["pane"], {"open": "cve", "target": {"view": "impacts", "project": "MB"}})
        self.assertIn("already recorded", self.refused("cve.add", {"advisory": "CVE-2026-1234", "project": "MB"}))
        listed = self.run_command("cve.impacts", {"project": "MB"})["text"]             # offline: it says why
        self.assertIn("Known-exploited and EPSS couldn't be had (CISA's KEV list: offline", listed)
        self.assertIn("open ones are in severity order", listed)

        got = self.run_command("cve.set", {"advisory": "CVE-2026-1234", "project": "MB", "status": "fixed",
                                           "pr": "https://github.com/pointman-ai/pointman/pull/1", "fixed_in": "release 35"})
        self.assertEqual(got["version"], 2, got)
        text = self.files.versions["impacts/mb/cve-2026-1234.toml"][1]
        self.assertIn('status = "fixed"', text)
        self.assertIn('threads = ["pointman://thread/17856"]', text)
        self.assertIn("found in the sweep", text)
        asked = [(m, getattr(r, "path", None)) for m, r in self.node.asked if m == "files.put"]
        self.assertEqual(asked, [("files.put", "impacts/mb/cve-2026-1234.toml")] * 2)

        got = self.run_command("cve.impacts", {"project": "MB"})
        self.assertIn("**CVE-2026-1234** MB: fixed, fixed in release 35", got["text"])
        got = self.run_command("cve.show", {"advisory": "CVE-2026-1234"})
        self.assertIn("offline", got["text"])                  # the feed wasn't asked
        self.assertIn("- MB: fixed, fixed in release 35", got["text"])

    def test_not_affected_says_why_as_vex_does_and_every_change_is_kept(self):
        self.run_command("cve.add", {"advisory": "CVE-2026-77", "project": "MB", "by": "@scanner-agent",
                                     "note": "zstd-safe 7.3.0 in node/Cargo.lock"})
        for params, says in [({}, "not_affected needs VEX's justification"),
                             ({"justification": "not_reachable"}, "(not not_reachable)"),
                             ({"justification": "vulnerable_code_not_in_execute_path"}, "needs a note saying why")]:
            self.assertIn(says, self.refused("cve.set", {"advisory": "CVE-2026-77", "project": "MB",
                                                         "status": "not_affected", **params}))
        self.assertEqual(len(self.files.versions["impacts/mb/cve-2026-77.toml"]), 1)    # nothing written
        self.run_command("cve.set", {"advisory": "CVE-2026-77", "project": "MB", "status": "not_affected",
                                     "justification": "vulnerable_code_not_in_execute_path", "by": "@cvescan",
                                     "note": "the vault only uses the plain stream encoder, on data it has authenticated"})
        self.run_command("cve.set", {"advisory": "CVE-2026-77", "project": "MB", "status": "affected",
                                     "note": "the encoder is reachable after all"})
        shown = self.run_command("cve.show", {"advisory": "CVE-2026-77"})["text"]
        history = [line.strip() for line in shown.splitlines() if line.startswith("  - ")]
        self.assertEqual(len(history), 3, shown)
        self.assertIn("@scanner-agent (said): investigating, zstd-safe 7.3.0 in node/Cargo.lock", history[0])
        self.assertIn("@cvescan (said): investigating → not_affected (vulnerable_code_not_in_execute_path), "
                      "the vault only uses the plain stream encoder", history[1])
        self.assertIn("someone (not said): not_affected → affected, the encoder is reachable after all", history[2])
        text = self.files.versions["impacts/mb/cve-2026-77.toml"][-1]
        self.assertIn('justification = ""', text)                                     # not not_affected now
        self.assertEqual(text.count("[[history]]"), 3)

    def test_vex_posts_an_openvex_document_that_validates(self):
        from test_core import vex_errors
        self.run_command("cve.add", {"advisory": "CVE-2026-77", "project": "MB", "status": "affected",
                                     "package": "rustls", "version": "0.23.45", "fixed_version": "0.23.46",
                                     "repo": "pointman-ai/pointman"})
        self.run_command("cve.add", {"advisory": "MAL-2026-2144", "project": "MB", "status": "not_affected",
                                     "justification": "component_not_present", "note": "test fixture"})
        done = self.node.run("cve.vex", {"project": "mb"})
        self.assertEqual((done.result["statements"], done.result["counts"]), (2, {"affected": 1, "not_affected": 1}))
        self.assertIn("OpenVEX for MB: 2 statements (1 affected, 1 not affected), posted as openvex-mb-", done.result["text"])
        (out,) = done.outputs
        self.assertEqual((out.kind, out.role, Path(out.path).name), ("document", types.OutputRequest.Role.ROLE_MAIN,
                                                                     done.result["file"]))
        doc = json.loads(Path(out.path).read_text())
        self.assertEqual(vex_errors(doc), [])
        self.assertEqual((doc["@id"], doc["tooling"][:13]), (done.result["id"], "pointman-cve "))
        self.assertIn("which project?", self.refused("cve.vex", {}))
        self.assertIn("nothing is recorded for PFE", self.refused("cve.vex", {"project": "PFE"}))

    def test_report_posts_a_page_of_each_pr_and_what_it_fixes(self):
        self.assertIn("nothing is open, so there's nothing to report", self.refused("cve.report", {}))
        self.run_command("cve.add", {"advisory": "CVE-2026-77,CVE-2026-78", "project": "MB", "status": "affected",
                                     "package": "zstd-safe", "version": "7.3.0", "fixed_version": "8.2.0",
                                     "repo": "pointman-ai/pointman"})
        self.run_command("cve.add", {"advisory": "CVE-2026-79", "project": "SPARK", "package": "xlsx", "version": "0.18.5"})
        self.run_command("cve.set", {"advisory": "CVE-2026-77,CVE-2026-78", "project": "MB",
                                     "pr": "https://github.com/pointman-ai/pointman/pull/20", "note": "fix PR open"})
        versions = {path: len(v) for path, v in self.files.versions.items()}
        done = self.node.run("cve.report", {})
        got = done.result
        self.assertEqual({k: got[k] for k in ("prs", "open", "fixed_by_prs", "kev", "without_pr")},
                         {"prs": 1, "open": 3, "fixed_by_prs": 2, "kev": 0, "without_pr": 1}, got)
        self.assertEqual([p["project"] for p in got["projects"]], ["MB", "SPARK"])
        self.assertEqual(got["projects"][0]["prs"], [{"pr": "https://github.com/pointman-ai/pointman/pull/20",
                                                      "advisories": ["CVE-2026-77", "CVE-2026-78"]}])
        self.assertIn("1 PRs fix 2 of 3 open advisories", got["text"])
        self.assertIn("Known-exploited and EPSS couldn't be had", got["text"])          # offline
        (out,) = done.outputs
        self.assertEqual((out.kind, Path(out.path).name), ("document", got["file"]))
        page = Path(out.path).read_text()
        self.assertIn('<a href="https://github.com/pointman-ai/pointman/pull/20">pointman-ai/pointman#20</a>', page)
        self.assertIn("zstd-safe 7.3.0 → 8.2.0", page)
        only = self.run_command("cve.report", {"project": "spark"})
        self.assertEqual((only["prs"], only["without_pr"], [p["project"] for p in only["projects"]]), (0, 1, ["SPARK"]))
        self.assertEqual({path: len(v) for path, v in self.files.versions.items()}, versions)  # it wrote nothing

    def test_one_fix_records_several_advisories_at_once(self):
        got = self.run_command("cve.add", {"advisory": "RUSTSEC-2026-0367, RUSTSEC-2026-0368", "project": "MB",
                                           "package": "zip", "version": "8.6.0", "status": "affected"})
        self.assertEqual(got["impacts"], ["impacts/mb/rustsec-2026-0367.toml", "impacts/mb/rustsec-2026-0368.toml"])
        got = self.run_command("cve.add", {"advisory": ["RUSTSEC-2026-0368", "RUSTSEC-2026-0369"],
                                           "project": "MB", "status": "affected"})
        self.assertEqual(got["already"], ["RUSTSEC-2026-0368"])
        got = self.run_command("cve.set", {"advisory": "RUSTSEC-2026-0367,RUSTSEC-2026-0368,RUSTSEC-2026-0370",
                                           "project": "MB", "status": "fixed", "fixed_in": "release 36",
                                           "pr": "https://github.com/pointman-ai/pointman/commit/d9ea9a8b"})
        self.assertEqual(got["missing"], ["RUSTSEC-2026-0370"], got)
        self.assertIn("Changed 2 advisories in MB", got["text"])
        got = self.run_command("cve.impacts", {"project": "MB"})
        self.assertEqual(got["text"].count("fixed, fixed in release 36"), 2)

    def test_a_long_list_says_how_many_more_are_in_the_pane(self):
        ids = ", ".join(f"RUSTSEC-2026-{n:04}" for n in range(1, 33))
        self.run_command("cve.add", {"advisory": ids, "project": "MB", "status": "affected"})
        text = self.run_command("cve.impacts", {"project": "MB"})["text"]
        self.assertTrue(text.startswith("32 impacts:"), text)
        self.assertEqual(text.count("\n- **"), 30)
        self.assertTrue(text.endswith("\n…and 2 more in the pane."), text)
        self.assertNotIn("couldn't be had", text)                     # RUSTSEC ids: KEV and EPSS know only CVEs

    def test_refusals_say_what_to_do(self):
        self.assertIn("isn't recorded for MB: add it with /cve add",
                      self.refused("cve.set", {"advisory": "CVE-2026-404", "project": "MB", "status": "fixed"}))
        self.assertIn("not_affected needs VEX's justification, one of component_not_present",
                      self.refused("cve.add", {"advisory": "CVE-2026-5", "project": "MB", "status": "not_affected"}))
        self.assertIn("outside the folders", self.refused("cve.check", {"folder": "/etc"}))
        self.assertIn("which folder?", self.refused("cve.check", {}))
        (self.dir / "app" / "lib" / "tests").mkdir(parents=True)
        shutil.copy(ROOT / "tests" / "fixtures" / "Cargo.lock", self.dir / "app" / "lib" / "tests")
        got = self.run_command("cve.check", {"folder": str(self.dir / "app" / "lib")})         # test data only
        self.assertEqual((got["skipped"], got["found"]), (1, []))
        self.assertIn("but test data (1 skipped)", got["text"])

    def test_the_pane_goes_from_projects_to_a_project_to_a_record_and_back(self):
        self.run_command("cve.add", {"advisory": "GHSA-abcd-efgh-ijkl", "project": "PFE", "status": "affected",
                                     "package": "zip", "version": "8.6.0", "fixed_version": "9.0.0"})
        self.run_command("cve.add", {"advisory": "CVE-2026-5", "project": "MB", "by": "@scanner",
                                     "note": "zstd-safe in node/Cargo.lock", "package": "zstd-safe", "version": "7.3.0"})
        self.run_command("cve.add", {"advisory": "MAL-2026-2144", "project": "MB", "status": "not_affected",
                                     "justification": "component_not_present", "note": "test fixture"})
        self.run_command("cve.set", {"advisory": "CVE-2026-5", "project": "MB", "status": "affected", "by": "@cvescan",
                                     "note": "the vault decodes it", "pr": "https://github.com/x/y/pull/3"})
        view = self.node.open_pane("cve")                                    # it opens on the project picker
        self.assertEqual((view.title, [b.name for b in view.blocks]), ("CVE tracker", ["h", "projects", "nav"]))
        picks = view.block("projects").list.items
        self.assertEqual([(i.id, i.subtitle) for i in picks], [("MB", "1 open · not scanned yet"),
                                                               ("PFE", "1 open · not scanned yet")])
        self.assertEqual(view.problems, [])

        view.input("tap", block="projects", value="MB")                      # a project
        self.assertEqual(view.title, "CVE · MB")
        self.assertEqual([b.name for b in view.blocks],
                         ["h", "nav", "st", "oh", "open", "ph", "plan", "sh", "scans", "ch", "closed"])
        (opened,) = view.block("open").list.items
        self.assertEqual((opened.title, opened.subtitle), ("CVE-2026-5", "affected · zstd-safe 7.3.0"))
        self.assertEqual([i.subtitle for i in view.block("closed").list.items], ["not affected (component not present)"])
        self.assertEqual(view.block("saffected").chart.data.rows, [[1]])
        self.assertEqual(view.block("scans").empty.title, "Not scanned yet")
        self.assertEqual(view.problems, [])

        view.input("tap", block="open", value=opened.id)                     # a record: its history and evidence
        self.assertEqual((view.title, view.block("h").text.heading.subtitle), ("CVE-2026-5", "MB · affected"))
        self.assertEqual([(i.title, i.subtitle) for i in view.block("where").list.items], [("zstd-safe 7.3.0", "")])
        self.assertEqual([(i.title, i.link) for i in view.block("evidence").list.items],
                         [("pull/3", "https://github.com/x/y/pull/3")])
        history = [(i.title, i.subtitle.split(" · ")[0], i.subtitle.split(" · ")[2:]) for i in view.block("history").list.items]
        self.assertEqual(history, [("investigating → affected", "@cvescan (said)",
                                    ["the vault decodes it", "https://github.com/x/y/pull/3"]),
                                   ("investigating", "@scanner (said)", ["zstd-safe in node/Cargo.lock"])])
        self.assertEqual(view.problems, [])

        view.input("tap", block="nav", value="project:MB")                   # and back
        self.assertEqual(view.title, "CVE · MB")
        view.input("tap", block="nav", value="projects")
        self.assertEqual(view.title, "CVE tracker")
        for kind, fields in [("tap", {"block": "h", "value": "x"}), ("submit", {"block": "open", "value": {}})]:
            with self.assertRaises(InputRefused) as e:
                view.input(kind, **fields)
            self.assertIn("only shows records: change one with /cve set", str(e.exception))
        linked = self.node.open_pane("cve", target={"view": "impacts", "project": "PFE"})   # as /cve add links it
        self.assertEqual(linked.title, "CVE · PFE")
        self.assertEqual(linked.block("open").list.items[0].subtitle, "affected · zip 8.6.0")
        self.assertEqual(linked.problems, [])

    def test_the_pane_says_why_when_the_feed_cant_be_had(self):
        view = self.node.open_pane("cve", target={"view": "recent", "ecosystem": "rust"})
        self.assertEqual(view.title, "CVE tracker")
        self.assertEqual(view.block("e").empty.title, "Couldn't load it")
        self.assertIn("offline", view.block("e").empty.note)
        self.assertEqual(view.problems, [])

    def test_a_node_without_its_files_still_shows_an_advisory(self):
        self.node.stop()
        self.node = self.start(methods={})
        text = self.run_command("cve.show", {"advisory": "CVE-2026-1234"})["text"]
        self.assertIn("Our records aren't readable here: this node can't keep an extension's files yet", text)

    def osv(self) -> str:
        """A stand-in OSV over HTTP (test_core's OSV), for the extension's process: its URL."""
        fake = OSV()

        class Answer(BaseHTTPRequestHandler):
            def reply(self, body):
                try:
                    got, code = fake.fetch(self.path, body), 200
                except ValueError:
                    got, code = {"code": 5, "message": "Bug not found."}, 404
                data = json.dumps(got).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self.reply(None)

            def do_POST(self):
                self.reply(self.rfile.read(int(self.headers["Content-Length"])))

            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Answer)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.asked = fake.asked
        return f"http://127.0.0.1:{server.server_port}/v1"

    def scanning(self, *projects):
        """The extension again with these projects, asking the stand-in OSV (and its KEV and EPSS) at self.url."""
        base = self.url.removesuffix("/v1")
        env = ({"CVE_OSV_URL": self.url, "CVE_KEV_URL": f"{base}/kev.json", "CVE_EPSS_URL": f"{base}/epss"}
               if self.url else {"CVE_OFFLINE": "1"})
        self.node.stop()
        self.node = self.start(settings={"projects": list(projects)}, env=env)

    def test_a_scan_opens_a_record_for_a_hit_at_one_ref_and_finds_it_gone_at_the_other(self):
        repo = Repo(self.dir / "app" / "repo")
        self.url = self.osv()
        (self.dir / "app" / "web").mkdir()
        shutil.copy(ROOT / "tests" / "fixtures" / "package-lock.json", self.dir / "app" / "web")
        self.scanning({"key": "mb", "repo": str(repo.checkout), "ref": "v1"}, {"key": "WEB", "repo": str(self.dir / "app" / "web")})
        got = self.run_command("cve.scan", {})
        hit = {"advisory": "CVE-2026-9999", "package": "rustls-webpki", "version": "0.103.15", "ecosystem": "rust",
               "severity": "medium", "fixed": "0.103.16", "kev": True, "epss": 0.42, "cvss": 4.8}
        self.assertEqual({k: got[k] for k in ("new", "reopened", "gone", "open", "failed")},
                         {"new": 1, "reopened": 0, "gone": 0, "open": 1, "failed": 0})
        mb, web = got["projects"]
        self.assertEqual(mb, {"project": "MB", "repo": str(repo.checkout), "ref": "v1", "commit": repo.v1,
                              "new": [hit], "reopened": [], "still": [], "confirmed": [], "gone": [], "open": 1,
                              "note": "",
                              "plan": [{"ecosystem": "rust", "package": "rustls-webpki", "from": "0.103.15",
                                        "to": "0.103.16", "fixes": 1, "advisories": ["CVE-2026-9999"],
                                        "unfixed": [], "kev": True, "files": ["node/Cargo.lock"]}], "skipped": 0})
        self.assertEqual((web["ref"], web["commit"], web["new"], web["open"]), ("", "", [], 0))
        self.assertEqual(web["note"], "read as files, not from git: it isn't a git repo")
        self.assertTrue(got["text"].startswith("Scanned MB, WEB: 1 new, 0 reopened, 0 gone, 1 open."), got["text"])
        self.assertIn("Read as files, not from git: it isn't a git repo.", got["text"])
        self.assertIn("- new: **CVE-2026-9999** (medium 4.8, known exploited, EPSS 42%) rust rustls-webpki", got["text"])
        self.assertTrue(got["text"].endswith("EPSS scores: FIRST, https://www.first.org/epss"), got["text"])
        listed = self.run_command("cve.impacts", {"project": "MB"})["text"]           # open ones fix-first
        self.assertIn("- **CVE-2026-9999** MB: investigating, known exploited, EPSS 42%", listed)
        self.assertIn("Upgrade plan: 1 upgrade fixes 1 of 1 advisory.", got["text"])

        planned = self.run_command("cve.plan", {"project": "mb"})                     # read again: nothing written
        self.assertEqual(([(x["package"], x["from"], x["to"], x["fixes"]) for x in planned["plan"]], planned["upgrades"]),
                         ([("rustls-webpki", "0.103.15", "0.103.16", 1)], 1))
        self.assertEqual((planned["plan"][0]["repo"], planned["plan"][0]["commit"]), (str(repo.checkout), repo.v1))
        self.assertTrue(planned["text"].startswith("**MB**: Upgrade plan: 1 upgrade fixes 1 of 1 advisory.\n"
                                                   "- rust rustls-webpki 0.103.15 → 0.103.16: fixes 1, one known exploited"),
                        planned["text"])
        self.assertIn("which project?", self.refused("cve.plan", {}))
        self.assertIn("PFE isn't", self.refused("cve.plan", {"project": "PFE"}))

        kept = [k for k in self.files.versions if k.startswith("scans/mb/")]           # the last scan, for the pane
        self.assertEqual(len(kept), 1, kept)
        view = self.node.open_pane("cve", target={"view": "impacts", "project": "MB"})
        (row,) = view.block("open").list.items                               # known exploited, flagged
        self.assertEqual((row.title, row.badge, row.tone), ("CVE-2026-9999", "KEV", types.Tone.TONE_BAD))
        self.assertIn("known exploited · EPSS 42%", row.subtitle)
        (up,) = view.block("plan").list.items
        self.assertEqual((up.title, up.subtitle), ("rustls-webpki 0.103.15 → 0.103.16",
                                                   f"fixes 1 · known exploited · node/Cargo.lock · {repo.checkout}"))
        (last,) = view.block("scans").list.items
        self.assertTrue(last.subtitle.startswith(f"v1 ({repo.v1[:8]}) · scanned "), last.subtitle)
        self.assertTrue(last.subtitle.endswith("1 new, 0 gone, 1 open"), last.subtitle)
        self.assertTrue(view.block("h").text.heading.subtitle.startswith("last scanned "))
        self.assertEqual(view.problems, [])
        picker = self.node.open_pane("cve")
        self.assertEqual(picker.block("projects").list.items[0].badge, "KEV")
        record = self.files.versions["impacts/mb/cve-2026-9999.toml"]
        self.assertEqual(len(record), 1)
        self.assertIn('status = "investigating"', record[0])
        self.assertIn(f'found_by = "cve scan on mac-test at v1 ({repo.v1[:8]})"', record[0])
        event = self.node.events["cve.scanned"]
        self.assertEqual({k: event[k] for k in ("new", "reopened", "gone", "open")},
                         {"new": 1, "reopened": 0, "gone": 0, "open": 1})
        self.assertEqual(event["projects"][0], {"project": "MB", "ref": "v1", "commit": repo.v1, "new": 1,
                                                "reopened": 0, "gone": 0, "still": 0, "confirmed": 0, "open": 1})

        self.scanning({"key": "MB", "repo": str(repo.checkout)}, {"key": "WEB", "repo": str(self.dir / "app" / "web")})
        got = self.run_command("cve.scan", {"project": "mb"})                  # origin/main, after a fetch
        self.assertEqual([p["project"] for p in got["projects"]], ["MB"])
        self.assertEqual((got["new"], got["gone"], got["open"]), (0, 1, 1))     # nothing new still answers
        gone = {**hit, "kev": None, "epss": None, "cvss": None}                 # gone isn't looked up again
        self.assertEqual((got["projects"][0]["commit"], got["projects"][0]["gone"]), (repo.v2, [gone]))
        self.assertEqual(len(self.files.versions["impacts/mb/cve-2026-9999.toml"]), 1)      # left as it was
        self.assertEqual(self.node.events["cve.scanned"]["gone"], 1)
        self.assertNotIn("0.103.99", {v for _, _, v in self.asked})             # never the working tree

    def test_one_project_that_can_t_be_read_doesn_t_stop_the_others(self):
        repo = Repo(self.dir / "app" / "repo")
        self.url = self.osv()
        self.scanning({"key": "MB", "repo": str(repo.checkout), "ref": "v1"},
                      {"key": "PFE", "repo": str(repo.checkout), "ref": "origin/nope"})
        got = self.run_command("cve.scan", {})
        self.assertEqual({k: got[k] for k in ("new", "reopened", "gone", "open", "failed")},
                         {"new": 1, "reopened": 0, "gone": 0, "open": 1, "failed": 1})
        mb, pfe = got["projects"]
        self.assertEqual((mb["commit"], [h["advisory"] for h in mb["new"]]), (repo.v1, ["CVE-2026-9999"]))
        why = f"origin/nope isn't a branch, tag or commit in {repo.checkout}"
        self.assertEqual(pfe, {"project": "PFE", "repo": str(repo.checkout), "ref": "origin/nope", "error": why})
        self.assertTrue(got["text"].startswith("Scanned MB, PFE: 1 new, 0 reopened, 0 gone, 1 open, 1 failed."),
                        got["text"])
        self.assertIn(f"**PFE** couldn't be scanned: {why}.", got["text"])
        event = self.node.events["cve.scanned"]
        self.assertEqual((event["failed"], event["new"]), (1, 1))
        self.assertEqual(event["projects"][1], {"project": "PFE", "ref": "origin/nope", "error": why})
        self.assertIn("impacts/mb/cve-2026-9999.toml", self.files.versions)

    def test_fixed_needs_its_evidence_and_scans_check_it(self):
        repo = Repo(self.dir / "app" / "repo")
        self.url = self.osv()
        self.scanning({"key": "MB", "repo": str(repo.checkout), "ref": "v1"})
        self.run_command("cve.scan", {})
        said = self.refused("cve.set", {"advisory": "CVE-2026-9999", "project": "MB", "status": "fixed"})
        self.assertIn("fixed needs its evidence: pr=<link>, commit=<link> or fixed_in=<release>", said)
        self.assertIn("fixed needs its evidence",
                      self.refused("cve.add", {"advisory": "CVE-2026-1", "project": "MB", "status": "fixed"}))
        self.assertNotIn("impacts/mb/cve-2026-1.toml", self.files.versions)          # nothing written
        self.run_command("cve.set", {"advisory": "CVE-2026-9999", "project": "MB", "status": "fixed",
                                     "commit": "https://github.com/x/app/commit/abc1234"})
        self.assertIn('prs = ["https://github.com/x/app/commit/abc1234"]',
                      self.files.versions["impacts/mb/cve-2026-9999.toml"][-1])
        self.assertIn("MB: fixed, not confirmed by a scan yet", self.run_command("cve.show", {"advisory": "CVE-2026-9999"})["text"])

        got = self.run_command("cve.scan", {})                                        # still at v1
        self.assertEqual(([h["advisory"] for h in got["projects"][0]["still"]], got["still"]), (["CVE-2026-9999"], 1))
        self.assertIn("Marked fixed but still there (the fix isn't at this ref yet): CVE-2026-9999.", got["text"])

        self.scanning({"key": "MB", "repo": str(repo.checkout)})                       # origin/main: gone
        got = self.run_command("cve.scan", {})
        self.assertEqual((got["projects"][0]["confirmed"], got["confirmed"]), (["CVE-2026-9999"], 1))
        self.assertEqual(self.node.events["cve.scanned"]["projects"][0]["confirmed"], 1)
        self.assertIn(f"MB: fixed, confirmed in repo/origin at origin/main ({repo.v2[:8]}) on 20",
                      self.run_command("cve.impacts", {"project": "MB"})["text"])

    def test_scan_refusals_say_what_to_do(self):
        self.assertIn("no projects to scan: add them to the projects setting", self.refused("cve.scan", {}))
        self.url = ""
        self.scanning({"key": "MB", "repo": str(self.dir / "app")})
        self.assertIn("XYZ isn't in the projects setting (MB)", self.refused("cve.scan", {"project": "xyz"}))
        self.scanning({"key": "MB", "repo": "/etc"}, {"key": "PFE", "repo": str(self.dir / "app" / "gone")})
        said = self.refused("cve.scan", {})                     # every project failed: only then is it refused
        self.assertIn("no project could be scanned: MB: /etc is outside the folders", said)
        self.assertIn(f"PFE: {self.dir / 'app' / 'gone'} isn't a folder on mac-test", said)
        self.scanning({"key": "my project", "repo": str(self.dir / "app")})
        self.assertIn("the projects setting: projects #1: key is a project's key", self.refused("cve.scan", {}))

    def test_nothing_scans_on_its_own(self):
        self.url = ""
        self.scanning({"key": "MB", "repo": str(self.dir / "app")})
        time.sleep(1.5)
        self.assertNotIn("cve.scanned", self.node.events)
        self.assertEqual([m for m, _ in self.node.asked if m.startswith("files.")], [])


if __name__ == "__main__":
    unittest.main()
