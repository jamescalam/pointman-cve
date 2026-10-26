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

    def test_refusals_say_what_to_do(self):
        self.assertIn("isn't recorded for MB: add it with /cve add",
                      self.refused("cve.set", {"advisory": "CVE-2026-404", "project": "MB", "status": "fixed"}))
        self.assertIn("not_affected says why",
                      self.refused("cve.add", {"advisory": "CVE-2026-5", "project": "MB", "status": "not_affected"}))
        self.assertIn("outside the folders", self.refused("cve.check", {"folder": "/etc"}))
        self.assertIn("which folder?", self.refused("cve.check", {}))

    def test_the_pane_shows_our_impacts(self):
        self.run_command("cve.add", {"advisory": "GHSA-abcd-efgh-ijkl", "project": "PFE", "status": "affected"})
        view = self.node.open_pane("cve", target={"view": "impacts"})
        self.assertEqual(view.title, "CVE impacts")
        self.assertEqual([b.name for b in view.blocks], ["h", "st", "t"])
        self.assertEqual(view.block("h").text.heading.subtitle, "every project")
        table = view.block("t").chart
        self.assertEqual(table.type, types.Chart.Type.TYPE_TABLE)
        self.assertEqual(table.data.row_ids, ["impacts/pfe/ghsa-abcd-efgh-ijkl.toml"])
        self.assertEqual(table.data.rows[0][:3], ["GHSA-abcd-efgh-ijkl", "PFE", "affected"])
        affected = view.block("saffected").chart
        self.assertEqual((affected.title, affected.data.rows, affected.tone), ("Affected", [[1]], types.Tone.TONE_BAD))
        self.assertEqual([c.name for c in view.block("st").layout.stack.children],
                         ["sinvestigating", "saffected", "snot_affected", "sfixed"])
        self.assertEqual(view.problems, [])
        with self.assertRaises(InputRefused) as e:
            view.input("tap", block="t", item="impacts/pfe/ghsa-abcd-efgh-ijkl.toml")
        self.assertIn("read-only", str(e.exception))

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
        self.node.stop()
        self.node = self.start(settings={"projects": list(projects)}, env={"CVE_OSV_URL": self.url})

    def test_a_scan_opens_a_record_for_a_hit_at_one_ref_and_finds_it_gone_at_the_other(self):
        repo = Repo(self.dir / "app" / "repo")
        self.url = self.osv()
        (self.dir / "app" / "web").mkdir()
        shutil.copy(ROOT / "tests" / "fixtures" / "package-lock.json", self.dir / "app" / "web")
        self.scanning({"key": "mb", "repo": str(repo.checkout), "ref": "v1"}, {"key": "WEB", "repo": str(self.dir / "app" / "web")})
        got = self.run_command("cve.scan", {})
        hit = {"advisory": "CVE-2026-9999", "package": "rustls-webpki", "version": "0.103.15", "ecosystem": "rust",
               "severity": "medium", "fixed": "0.103.16"}
        self.assertEqual({k: got[k] for k in ("new", "reopened", "gone", "open", "failed")},
                         {"new": 1, "reopened": 0, "gone": 0, "open": 1, "failed": 0})
        mb, web = got["projects"]
        self.assertEqual(mb, {"project": "MB", "repo": str(repo.checkout), "ref": "v1", "commit": repo.v1,
                              "new": [hit], "reopened": [], "gone": [], "open": 1, "note": ""})
        self.assertEqual((web["ref"], web["commit"], web["new"], web["open"]), ("", "", [], 0))
        self.assertEqual(web["note"], "read as files, not from git: it isn't a git repo")
        self.assertTrue(got["text"].startswith("Scanned MB, WEB: 1 new, 0 reopened, 0 gone, 1 open."), got["text"])
        self.assertIn("Read as files, not from git: it isn't a git repo.", got["text"])
        record = self.files.versions["impacts/mb/cve-2026-9999.toml"]
        self.assertEqual(len(record), 1)
        self.assertIn('status = "investigating"', record[0])
        self.assertIn(f'found_by = "cve scan on mac-test at v1 ({repo.v1[:8]})"', record[0])
        event = self.node.events["cve.scanned"]
        self.assertEqual({k: event[k] for k in ("new", "reopened", "gone", "open")},
                         {"new": 1, "reopened": 0, "gone": 0, "open": 1})
        self.assertEqual(event["projects"][0], {"project": "MB", "ref": "v1", "commit": repo.v1, "new": 1,
                                                "reopened": 0, "gone": 0, "open": 1})

        self.scanning({"key": "MB", "repo": str(repo.checkout)}, {"key": "WEB", "repo": str(self.dir / "app" / "web")})
        got = self.run_command("cve.scan", {"project": "mb"})                  # origin/main, after a fetch
        self.assertEqual([p["project"] for p in got["projects"]], ["MB"])
        self.assertEqual((got["new"], got["gone"], got["open"]), (0, 1, 1))     # nothing new still answers
        self.assertEqual((got["projects"][0]["commit"], got["projects"][0]["gone"]), (repo.v2, [hit]))
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
