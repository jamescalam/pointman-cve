"""The extension's process as the node runs it, under the SDK's stand-in node, with a stand-in for the node's own
files (files.put, files.list, files.get) and no network (CVE_OFFLINE). Skipped where $POINTMAN_EXTENSIONS_SDK
doesn't name the node's Python SDK (one with pointman_extension_types, the typed protocol)."""

import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

from pointman_cve.store import path_ok

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

    def start(self, settings=None, methods=None):
        """The extension under a stand-in node (with these settings, or its files' stand-in left out)."""
        node = StandInNode(ROOT, settings=settings, methods=self.files.methods() if methods is None else methods,
                           env={"CVE_OFFLINE": "1"}, roots=[self.dir / "app"], machine="mac-test",
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

    def test_the_daily_check_says_when_it_looked(self):
        (self.dir / "app" / "empty").mkdir()
        self.node.stop()
        self.node = self.start(settings={"folders": [str(self.dir / "app" / "empty")], "thread": 17856})
        for _ in range(200):
            if "cve.status" in self.node.events:
                break
            time.sleep(0.05)
        self.assertEqual({k: v for k, v in self.node.events.get("cve.status", {}).items() if k != "checked"},
                         {"advisories": 0, "new": 0}, self.node.log)
        self.assertNotIn("board.post", [m for m, _ in self.node.asked])     # nothing new: nothing posted


if __name__ == "__main__":
    unittest.main()
