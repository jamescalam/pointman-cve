"""The extension's process as the node runs it, through the node's Python SDK, with impacts kept in a folder
(CVE_FILES_DIR) and no network (CVE_OFFLINE). Skipped where $POINTMAN_EXTENSIONS_SDK doesn't name the SDK."""

import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SDK = os.environ.get("POINTMAN_EXTENSIONS_SDK")


@unittest.skipUnless(SDK and Path(SDK, "pointman_extension.py").is_file(), "needs the node's Python SDK")
class ExtensionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        (self.dir / "files").mkdir()
        (self.dir / "app" / "node").mkdir(parents=True)
        shutil.copy(ROOT / "tests" / "fixtures" / "Cargo.lock", self.dir / "app" / "node")
        env = {**os.environ, "PYTHONPATH": os.pathsep.join([SDK, str(ROOT)]),
               "CVE_FILES_DIR": str(self.dir / "files"), "CVE_OFFLINE": "1"}
        self.proc = subprocess.Popen([sys.executable, "-m", "pointman_cve"], cwd=ROOT, env=env, text=True,
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.lines, self.seen, self.n = queue.Queue(), [], 0
        threading.Thread(target=lambda: [self.lines.put(json.loads(x)) for x in self.proc.stdout], daemon=True).start()
        self.call("initialize", {"protocol": 1, "machine": "mac-test", "settings": {},
                                 "roots": [str(self.dir / "app")], "state_dir": str(self.dir / "state")})

    def tearDown(self):
        self.proc.stdin.close()
        self.proc.wait(5)
        self.proc.stdout.close()
        self.proc.stderr.close()
        self.tmp.cleanup()

    def send(self, method, params, rid=None):
        msg = {"jsonrpc": "2.0", "method": method, "params": params, **({"id": rid} if rid else {})}
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def wait(self, want, timeout=10.0):
        end = time.time() + timeout
        while time.time() < end:
            try:
                m = self.lines.get(timeout=0.2)
            except queue.Empty:
                continue
            self.seen.append(m)
            if want(m):
                return m
        self.fail(f"nothing came: {self.seen[-4:]}")

    def call(self, method, params):
        self.n += 1
        rid = f"n{self.n}"
        self.send(method, params, rid)
        return self.wait(lambda m: m.get("id") == rid)

    def run_command(self, kind, params):
        self.n += 1
        cid = f"c{self.n}"
        self.send("command.start", {"id": cid, "kind": kind, "params": params}, f"s{self.n}")
        m = self.wait(lambda m: m.get("method") in ("done", "failed") and m["params"]["id"] == cid)
        return m["method"], m["params"]

    def test_record_update_and_list_an_impact(self):
        kind, got = self.run_command("cve.add", {"advisory": "CVE-2026-1234", "project": "mb", "package": "rustls-webpki",
                                                 "version": "0.103.15", "thread": "17856", "note": "found in the sweep"})
        self.assertEqual(kind, "done", got)
        self.assertEqual(got["result"]["impact"], "impacts/mb/cve-2026-1234.toml")
        self.assertEqual(got["result"]["pane"], {"open": "cve", "target": {"view": "impacts", "project": "MB"}})
        kind, got = self.run_command("cve.add", {"advisory": "CVE-2026-1234", "project": "MB"})
        self.assertEqual(kind, "failed")
        self.assertIn("already recorded", got["error"])

        kind, got = self.run_command("cve.set", {"advisory": "CVE-2026-1234", "project": "MB", "status": "fixed",
                                                 "pr": "https://github.com/pointman-ai/pointman/pull/1", "fixed_in": "release 35"})
        self.assertEqual((kind, got["result"]["version"]), ("done", 2), got)
        text = (self.dir / "files" / "impacts" / "mb" / "cve-2026-1234.toml@2").read_text()
        self.assertIn('status = "fixed"', text)
        self.assertIn('threads = ["pointman://thread/17856"]', text)
        self.assertIn("found in the sweep", text)

        kind, got = self.run_command("cve.impacts", {"project": "MB"})
        self.assertIn("**CVE-2026-1234** MB: fixed, fixed in release 35", got["result"]["text"])
        kind, got = self.run_command("cve.show", {"advisory": "CVE-2026-1234"})
        self.assertIn("offline", got["result"]["text"])                  # the feed wasn't asked
        self.assertIn("- MB: fixed, fixed in release 35", got["result"]["text"])

    def test_one_fix_records_several_advisories_at_once(self):
        kind, got = self.run_command("cve.add", {"advisory": "RUSTSEC-2026-0367, RUSTSEC-2026-0368", "project": "MB",
                                                 "package": "zip", "version": "8.6.0", "status": "affected"})
        self.assertEqual(kind, "done", got)
        self.assertEqual(got["result"]["impacts"], ["impacts/mb/rustsec-2026-0367.toml",
                                                    "impacts/mb/rustsec-2026-0368.toml"])
        kind, got = self.run_command("cve.add", {"advisory": ["RUSTSEC-2026-0368", "RUSTSEC-2026-0369"],
                                                 "project": "MB", "status": "affected"})
        self.assertEqual(got["result"]["already"], ["RUSTSEC-2026-0368"])
        kind, got = self.run_command("cve.set", {"advisory": "RUSTSEC-2026-0367,RUSTSEC-2026-0368,RUSTSEC-2026-0370",
                                                 "project": "MB", "status": "fixed", "fixed_in": "release 36",
                                                 "pr": "https://github.com/pointman-ai/pointman/commit/d9ea9a8b"})
        self.assertEqual((kind, got["result"]["missing"]), ("done", ["RUSTSEC-2026-0370"]), got)
        self.assertIn("Changed 2 advisories in MB", got["result"]["text"])
        kind, got = self.run_command("cve.impacts", {"project": "MB"})
        self.assertEqual(got["result"]["text"].count("fixed, fixed in release 36"), 2)

    def test_refusals_say_what_to_do(self):
        kind, got = self.run_command("cve.set", {"advisory": "CVE-2026-404", "project": "MB", "status": "fixed"})
        self.assertIn("isn't recorded for MB: add it with /cve add", got["error"])
        kind, got = self.run_command("cve.add", {"advisory": "CVE-2026-5", "project": "MB", "status": "not_affected"})
        self.assertIn("not_affected says why", got["error"])
        kind, got = self.run_command("cve.check", {"folder": "/etc"})
        self.assertEqual(kind, "failed")
        self.assertIn("outside the folders", got["error"])
        kind, got = self.run_command("cve.check", {})
        self.assertIn("which folder?", got["error"])

    def test_the_pane_shows_our_impacts(self):
        self.run_command("cve.add", {"advisory": "GHSA-abcd-efgh-ijkl", "project": "PFE", "status": "affected"})
        opened = self.call("pane.open", {"pane": "pane_1", "open": "cve", "target": {"view": "impacts"},
                                         "context": {}, "viewer": {"person": "james"}})
        blocks = opened["result"]["blocks"]
        self.assertEqual([b["type"] for b in blocks], ["heading", "stack", "table"])
        self.assertEqual(blocks[2]["rows"][0]["cells"][:3], ["GHSA-abcd-efgh-ijkl", "PFE", "affected"])
        self.assertEqual(blocks[1]["children"][1]["value"], 1)          # affected: 1


if __name__ == "__main__":
    unittest.main()
