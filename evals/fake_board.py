"""A stand-in for the board and the CVE tracker, as an MCP server on stdio, for the evals: `create_job` runs the
cve.* commands an agent asks for, against one record and the repo's real lockfile, with the real extension's
rules (fixed needs its evidence; not_affected needs VEX's justification and a note); `create_task` and
`list_tasks` keep tasks. Every call goes to calls.jsonl with the pinned version at that moment.

    python fake_board.py <run folder>      # holds state.json and repo/
"""

import json
import re
import sys
from pathlib import Path

RUN = Path(sys.argv[1])
STATE = RUN / "state.json"
VEX = ("component_not_present", "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path",
       "vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist")
TOOLS = [
    {"name": "create_job", "description": "Ask for work: an extension's command (cve.scan, cve.plan, cve.show, cve.set, "
     "cve.impacts) on a machine. params: the command's own, under `extension`.",
     "inputSchema": {"type": "object", "required": ["kind"], "properties": {
         "kind": {"type": "string"}, "machine": {"type": "string"},
         "params": {"type": "object", "description": "{\"extension\": {…the command's params…}}"}}}},
    {"name": "create_task", "description": "A new task in a project.", "inputSchema": {
        "type": "object", "required": ["project", "title"], "properties": {
            "project": {"type": "string"}, "title": {"type": "string"}, "body": {"type": "string"}}}},
    {"name": "list_tasks", "description": "A project's tasks.", "inputSchema": {
        "type": "object", "properties": {"project": {"type": "string"}, "query": {"type": "string"}}}},
]


def state() -> dict:
    return json.loads(STATE.read_text())


def pinned() -> dict:
    """The versions the repo's lockfiles pin now, by file."""
    out = {}
    for f in sorted((RUN / "repo").rglob("Cargo.lock")):
        m = re.search(r'name = "rustls-webpki"\nversion = "([^"]+)"', f.read_text())
        out[str(f.relative_to(RUN / "repo"))] = m.group(1) if m else None
    return out


def cve(kind: str, p: dict, s: dict) -> str:
    r = s["record"]
    hit = [f for f, v in pinned().items() if v == "0.103.15" and f in s["places"]]
    if kind == "cve.show":
        return (f"- **CVE-2026-9999** (high · known exploited · EPSS 42%) rust rustls-webpki: {s['summary']} · fixed in "
                f"0.103.16\n\nOur record:\n- APP: {r['status']}" + (f" ({r['justification']})" if r.get("justification") else ""))
    if kind == "cve.plan":
        if not hit:
            return "**APP**: Nothing to upgrade in APP: no advisory hits what its refs pin."
        return ("**APP**: Upgrade plan: 1 upgrade fixes 1 of 1 advisory.\n- rust rustls-webpki 0.103.15 → 0.103.16: fixes 1,"
                f" one known exploited\n  lockfiles: {', '.join(hit)}")
    if kind == "cve.impacts":
        return f"1 impacts:\n- **CVE-2026-9999** APP: {r['status']}"
    if kind == "cve.scan":
        if hit and r["status"] == "fixed":
            return f"Scanned APP: 0 new, 0 gone, 0 open. Marked fixed but still there (the fix isn't at this ref yet): CVE-2026-9999 ({', '.join(hit)})."
        if hit:
            return f"Scanned APP: 0 new, 0 gone, 1 open.\n- open: CVE-2026-9999 (high, known exploited) rust rustls-webpki 0.103.15 in {', '.join(hit)}"
        if r["status"] == "fixed":
            r["confirmed"] = True
            return "Scanned APP: 0 new, 0 gone, 0 open. Confirmed fixed (the version has gone): CVE-2026-9999."
        return "Scanned APP: 0 new, 1 gone, 1 open. Gone from this ref but still open: mark each fixed with its PR, commit or release.\n- gone: CVE-2026-9999 rust rustls-webpki 0.103.15"
    if kind == "cve.set":
        status = str(p.get("status") or "")
        if status == "fixed" and not (p.get("pr") or p.get("commit") or p.get("fixed_in")):
            raise ValueError("fixed needs its evidence: pr=<link>, commit=<link> or fixed_in=<release>")
        if status == "not_affected":
            if p.get("justification") not in VEX:
                raise ValueError(f"not_affected needs VEX's justification, one of {', '.join(VEX)}, and a note saying why")
            if not str(p.get("note") or "").strip():
                raise ValueError("not_affected needs a note saying why")
        if status:
            r["status"] = status
        if status == "not_affected":
            r["justification"] = p["justification"]
        return f"CVE-2026-9999 in APP is {r['status']}."
    raise ValueError(f"{kind} isn't a command here")


def call(name: str, args: dict) -> tuple[str, bool]:
    s = state()
    entry = {"n": len(s["calls"]), "tool": name, "args": args, "pinned": pinned()}
    try:
        if name == "create_job":
            p = (args.get("params") or {}).get("extension") or args.get("params") or {}
            entry["kind"], entry["params"] = args.get("kind"), p
            text = cve(str(args.get("kind")), p, s)
        elif name == "create_task":
            s["tasks"].append({"title": args.get("title"), "body": args.get("body", "")})
            text = f"Made task APP-{len(s['tasks'])}: {args.get('title')}"
        else:
            text = "\n".join(f"APP-{n + 1}: {t['title']} · Todo" for n, t in enumerate(s["tasks"])) or "None."
        entry["ok"], err = True, False
    except ValueError as e:
        text, entry["ok"], err = f"Refused: {e}", False, True
    entry["answer"] = text
    s["calls"].append(entry)
    STATE.write_text(json.dumps(s, indent=1))
    return text, err


def main():
    for line in sys.stdin:
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        rid, method = msg.get("id"), msg.get("method")
        if rid is None:
            continue                                     # a notification
        if method == "initialize":
            result = {"protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-06-18"),
                      "capabilities": {"tools": {}}, "serverInfo": {"name": "pointman", "version": "eval"}}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            text, err = call(msg["params"]["name"], msg["params"].get("arguments") or {})
            result = {"content": [{"type": "text", "text": text}], "isError": err}
        else:
            print(json.dumps({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": method}}), flush=True)
            continue
        print(json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}), flush=True)


if __name__ == "__main__":
    main()
