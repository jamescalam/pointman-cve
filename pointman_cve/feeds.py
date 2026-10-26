"""Where advisories come from. We never keep or edit them: they're fetched when asked for.

- **Recent:** GitHub's advisory database (`api.github.com/advisories`), newest first, reviewed and malware
  advisories across ecosystems, with CVE ids, severities and the versions that fix them. No sign-in needed.
- **Our versions and any one advisory:** OSV.dev (`api.osv.dev`), asked in one batch for every package and
  version our lockfiles pin, and then for each advisory it names. It covers CVE, GHSA, RUSTSEC, PYSEC and
  malicious-package ids, with no hourly limit: GitHub's 60 an hour are kept for the recent list.
- **GitHub Actions** are the exception: OSV keeps their advisories but doesn't compare their versions (asked with
  one, it finds nothing). Each action is asked by name alone, and its pinned tag is checked against each
  advisory's ranges here.
"""

from __future__ import annotations

import json
import math
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field

GITHUB = "https://api.github.com/advisories"
OSV = os.environ.get("CVE_OSV_URL") or "https://api.osv.dev/v1"       # CVE_OSV_URL: tests' stand-in OSV
TIMEOUT = 20
CACHE_FOR = 600          # seconds a recent list is reused
BATCH = 500              # OSV's querybatch limit is 1000

# our ecosystem names (as GitHub's) → OSV's
OSV_ECOSYSTEM = {"rust": "crates.io", "pip": "PyPI", "go": "Go", "npm": "npm", "rubygems": "RubyGems",
                 "maven": "Maven", "nuget": "NuGet", "composer": "Packagist", "swift": "SwiftURL",
                 "actions": "GitHub Actions"}
GITHUB_ECOSYSTEM = {v: k for k, v in OSV_ECOSYSTEM.items()}

Fetch = Callable[[str, bytes | None], object]


def fetch_json(url: str, body: bytes | None = None) -> object:
    """GET (or POST with a JSON body) and the JSON answer; a ValueError saying what went wrong. CVE_OFFLINE=1
    (tests) answers every call that way."""
    if os.environ.get("CVE_OFFLINE") == "1":
        raise ValueError(f"offline: {urllib.parse.urlsplit(url).netloc} not asked")
    req = urllib.request.Request(url, data=body, headers={
        "Accept": "application/json", "User-Agent": "pointman-cve",
        **({"Content-Type": "application/json"} if body is not None else {})})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 403 and "rate limit" in (e.read() or b"").decode("utf-8", "replace").lower():
            raise ValueError("GitHub's advisory database is rate-limited for now (60 an hour without "
                             "sign-in): try again in a while") from None
        raise ValueError(f"{urllib.parse.urlsplit(url).netloc} answered {e.code}") from None
    except (urllib.error.URLError, TimeoutError) as e:
        raise ValueError(f"couldn't reach {urllib.parse.urlsplit(url).netloc}: {e}") from None


@dataclass
class Advisory:
    id: str                               # GHSA, CVE, OSV or MAL id
    aliases: list[str]
    summary: str
    severity: str                         # critical, high, medium, low, unknown
    published: str
    url: str
    kind: str = "reviewed"                # reviewed or malware
    packages: list[dict] = field(default_factory=list)   # {ecosystem, name, vulnerable, fixed}
    score: float | None = None

    @property
    def cve(self) -> str | None:
        return next((a for a in [self.id, *self.aliases] if a.startswith("CVE-")), None)

    def ids(self) -> list[str]:
        """Its ids, the CVE first when there is one."""
        out = [self.cve] if self.cve else []
        return out + [i for i in [self.id, *self.aliases] if i not in out]


def from_github(a: dict) -> Advisory:
    pkgs = []
    for v in a.get("vulnerabilities") or []:
        p = v.get("package") or {}
        pkgs.append({"ecosystem": p.get("ecosystem") or "", "name": p.get("name") or "",
                     "vulnerable": v.get("vulnerable_version_range") or "",
                     "fixed": v.get("first_patched_version") or ""})
    cvss = (a.get("cvss") or {}).get("score")
    return Advisory(id=a.get("ghsa_id") or "", aliases=[a["cve_id"]] if a.get("cve_id") else [],
                    summary=a.get("summary") or "", severity=a.get("severity") or "unknown",
                    published=a.get("published_at") or "", url=a.get("html_url") or "",
                    kind=a.get("type") or "reviewed", packages=pkgs,
                    score=cvss if isinstance(cvss, (int, float)) else None)


def from_osv(v: dict) -> Advisory:
    pkgs = []
    for aff in v.get("affected") or []:
        p = aff.get("package") or {}
        fixed = [e["fixed"] for r in aff.get("ranges") or [] for e in r.get("events") or [] if "fixed" in e]
        pkgs.append({"ecosystem": GITHUB_ECOSYSTEM.get(p.get("ecosystem"), p.get("ecosystem") or ""),
                     "name": p.get("name") or "", "vulnerable": "", "fixed": ", ".join(fixed)})
    sev = ((v.get("database_specific") or {}).get("severity") or "unknown").lower()
    sev = {"moderate": "medium"}.get(sev, sev)
    vid = v.get("id") or ""
    return Advisory(id=vid, aliases=list(v.get("aliases") or []), summary=v.get("summary") or v.get("details", "")[:200],
                    severity=sev, published=v.get("published") or "", url=f"https://osv.dev/vulnerability/{vid}",
                    kind="malware" if vid.startswith("MAL-") else "reviewed", packages=pkgs)


def merge_aliases(by_advisory: dict[str, list[tuple]], details: dict[str, Advisory | None]) -> dict[str, list[tuple]]:
    """One entry an advisory: OSV names the same one under each database's id (GHSA-…, RUSTSEC-…)."""
    out: dict[str, list[tuple]] = {}
    seen: dict[str, str] = {}
    for aid, keys in by_advisory.items():
        a = details.get(aid)
        names = {aid.upper(), *(i.upper() for i in (a.ids() if a else []))}
        first = next((seen[n] for n in names if n in seen), None)
        if first is None:
            out[aid] = list(keys)
            first = aid
        else:
            out[first] += [k for k in keys if k not in out[first]]
        for n in names:
            seen.setdefault(n, first)
    return out


class Feeds:
    def __init__(self, fetch: Fetch = fetch_json):
        self.fetch = fetch
        self._recent: dict[tuple, tuple[float, list[Advisory]]] = {}

    def recent(self, ecosystem: str | None = None, days: int = 7, limit: int = 30) -> list[Advisory]:
        """Advisories published in the last `days`, newest first: one ecosystem (GitHub's name), or all."""
        key = (ecosystem, days, limit)
        hit = self._recent.get(key)
        if hit and time.time() - hit[0] < CACHE_FOR:
            return hit[1]
        since = time.strftime("%Y-%m-%d", time.gmtime(time.time() - days * 86400))
        q = {"per_page": str(min(limit, 100)), "sort": "published", "direction": "desc",
             "published": f">={since}"}
        if ecosystem:
            q["ecosystem"] = ecosystem
        got = self.fetch(f"{GITHUB}?{urllib.parse.urlencode(q)}", None)
        out = [from_github(a) for a in got if isinstance(a, dict)] if isinstance(got, list) else []
        self._recent[key] = (time.time(), out)
        return out

    def advisory(self, aid: str) -> Advisory | None:
        """One advisory by any of its ids, from OSV (GHSA and CVE ids too)."""
        aid = aid.strip()
        if aid.upper().startswith(("CVE-", "GHSA-")):
            aid = aid[:5].upper() + aid[5:]
        try:
            got = self.fetch(f"{OSV}/vulns/{urllib.parse.quote(aid)}", None)
            return from_osv(got) if isinstance(got, dict) and got.get("id") else None
        except ValueError as e:
            if "answered 404" in str(e):
                return None
            raise

    def affecting(self, pinned: list[tuple[str, str, str]]) -> dict[tuple[str, str, str], list[str]]:
        """Which of (ecosystem, name, version) have advisories, by OSV id."""
        out = self.actions_affected([k for k in pinned if k[0] == "actions"])
        pinned = [k for k in pinned if k[0] != "actions"]
        for i in range(0, len(pinned), BATCH):
            chunk = pinned[i:i + BATCH]
            body = json.dumps({"queries": [{"package": {"ecosystem": OSV_ECOSYSTEM.get(e, e), "name": n}, "version": v}
                                           for e, n, v in chunk]}).encode()
            got = self.fetch(f"{OSV}/querybatch", body)
            for key, res in zip(chunk, (got or {}).get("results") or [], strict=False):  # type: ignore[union-attr]
                ids = [v["id"] for v in (res or {}).get("vulns") or [] if isinstance(v, dict) and v.get("id")]
                if ids:
                    out[key] = ids
        return out

    def actions_affected(self, pinned: list[tuple[str, str, str]]) -> dict[tuple[str, str, str], list[str]]:
        """affecting() for GitHub Actions: each action's advisories asked by its name alone, in one batch, and the
        pinned tag checked against each one's ranges."""
        names = sorted({n for _, n, _ in pinned})
        ids: dict[str, list[str]] = {}
        for i in range(0, len(names), BATCH):
            chunk = names[i:i + BATCH]
            body = json.dumps({"queries": [{"package": {"ecosystem": OSV_ECOSYSTEM["actions"], "name": n}}
                                           for n in chunk]}).encode()
            got = self.fetch(f"{OSV}/querybatch", body)
            for n, res in zip(chunk, (got or {}).get("results") or [], strict=False):  # type: ignore[union-attr]
                ids[n] = [v["id"] for v in (res or {}).get("vulns") or [] if isinstance(v, dict) and v.get("id")]
        vulns: dict[str, dict] = {}
        out: dict[tuple[str, str, str], list[str]] = {}
        for key in pinned:
            for vid in ids.get(key[1], []):
                if vid not in vulns:
                    got = self.fetch(f"{OSV}/vulns/{urllib.parse.quote(vid)}", None)
                    vulns[vid] = got if isinstance(got, dict) else {}
                if action_affected(vulns[vid], key[1], key[2]):
                    out.setdefault(key, []).append(vid)
        return out


def tag(version: str, missing: float) -> tuple:
    """A version as numbers to compare (v4.1.0 → 4, 1, 0), the parts it leaves out as `missing`."""
    nums: list[float] = []
    for part in version.strip().lstrip("vV").split(".")[:3]:
        m = re.match(r"\d+", part)
        if not m:
            break
        nums.append(int(m.group()))
    return tuple(nums + [missing] * (3 - len(nums)))


def action_affected(vuln: dict, name: str, version: str) -> bool:
    """Whether an action pinned at a tag falls in an OSV advisory's ranges for it. A major tag (v4) moves with its
    releases, so it counts as its newest: only a fix in a later major leaves it affected."""
    v = tag(version, math.inf)
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != OSV_ECOSYSTEM["actions"] or str(pkg.get("name", "")).lower() != name.lower():
            continue
        if any(tag(x, 0) == v for x in aff.get("versions") or []):
            return True
        for r in aff.get("ranges") or []:
            if r.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            hit = False
            for e in r.get("events") or []:
                if "introduced" in e and v >= tag(e["introduced"], 0):
                    hit = True
                elif "fixed" in e and v >= tag(e["fixed"], 0):
                    hit = False
                elif "last_affected" in e and v > tag(e["last_affected"], 0):
                    hit = False
            if hit:
                return True
    return False
