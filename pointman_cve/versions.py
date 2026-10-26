"""Versions compared across ecosystems, and what OSV's ranges say about one: whether it's affected, and the
lowest version that fixes it. One ordering serves semver (1.0.0-rc.1 < 1.0.0), PEP 440 (1.0rc1 < 1.0 < 1.0.post1
< 1.0.1), RubyGems (1.0.pre), Go (v0.17.0) and Composer (v4.4.0): numbers by value, a pre-release before its
release, a post-release after it. Maven's and NuGet's finer rules aren't modelled."""

from __future__ import annotations

import functools
import re

PRE = {"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "pre": 3, "preview": 3, "c": 3, "rc": 3, "cr": 3}
POST = {"post", "p", "pl", "patch", "r", "rev", "sp"}
RELEASE = {"final", "ga", "release"}
END = (1,)                      # where a version stops: after its pre-releases, before its post-releases


def key(version: str) -> tuple:
    """A version as a tuple that sorts as versions do: its release numbers (trailing zeros dropped, so 1.0 equals
    1.0.0), then what follows them: a pre-release word before the release itself, a post-release word after."""
    v = str(version).strip().lower().removeprefix("v").split("+", 1)[0]
    tokens = re.findall(r"\d+|[a-z]+", v)
    n = next((i for i, t in enumerate(tokens) if not t.isdigit()), len(tokens))
    release = [int(t) for t in tokens[:n]]
    while release and release[-1] == 0:
        release.pop()
    hyphen = bool(re.match(r"[\d.]*\d-", v))   # semver: whatever follows the hyphen is a pre-release
    rest = []
    for token in tokens[n:]:
        if token.isdigit():
            rest.append((3, int(token)))
        elif token in PRE:
            rest.append((0, PRE[token]))
        elif token in POST:
            rest.append((2,))
        elif hyphen and token not in RELEASE:
            rest.append((0, 4))          # 2.0.0-next.5, 1.0-SNAPSHOT
        else:
            rest.append(END)             # final, ga, release: the release itself
    return (tuple(release), tuple(rest) or (END,))


def compare(a: tuple, b: tuple) -> int:
    return (a > b) - (a < b)


def less(a: str, b: str) -> bool:
    return compare(key(a), key(b)) < 0


def lowest(versions: list[str]) -> str:
    out = ""
    for v in versions:
        if v and (not out or less(v, out)):
            out = v
    return out


def highest(versions: list[str]) -> str:
    out = ""
    for v in versions:
        if v and (not out or less(out, v)):
            out = v
    return out


def intervals(events: list[dict]) -> list[tuple[str, str, str]]:
    """One OSV range's affected intervals, (introduced, end, how it ends): ends "fixed" (end excluded),
    "last_affected" (end included) or "" (still open). OSV doesn't promise its events are in order."""
    marks = sorted(((k, v) for e in events for k, v in e.items() if k in ("introduced", "fixed", "last_affected")),
                   key=functools.cmp_to_key(lambda a, b: compare(key(a[1]), key(b[1]))))
    out, start = [], None
    for kind, value in marks:
        if kind == "introduced":
            if start is None:
                start = value
        elif start is not None:
            out.append((start, value, kind))
            start = None
    if start is not None:
        out.append((start, "", ""))
    return out


def inside(version: str, interval: tuple[str, str, str]) -> bool:
    start, end, how = interval
    v = key(version)
    if start not in ("0", "") and compare(v, key(start)) < 0:
        return False
    if how == "fixed":
        return compare(v, key(end)) < 0
    if how == "last_affected":
        return compare(v, key(end)) <= 0
    return True


def ranges_of(entry: dict) -> list[list[dict]]:
    return [r for r in entry.get("ranges") or [] if isinstance(r, list)]


def affected(entries: list[dict], version: str) -> bool:
    """Whether a version falls in any of a package's affected entries (OSV's ranges, or its listed versions)."""
    for entry in entries:
        if any(compare(key(version), key(x)) == 0 for x in entry.get("versions") or []):
            return True
        if any(inside(version, i) for events in ranges_of(entry) for i in intervals(events)):
            return True
    return False


def fixed_above(entries: list[dict], version: str) -> str:
    """The lowest version that fixes this one: the fix of each interval that holds it, the highest of them (all
    must be passed). None of them holding it, the lowest fix above it. "" when no fix is named."""
    holding = [i for entry in entries for events in ranges_of(entry) for i in intervals(events) if inside(version, i)]
    if holding:
        if any(how != "fixed" for _, _, how in holding):
            return ""                  # an interval with no fix named: no upgrade is known to leave it
        return highest([end for _, end, _ in holding])
    above = [end for entry in entries for events in ranges_of(entry) for _, end, how in intervals(events)
             if how == "fixed" and less(version, end)]
    return lowest(above)
