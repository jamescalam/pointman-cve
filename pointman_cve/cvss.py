"""CVSS base scores from the vectors OSV gives (CVSS:3.0 and 3.1), and a score's severity. A CVSS 4.0 vector isn't
scored here: its advisory's own severity stands."""

from __future__ import annotations

import math

WEIGHTS = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
           "UI": {"N": 0.85, "R": 0.62}, "C": {"H": 0.56, "L": 0.22, "N": 0.0}}
PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def roundup(x: float) -> float:
    """CVSS 3.1's round up to one decimal, done in integers so 4.000000001 stays 4.0."""
    n = round(x * 100000)
    return n / 100000.0 if n % 10000 == 0 else (math.floor(n / 10000) + 1) / 10.0


def score(vector: str) -> float | None:
    """A CVSS 3.x vector's base score (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H → 7.5); None for anything else."""
    parts = vector.strip().split("/")
    if not parts or parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
        return None
    m = dict(p.split(":", 1) for p in parts[1:] if ":" in p)
    try:
        scope = m["S"]
        av, ac, ui = WEIGHTS["AV"][m["AV"]], WEIGHTS["AC"][m["AC"]], WEIGHTS["UI"][m["UI"]]
        pr = PR[scope][m["PR"]]
        c, i, a = (WEIGHTS["C"][m[k]] for k in ("C", "I", "A"))
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 6.42 * iss if scope == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    total = impact + exploitability if scope == "U" else 1.08 * (impact + exploitability)
    return roundup(min(total, 10))


def severity(base: float | None) -> str:
    """CVSS's own bands: critical from 9.0, high from 7.0, medium from 4.0, low above 0."""
    if base is None:
        return "unknown"
    return "critical" if base >= 9 else "high" if base >= 7 else "medium" if base >= 4 else "low" if base > 0 else "unknown"
