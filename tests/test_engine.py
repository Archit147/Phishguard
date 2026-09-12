"""Offline engine tests — no server required.

Run:  python -m tests.test_engine
"""

from __future__ import annotations

import sys

from backend.analyzer import analyze, is_trusted_host, parse_url
from backend.scoring import aggregate, verdict_for
from tests.fixtures import CASES


def run() -> int:
    failures: list[str] = []
    rows: list[tuple[str, str, str, int, str]] = []

    for name, url, html, expected in CASES:
        facts, signals, brand = analyze(url, html)
        score, _conf = aggregate(signals)
        verdict = verdict_for(score).value
        ok = (expected == "Dangerous" and score >= 60) or (expected == "Safe" and score < 30)
        if not ok:
            failures.append(
                f"{name}: expected {expected}, got {verdict} ({score}) "
                f"[{', '.join(s.id for s in signals[:4])}]"
            )
        rows.append((name, expected, verdict, score, signals[0].id if signals else "-"))

    width = max(len(r[0]) for r in rows) + 2
    print(f"{'CASE':<{width}}{'EXPECT':<11}{'GOT':<13}{'SCORE':>5}  TOP SIGNAL")
    print("-" * (width + 50))
    for name, exp, got, score, top in rows:
        mark = "" if (exp == "Dangerous" and score >= 60) or (exp == "Safe" and score < 30) else "  <-- FAIL"
        print(f"{name:<{width}}{exp:<11}{got:<13}{score:>5}  {top}{mark}")

    # --- unit-level invariants ----------------------------------------- #
    checks: list[tuple[str, bool]] = [
        ("github.com is trusted", is_trusted_host(parse_url("https://github.com/login"))),
        ("localhost is trusted", is_trusted_host(parse_url("http://localhost:3000/"))),
        ("private IP is trusted", is_trusted_host(parse_url("http://192.168.1.10/admin"))),
        ("public IP is not trusted", not is_trusted_host(parse_url("http://185.212.44.9/"))),
        ("random .tk is not trusted", not is_trusted_host(parse_url("http://evil.tk/"))),
        ("empty signals score 0", aggregate([])[0] == 0),
        ("verdict boundary 59 -> Suspicious", verdict_for(59).value == "Suspicious"),
        ("verdict boundary 60 -> Dangerous", verdict_for(60).value == "Dangerous"),
        ("verdict boundary 29 -> Safe", verdict_for(29).value == "Safe"),
        ("verdict boundary 30 -> Suspicious", verdict_for(30).value == "Suspicious"),
    ]
    print("\nInvariants:")
    for label, passed in checks:
        print(f"  [{'PASS' if passed else 'FAIL'}] {label}")
        if not passed:
            failures.append(f"invariant: {label}")

    print()
    if failures:
        print(f"{len(failures)} FAILURE(S):")
        for f in failures:
            print("  -", f)
        return 1
    print(f"All {len(CASES)} scenario cases and {len(checks)} invariants passed.")
    return 0


if __name__ == "__main__":
    sys.exit(run())
