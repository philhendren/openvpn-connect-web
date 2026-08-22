#!/usr/bin/env python3
"""Keep the test count in README.md equal to the number of tests there actually are.

    uv run python tools/sync_readme.py          # check; exits 1 if the README is wrong
    uv run python tools/sync_readme.py --fix    # rewrite it to the real number

The number is a claim the README makes in its own defence -- "the tests are real (N ...)" -- which
makes it the one number in the file that must never be generous. It had drifted and been corrected
by hand three times before this existed, always noticed by luck.

**Counted by collecting them, not by reading the source.** The obvious implementation is to walk
the AST for `def test_*`, and it is wrong here: `@pytest.mark.parametrize` appears twenty-odd times
and each case is a test pytest counts and the AST does not. At the time of writing that is 631
functions and 716 tests. So this shells out to `pytest --collect-only`, which is the same
arithmetic the suite itself does, and costs about a tenth of a second.

Only `tests/` is counted. `uitests/` needs Playwright, which the dev environment CI runs the suite
in does not have, so including it would turn a missing optional dependency into a failing test
about a README. The browser scenarios are described in that sentence without a number instead --
nothing to drift, nothing to check.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
SUITE = "tests"

#: Anchored to the sentence rather than to a bare number, so it cannot wander onto a port, a year
#: or a coverage percentage if the file is rearranged around it.
CLAIM = re.compile(r"(the tests are real \()([\d,]+)(,)")

#: pytest's own summary line, which is the only place the post-parametrise total appears.
COLLECTED = re.compile(r"^(\d+) tests collected", re.MULTILINE)


class SyncError(RuntimeError):
    """Raised when the count cannot be established -- never to report a mismatch."""


def collected_count() -> int:
    """How many tests pytest finds in ``tests/``.

    Collection only: nothing is executed, so this is safe to call from inside a test run and
    cannot recurse into itself.
    """
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell, no caller-supplied content
        [sys.executable, "-m", "pytest", "--collect-only", "-q", SUITE],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    match = COLLECTED.search(result.stdout)
    if not match:
        raise SyncError(
            f"could not read a test count out of pytest (exit {result.returncode}).\n"
            f"--- stdout ---\n{result.stdout[-2000:]}\n--- stderr ---\n{result.stderr[-2000:]}"
        )
    return int(match.group(1))


def stated_count(text: str | None = None) -> int:
    """The number the README currently claims."""
    match = CLAIM.search(README.read_text(encoding="utf-8") if text is None else text)
    if not match:
        raise SyncError(
            f"the sentence this number lives in is no longer in {README.name}. If it was reworded,"
            f" update CLAIM in {Path(__file__).name} to match -- do not delete the check."
        )
    return int(match.group(2).replace(",", ""))


def apply(count: int) -> bool:
    """Write ``count`` into the README. True if that changed anything."""
    text = README.read_text(encoding="utf-8")
    updated = CLAIM.sub(lambda m: f"{m.group(1)}{count:,}{m.group(3)}", text, count=1)
    if updated == text:
        return False
    README.write_text(updated, encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--fix", action="store_true", help="rewrite the README instead of only reporting"
    )
    args = parser.parse_args()

    try:
        real = collected_count()
        stated = stated_count()
    except SyncError as exc:
        print(f"sync_readme: {exc}", file=sys.stderr)
        return 2

    if stated == real:
        print(f"README says {stated:,} tests, and there are {real:,}.")
        return 0

    if not args.fix:
        print(
            f"README says {stated:,} tests, but there are {real:,}.\n"
            f"Fix it with: uv run python {Path(__file__).relative_to(ROOT)} --fix",
            file=sys.stderr,
        )
        return 1

    apply(real)
    print(f"README updated: {stated:,} -> {real:,}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
