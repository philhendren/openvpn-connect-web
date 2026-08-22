"""The README's count of its own tests, checked against the tests there actually are.

Here rather than in CI alone on purpose: the moment this can be wrong is the moment somebody adds
a test, and that is a moment they are already running the suite. Catching it then costs one
command; catching it in CI costs a push, a wait and a second commit, and catching it by eye --
which is what happened three times before this file existed -- costs however long it takes
somebody to notice a number nobody has any reason to look at.
"""

from __future__ import annotations

import pytest

from tools.sync_readme import SyncError, collected_count, stated_count


def test_the_readme_states_the_real_number_of_tests():
    """A README that overstates its own test count is the one kind of stale number that matters.

    The sentence exists to answer "should I trust this", so it is the last place a generous
    figure belongs -- and it is quoted in defence of a project written by an AI, which raises the
    bar rather than lowering it.
    """
    try:
        real = collected_count()
    except SyncError as exc:  # pragma: no cover - only when pytest itself cannot be run
        pytest.fail(str(exc))

    assert stated_count() == real, (
        f"README.md claims {stated_count():,} tests; there are {real:,}. "
        "Fix it with: uv run python tools/sync_readme.py --fix"
    )
