"""Version arithmetic for the release workflow.

Tested because a tag is the one artefact here that cannot be taken back once somebody has fetched
it. Everything else in this repository can be fixed by another commit.
"""

from __future__ import annotations

import pytest

from tools.next_version import VersionError, bump, highest, parse, resolve, seed_version

SEED = "0.1.0"


# --- reading a version -----------------------------------------------------


@pytest.mark.parametrize("value", ["1.2.3", "v1.2.3", " v1.2.3 "])
def test_a_version_is_read_with_or_without_its_v(value):
    assert parse(value) == (1, 2, 3)


@pytest.mark.parametrize("value", ["1.2", "1.2.3.4", "1.2.x", "v", "", "1.2.3-rc1", "1.2.3+build"])
def test_anything_that_is_not_three_numbers_is_refused(value):
    """Pre-release and build metadata included: what cannot be ordered cannot be checked."""
    with pytest.raises(VersionError):
        parse(value)


# --- picking the latest ----------------------------------------------------


def test_no_tags_means_no_latest():
    assert highest([]) is None


def test_the_latest_is_the_greatest_not_the_last():
    assert highest(["v0.1.0", "v0.3.0", "v0.2.0"]) == "0.3.0"


def test_versions_sort_as_numbers_not_as_text():
    """The bug this exists to prevent: v0.9.0 sorts *after* v0.10.0 as a string."""
    assert highest(["v0.9.0", "v0.10.0"]) == "0.10.0"
    assert highest(["v1.9.9", "v1.10.0"]) == "1.10.0"


def test_tags_that_are_not_releases_are_ignored():
    assert highest(["v1.0.0", "nightly", "v-broken", "release-2"]) == "1.0.0"


def test_a_tag_list_with_nothing_usable_in_it_reads_as_no_releases():
    assert highest(["nightly", "wip"]) is None


# --- bumping ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("part", "expected"),
    [("major", "2.0.0"), ("minor", "1.5.0"), ("patch", "1.4.3")],
)
def test_each_part_bumps_and_clears_the_ones_below_it(part, expected):
    assert bump("1.4.2", part) == expected


def test_an_unknown_part_is_refused():
    with pytest.raises(VersionError):
        bump("1.0.0", "epoch")


# --- the whole decision ----------------------------------------------------


def test_the_first_release_is_what_the_project_already_says_it_is():
    """No tags means nothing has been released, so 0.1.0 is released as 0.1.0 -- not 0.1.1."""
    assert resolve([], "patch", seed=SEED) == ("0.1.0", None)


def test_the_first_release_ignores_the_requested_bump():
    assert resolve([], "major", seed=SEED) == ("0.1.0", None)


def test_a_later_release_bumps_the_highest_tag():
    assert resolve(["v0.1.0", "v0.2.0"], "minor", seed=SEED) == ("0.3.0", "0.2.0")


def test_the_previous_version_is_reported_so_the_notes_can_span_it():
    _, previous = resolve(["v1.0.0"], "patch", seed=SEED)
    assert previous == "1.0.0"


def test_an_exact_version_overrides_the_bump():
    assert resolve(["v0.4.0"], "patch", seed=SEED, explicit="1.0.0") == ("1.0.0", "0.4.0")


def test_an_exact_version_may_skip_ahead():
    assert resolve(["v0.4.0"], "patch", seed=SEED, explicit="v2.0.0") == ("2.0.0", "0.4.0")


def test_an_exact_version_works_for_the_first_release_too():
    assert resolve([], "patch", seed=SEED, explicit="1.0.0") == ("1.0.0", None)


@pytest.mark.parametrize("explicit", ["0.4.0", "0.3.9", "0.1.0"])
def test_a_version_that_is_not_ahead_of_the_latest_is_refused(explicit):
    """Releases only ever go forwards. Re-releasing a number is how two builds share one."""
    with pytest.raises(VersionError, match="not ahead"):
        resolve(["v0.4.0"], "patch", seed=SEED, explicit=explicit)


def test_a_nonsense_exact_version_is_refused():
    with pytest.raises(VersionError):
        resolve(["v0.4.0"], "patch", seed=SEED, explicit="next")


# --- the seed --------------------------------------------------------------


def test_the_seed_comes_from_pyproject(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nname = "x"\nversion = "3.4.5"\n')
    assert seed_version(pyproject) == "3.4.5"


def test_a_pyproject_with_no_version_is_refused(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nname = "x"\n')
    with pytest.raises(VersionError):
        seed_version(pyproject)


def test_a_pyproject_whose_version_is_not_a_version_is_refused(tmp_path):
    """Caught here rather than at the tag, where the failure would be far less obvious."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nname = "x"\nversion = "0.1"\n')
    with pytest.raises(VersionError):
        seed_version(pyproject)


def test_this_projects_own_pyproject_is_a_usable_seed():
    """The real file, so a hand-edit that breaks the first release is caught before the release."""
    parse(seed_version())
