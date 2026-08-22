#!/usr/bin/env python3
"""Work out which version the next release should be.

    uv run python tools/next_version.py --bump minor

Prints ``key=value`` lines for the release workflow to append to ``$GITHUB_OUTPUT``. Kept as a
module with tests rather than as shell inside the workflow: version arithmetic is exactly the kind
of thing that is wrong once, ships a `v2` where a `v1.1` was meant, and is then permanent, because
a pushed tag other people have fetched is not something you take back.

Three rules, and the first is the one that makes the first run work without being told anything:

* **No tags yet** -- the version in ``pyproject.toml`` is released as-is, not bumped. A project
  that has declared itself 0.1.0 and never released should get ``v0.1.0``, not ``v0.1.1``.
* **Tags exist** -- the highest is bumped by the requested part.
* **An exact version was asked for** -- it is used, provided it is a real version and is actually
  ahead of the highest tag. Going backwards is refused rather than obeyed.

Tags are the source of truth once the first one exists; ``pyproject.toml`` is only ever the seed.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"

PARTS = ("major", "minor", "patch")

#: Plain three-part versions only. No pre-release or build metadata: nothing here needs them, and
#: accepting what cannot be ordered sensibly would make "is this ahead of the last tag" a guess.
VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


class VersionError(ValueError):
    """Raised for anything that would produce a wrong or backwards tag."""


def parse(value: str) -> tuple[int, int, int]:
    match = VERSION.match(value.strip().removeprefix("v"))
    if not match:
        raise VersionError(f"{value!r} is not a MAJOR.MINOR.PATCH version")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def highest(tags: list[str]) -> str | None:
    """The greatest release tag, or None if there are none.

    Sorted as numbers rather than as text, because `git tag` and the shell both order v0.10.0
    before v0.9.0 and that mistake only shows up on the tenth release.
    """
    versions = []
    for tag in tags:
        try:
            versions.append(parse(tag))
        except VersionError:
            continue  # somebody else's tag, or a typo -- not this workflow's business
    if not versions:
        return None
    return ".".join(str(part) for part in max(versions))


def bump(version: str, part: str) -> str:
    if part not in PARTS:
        raise VersionError(f"{part!r} is not one of {', '.join(PARTS)}")
    major, minor, patch = parse(version)
    if part == "major":
        return f"{major + 1}.0.0"
    if part == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def seed_version(pyproject: Path = PYPROJECT) -> str:
    """The version declared in pyproject.toml, used only for the very first release."""
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    try:
        declared = data["project"]["version"]
    except (KeyError, TypeError) as exc:
        raise VersionError(f"no [project] version in {pyproject.name}") from exc
    parse(declared)  # fail here rather than at the tag
    return declared


def resolve(
    tags: list[str], part: str = "patch", *, seed: str, explicit: str | None = None
) -> tuple[str, str | None]:
    """Return ``(next version, previous version or None)``, both without a leading ``v``."""
    previous = highest(tags)

    if explicit:
        chosen = ".".join(str(p) for p in parse(explicit))
        if previous and parse(chosen) <= parse(previous):
            raise VersionError(
                f"{chosen} is not ahead of the latest release v{previous}. "
                "Releases only ever go forwards."
            )
        return chosen, previous

    if previous is None:
        # First release: honour what the project already says it is.
        return seed, None
    return bump(previous, part), previous


def git_tags() -> list[str]:
    # `git` off PATH is deliberate: this runs on a CI runner and in a working checkout, where an
    # absolute path would be wrong more often than it would be safe.
    argv = ["git", "tag", "--list", "v*"]  # noqa: S607 - see above
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell, nothing from a caller
        argv, cwd=ROOT, capture_output=True, text=True, check=True
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bump", choices=PARTS, default="patch")
    parser.add_argument("--version", default="", help="release exactly this version instead")
    args = parser.parse_args()

    try:
        version, previous = resolve(
            git_tags(), args.bump, seed=seed_version(), explicit=args.version or None
        )
    except VersionError as exc:
        print(f"next_version: {exc}", file=sys.stderr)
        return 1

    print(f"version={version}")
    print(f"tag=v{version}")
    print(f"previous={'v' + previous if previous else ''}")
    print(f"first={'true' if previous is None else 'false'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
