"""Is what is running actually what is in the repo?

Every other reporting module here answers that question about the *system* -- ``routing.py``
reads the kernel's table rather than the routes that were offered, ``resolver.py`` reads
systemd-resolved rather than what the server pushed. This one asks it about the app's own
deployment, for the same reason: the answer has repeatedly been "no", and nothing said so.

Three ways this install has drifted in practice, all of them silent:

* **The helper.** ``install.sh`` renders a template into ``/usr/local/sbin``. Editing the
  template changes nothing until it is re-run, and the failure that follows is a puzzle rather
  than a message -- an unknown verb, or a flag that is no longer passed.
* **The Python.** Jinja templates reload on edit; the modules behind them do not. A change can
  be half-live, with the page showing new markup driven by old code.
* **The environment file.** The documented way to set a password appends a command's output to
  it, so anything else that command printed is appended too. systemd skips the unparseable lines
  and takes the last value of any repeated key, both without complaint.

Read-only and unprivileged: every check is a file the app can already see, and the report is
advice, never an action. Nothing here edits or repairs anything.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

#: The stamp install.sh bakes into the rendered helper -- see deploy/vpn-connect-helper.in.
_STAMP = re.compile(r'^HELPER_VERSION="([0-9a-f]{64})"', re.MULTILINE)

#: A line of an environment file that assigns something. Everything else in such a file is
#: either blank, a comment, or damage.
_ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=")


@dataclass(frozen=True)
class DriftItem:
    """One way the running system differs from the repo, and what to do about it."""

    kind: str
    headline: str
    detail: str
    #: The command that resolves it, shown verbatim for the operator to copy.
    fix: str

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "headline": self.headline,
            "detail": self.detail,
            "fix": self.fix,
        }


@dataclass(frozen=True)
class DeployReport:
    items: list[DriftItem] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.items

    def to_dict(self) -> dict[str, object]:
        return {"clean": self.clean, "items": [item.to_dict() for item in self.items]}


def digest(path: Path) -> str | None:
    """sha256 of a file, or None if it cannot be read. Never raises."""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


# --- the individual checks ---------------------------------------------------


def helper_drift(*, installed: Path, template: Path) -> DriftItem | None:
    """Compare the stamp in the installed helper against the template it came from."""
    expected = digest(template)
    if expected is None:
        return None  # not running from a checkout; nothing to compare against

    try:
        text = installed.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return DriftItem(
            kind="helper",
            headline="The root helper is not installed.",
            detail=f"Nothing readable at {installed}. Connecting will fail until it is installed.",
            fix="sudo ./deploy/install.sh",
        )

    found = _STAMP.search(text)
    if found is None:
        return DriftItem(
            kind="helper",
            headline="The installed root helper is out of date.",
            detail=(
                "It predates version stamping, so it is at least several changes behind the "
                "template in this checkout."
            ),
            fix="sudo ./deploy/install.sh",
        )
    if found.group(1) != expected:
        return DriftItem(
            kind="helper",
            headline="The installed root helper does not match this checkout.",
            detail=(
                "deploy/vpn-connect-helper.in has changed since it was last installed. Until it "
                "is re-installed, the app and the helper disagree about what root will do."
            ),
            fix="sudo ./deploy/install.sh",
        )
    return None


def migration_drift(*, applied: int, migrations_dir: Path) -> DriftItem | None:
    """Compare the database's schema version against the migrations on disk."""
    try:
        available = [int(p.name[:4]) for p in migrations_dir.glob("[0-9][0-9][0-9][0-9]_*.sql")]
    except OSError:
        return None
    if not available or max(available) <= applied:
        return None
    return DriftItem(
        kind="migrations",
        headline="The database is behind the migrations in this checkout.",
        detail=(
            f"The schema is at version {applied}; migration {max(available):04d} is present but "
            "unapplied. Migrations run at start-up, so a restart is all this needs."
        ),
        fix="sudo systemctl restart vpn-connect",
    )


def code_drift(*, source_root: Path, started_at: float) -> DriftItem | None:
    """Has any module been edited since this process began?

    Templates are deliberately excluded: Jinja reloads those, so an edited template is already
    live and reporting it would be noise. It is precisely the split between the two that makes
    this worth surfacing -- a page can show new markup driven by code that never reloaded.
    """
    newest: tuple[float, str] | None = None
    try:
        for path in source_root.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            mtime = path.stat().st_mtime
            if newest is None or mtime > newest[0]:
                newest = (mtime, path.name)
    except OSError:
        return None
    if newest is None or newest[0] <= started_at:
        return None

    minutes = max(1, int((time.time() - newest[0]) // 60))
    return DriftItem(
        kind="code",
        headline="The running app is older than its source.",
        detail=(
            f"{newest[1]} was edited {minutes} minute{'s' if minutes != 1 else ''} after this "
            "process started. Templates reload on their own; Python does not."
        ),
        fix="sudo systemctl restart vpn-connect",
    )


def env_file_damage(path: Path) -> DriftItem | None:
    """Repeated keys and lines that are not assignments at all.

    systemd takes the last value of a repeated key and silently skips anything it cannot parse,
    so a damaged file behaves *almost* correctly -- which is what makes it worth reporting.
    """
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None

    seen: dict[str, int] = {}
    repeated: list[str] = []
    junk = 0
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _ASSIGNMENT.match(stripped)
        if match is None:
            junk += 1
            continue
        key = match.group(1)
        seen[key] = seen.get(key, 0) + 1
        if seen[key] == 2:
            repeated.append(key)

    if not repeated and not junk:
        return None

    parts = []
    if repeated:
        parts.append(
            f"{', '.join(sorted(repeated))} "
            f"{'is' if len(repeated) == 1 else 'are'} set more than once; systemd keeps the last"
        )
    if junk:
        parts.append(
            f"{junk} line{'s' if junk != 1 else ''} are not settings at all and are ignored"
        )
    return DriftItem(
        kind="env",
        headline="The environment file has been damaged.",
        detail=f"{path}: {'; '.join(parts)}.",
        fix=f"Edit {path} by hand: keep one copy of each setting and delete the rest.",
    )


# --- the report --------------------------------------------------------------


def client_drift(clients) -> DriftItem | None:
    """Is the client this panel drives actually installed?

    Worth a banner rather than a comment in a log: the failure without it arrives at the first
    connect, as a helper that cannot start a binary that is not there, which reads as a broken
    panel rather than as a missing package. The ``openvpn3``-only case gets its own wording
    because "install openvpn" is confusing advice to somebody who can see an OpenVPN on their
    PATH already.
    """
    if clients is None or clients.supported:
        return None
    if clients.v3_only:
        return DriftItem(
            kind="client",
            headline="Only OpenVPN 3 is installed, and this panel cannot drive it.",
            detail=(
                f"{clients.v3} is on this machine, but the classic openvpn client is not. This "
                "panel drives the classic client over OpenVPN's management interface -- the "
                "socket its state, byte counters, log and credential prompts all come from -- "
                "and OpenVPN 3 does not provide one. The two can be installed side by side."
            ),
            fix="sudo ./install_prerequisites.sh",
        )
    return DriftItem(
        kind="client",
        headline="No OpenVPN client is installed.",
        detail=(
            "Nothing on PATH, or in the usual sbin directories, answers to openvpn. Nothing can "
            "connect until the classic client is installed."
        ),
        fix="sudo ./install_prerequisites.sh",
    )


def report(
    *,
    config,
    schema_version: int,
    source_root: Path,
    migrations_dir: Path,
    started_at: float,
    clients=None,
) -> DeployReport:
    """Every check, in the order the operator would act on them. Never raises."""
    checks = (
        # First, because nothing else matters if the binary is missing.
        lambda: client_drift(clients),
        lambda: helper_drift(
            installed=config.HELPER,
            template=source_root / "deploy" / "vpn-connect-helper.in",
        ),
        lambda: migration_drift(applied=schema_version, migrations_dir=migrations_dir),
        lambda: code_drift(source_root=source_root, started_at=started_at),
        lambda: env_file_damage(config.env_file),
    )

    items: list[DriftItem] = []
    for check in checks:
        try:
            found = check()
        except Exception:  # noqa: BLE001 - a broken self-check must never break the page
            log.exception("a deployment check failed")
            continue
        if found is not None:
            items.append(found)
    return DeployReport(items=items)
