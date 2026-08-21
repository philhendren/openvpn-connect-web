"""SQLite connection handling and schema migrations.

Migrations are numbered ``.sql`` files under ``app/migrations/`` applied in order, with SQLite's
own ``PRAGMA user_version`` as the bookkeeping. That pragma lives in the database header, is
transactional, and needs no table of its own -- which is why this needs no migration library.

Two rules for anyone adding a migration:

* **Never edit an applied file.** Add a new one. A file that has already run somewhere is
  history, and rewriting it means two databases with the same ``user_version`` and different
  shapes.
* **Numbers are contiguous and unique.** The runner refuses a gap or a duplicate rather than
  guessing, because either usually means two branches added ``0007`` independently.
"""

from __future__ import annotations

import logging
import re
import sqlite3
import stat
from pathlib import Path

log = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).parent / "migrations"

_MIGRATION_NAME = re.compile(r"^(\d{4})_[a-z0-9_]+\.sql$")


class MigrationError(RuntimeError):
    """Raised when the migration set is malformed or a migration fails to apply."""


def connect(path: Path) -> sqlite3.Connection:
    """Open the database with the pragmas this app depends on.

    ``isolation_level=None`` turns off the driver's implicit transaction handling so the
    migration runner can drive ``BEGIN``/``COMMIT`` itself; everywhere else uses the explicit
    :func:`transaction` helper.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Owner-only, and *before* WAL is enabled: SQLite gives the -wal and -shm files the same
    # permissions as the database, so tightening this first means they are created correct.
    # The encrypted columns would survive being read, but the ntfy topic and the connection
    # names are stored in the clear and are nobody else's business.
    _restrict(path)
    # WAL: the status page reads while a connect writes, and WAL lets those overlap.
    conn.execute("PRAGMA journal_mode = WAL")
    # An existing database predating the line above, plus any sidecars already on disk.
    for sidecar in (path, path.with_name(path.name + "-wal"), path.with_name(path.name + "-shm")):
        _restrict(sidecar)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


def _restrict(path: Path) -> None:
    """chmod 0600. A sidecar that does not exist yet is normal, not a problem."""
    if not path.exists():
        return
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError as exc:
        log.warning("could not restrict permissions on %s: %s", path, exc)


class transaction:  # noqa: N801 - used as a context manager, reads better lowercase
    """Explicit transaction, since ``isolation_level=None`` disables the implicit one."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def __enter__(self) -> sqlite3.Connection:
        self._conn.execute("BEGIN IMMEDIATE")
        return self._conn

    def __exit__(self, exc_type, _exc, _tb) -> bool:
        self._conn.execute("ROLLBACK" if exc_type else "COMMIT")
        return False


def discover(directory: Path = MIGRATIONS_DIR) -> list[tuple[int, Path]]:
    """Every migration, ordered, with its version. Raises on a malformed set."""
    found: dict[int, Path] = {}
    for path in sorted(directory.glob("*.sql")):
        match = _MIGRATION_NAME.match(path.name)
        if not match:
            raise MigrationError(
                f"{path.name} is not a migration name -- use NNNN_lower_snake_case.sql"
            )
        version = int(match.group(1))
        if version in found:
            raise MigrationError(
                f"two migrations numbered {version:04d}: {found[version].name} and {path.name}"
            )
        found[version] = path

    if not found:
        return []

    expected = list(range(1, max(found) + 1))
    missing = sorted(set(expected) - set(found))
    if missing:
        raise MigrationError(
            "migration numbers must be contiguous from 0001; missing "
            + ", ".join(f"{version:04d}" for version in missing)
        )
    return [(version, found[version]) for version in sorted(found)]


def schema_version(conn: sqlite3.Connection) -> int:
    return int(conn.execute("PRAGMA user_version").fetchone()[0])


def migrate(conn: sqlite3.Connection, directory: Path = MIGRATIONS_DIR) -> int:
    """Apply every migration newer than the database's ``user_version``.

    Each migration and its version bump go in one transaction, so a failure leaves the database
    at the last version that fully applied rather than half-way through this one.
    """
    current = schema_version(conn)
    pending = [(version, path) for version, path in discover(directory) if version > current]
    if not pending:
        return current

    for version, path in pending:
        sql = path.read_text(encoding="utf-8")
        log.info("applying migration %04d %s", version, path.stem)
        try:
            # BEGIN/COMMIT live inside the script: executescript commits any transaction the
            # driver has open before it runs, so an outer BEGIN here would be discarded.
            conn.executescript(f"BEGIN;\n{sql}\nPRAGMA user_version = {version};\nCOMMIT;")
        except sqlite3.Error as exc:
            # execute(), never executescript(): executescript issues a COMMIT before it runs, so
            # rolling back that way would *commit* the half-applied migration first.
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise MigrationError(f"migration {path.name} failed: {exc}") from exc

    return schema_version(conn)


def open_migrated(path: Path, directory: Path = MIGRATIONS_DIR) -> sqlite3.Connection:
    """The normal entry point: open the database and bring it up to date."""
    conn = connect(path)
    migrate(conn, directory)
    return conn
