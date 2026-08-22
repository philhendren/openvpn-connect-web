"""Schema migrations. The runner is hand-rolled, so its edge cases are the tests that matter."""

from __future__ import annotations

import sqlite3

import pytest

from app.db import (
    MIGRATIONS_DIR,
    MigrationError,
    discover,
    migrate,
    schema_version,
    transaction,
)


def _write(directory, name: str, sql: str) -> None:
    (directory / name).write_text(sql)


def _shipped_through(directory, version: int) -> None:
    """Copy the real migrations up to ``version`` into a directory of their own.

    Lets a test stand a database up as it was at some point in this project's history and then
    run the newer migrations against it -- which is the only way to exercise an upgrade, since
    the ordinary fixtures build every database from scratch at the current version.
    """
    for number, path in discover():
        if number <= version:
            (directory / path.name).write_text(path.read_text(encoding="utf-8"))


@pytest.fixture
def migrations(tmp_path):
    directory = tmp_path / "migrations"
    directory.mkdir()
    return directory


# --- the real migration set ------------------------------------------------


def test_the_shipped_migrations_apply(db):
    conn = db
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"vault", "connections", "settings", "events", "sessions", "log_lines"} <= tables
    assert schema_version(conn) >= 1


def test_the_shipped_migration_set_is_well_formed():
    """Catches a duplicate or missing number before it reaches anyone's database."""
    versions = [version for version, _ in discover()]
    assert versions == list(range(1, len(versions) + 1))


def test_migrating_twice_changes_nothing(db):
    conn = db
    before = schema_version(conn)
    assert migrate(conn) == before


def test_pragmas_are_set(db):
    conn = db
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_foreign_keys_cascade(db):
    """log_lines must go when their session does, or pruning would leak rows."""
    conn = db
    with transaction(conn):
        conn.execute("INSERT INTO sessions (id, started_at) VALUES (1, 'now')")
        conn.execute("INSERT INTO log_lines (session_id, at, line) VALUES (1, 'now', 'x')")
    with transaction(conn):
        conn.execute("DELETE FROM sessions WHERE id = 1")
    assert conn.execute("SELECT COUNT(*) FROM log_lines").fetchone()[0] == 0


# --- 0007, the log_sessions -> sessions rename -----------------------------


def _seed_session(conn) -> None:
    with transaction(conn):
        conn.execute(
            "INSERT INTO log_sessions (id, connection, started_at, ended_at, outcome)"
            " VALUES (1, 'examplecorp', 'then', 'later', 'connected')"
        )
        conn.execute("INSERT INTO log_lines (session_id, at, line) VALUES (1, 'then', 'x')")
        conn.execute(
            "INSERT INTO traffic_samples (session_id, at, bytes_in, bytes_out)"
            " VALUES (1, 1.0, 10, 20)"
        )


def test_the_rename_keeps_the_rows_that_were_already_there(open_db, migrations, tmp_path):
    """A rename that lost history would be worse than the name it fixed."""
    _shipped_through(migrations, 6)
    conn = open_db(directory=tmp_path)
    migrate(conn, migrations)
    _seed_session(conn)

    assert migrate(conn, MIGRATIONS_DIR) >= 7

    row = conn.execute("SELECT connection, outcome FROM sessions WHERE id = 1").fetchone()
    assert (row["connection"], row["outcome"]) == ("examplecorp", "connected")


def test_the_rename_leaves_no_table_behind(open_db, migrations, tmp_path):
    _shipped_through(migrations, 6)
    conn = open_db(directory=tmp_path)
    migrate(conn, migrations)
    migrate(conn, MIGRATIONS_DIR)

    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "sessions" in tables
    assert "log_sessions" not in tables


def test_the_rename_carries_the_cascades_with_it(open_db, migrations, tmp_path):
    """SQLite rewrites the REFERENCES clauses during the rename -- prove it, do not assume it."""
    _shipped_through(migrations, 6)
    conn = open_db(directory=tmp_path)
    migrate(conn, migrations)
    _seed_session(conn)
    migrate(conn, MIGRATIONS_DIR)

    with transaction(conn):
        conn.execute("DELETE FROM sessions WHERE id = 1")
    assert conn.execute("SELECT COUNT(*) FROM log_lines").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM traffic_samples").fetchone()[0] == 0


def test_the_rename_takes_the_indexes_with_it(open_db, migrations, tmp_path):
    """A table rename leaves index names behind, so 0007 has to move them itself."""
    _shipped_through(migrations, 6)
    conn = open_db(directory=tmp_path)
    migrate(conn, migrations)
    migrate(conn, MIGRATIONS_DIR)

    indexes = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert {"sessions_recent", "sessions_ended"} <= indexes
    assert not {name for name in indexes if name.startswith("log_sessions")}


def test_only_one_connection_can_be_default(db):
    """Enforced by a partial unique index, so a bug in the app cannot produce two defaults."""
    conn = db
    insert = (
        "INSERT INTO connections (name, profile, username, password, is_default,"
        " created_at, updated_at) VALUES (?, x'00', x'00', x'00', 1, 't', 't')"
    )
    conn.execute(insert, ("a",))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(insert, ("b",))


# --- the runner's own rules ------------------------------------------------


def test_migrations_apply_in_order(open_db, migrations):
    _write(migrations, "0001_first.sql", "CREATE TABLE a (id INTEGER);")
    _write(migrations, "0002_second.sql", "ALTER TABLE a ADD COLUMN b TEXT;")
    conn = open_db()
    assert migrate(conn, migrations) == 2
    columns = {row[1] for row in conn.execute("PRAGMA table_info(a)")}
    assert columns == {"id", "b"}


def test_only_pending_migrations_run(open_db, migrations):
    _write(migrations, "0001_first.sql", "CREATE TABLE a (id INTEGER);")
    conn = open_db()
    migrate(conn, migrations)
    # A second migration added later applies on top without re-running the first, which would
    # fail with "table a already exists".
    _write(migrations, "0002_second.sql", "CREATE TABLE b (id INTEGER);")
    assert migrate(conn, migrations) == 2


def test_a_gap_in_the_numbering_is_refused(open_db, migrations):
    _write(migrations, "0001_first.sql", "SELECT 1;")
    _write(migrations, "0003_third.sql", "SELECT 1;")
    with pytest.raises(MigrationError, match="0002"):
        migrate(open_db(), migrations)


def test_a_duplicate_number_is_refused(open_db, migrations):
    """Two branches both adding 0007 is the failure this catches."""
    _write(migrations, "0001_one.sql", "SELECT 1;")
    _write(migrations, "0001_other.sql", "SELECT 1;")
    with pytest.raises(MigrationError, match="two migrations numbered"):
        migrate(open_db(), migrations)


def test_a_misnamed_file_is_refused(open_db, migrations):
    _write(migrations, "initial.sql", "SELECT 1;")
    with pytest.raises(MigrationError, match="not a migration name"):
        migrate(open_db(), migrations)


def test_a_failing_migration_leaves_the_previous_version_intact(open_db, migrations):
    _write(migrations, "0001_good.sql", "CREATE TABLE good (id INTEGER);")
    _write(migrations, "0002_bad.sql", "CREATE TABLE oops (id INTEGER); THIS IS NOT SQL;")
    conn = open_db()
    with pytest.raises(MigrationError, match="0002_bad"):
        migrate(conn, migrations)

    assert schema_version(conn) == 1
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "good" in tables
    assert "oops" not in tables  # the failed migration rolled back whole


def test_an_empty_migration_directory_is_fine(open_db, migrations):
    assert migrate(open_db(), migrations) == 0


# --- the transaction helper ------------------------------------------------


def test_transaction_commits(db):
    conn = db
    with transaction(conn):
        conn.execute("INSERT INTO settings (key, value, updated_at) VALUES ('k', 'v', 't')")
    assert conn.execute("SELECT value FROM settings WHERE key='k'").fetchone()[0] == "v"


def test_transaction_rolls_back_on_error(db):
    conn = db
    with pytest.raises(RuntimeError), transaction(conn):
        conn.execute("INSERT INTO settings (key, value, updated_at) VALUES ('k', 'v', 't')")
        raise RuntimeError("boom")
    assert conn.execute("SELECT COUNT(*) FROM settings").fetchone()[0] == 0


def test_the_database_is_owner_only(tmp_path):
    """It holds the ntfy topic and the connection names in the clear."""
    import stat as stat_module

    from app.db import open_migrated

    path = tmp_path / "app.db"
    conn = open_migrated(path)
    try:
        assert stat_module.S_IMODE(path.stat().st_mode) == 0o600
        for suffix in ("-wal", "-shm"):
            sidecar = path.with_name(path.name + suffix)
            if sidecar.exists():
                assert stat_module.S_IMODE(sidecar.stat().st_mode) == 0o600, suffix
    finally:
        conn.close()


def test_an_existing_loose_database_is_tightened(tmp_path):
    """Upgrade path: a database created before this rule gets fixed on the next open."""
    import stat as stat_module

    from app.db import open_migrated

    path = tmp_path / "app.db"
    open_migrated(path).close()
    path.chmod(0o644)
    conn = open_migrated(path)
    try:
        assert stat_module.S_IMODE(path.stat().st_mode) == 0o600
    finally:
        conn.close()
