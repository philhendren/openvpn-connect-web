"""Reading and writing everything the app keeps in SQLite.

Split by what a caller needs rather than by table: listing connections works while the vault is
locked, because names and timestamps are not secret; reaching the profile, username or password
needs an unlocked :class:`~app.services.vault.Key` passed in explicitly. Nothing here reaches for
ambient state to decrypt with -- if a function can return a secret, the key is one of its
arguments.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from app.db import transaction
from app.services.dns import DnsError, validate_address, validate_domain
from app.services.notify import DEFAULT_BODIES, MESSAGE_KINDS, clean_body
from app.services.vault import Key

#: Must match the character class the root helper validates independently. The name is also the
#: basename of the .ovpn written to disk, so it can never contain a path separator.
NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

#: Keep the log bounded: a chatty reconnect loop should not grow the database without limit.
MAX_LINES_PER_SESSION = 2000

#: How long a connection attempt is kept. Age is what the history is described by -- "the last
#: week" -- so age is what is enforced; the count is only a backstop against a reconnect loop
#: filling the disk in less than a week, and at any sane rate of connecting it never binds.
RETENTION_DAYS = 7
KEEP_SESSIONS = 200

#: Byte counters arrive every few seconds; this is roughly a day of them at OpenVPN's default
#: interval, which is longer than the concentrator will keep a session alive anyway.
MAX_SAMPLES_PER_SESSION = 17_280

# Setting keys. Namespaced so an unrelated setting cannot collide with a notification one.
NTFY_TOPIC = "notify.topic"
NOTIFY_BODY = {
    "up": "notify.body.up",
    "down_manual": "notify.body.down_manual",
    "down_severed": "notify.body.down_severed",
}


class StoreError(ValueError):
    """Raised for input the store refuses -- a bad name, a missing connection."""


@dataclass(frozen=True)
class Connection:
    """A connection without its secrets. Safe to render while the vault is locked."""

    id: int
    name: str
    label: str
    static_challenge: str
    is_default: bool
    created_at: str
    updated_at: str
    #: Drop the DNS servers this connection's server pushes -- see 0004_ignore_pushed_dns.sql.
    ignore_pushed_dns: bool = False
    #: Does the profile ask for a second factor? Derived from its `static-challenge` line on
    #: save -- see 0005_requires_mfa.sql. Defaults on, which is what every row predating it was.
    requires_mfa: bool = True

    @property
    def display_name(self) -> str:
        return self.label or self.name

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "label": self.label,
            "display_name": self.display_name,
            "static_challenge": self.static_challenge,
            "is_default": self.is_default,
            "ignore_pushed_dns": self.ignore_pushed_dns,
            "requires_mfa": self.requires_mfa,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True)
class Secrets:
    """The decrypted half of a connection. Never logged, never serialised to a response."""

    profile: str
    username: str
    password: str


@dataclass(frozen=True)
class DnsRule:
    """One line of the rendered dnsmasq config. Not secret -- safe to render as-is."""

    id: int
    kind: str  # "domain" | "fallback"
    domain: str | None
    address: str
    position: int | None
    updated_at: str

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "kind": self.kind,
            "domain": self.domain,
            "address": self.address,
            "position": self.position,
            "updated_at": self.updated_at,
        }


# --- connections -----------------------------------------------------------


def _connection(row: sqlite3.Row) -> Connection:
    return Connection(
        id=row["id"],
        name=row["name"],
        label=row["label"],
        static_challenge=row["static_challenge"],
        is_default=bool(row["is_default"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        ignore_pushed_dns=bool(row["ignore_pushed_dns"]),
        requires_mfa=bool(row["requires_mfa"]),
    )


def list_connections(conn: sqlite3.Connection) -> list[Connection]:
    rows = conn.execute(
        "SELECT * FROM connections ORDER BY is_default DESC, name COLLATE NOCASE"
    ).fetchall()
    return [_connection(row) for row in rows]


def get_connection(conn: sqlite3.Connection, name: str) -> Connection | None:
    row = conn.execute("SELECT * FROM connections WHERE name = ?", (name,)).fetchone()
    return _connection(row) if row else None


def default_connection(conn: sqlite3.Connection) -> Connection | None:
    """The connection marked default, else the only one, else nothing."""
    row = conn.execute("SELECT * FROM connections WHERE is_default = 1").fetchone()
    if row:
        return _connection(row)
    rows = conn.execute("SELECT * FROM connections LIMIT 2").fetchall()
    return _connection(rows[0]) if len(rows) == 1 else None


def save_connection(
    conn: sqlite3.Connection,
    key: Key,
    *,
    name: str,
    profile: str,
    username: str,
    password: str,
    label: str = "",
    static_challenge: str = "Enter Authenticator Code",
    make_default: bool = False,
    ignore_pushed_dns: bool = False,
    requires_mfa: bool = True,
) -> Connection:
    """Create or replace a connection. Every secret is encrypted before it reaches the database."""
    name = (name or "").strip()
    if not NAME.match(name):
        raise StoreError(
            "A connection name may only contain letters, digits, '-' and '_', up to 64 characters."
        )
    if not (profile or "").strip():
        raise StoreError("The profile is empty -- upload an .ovpn file.")
    if not username:
        raise StoreError("A username is required.")

    now = _now()
    with transaction(conn):
        existing = conn.execute("SELECT id FROM connections WHERE name = ?", (name,)).fetchone()
        values = (
            label.strip(),
            key.encrypt(profile),
            key.encrypt(username),
            key.encrypt(password),
            static_challenge.strip() or "Enter Authenticator Code",
            1 if ignore_pushed_dns else 0,
            1 if requires_mfa else 0,
            now,
        )
        if existing:
            conn.execute(
                "UPDATE connections SET label = ?, profile = ?, username = ?, password = ?,"
                " static_challenge = ?, ignore_pushed_dns = ?, requires_mfa = ?,"
                " updated_at = ? WHERE id = ?",
                (*values, existing["id"]),
            )
        else:
            conn.execute(
                "INSERT INTO connections (name, label, profile, username, password,"
                " static_challenge, ignore_pushed_dns, requires_mfa, updated_at, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (name, *values, now),
            )
        # The first connection is the default; the partial unique index allows only one, so the
        # old one is cleared in the same transaction rather than left to collide.
        only_one = conn.execute("SELECT COUNT(*) AS n FROM connections").fetchone()["n"] == 1
        if make_default or only_one:
            conn.execute("UPDATE connections SET is_default = 0")
            conn.execute("UPDATE connections SET is_default = 1 WHERE name = ?", (name,))

    saved = get_connection(conn, name)
    assert saved is not None  # noqa: S101 - just written in this transaction
    return saved


def set_default(conn: sqlite3.Connection, name: str) -> None:
    if get_connection(conn, name) is None:
        raise StoreError(f"No connection named {name!r}.")
    with transaction(conn):
        conn.execute("UPDATE connections SET is_default = 0")
        conn.execute("UPDATE connections SET is_default = 1 WHERE name = ?", (name,))


def toggle_ignore_pushed_dns(conn: sqlite3.Connection, name: str) -> bool:
    """Flip whether this connection refuses the server's pushed DNS. Returns the new value.

    Deliberately does not need the vault: only the flag moves, and the ``.ovpn`` that carries the
    directive is rewritten from the database on every connect anyway. Toggling therefore works
    while locked, and takes effect on the next connect.
    """
    connection = get_connection(conn, name)
    if connection is None:
        raise StoreError(f"No connection named {name!r}.")
    enabled = not connection.ignore_pushed_dns
    with transaction(conn):
        conn.execute(
            "UPDATE connections SET ignore_pushed_dns = ?, updated_at = ? WHERE name = ?",
            (1 if enabled else 0, _now(), name),
        )
    return enabled


def delete_connection(conn: sqlite3.Connection, name: str) -> None:
    with transaction(conn):
        deleted = conn.execute("DELETE FROM connections WHERE name = ?", (name,)).rowcount
        if not deleted:
            raise StoreError(f"No connection named {name!r}.")
        # Promote a survivor so the app is never left with connections but no default.
        if conn.execute("SELECT 1 FROM connections WHERE is_default = 1").fetchone() is None:
            row = conn.execute("SELECT name FROM connections ORDER BY name LIMIT 1").fetchone()
            if row:
                conn.execute("UPDATE connections SET is_default = 1 WHERE name = ?", (row["name"],))


def secrets_for(conn: sqlite3.Connection, key: Key, name: str) -> Secrets:
    """The decrypted profile and credentials. Requires an unlocked key."""
    row = conn.execute(
        "SELECT profile, username, password FROM connections WHERE name = ?", (name,)
    ).fetchone()
    if row is None:
        raise StoreError(f"No connection named {name!r}.")
    return Secrets(
        profile=key.decrypt_text(row["profile"]),
        username=key.decrypt_text(row["username"]),
        password=key.decrypt_text(row["password"]),
    )


def write_profile(path: Path, profile: str) -> Path:
    """Write the .ovpn where openvpn can read it, owner-only and atomically.

    The database is the source of truth; this file is a derived artefact. It exists because the
    root helper takes a *name* and resolves it under VPN_DIR -- widening that to an arbitrary
    path would hand the caller control of what root reads.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.tmp")
    try:
        temp.write_text(profile, encoding="utf-8")
        temp.chmod(0o600)  # inline private keys live in here
        temp.replace(path)
    except OSError:
        temp.unlink(missing_ok=True)
        raise
    return path


def write_dns_staging(path: Path, content: str) -> Path:
    """Write the rendered dnsmasq text where the root helper can read it, atomically.

    Mode 0644, unlike write_profile(): a DNS rule is not secret, and dnsmasq itself must be able
    to read the file once the helper installs it under /etc/dnsmasq.d/.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.tmp")
    try:
        temp.write_text(content, encoding="utf-8")
        temp.chmod(0o644)
        temp.replace(path)
    except OSError:
        temp.unlink(missing_ok=True)
        raise
    return path


# --- settings --------------------------------------------------------------


def get_setting(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    with transaction(conn):
        conn.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value,"
            " updated_at = excluded.updated_at",
            (key, value, _now()),
        )


def set_settings(conn: sqlite3.Connection, values: dict[str, str]) -> None:
    """Write several settings in one transaction, so a partial save cannot happen."""
    now = _now()
    with transaction(conn):
        for key, value in values.items():
            conn.execute(
                "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value,"
                " updated_at = excluded.updated_at",
                (key, value, now),
            )


# --- notification settings -------------------------------------------------


def notify_topic(conn: sqlite3.Connection) -> str:
    return get_setting(conn, NTFY_TOPIC)


def notify_bodies(conn: sqlite3.Connection) -> dict[str, str]:
    """Configured bodies, falling back to the default kind by kind."""
    bodies = dict(DEFAULT_BODIES)
    for kind in MESSAGE_KINDS:
        stored = get_setting(conn, NOTIFY_BODY[kind])
        if stored:
            bodies[kind] = stored
    return bodies


def save_notify(
    conn: sqlite3.Connection, topic: str | None = None, bodies: dict[str, str] | None = None
) -> None:
    """Save the topic, the bodies, or both, in one transaction.

    A blank body is a request to restore that default rather than to send an empty push, so it
    is stored as the empty string and read back as the default.
    """
    values: dict[str, str] = {}
    if topic is not None:
        values[NTFY_TOPIC] = topic
    for kind in MESSAGE_KINDS:
        if bodies is not None and kind in bodies:
            values[NOTIFY_BODY[kind]] = clean_body(bodies[kind])
    if values:
        set_settings(conn, values)


# --- dns rules ---------------------------------------------------------------


def _dns_rule(row: sqlite3.Row) -> DnsRule:
    return DnsRule(
        id=row["id"],
        kind=row["kind"],
        domain=row["domain"],
        address=row["address"],
        position=row["position"],
        updated_at=row["updated_at"],
    )


def list_dns_rules(conn: sqlite3.Connection) -> list[DnsRule]:
    rows = conn.execute(
        "SELECT * FROM dns_rules ORDER BY kind, domain COLLATE NOCASE, position"
    ).fetchall()
    return [_dns_rule(row) for row in rows]


def add_dns_rule(
    conn: sqlite3.Connection, *, kind: str, domain: str | None, address: str
) -> DnsRule:
    """Validate and save one rule.

    A ``kind="domain"`` add upserts by domain: re-adding an existing domain with a new address
    replaces it rather than raising, so a concentrator-IP change does not need delete-then-add.
    A duplicate ``fallback`` address is refused outright -- there is no sensible "replace" for an
    unkeyed row.
    """
    if kind not in ("domain", "fallback"):
        raise DnsError(f"Unknown rule kind {kind!r}.")
    address = validate_address(address)
    now = _now()

    with transaction(conn):
        if kind == "domain":
            clean_domain = validate_domain(domain or "")
            existing = conn.execute(
                "SELECT id FROM dns_rules WHERE kind = 'domain' AND domain = ?", (clean_domain,)
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE dns_rules SET address = ?, updated_at = ? WHERE id = ?",
                    (address, now, existing["id"]),
                )
                rule_id = existing["id"]
            else:
                cursor = conn.execute(
                    "INSERT INTO dns_rules (kind, domain, address, position, created_at,"
                    " updated_at) VALUES ('domain', ?, ?, NULL, ?, ?)",
                    (clean_domain, address, now, now),
                )
                rule_id = cursor.lastrowid
        else:
            duplicate = conn.execute(
                "SELECT id FROM dns_rules WHERE kind = 'fallback' AND address = ?", (address,)
            ).fetchone()
            if duplicate:
                raise StoreError(f"{address} is already a fallback server.")
            next_position = conn.execute(
                "SELECT COALESCE(MAX(position), -1) + 1 AS n FROM dns_rules WHERE kind = 'fallback'"
            ).fetchone()["n"]
            cursor = conn.execute(
                "INSERT INTO dns_rules (kind, domain, address, position, created_at, updated_at)"
                " VALUES ('fallback', NULL, ?, ?, ?, ?)",
                (address, next_position, now, now),
            )
            rule_id = cursor.lastrowid

    row = conn.execute("SELECT * FROM dns_rules WHERE id = ?", (rule_id,)).fetchone()
    assert row is not None  # noqa: S101 - just written in this transaction
    return _dns_rule(row)


def delete_dns_rule(conn: sqlite3.Connection, rule_id: int) -> None:
    with transaction(conn):
        deleted = conn.execute("DELETE FROM dns_rules WHERE id = ?", (rule_id,)).rowcount
        if not deleted:
            raise StoreError(f"No DNS rule with id {rule_id}.")


def move_fallback_rule(conn: sqlite3.Connection, rule_id: int, direction: str) -> None:
    """Swap a fallback rule's position with its neighbour.

    Clamped at the ends, a no-op if the rule is already there rather than an error -- the UI need
    not disable the buttons perfectly.
    """
    if direction not in ("up", "down"):
        raise StoreError(f"Unknown direction {direction!r}.")
    with transaction(conn):
        row = conn.execute(
            "SELECT id, position FROM dns_rules WHERE id = ? AND kind = 'fallback'", (rule_id,)
        ).fetchone()
        if row is None:
            raise StoreError(f"No fallback rule with id {rule_id}.")
        if direction == "up":
            neighbour = conn.execute(
                "SELECT id, position FROM dns_rules WHERE kind = 'fallback' AND position < ?"
                " ORDER BY position DESC LIMIT 1",
                (row["position"],),
            ).fetchone()
        else:
            neighbour = conn.execute(
                "SELECT id, position FROM dns_rules WHERE kind = 'fallback' AND position > ?"
                " ORDER BY position ASC LIMIT 1",
                (row["position"],),
            ).fetchone()
        if neighbour is None:
            return
        now = _now()
        conn.execute(
            "UPDATE dns_rules SET position = ?, updated_at = ? WHERE id = ?",
            (neighbour["position"], now, row["id"]),
        )
        conn.execute(
            "UPDATE dns_rules SET position = ?, updated_at = ? WHERE id = ?",
            (row["position"], now, neighbour["id"]),
        )


# --- events ----------------------------------------------------------------


def record_event(
    conn: sqlite3.Connection, kind: str, reason: str = "", connection: str | None = None
) -> None:
    with transaction(conn):
        conn.execute(
            "INSERT INTO events (at, kind, reason, connection) VALUES (?, ?, ?, ?)",
            (_now(), kind, reason, connection),
        )


def recent_events(conn: sqlite3.Connection, limit: int = 10) -> list[str]:
    """Newest first, formatted the way the old hook-written log file read."""
    rows = conn.execute(
        "SELECT at, kind, reason FROM events ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [f"{row['at']} {row['kind']} {row['reason']}".rstrip() for row in rows]


# --- sessions --------------------------------------------------------------


def window_start(days: int = RETENTION_DAYS, now: datetime | None = None) -> str:
    """The oldest moment the history reaches back to, in the same format the rows use."""
    moment = now or datetime.now().astimezone()
    return (moment - timedelta(days=days)).isoformat(timespec="seconds")


def _in_window(alias: str = "") -> str:
    """SQL for "this session is inside the retention window", taking the cutoff as a parameter.

    Inside means it *ended* inside the window -- or has not ended at all. Deliberately not
    "started inside it": an attempt that began eight days ago and ended yesterday is a session
    you were in for most of the last week, and cutting it off at the boundary would report a
    nine-hour tunnel as a one-hour one. A session is kept whole, back to its beginning, or not
    at all, so the history is *at least* seven days and occasionally a little more.

    Written once and used twice, by the reader and by the sweep, because a window the two
    disagreed about would show rows that the next connect silently deleted.
    """
    column = f"{alias}.ended_at" if alias else "ended_at"
    return f"({column} IS NULL OR julianday({column}) >= julianday(?))"


# Built once each from that predicate, so the reader and the sweep cannot drift apart. The
# interpolation is the constant above and nothing else -- the cutoff itself is bound as a
# parameter, like every other value in this file -- which is why the injection check is silenced
# here by name rather than left to be ignored by eye.
_LIST_SESSIONS = (
    "SELECT s.id, s.connection, s.started_at,"  # noqa: S608
    " s.connected_at, s.ended_at, s.outcome, s.reason,"
    " (SELECT COUNT(*) FROM log_lines l WHERE l.session_id = s.id) AS lines,"
    " (SELECT MAX(t.bytes_in) FROM traffic_samples t WHERE t.session_id = s.id) AS bytes_in,"
    " (SELECT MAX(t.bytes_out) FROM traffic_samples t WHERE t.session_id = s.id) AS bytes_out"
    f" FROM sessions s WHERE {_in_window('s')} ORDER BY s.id DESC LIMIT ?"
)

_SWEEP_SESSIONS = f"DELETE FROM sessions WHERE NOT {_in_window()}"  # noqa: S608


def start_session(conn: sqlite3.Connection, connection: str | None) -> int:
    with transaction(conn):
        cursor = conn.execute(
            "INSERT INTO sessions (connection, started_at) VALUES (?, ?)",
            (connection, _now()),
        )
        return int(cursor.lastrowid or 0)


def append_lines(conn: sqlite3.Connection, session_id: int, lines: list[str]) -> None:
    """Append log lines, then trim the session back to its cap.

    Trimming keeps the *newest* lines: when a connect goes wrong the tail is what explains it.
    """
    if not lines:
        return
    now = _now()
    with transaction(conn):
        conn.executemany(
            "INSERT INTO log_lines (session_id, at, line) VALUES (?, ?, ?)",
            [(session_id, now, line) for line in lines],
        )
        conn.execute(
            "DELETE FROM log_lines WHERE session_id = ? AND id NOT IN ("
            "  SELECT id FROM log_lines WHERE session_id = ? ORDER BY id DESC LIMIT ?)",
            (session_id, session_id, MAX_LINES_PER_SESSION),
        )


def end_session(conn: sqlite3.Connection, session_id: int, outcome: str, reason: str = "") -> None:
    """Close an attempt. ``reason`` is the controller's own verdict on *why* it ended."""
    with transaction(conn):
        conn.execute(
            "UPDATE sessions SET ended_at = ?, outcome = ?, reason = ? WHERE id = ?",
            (_now(), outcome, reason, session_id),
        )


def mark_session_connected(conn: sqlite3.Connection, session_id: int) -> None:
    """Record that this attempt reached CONNECTED, and when.

    Written the moment it happens rather than inferred afterwards: whether a tunnel came up is
    the difference between "failed twice" and "dropped twice", and nothing else in the row can
    tell them apart once the process is gone. Only the first transition counts, so a re-adopted
    tunnel cannot restart its own clock.
    """
    with transaction(conn):
        conn.execute(
            "UPDATE sessions SET connected_at = ? WHERE id = ? AND connected_at IS NULL",
            (_now(), session_id),
        )


def session_lines(conn: sqlite3.Connection, session_id: int, limit: int = 500) -> list[str]:
    rows = conn.execute(
        "SELECT line FROM (SELECT id, line FROM log_lines WHERE session_id = ?"
        " ORDER BY id DESC LIMIT ?) ORDER BY id",
        (session_id, limit),
    ).fetchall()
    return [row["line"] for row in rows]


def recent_sessions(conn: sqlite3.Connection, limit: int = 10) -> list[dict[str, object]]:
    rows = conn.execute(
        "SELECT s.id, s.connection, s.started_at, s.ended_at, s.outcome,"
        " (SELECT COUNT(*) FROM log_lines l WHERE l.session_id = s.id) AS lines"
        " FROM sessions s ORDER BY s.id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def list_sessions(
    conn: sqlite3.Connection,
    *,
    days: int = RETENTION_DAYS,
    limit: int = KEEP_SESSIONS,
    now: datetime | None = None,
) -> list[dict[str, object]]:
    """Every attempt inside the retention window, newest first, with what it moved.

    Filtered on read as well as swept on write, because the sweep only runs when a new attempt
    starts: on a machine that has not connected for a fortnight the rows are still there, and a
    panel that showed them would be quietly contradicting its own "last seven days" heading.

    Byte totals are the *largest* reading rather than the last one. OpenVPN's counters are
    cumulative for the life of the tunnel, so the largest is the total; taking the last would
    under-report an attempt whose counter was reset underneath us, which is the same
    going-backwards case :mod:`app.services.traffic` guards when it draws the graph.
    """
    rows = conn.execute(_LIST_SESSIONS, (window_start(days, now), limit)).fetchall()
    return [dict(row) for row in rows]


def prune_sessions(
    conn: sqlite3.Connection,
    keep: int = KEEP_SESSIONS,
    *,
    days: int = RETENTION_DAYS,
    now: datetime | None = None,
) -> int:
    """Drop sessions that have fallen out of the retention window, newest ``keep`` regardless.

    Two rules, and the age one is the point: anything that ended before the cutoff goes, and a
    session still in progress is never touched however long it has been up. The count is the
    backstop described at :data:`KEEP_SESSIONS`. Lines and traffic samples go with the row via
    ON DELETE CASCADE, so retention needs no separate sweep for either.
    """
    with transaction(conn):
        aged = conn.execute(_SWEEP_SESSIONS, (window_start(days, now),)).rowcount
        excess = conn.execute(
            "DELETE FROM sessions WHERE id NOT IN ("
            "  SELECT id FROM sessions ORDER BY id DESC LIMIT ?)",
            (keep,),
        ).rowcount
    return aged + excess


# --- traffic samples -------------------------------------------------------


def record_sample(
    conn: sqlite3.Connection, session_id: int, at: float, bytes_in: int, bytes_out: int
) -> None:
    """Store one cumulative byte-counter reading.

    Written through rather than buffered, unlike log lines: these arrive one at a time on a fixed
    interval rather than in bursts, and a buffered sample is one the live graph cannot see.
    """
    with transaction(conn):
        conn.execute(
            "INSERT INTO traffic_samples (session_id, at, bytes_in, bytes_out) VALUES (?, ?, ?, ?)",
            (session_id, at, bytes_in, bytes_out),
        )
        conn.execute(
            "DELETE FROM traffic_samples WHERE session_id = ? AND id NOT IN ("
            "  SELECT id FROM traffic_samples WHERE session_id = ? ORDER BY id DESC LIMIT ?)",
            (session_id, session_id, MAX_SAMPLES_PER_SESSION),
        )


def session_samples(conn: sqlite3.Connection, session_id: int) -> list[tuple[float, int, int]]:
    """Raw cumulative readings for a session, oldest first."""
    rows = conn.execute(
        "SELECT at, bytes_in, bytes_out FROM traffic_samples WHERE session_id = ? ORDER BY id",
        (session_id,),
    ).fetchall()
    return [(row["at"], row["bytes_in"], row["bytes_out"]) for row in rows]


def _now() -> str:
    """Local time with offset -- the format the event log has always used."""
    return datetime.now().astimezone().isoformat(timespec="seconds")
