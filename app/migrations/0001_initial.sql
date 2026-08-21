-- Initial schema: connections, settings, and history.
--
-- Everything secret is stored as an encrypted BLOB. The key is derived from the operator's web
-- login password (see app/services/vault.py) and never written to disk, so a copy of this file
-- on its own reveals nothing but connection names and timestamps.

-- One row, holding the key-derivation parameters and a verifier that proves a password is right.
CREATE TABLE vault (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    salt         BLOB    NOT NULL,
    verifier     BLOB    NOT NULL,
    created_at   TEXT    NOT NULL
);

CREATE TABLE connections (
    id                 INTEGER PRIMARY KEY,
    -- Passed to the root helper, which independently validates it against the same character
    -- class. Also the basename of the .ovpn file written out for openvpn to read.
    name               TEXT    NOT NULL UNIQUE,
    label              TEXT    NOT NULL DEFAULT '',
    profile            BLOB    NOT NULL,   -- the .ovpn, encrypted; holds inline keys
    username           BLOB    NOT NULL,   -- encrypted
    password           BLOB    NOT NULL,   -- encrypted
    static_challenge   TEXT    NOT NULL DEFAULT 'Enter Authenticator Code',
    is_default         INTEGER NOT NULL DEFAULT 0 CHECK (is_default IN (0, 1)),
    created_at         TEXT    NOT NULL,
    updated_at         TEXT    NOT NULL
);

-- At most one default connection.
CREATE UNIQUE INDEX connections_one_default ON connections(is_default) WHERE is_default = 1;

-- Key/value for everything that is not a connection: the ntfy topic, the message bodies, and
-- whatever later settings arrive. Deliberately schemaless so a new setting needs no migration.
CREATE TABLE settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

-- The UP/DOWN history the status page tails. Small, and kept forever.
CREATE TABLE events (
    id          INTEGER PRIMARY KEY,
    at          TEXT NOT NULL,
    kind        TEXT NOT NULL,               -- UP | DOWN
    reason      TEXT NOT NULL DEFAULT '',    -- operator-requested | link-lost
    connection  TEXT
);

CREATE INDEX events_recent ON events(id DESC);

-- One row per connection attempt, so a *failed* attempt's log survives the process exiting --
-- which the in-memory ring buffer never did.
CREATE TABLE log_sessions (
    id          INTEGER PRIMARY KEY,
    connection  TEXT,
    started_at  TEXT NOT NULL,
    ended_at    TEXT,
    outcome     TEXT                          -- connected | failed | disconnected
);

CREATE INDEX log_sessions_recent ON log_sessions(id DESC);

CREATE TABLE log_lines (
    id          INTEGER PRIMARY KEY,
    session_id  INTEGER NOT NULL REFERENCES log_sessions(id) ON DELETE CASCADE,
    at          TEXT    NOT NULL,
    line        TEXT    NOT NULL
);

CREATE INDEX log_lines_session ON log_lines(session_id, id);
