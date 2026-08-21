"""Encryption for everything secret in the database.

The key is derived with scrypt from the operator's **web login password** and is never written
anywhere -- not to the database, not to the env file. A copy of ``vpn-connect.db`` therefore
reveals connection names and timestamps and nothing else.

Deriving from the login password costs nothing operationally, which is what makes it the right
choice here: connecting is *already* interactive, because somebody has to type an authenticator
code. There is no unattended path to break.

Two details worth knowing:

* The vault has **its own salt**, unrelated to the one behind ``PASSWORD_HASH``. The stored login
  hash and the encryption key are both derived from the same password and must not be derivable
  from each other.
* Unlocking is **process-wide**, not per-session. This is a single-operator appliance with one
  worker; a per-session key store would add plumbing to protect one person from themselves.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
import sqlite3
from datetime import UTC, datetime

from cryptography.fernet import Fernet, InvalidToken

from app.db import transaction

log = logging.getLogger(__name__)

#: scrypt parameters. n=2**15 costs roughly a tenth of a second and 32MB, which is a sensible
#: price on a login that happens a few times a day.
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 64 * 1024 * 1024
KEY_BYTES = 32
SALT_BYTES = 16

#: Encrypted under the derived key when the vault is created, and decrypted on every unlock to
#: tell "wrong password" apart from "corrupt database".
_VERIFIER_PLAINTEXT = b"vpn-connect vault v1"

#: Every encrypted column, by table. **Add to this when you add an encrypted column** -- rekeying
#: walks this map, and a column missing from it would keep the old key after a password change.
#: ``test_vault.py`` checks it against the schema so the omission cannot go unnoticed.
ENCRYPTED_COLUMNS: dict[str, tuple[str, ...]] = {
    "connections": ("profile", "username", "password"),
}


class VaultError(RuntimeError):
    """Raised when the vault cannot be unlocked or is used before it exists."""


class VaultLocked(VaultError):
    """Raised when secrets are needed but nobody has signed in since the app started."""


class Key:
    """A derived encryption key. Deliberately awkward to print or serialise."""

    __slots__ = ("_fernet",)

    def __init__(self, raw: bytes) -> None:
        self._fernet = Fernet(base64.urlsafe_b64encode(raw))

    def encrypt(self, value: str | bytes) -> bytes:
        if isinstance(value, str):
            value = value.encode("utf-8")
        return self._fernet.encrypt(value)

    def decrypt(self, token: bytes) -> bytes:
        try:
            return self._fernet.decrypt(token)
        except InvalidToken as exc:
            raise VaultError("Could not decrypt -- wrong key or corrupt data.") from exc

    def decrypt_text(self, token: bytes) -> str:
        return self.decrypt(token).decode("utf-8")

    def __repr__(self) -> str:  # pragma: no cover - defensive
        return "<Key (redacted)>"


def derive(password: str, salt: bytes) -> Key:
    """scrypt the password into an encryption key."""
    raw = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=KEY_BYTES,
        maxmem=SCRYPT_MAXMEM,
    )
    return Key(raw)


def exists(conn: sqlite3.Connection) -> bool:
    return conn.execute("SELECT 1 FROM vault WHERE id = 1").fetchone() is not None


def initialise(conn: sqlite3.Connection, password: str) -> Key:
    """Create the vault for this password. Idempotent only in the sense that it refuses twice."""
    if exists(conn):
        raise VaultError("The vault already exists.")
    salt = secrets.token_bytes(SALT_BYTES)
    key = derive(password, salt)
    with transaction(conn):
        conn.execute(
            "INSERT INTO vault (id, salt, verifier, created_at) VALUES (1, ?, ?, ?)",
            (salt, key.encrypt(_VERIFIER_PLAINTEXT), _now()),
        )
    return key


def unlock(conn: sqlite3.Connection, password: str) -> Key:
    """Derive the key and prove it is the right one."""
    row = conn.execute("SELECT salt, verifier FROM vault WHERE id = 1").fetchone()
    if row is None:
        raise VaultError("The vault has not been set up yet.")
    key = derive(password, row["salt"])
    try:
        plaintext = key.decrypt(row["verifier"])
    except VaultError as exc:
        raise VaultError("That password does not unlock the vault.") from exc
    if not hmac.compare_digest(plaintext, _VERIFIER_PLAINTEXT):
        raise VaultError("The vault verifier does not match -- the database may be corrupt.")
    return key


def rekey(conn: sqlite3.Connection, old_password: str, new_password: str) -> Key:
    """Re-encrypt every secret under a key derived from ``new_password``.

    Must be called whenever the login password changes: the old key is unreachable afterwards,
    and without this the connections in the database become permanently undecryptable.
    """
    old_key = unlock(conn, old_password)
    salt = secrets.token_bytes(SALT_BYTES)
    new_key = derive(new_password, salt)

    with transaction(conn):
        for table, columns in ENCRYPTED_COLUMNS.items():
            selected = ", ".join(("id", *columns))
            rows = conn.execute(f"SELECT {selected} FROM {table}").fetchall()  # noqa: S608
            assignments = ", ".join(f"{column} = ?" for column in columns)
            for row in rows:
                values = [new_key.encrypt(old_key.decrypt(row[column])) for column in columns]
                conn.execute(
                    f"UPDATE {table} SET {assignments} WHERE id = ?",  # noqa: S608
                    (*values, row["id"]),
                )
        conn.execute(
            "UPDATE vault SET salt = ?, verifier = ?, created_at = ? WHERE id = 1",
            (salt, new_key.encrypt(_VERIFIER_PLAINTEXT), _now()),
        )
    return new_key


class VaultState:
    """Holds the unlocked key for the life of the process.

    Signing in unlocks; nothing re-locks except a restart or an explicit :meth:`lock`. Signing
    *out* deliberately does not, because one browser tab logging out should not sever a tunnel
    operation another is in the middle of.
    """

    def __init__(self) -> None:
        self._key: Key | None = None

    @property
    def unlocked(self) -> bool:
        return self._key is not None

    def store(self, key: Key) -> None:
        self._key = key

    def lock(self) -> None:
        self._key = None

    def require(self) -> Key:
        if self._key is None:
            raise VaultLocked("Sign in to unlock the stored credentials.")
        return self._key


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")
