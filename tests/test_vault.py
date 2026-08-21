"""Encryption at rest. The key comes from the login password and is never stored."""

from __future__ import annotations

import pytest

from app.services import vault
from app.services.vault import ENCRYPTED_COLUMNS, VaultError, VaultLocked, VaultState

PASSWORD = "correct-horse-battery-staple"


def _insert(db, key, name="examplecorp", profile="PROFILE", username="alice", password="s3cret"):
    db.execute(
        "INSERT INTO connections (name, profile, username, password, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, 't', 't')",
        (name, key.encrypt(profile), key.encrypt(username), key.encrypt(password)),
    )


# --- lifecycle -------------------------------------------------------------


def test_a_fresh_database_has_no_vault(db):
    assert not vault.exists(db)
    with pytest.raises(VaultError, match="not been set up"):
        vault.unlock(db, PASSWORD)


def test_initialise_then_unlock(db):
    key = vault.initialise(db, PASSWORD)
    token = key.encrypt("secret text")
    assert vault.unlock(db, PASSWORD).decrypt_text(token) == "secret text"


def test_initialising_twice_is_refused(db):
    vault.initialise(db, PASSWORD)
    with pytest.raises(VaultError, match="already exists"):
        vault.initialise(db, PASSWORD)


def test_the_wrong_password_does_not_unlock(db):
    vault.initialise(db, PASSWORD)
    with pytest.raises(VaultError, match="does not unlock"):
        vault.unlock(db, "not-the-password")


def test_a_corrupt_verifier_is_reported_as_corruption(db):
    """Distinguishable from a wrong password, because the fixes are different."""
    vault.initialise(db, PASSWORD)
    db.execute("UPDATE vault SET verifier = ?", (b"not a fernet token",))
    with pytest.raises(VaultError):
        vault.unlock(db, PASSWORD)


# --- what actually lands on disk -------------------------------------------


def test_the_key_is_never_stored(db):
    vault.initialise(db, PASSWORD)
    row = db.execute("SELECT salt, verifier FROM vault").fetchone()
    blob = bytes(row["salt"]) + bytes(row["verifier"])
    assert PASSWORD.encode() not in blob


def test_secrets_are_not_readable_without_the_key(db):
    key = vault.initialise(db, PASSWORD)
    _insert(db, key, password="hunter2-in-the-clear")
    dump = db.execute("SELECT password FROM connections").fetchone()["password"]
    assert b"hunter2-in-the-clear" not in bytes(dump)


def test_every_salt_is_unique(db, open_db):
    vault.initialise(db, PASSWORD)
    other = open_db("second.db")
    from app.db import migrate

    migrate(other)
    vault.initialise(other, PASSWORD)
    assert (
        db.execute("SELECT salt FROM vault").fetchone()["salt"]
        != (other.execute("SELECT salt FROM vault").fetchone()["salt"])
    )


def test_the_same_plaintext_encrypts_differently_each_time(db):
    key = vault.initialise(db, PASSWORD)
    assert key.encrypt("same") != key.encrypt("same")


def test_a_key_does_not_print_itself(db):
    assert "redacted" in repr(vault.initialise(db, PASSWORD))


def test_tampered_ciphertext_is_rejected(db):
    """Fernet is authenticated, so an edited blob fails rather than decrypting to garbage."""
    key = vault.initialise(db, PASSWORD)
    token = bytearray(key.encrypt("secret"))
    token[-1] ^= 0xFF
    with pytest.raises(VaultError):
        key.decrypt(bytes(token))


# --- rekeying on a password change -----------------------------------------


def test_rekey_re_encrypts_every_secret(db):
    key = vault.initialise(db, PASSWORD)
    _insert(db, key)
    new_key = vault.rekey(db, PASSWORD, "a-new-password")

    row = db.execute("SELECT profile, username, password FROM connections").fetchone()
    assert new_key.decrypt_text(row["username"]) == "alice"
    assert new_key.decrypt_text(row["password"]) == "s3cret"
    assert new_key.decrypt_text(row["profile"]) == "PROFILE"


def test_after_rekey_the_old_password_is_useless(db):
    key = vault.initialise(db, PASSWORD)
    _insert(db, key)
    vault.rekey(db, PASSWORD, "a-new-password")
    with pytest.raises(VaultError):
        vault.unlock(db, PASSWORD)
    assert vault.unlock(db, "a-new-password") is not None


def test_rekey_with_the_wrong_old_password_changes_nothing(db):
    key = vault.initialise(db, PASSWORD)
    _insert(db, key)
    with pytest.raises(VaultError):
        vault.rekey(db, "wrong", "a-new-password")
    assert (
        vault.unlock(db, PASSWORD).decrypt_text(
            db.execute("SELECT username FROM connections").fetchone()["username"]
        )
        == "alice"
    )


def test_rekey_covers_every_encrypted_column(db):
    """If a column is missing from ENCRYPTED_COLUMNS it silently keeps the old key forever.

    Compared against the schema rather than a hand-written list, so adding an encrypted column
    without registering it fails here instead of on somebody's next password change.
    """
    for table, columns in ENCRYPTED_COLUMNS.items():
        blobs = {
            row["name"]
            for row in db.execute(f"PRAGMA table_info({table})")
            if row["type"].upper() == "BLOB"
        }
        assert blobs == set(columns), (
            f"{table}: schema has {blobs}, ENCRYPTED_COLUMNS has {set(columns)}"
        )


def test_the_vault_table_is_not_rekeyed_as_data(db):
    """vault.salt/verifier are BLOBs too, but they are the key material, not secrets under it."""
    assert "vault" not in ENCRYPTED_COLUMNS


# --- process-wide unlock state ---------------------------------------------


def test_state_starts_locked():
    state = VaultState()
    assert not state.unlocked
    with pytest.raises(VaultLocked, match="Sign in"):
        state.require()


def test_state_holds_and_releases_the_key(db):
    state = VaultState()
    key = vault.initialise(db, PASSWORD)
    state.store(key)
    assert state.unlocked
    assert state.require() is key
    state.lock()
    assert not state.unlocked
