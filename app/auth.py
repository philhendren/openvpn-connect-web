"""Session login, CSRF and login rate limiting.

The app can change this machine's routing table, so the login is the only thing between the
network and root-equivalent control.  Keep it boring and strict: a scrypt-hashed password, a
signed session cookie, per-IP lockout, and a CSRF token on every state change.
"""

from __future__ import annotations

import secrets
import threading
import time
from collections.abc import Callable
from functools import wraps
from typing import Any

from flask import current_app, flash, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from app.services import vault

CSRF_SESSION_KEY = "_csrf_token"
CSRF_FORM_FIELD = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"


class CsrfError(Exception):
    """Raised when a state-changing request arrives without a valid CSRF token."""


class LoginThrottle:
    """Per-remote-address failure counter with a fixed lockout window."""

    def __init__(self, max_attempts: int, lockout_seconds: int) -> None:
        self._max = max_attempts
        self._lockout = lockout_seconds
        self._lock = threading.Lock()
        self._failures: dict[str, tuple[int, float]] = {}

    def seconds_remaining(self, key: str) -> int:
        with self._lock:
            count, last = self._failures.get(key, (0, 0.0))
            if count < self._max:
                return 0
            remaining = int(self._lockout - (time.time() - last))
            if remaining <= 0:
                self._failures.pop(key, None)
                return 0
            return remaining

    def record_failure(self, key: str) -> None:
        with self._lock:
            count, _ = self._failures.get(key, (0, 0.0))
            self._failures[key] = (count + 1, time.time())

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)


#: How a login password is hashed. Werkzeug's bare "scrypt" is n=2**15, r=8, p=1.
#:
#: Verification cost follows whatever the stored hash was made with, so lowering this in tests
#: (see tests/conftest.py) makes both hashing and checking cheap. ``PASSWORD_HASH_METHOD`` is what
#: the tests patch; ``..._PRODUCTION`` is what a real install must use, and a test asserts it.
PASSWORD_HASH_METHOD_PRODUCTION = "scrypt"  # noqa: S105 -- an algorithm name, not a password
PASSWORD_HASH_METHOD = PASSWORD_HASH_METHOD_PRODUCTION


def hash_password(password: str) -> str:
    return generate_password_hash(password, method=PASSWORD_HASH_METHOD)


def verify_password(password: str) -> bool:
    """Constant-time-ish check against the configured hash."""
    stored = current_app.config["APP_CONFIG"].PASSWORD_HASH
    if not stored:
        return False
    return check_password_hash(stored, password)


def is_logged_in() -> bool:
    return bool(session.get("authenticated"))


def log_in() -> None:
    session.clear()
    session["authenticated"] = True
    session[CSRF_SESSION_KEY] = secrets.token_urlsafe(32)
    session.permanent = True


def log_out() -> None:
    session.clear()


def csrf_token() -> str:
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def validate_csrf() -> None:
    expected = session.get(CSRF_SESSION_KEY, "")
    supplied = request.form.get(CSRF_FORM_FIELD) or request.headers.get(CSRF_HEADER, "")
    if not expected or not supplied or not secrets.compare_digest(expected, supplied):
        raise CsrfError("Invalid or missing CSRF token.")


def unlock_vault(password: str) -> None:
    """Turn the login password into the encryption key and hold it for this process.

    Creates the vault on first sign-in. Raises :class:`~app.services.vault.VaultError` if the
    login hash matches but the vault does not -- which means the password was changed without
    ``flask --app app set-password`` rekeying, and the stored connections need the old one.
    """
    db = current_app.config["DB"]
    state = current_app.config["VAULT"]
    if vault.exists(db):
        state.store(vault.unlock(db, password))
    else:
        state.store(vault.initialise(db, password))


def vault_locked() -> bool:
    """True when there are stored secrets but no key in memory to read them with.

    Happens routinely: the session cookie is signed and survives a restart, the derived key
    lives only in memory and does not.
    """
    db = current_app.config.get("DB")
    state = current_app.config.get("VAULT")
    if db is None or state is None or state.unlocked:
        return False
    return vault.exists(db)


def login_required(view: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(view)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if is_logged_in() and vault_locked():
            # A valid session over a locked vault can read nothing useful, so end it rather
            # than let the page half-work with unexplained errors.
            log_out()
            if request.path.startswith("/api/"):
                return {"error": "Signed out -- the app restarted. Sign in again."}, 401
            flash("The app restarted. Sign in again to unlock your connections.", "error")
            return redirect(url_for("ui.login", next=request.path))
        if not is_logged_in():
            if request.path.startswith("/api/"):
                return {"error": "Authentication required."}, 401
            flash("Please sign in.", "error")
            return redirect(url_for("ui.login", next=request.path))
        return view(*args, **kwargs)

    return wrapper
