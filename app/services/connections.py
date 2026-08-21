"""Connections as the controller sees them.

This is the seam between the database and OpenVPN. The controller asks for a name and gets back
a username, a password, a challenge prompt and a **path on disk** -- it never learns that there
is a vault or a database behind that.

Resolving writes the ``.ovpn`` out as a side effect. It has to exist as a file: openvpn runs as
root and the helper takes a *name*, resolving it under ``VPN_DIR`` itself, because letting the
caller pass a path would hand them control of what root reads.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

from app.services import store
from app.services.store import Connection, StoreError
from app.services.vault import VaultState

log = logging.getLogger(__name__)

#: Makes OpenVPN discard the DNS servers the server pushes instead of handing them to
#: systemd-resolved. The match is a prefix, so this covers ``dhcp-option DNS6`` too.
PULL_FILTER_DNS = 'pull-filter ignore "dhcp-option DNS"'

_OVERRIDE_HEADER = "# Added by vpn-connect: 'Ignore pushed DNS' is on for this connection."

#: Any existing pull-filter already dealing with pushed DNS, however it is quoted.
_HAS_DNS_PULL_FILTER = re.compile(
    r"^\s*pull-filter\s+(?:ignore|reject)\s+[\"']?dhcp-option\s+DNS",
    re.IGNORECASE | re.MULTILINE,
)


#: OpenVPN's own declaration that the server will ask for a second field alongside the password.
#: The prompt text and the trailing echo flag are optional in the grammar, so only the directive
#: is matched -- its presence is the whole signal.
_HAS_STATIC_CHALLENGE = re.compile(r"^\s*static-challenge(?:\s|$)", re.IGNORECASE | re.MULTILINE)


def profile_wants_mfa(profile: str) -> bool:
    """Whether this profile asks for a second factor.

    Read from the profile rather than offered as a checkbox: ``static-challenge`` *is* the
    statement that a code is required, and a checkbox beside it would only be a second place for
    the same fact to be wrong. A profile without the line signs in with its password alone, which
    the app used to make impossible.
    """
    return bool(_HAS_STATIC_CHALLENGE.search(profile))


def with_dns_override(profile: str, *, ignore: bool) -> str:
    """The profile as it should be written to disk, given the connection's DNS flag.

    Appended to the *derived* file rather than stored in the profile text, which is the operator's
    own vendor-supplied file: rewriting that on a tick could not be undone on an untick. Doing it
    here means the flag is the only state, and turning it off genuinely reverts the file.

    A no-op when the profile already filters pushed DNS itself -- a second, identical pull-filter
    would be harmless to OpenVPN but would imply this added something it did not.
    """
    if not ignore or _HAS_DNS_PULL_FILTER.search(profile):
        return profile
    separator = "" if profile.endswith("\n") else "\n"
    return f"{profile}{separator}{_OVERRIDE_HEADER}\n{PULL_FILTER_DNS}\n"


@dataclass(frozen=True)
class Resolved:
    """Everything needed to start a tunnel. Holds a password -- never log or serialise it."""

    name: str
    username: str
    password: str
    static_challenge: str
    profile_path: Path
    #: Decides how the credential is encoded for OpenVPN: a bare password, or the
    #: ``SCRV1:<password>:<code>`` challenge response.
    requires_mfa: bool = True


class Connections:
    """Connection CRUD plus resolution for the controller."""

    def __init__(self, db, vault_state: VaultState, vpn_dir: Path) -> None:
        self._db = db
        self._vault = vault_state
        self._vpn_dir = vpn_dir

    # -- reading, no key needed -------------------------------------------

    def list(self) -> list[Connection]:
        return store.list_connections(self._db)

    def get(self, name: str) -> Connection | None:
        return store.get_connection(self._db, name)

    def default(self) -> Connection | None:
        return store.default_connection(self._db)

    def any_configured(self) -> bool:
        return bool(store.list_connections(self._db))

    # -- writing, needs the vault unlocked --------------------------------

    def save(
        self,
        *,
        name: str,
        profile: str,
        username: str,
        password: str,
        label: str = "",
        static_challenge: str = "Enter Authenticator Code",
        make_default: bool = False,
        ignore_pushed_dns: bool = False,
    ) -> Connection:
        key = self._vault.require()
        connection = store.save_connection(
            self._db,
            key,
            name=name,
            profile=profile,
            username=username,
            password=password,
            label=label,
            static_challenge=static_challenge,
            make_default=make_default,
            ignore_pushed_dns=ignore_pushed_dns,
            # Derived here rather than asked for: the file the operator just uploaded already
            # says whether a code is needed.
            requires_mfa=profile_wants_mfa(profile),
        )
        # Write it out now rather than at connect time, so a broken profile is discovered while
        # the operator is looking at the form.
        store.write_profile(
            self._profile_path(name), with_dns_override(profile, ignore=ignore_pushed_dns)
        )
        return connection

    def set_default(self, name: str) -> None:
        store.set_default(self._db, name)

    def toggle_ignore_pushed_dns(self, name: str) -> bool:
        """Flip the DNS flag. No vault needed: resolve() rewrites the .ovpn on the next connect."""
        return store.toggle_ignore_pushed_dns(self._db, name)

    def delete(self, name: str) -> None:
        store.delete_connection(self._db, name)
        # The database is the source of truth, so the derived file goes with the row.
        self._profile_path(name).unlink(missing_ok=True)

    # -- resolution for the controller ------------------------------------

    def resolve(self, name: str) -> Resolved:
        """Decrypt a connection and make sure its profile is on disk."""
        # Checked before the lookup so a malformed name says so, rather than reporting the
        # confusing "not found" it would otherwise get. Nothing reaches the helper either way.
        if not store.NAME.match(name or ""):
            raise StoreError("A connection name may only contain letters, digits, '-' and '_'.")
        connection = store.get_connection(self._db, name)
        if connection is None:
            raise StoreError(f"No connection named {name!r}. Add one first.")

        key = self._vault.require()
        secrets = store.secrets_for(self._db, key, name)
        path = self._profile_path(name)
        # Rewritten every time: cheap, and it repairs a file deleted or truncated out from under
        # us without the operator having to work out why the connect failed. It is also what makes
        # the DNS flag take effect on the next connect without re-saving the connection.
        store.write_profile(
            path, with_dns_override(secrets.profile, ignore=connection.ignore_pushed_dns)
        )
        return Resolved(
            name=connection.name,
            username=secrets.username,
            password=secrets.password,
            static_challenge=connection.static_challenge,
            profile_path=path,
            # From the profile that is about to be handed to openvpn, not the stored column: the
            # two agree on every save, and if they ever drift the file is what openvpn obeys.
            requires_mfa=profile_wants_mfa(secrets.profile),
        )

    def _profile_path(self, name: str) -> Path:
        # store.save_connection has already validated the name against the same class the root
        # helper enforces, so this cannot escape VPN_DIR.
        return self._vpn_dir / f"{name}.ovpn"
