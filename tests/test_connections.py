"""The seam between the database and OpenVPN.

The controller asks for a name and gets a path; these tests pin down what that costs -- the
profile reaching disk, the vault being required, and a bad name never becoming a filename.
"""

from __future__ import annotations

import stat

import pytest

from app.services import connections as conn_module
from app.services.connections import Connections
from app.services.store import StoreError
from app.services.vault import VaultLocked, VaultState

PROFILE = "client\nremote vpn.example.test 1194 udp\n<key>PRIVATE</key>\n"


def test_resolve_returns_what_the_controller_needs(connections, stored_connection):
    resolved = connections.resolve("client")
    assert resolved.name == "client"
    assert resolved.username == "alice"
    assert resolved.password == "s3cret"
    assert resolved.static_challenge == "Enter Authenticator Code"


def test_resolving_writes_the_profile_where_openvpn_can_read_it(
    connections, stored_connection, vpn_dir
):
    resolved = connections.resolve("client")
    assert resolved.profile_path == vpn_dir / "client.ovpn"
    assert resolved.profile_path.read_text().startswith("client")
    assert stat.S_IMODE(resolved.profile_path.stat().st_mode) == 0o600


def test_saving_writes_the_profile_immediately(connections, vpn_dir):
    """Written on save, so a broken profile surfaces while the operator is on the form."""
    connections.save(name="work", profile=PROFILE, username="a", password="b")
    assert (vpn_dir / "work.ovpn").read_text() == PROFILE


def test_resolving_repairs_a_deleted_profile_file(connections, stored_connection, vpn_dir):
    """The database is the source of truth, so a missing file is not a broken connection."""
    (vpn_dir / "client.ovpn").unlink()
    resolved = connections.resolve("client")
    assert resolved.profile_path.exists()


def test_deleting_removes_the_derived_file(connections, stored_connection, vpn_dir):
    assert (vpn_dir / "client.ovpn").exists()
    connections.delete("client")
    assert not (vpn_dir / "client.ovpn").exists()


def test_deleting_survives_a_missing_file(connections, stored_connection, vpn_dir):
    (vpn_dir / "client.ovpn").unlink()
    connections.delete("client")  # must not raise
    assert connections.list() == []


def test_an_unknown_name_is_refused(connections):
    with pytest.raises(StoreError, match="No connection named"):
        connections.resolve("nope")


@pytest.mark.parametrize("name", ["../../etc/passwd", "with/slash", "has space", "", "a;rm -rf /"])
def test_a_malformed_name_never_becomes_a_path(connections, name, vpn_dir):
    """Says the name is malformed rather than 'not found', and touches no filesystem."""
    with pytest.raises(StoreError, match="may only contain"):
        connections.resolve(name)
    assert list(vpn_dir.glob("*.ovpn")) == []


def test_reading_works_while_the_vault_is_locked(app_db, vpn_dir, connections, stored_connection):
    """The status page renders after a restart, before anyone has signed in."""
    locked = Connections(app_db, VaultState(), vpn_dir)
    assert [c.name for c in locked.list()] == ["client"]
    assert locked.default().name == "client"


def test_resolving_needs_the_vault_unlocked(app_db, vpn_dir, stored_connection):
    locked = Connections(app_db, VaultState(), vpn_dir)
    with pytest.raises(VaultLocked, match="Sign in"):
        locked.resolve("client")


def test_saving_needs_the_vault_unlocked(app_db, vpn_dir):
    locked = Connections(app_db, VaultState(), vpn_dir)
    with pytest.raises(VaultLocked):
        locked.save(name="work", profile=PROFILE, username="a", password="b")


def test_a_second_connection_can_take_the_default(connections, stored_connection):
    connections.save(name="home", profile=PROFILE, username="b", password="p", make_default=True)
    assert connections.default().name == "home"


def test_saving_over_a_name_replaces_the_profile_on_disk(connections, stored_connection, vpn_dir):
    connections.save(name="client", profile="replaced\n", username="a", password="b")
    assert (vpn_dir / "client.ovpn").read_text() == "replaced\n"
    assert connections.resolve("client").password == "b"


# --- ignoring pushed DNS ------------------------------------------------------


def test_the_directive_is_not_added_unless_the_flag_is_set():
    assert conn_module.with_dns_override(PROFILE, ignore=False) == PROFILE


def test_the_directive_is_appended_when_the_flag_is_set():
    result = conn_module.with_dns_override(PROFILE, ignore=True)
    assert result.startswith(PROFILE)
    assert conn_module.PULL_FILTER_DNS in result


def test_a_profile_without_a_trailing_newline_still_gets_its_own_line():
    result = conn_module.with_dns_override("client\nremote host 1194", ignore=True)
    assert f"\n{conn_module.PULL_FILTER_DNS}\n" in result


def test_a_profile_that_already_filters_pushed_dns_is_left_alone():
    """A second identical pull-filter is harmless to OpenVPN but would misreport what we did."""
    existing = PROFILE + 'pull-filter ignore "dhcp-option DNS"\n'
    assert conn_module.with_dns_override(existing, ignore=True) == existing


def test_an_existing_filter_is_recognised_however_it_is_quoted():
    existing = PROFILE + "pull-filter ignore dhcp-option DNS\n"
    assert conn_module.with_dns_override(existing, ignore=True) == existing


def test_the_flag_defaults_to_off(stored_connection):
    assert stored_connection.ignore_pushed_dns is False


def test_saving_with_the_flag_writes_the_directive_into_the_ovpn(connections, vpn_dir):
    connections.save(
        name="dnsoff",
        profile=PROFILE,
        username="alice",
        password="s3cret",
        ignore_pushed_dns=True,
    )
    written = (vpn_dir / "dnsoff.ovpn").read_text(encoding="utf-8")
    assert conn_module.PULL_FILTER_DNS in written


def test_toggling_the_flag_needs_no_vault_and_survives_a_round_trip(connections):
    connections.save(name="c", profile=PROFILE, username="alice", password="s3cret")
    assert connections.toggle_ignore_pushed_dns("c") is True
    assert connections.get("c").ignore_pushed_dns is True
    assert connections.toggle_ignore_pushed_dns("c") is False
    assert connections.get("c").ignore_pushed_dns is False


def test_toggling_an_unknown_connection_is_refused(connections):
    with pytest.raises(StoreError):
        connections.toggle_ignore_pushed_dns("nope")


def test_resolving_applies_the_flag_without_the_connection_being_re_saved(connections, vpn_dir):
    """The .ovpn is derived, so flipping the flag is enough -- no need to re-upload anything."""
    connections.save(name="c", profile=PROFILE, username="alice", password="s3cret")
    assert conn_module.PULL_FILTER_DNS not in (vpn_dir / "c.ovpn").read_text(encoding="utf-8")

    connections.toggle_ignore_pushed_dns("c")
    resolved = connections.resolve("c")
    assert conn_module.PULL_FILTER_DNS in resolved.profile_path.read_text(encoding="utf-8")


# --- whether a profile asks for a second factor ---------------------------------
#
# Read from the profile, not asked for: `static-challenge` is OpenVPN's own statement that the
# server wants a code, and a checkbox beside it would only be a second place to be wrong.

PASSWORD_ONLY = "client\nremote vpn.example.test 1194 udp\nauth-user-pass\n"
WITH_CHALLENGE = PASSWORD_ONLY + 'static-challenge "Enter Authenticator Code" 1\n'


def test_a_static_challenge_line_means_a_code_is_wanted():
    assert conn_module.profile_wants_mfa(WITH_CHALLENGE) is True


def test_a_profile_without_one_signs_in_with_its_password_alone():
    assert conn_module.profile_wants_mfa(PASSWORD_ONLY) is False


def test_the_directive_is_recognised_however_it_is_cased_or_indented():
    assert conn_module.profile_wants_mfa('client\n  STATIC-CHALLENGE "Code" 1\n') is True


def test_a_commented_out_directive_does_not_count():
    """Otherwise disabling MFA by commenting the line out would leave the app still demanding a
    code for a tunnel that no longer asks for one."""
    assert conn_module.profile_wants_mfa('client\n# static-challenge "Code" 1\n') is False


def test_saving_derives_the_flag_from_the_uploaded_profile(connections):
    connections.save(name="mfa", profile=WITH_CHALLENGE, username="alice", password="s3cret")
    connections.save(name="plain", profile=PASSWORD_ONLY, username="alice", password="s3cret")
    assert connections.get("mfa").requires_mfa is True
    assert connections.get("plain").requires_mfa is False


def test_resolving_carries_the_flag_to_the_controller(connections):
    connections.save(name="plain", profile=PASSWORD_ONLY, username="alice", password="s3cret")
    assert connections.resolve("plain").requires_mfa is False
