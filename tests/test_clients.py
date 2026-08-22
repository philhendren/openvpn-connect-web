"""Which OpenVPN client is installed -- answered without depending on the machine answering it.

Every lookup goes through an injected ``which``, so these tests say the same thing on a developer
box with openvpn, on a CI runner with neither, and on somebody's openvpn3-only machine.
"""

from __future__ import annotations

from app.services import clients
from app.services.clients import Clients


def _which(found: dict[str, str]):
    """A stand-in for shutil.which over a fixed set of installed programs."""

    def which(name: str, path: str | None = None) -> str | None:
        location = found.get(name)
        if location is None:
            return None
        if path is not None and location.rsplit("/", 1)[0] not in path.split(":"):
            return None
        return location

    return which


def test_nothing_installed():
    survey = clients.discover(which=_which({}))
    assert survey == Clients(classic=None, v3=None)
    assert survey.supported is False
    assert survey.v3_only is False


def test_the_classic_client_is_what_this_panel_can_drive():
    survey = clients.discover(which=_which({"openvpn": "/usr/sbin/openvpn"}))
    assert survey.classic == "/usr/sbin/openvpn"
    assert survey.supported is True
    assert survey.v3_only is False


def test_openvpn3_alone_is_found_but_not_usable():
    """The whole reason this module exists: an OpenVPN *is* installed and still cannot be driven."""
    survey = clients.discover(which=_which({"openvpn3": "/usr/bin/openvpn3"}))
    assert survey.v3 == "/usr/bin/openvpn3"
    assert survey.supported is False
    assert survey.v3_only is True


def test_both_installed_prefers_the_one_that_works():
    survey = clients.discover(
        which=_which({"openvpn": "/usr/sbin/openvpn", "openvpn3": "/usr/bin/openvpn3"})
    )
    assert survey.supported is True
    assert survey.v3_only is False
    assert "not used" in survey.summary


def test_sbin_is_searched_even_when_it_is_not_on_path():
    """A Flask process started from a login shell often has no sbin on its PATH; the unit does.

    The answer must not depend on which of those started the app, so the fallback directories are
    searched too -- here, by a ``which`` that only finds things when it is told where to look.
    """

    def path_only_which(name: str, path: str | None = None) -> str | None:
        if path is None:
            return None  # not on PATH at all
        return "/usr/sbin/openvpn" if name == "openvpn" and "/usr/sbin" in path else None

    assert clients.discover(which=path_only_which).classic == "/usr/sbin/openvpn"


def test_the_summary_says_which_situation_this_is():
    assert "none found" in Clients(None, None).summary
    assert "cannot drive it" in Clients(None, "/usr/bin/openvpn3").summary
    assert Clients("/usr/sbin/openvpn", None).summary == "/usr/sbin/openvpn (classic)"


def test_the_wire_format_carries_the_verdict_not_just_the_paths():
    payload = Clients(None, "/usr/bin/openvpn3").to_dict()
    assert payload == {"classic": None, "v3": "/usr/bin/openvpn3", "supported": False}
