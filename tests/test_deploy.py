"""The deployment self-check. Every case here has actually happened on the operator's box."""

from __future__ import annotations

import hashlib
import time

import pytest

from app.services import deploy

TEMPLATE = 'HELPER_VERSION="@HELPER_VERSION@"\nset -euo pipefail\n'


@pytest.fixture
def template(tmp_path):
    path = tmp_path / "vpn-connect-helper.in"
    path.write_text(TEMPLATE, encoding="utf-8")
    return path


def _installed(tmp_path, stamp: str | None):
    """The helper as install.sh would have rendered it, optionally without a stamp at all."""
    path = tmp_path / "vpn-connect-helper"
    body = "" if stamp is None else f'HELPER_VERSION="{stamp}"\n'
    path.write_text(f"{body}set -euo pipefail\n", encoding="utf-8")
    return path


def _stamp_of(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --- the helper --------------------------------------------------------------


def test_a_helper_installed_from_this_template_is_not_drift(tmp_path, template):
    installed = _installed(tmp_path, _stamp_of(template))
    assert deploy.helper_drift(installed=installed, template=template) is None


def test_an_edited_template_is_reported_until_it_is_reinstalled(tmp_path, template):
    installed = _installed(tmp_path, _stamp_of(template))
    template.write_text(TEMPLATE + "# a new verb\n", encoding="utf-8")
    item = deploy.helper_drift(installed=installed, template=template)
    assert item is not None
    assert item.kind == "helper"
    assert item.fix == "sudo ./deploy/install.sh"


def test_a_helper_predating_version_stamping_is_reported(tmp_path, template):
    item = deploy.helper_drift(installed=_installed(tmp_path, None), template=template)
    assert item is not None
    assert "out of date" in item.headline


def test_a_missing_helper_is_reported_rather_than_raising(tmp_path, template):
    item = deploy.helper_drift(installed=tmp_path / "nope", template=template)
    assert item is not None
    assert "not installed" in item.headline


def test_running_outside_a_checkout_reports_nothing(tmp_path):
    """No template to compare against is not the same as a mismatch."""
    installed = _installed(tmp_path, "0" * 64)
    assert deploy.helper_drift(installed=installed, template=tmp_path / "absent.in") is None


# --- migrations --------------------------------------------------------------


def test_an_unapplied_migration_asks_for_a_restart(tmp_path):
    (tmp_path / "0001_initial.sql").write_text("", encoding="utf-8")
    (tmp_path / "0002_later.sql").write_text("", encoding="utf-8")
    item = deploy.migration_drift(applied=1, migrations_dir=tmp_path)
    assert item is not None
    assert item.fix == "sudo systemctl restart vpn-connect"


def test_a_database_at_the_latest_version_is_not_drift(tmp_path):
    (tmp_path / "0001_initial.sql").write_text("", encoding="utf-8")
    assert deploy.migration_drift(applied=1, migrations_dir=tmp_path) is None


# --- source newer than the process -------------------------------------------


def test_a_module_edited_after_start_up_asks_for_a_restart(tmp_path):
    (tmp_path / "service.py").write_text("x = 1\n", encoding="utf-8")
    item = deploy.code_drift(source_root=tmp_path, started_at=time.time() - 3600)
    assert item is not None
    assert item.kind == "code"


def test_source_older_than_the_process_is_not_drift(tmp_path):
    (tmp_path / "service.py").write_text("x = 1\n", encoding="utf-8")
    assert deploy.code_drift(source_root=tmp_path, started_at=time.time() + 3600) is None


# --- the environment file ----------------------------------------------------


def test_a_clean_env_file_is_not_drift(tmp_path):
    path = tmp_path / "webapp.env"
    path.write_text("# a comment\nVPN_CONNECT_SECRET_KEY='abc'\n\n", encoding="utf-8")
    assert deploy.env_file_damage(path) is None


def test_a_repeated_setting_is_reported(tmp_path):
    """systemd keeps the last value, so five password hashes look like one working password."""
    path = tmp_path / "webapp.env"
    path.write_text("VPN_CONNECT_PASSWORD_HASH='a'\nVPN_CONNECT_PASSWORD_HASH='b'\n", "utf-8")
    item = deploy.env_file_damage(path)
    assert item is not None
    assert "VPN_CONNECT_PASSWORD_HASH" in item.detail


def test_output_that_is_not_a_setting_is_reported(tmp_path):
    """`set-password >> webapp.env` used to append its prompts and errors to the file."""
    path = tmp_path / "webapp.env"
    path.write_text(
        "VPN_CONNECT_SECRET_KEY='abc'\nError: The two entered values do not match.\n", "utf-8"
    )
    item = deploy.env_file_damage(path)
    assert item is not None
    assert "not settings" in item.detail


def test_a_missing_env_file_is_not_reported(tmp_path):
    """A checkout run without systemd has no environment file, and that is not damage."""
    assert deploy.env_file_damage(tmp_path / "absent.env") is None


# --- the whole report --------------------------------------------------------


def test_a_check_that_explodes_does_not_take_the_page_down(config, app_db, monkeypatch, tmp_path):
    def boom(**_):
        raise RuntimeError("nope")

    monkeypatch.setattr(deploy, "helper_drift", boom)
    report = deploy.report(
        config=config,
        schema_version=99,
        source_root=tmp_path,
        migrations_dir=tmp_path,
        started_at=time.time() + 3600,
    )
    assert report.clean is True
