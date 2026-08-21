"""DnsRules: CRUD plus applying to the live config through the root helper.

The core security property under test throughout is that no rule content ever reaches the
helper's argv -- everything crosses through the staged file on disk instead.
"""

from __future__ import annotations

import subprocess
from dataclasses import replace

import pytest

from app.services.dns_rules import DnsRules
from app.services.rooted import SUDO
from app.services.store import StoreError


def test_apply_invokes_the_fixed_argv_with_no_rule_content(dns_rules, dns_runner, config):
    dns_rules.add(kind="domain", domain="example.corp", address="10.100.53.2")
    assert dns_runner.calls[-1] == [SUDO, "-n", str(config.HELPER), "dns-apply"]


def test_no_shell_is_ever_used(dns_rules, dns_runner):
    dns_rules.add(kind="fallback", domain=None, address="8.8.8.8")
    for call in dns_runner.calls:
        assert isinstance(call, list)
        assert all(isinstance(arg, str) for arg in call)


def test_add_writes_the_rendered_staging_file(dns_rules, config):
    dns_rules.add(kind="domain", domain="example.corp", address="10.100.53.2")
    dns_rules.add(kind="fallback", domain=None, address="8.8.8.8")
    text = config.dns_staging.read_text(encoding="utf-8")
    assert "server=/example.corp/10.100.53.2" in text
    assert "server=8.8.8.8" in text


def test_a_failed_helper_call_is_a_warning_not_an_exception(dns_rules, dns_runner):
    dns_runner.returncode = 1
    dns_runner.stderr = "dnsmasq rejected the new rules"
    rule, warning = dns_rules.add(kind="fallback", domain=None, address="8.8.8.8")
    assert rule is not None  # the DB write already committed
    assert "dnsmasq rejected the new rules" in warning
    domain_rules, fallback_rules = dns_rules.list()
    assert fallback_rules == [rule]  # persisted despite the apply failure


def test_a_timeout_is_surfaced_as_a_warning(dns_rules, dns_runner):
    dns_runner.side_effect = subprocess.TimeoutExpired(cmd="helper", timeout=1)
    _, warning = dns_rules.add(kind="fallback", domain=None, address="8.8.8.8")
    assert "timed out" in warning


def test_dnsmasq_not_running_becomes_the_warning(dns_rules, dns_runner):
    dns_runner.stdout = "applied: dnsmasq is not running -- rules installed but not active"
    _, warning = dns_rules.add(kind="fallback", domain=None, address="8.8.8.8")
    assert warning == "dnsmasq is not running -- rules installed but not active"


def test_a_clean_apply_has_no_warning(dns_rules):
    _, warning = dns_rules.add(kind="fallback", domain=None, address="8.8.8.8")
    assert warning is None


def test_deleting_and_moving_also_apply(dns_rules, dns_runner):
    rule, _ = dns_rules.add(kind="fallback", domain=None, address="8.8.8.8")
    dns_runner.calls.clear()
    dns_rules.delete(rule.id)
    assert dns_runner.calls  # delete re-applied too

    dns_rules.add(kind="fallback", domain=None, address="1.1.1.1")
    b, _ = dns_rules.add(kind="fallback", domain=None, address="2.2.2.2")
    dns_runner.calls.clear()
    dns_rules.move(b.id, "up")
    assert dns_runner.calls


def test_legacy_preview_is_none_without_a_configured_file(dns_rules):
    assert dns_rules.legacy_preview() is None


def test_legacy_preview_is_none_once_a_rule_has_been_saved(app_db, config, dns_runner, tmp_path):
    legacy = tmp_path / "examplecorp.conf"
    legacy.write_text("server=8.8.8.8\n", encoding="utf-8")
    rules = DnsRules(app_db, replace(config, DNS_LEGACY_CONF=legacy), runner=dns_runner)
    rules.add(kind="fallback", domain=None, address="1.1.1.1")
    assert rules.legacy_preview() is None


def test_legacy_preview_parses_a_real_hand_written_conf(app_db, config, dns_runner, tmp_path):
    legacy = tmp_path / "examplecorp.conf"
    legacy.write_text(
        "server=/example.corp/10.100.53.2\nserver=8.8.8.8\nserver=8.8.4.4\n", encoding="utf-8"
    )
    rules = DnsRules(app_db, replace(config, DNS_LEGACY_CONF=legacy), runner=dns_runner)
    preview = rules.legacy_preview()
    assert preview is not None
    assert preview.path == str(legacy)
    assert len(preview.rules) == 3
    assert preview.unparsed == []


def test_import_legacy_inserts_everything_in_one_call(app_db, config, dns_runner, tmp_path):
    legacy = tmp_path / "examplecorp.conf"
    legacy.write_text("server=/example.corp/10.100.53.2\nserver=8.8.8.8\n", encoding="utf-8")
    rules = DnsRules(app_db, replace(config, DNS_LEGACY_CONF=legacy), runner=dns_runner)
    domain_rules, fallback_rules, warning, imported, skipped = rules.import_legacy()
    assert imported == 2
    assert skipped == []
    assert len(domain_rules) == 1
    assert len(fallback_rules) == 1
    assert warning is None


def test_import_legacy_with_nothing_to_import_is_refused(dns_rules):
    with pytest.raises(StoreError):
        dns_rules.import_legacy()
