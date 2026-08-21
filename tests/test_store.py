"""The store. Secrets only ever come back when a key is handed in explicitly."""

from __future__ import annotations

import stat

import pytest

from app.services import store, vault
from app.services.store import StoreError

PASSWORD = "correct-horse-battery-staple"
PROFILE = "client\nremote vpn.example.test 1194 udp\n<key>PRIVATE</key>\n"


@pytest.fixture
def key(db):
    return vault.initialise(db, PASSWORD)


@pytest.fixture
def saved(db, key):
    return store.save_connection(
        db,
        key,
        name="examplecorp",
        label="ExampleCorp ops",
        profile=PROFILE,
        username="alice",
        password="s3cret",
    )


# --- connections -----------------------------------------------------------


def test_a_fresh_database_has_no_connections(db):
    assert store.list_connections(db) == []
    assert store.default_connection(db) is None


def test_saving_and_listing(db, saved):
    assert [c.name for c in store.list_connections(db)] == ["examplecorp"]
    assert saved.display_name == "ExampleCorp ops"


def test_listing_works_without_the_key(db, saved):
    """The status page renders while the vault is locked, so names must not need decrypting."""
    connection = store.get_connection(db, "examplecorp")
    assert connection is not None
    assert connection.name == "examplecorp"
    assert "password" not in connection.to_dict()


def test_secrets_come_back_only_with_the_key(db, key, saved):
    secrets = store.secrets_for(db, key, "examplecorp")
    assert (secrets.username, secrets.password) == ("alice", "s3cret")
    assert secrets.profile == PROFILE


def test_secrets_for_an_unknown_connection(db, key):
    with pytest.raises(StoreError, match="No connection"):
        store.secrets_for(db, key, "nope")


def test_the_first_connection_becomes_the_default(db, saved):
    assert saved.is_default
    assert store.default_connection(db).name == "examplecorp"


def test_a_second_connection_does_not_steal_the_default(db, key, saved):
    store.save_connection(db, key, name="home", profile=PROFILE, username="bob", password="p")
    assert store.default_connection(db).name == "examplecorp"


def test_the_default_can_be_moved(db, key, saved):
    store.save_connection(db, key, name="home", profile=PROFILE, username="bob", password="p")
    store.set_default(db, "home")
    assert store.default_connection(db).name == "home"
    assert sum(c.is_default for c in store.list_connections(db)) == 1


def test_saving_with_make_default_moves_it(db, key, saved):
    store.save_connection(
        db, key, name="home", profile=PROFILE, username="b", password="p", make_default=True
    )
    assert store.default_connection(db).name == "home"


def test_saving_the_same_name_updates_in_place(db, key, saved):
    store.save_connection(
        db,
        key,
        name="examplecorp",
        profile=PROFILE,
        username="carol",
        password="new",
        label="Renamed",
    )
    assert len(store.list_connections(db)) == 1
    assert store.get_connection(db, "examplecorp").label == "Renamed"
    assert store.secrets_for(db, key, "examplecorp").username == "carol"


def test_deleting_promotes_a_survivor(db, key, saved):
    """Never leave connections with no default -- the connect form would have nothing selected."""
    store.save_connection(db, key, name="home", profile=PROFILE, username="b", password="p")
    store.delete_connection(db, "examplecorp")
    assert store.default_connection(db).name == "home"


def test_deleting_the_last_one_is_fine(db, saved):
    store.delete_connection(db, "examplecorp")
    assert store.list_connections(db) == []


def test_deleting_something_absent(db):
    with pytest.raises(StoreError, match="No connection"):
        store.delete_connection(db, "nope")


@pytest.mark.parametrize(
    "name", ["", "has space", "../escape", "with/slash", "a" * 65, "$(whoami)", "emoji-🎉"]
)
def test_bad_connection_names_are_refused(db, key, name):
    """The name is passed to the root helper and becomes a filename, so it stays strict."""
    with pytest.raises(StoreError):
        store.save_connection(db, key, name=name, profile=PROFILE, username="a", password="b")


def test_an_empty_profile_is_refused(db, key):
    with pytest.raises(StoreError, match="profile is empty"):
        store.save_connection(db, key, name="x", profile="   ", username="a", password="b")


def test_a_missing_username_is_refused(db, key):
    with pytest.raises(StoreError, match="username is required"):
        store.save_connection(db, key, name="x", profile=PROFILE, username="", password="b")


def test_an_empty_password_is_allowed(db, key):
    """Some profiles authenticate by certificate alone; the challenge still supplies the code."""
    store.save_connection(db, key, name="certonly", profile=PROFILE, username="a", password="")
    assert store.secrets_for(db, key, "certonly").password == ""


# --- the profile as a file -------------------------------------------------


def test_the_profile_is_written_owner_only(tmp_path):
    path = store.write_profile(tmp_path / "vpn" / "examplecorp.ovpn", PROFILE)
    assert path.read_text() == PROFILE
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_writing_the_profile_replaces_an_old_one(tmp_path):
    path = tmp_path / "examplecorp.ovpn"
    store.write_profile(path, "old")
    store.write_profile(path, "new")
    assert path.read_text() == "new"
    assert list(tmp_path.glob(".*tmp")) == []


# --- settings --------------------------------------------------------------


def test_settings_round_trip(db):
    store.set_setting(db, store.NTFY_TOPIC, "my-topic")
    assert store.get_setting(db, store.NTFY_TOPIC) == "my-topic"


def test_a_missing_setting_returns_the_fallback(db):
    assert store.get_setting(db, "nope", "fallback") == "fallback"
    assert store.get_setting(db, "nope") == ""


def test_setting_the_same_key_twice_updates(db):
    store.set_setting(db, "k", "one")
    store.set_setting(db, "k", "two")
    assert store.get_setting(db, "k") == "two"
    assert db.execute("SELECT COUNT(*) FROM settings").fetchone()[0] == 1


def test_settings_save_together(db):
    store.set_settings(db, {"a": "1", "b": "2"})
    assert (store.get_setting(db, "a"), store.get_setting(db, "b")) == ("1", "2")


# --- events ----------------------------------------------------------------


def test_events_come_back_newest_first(db):
    store.record_event(db, "UP", connection="examplecorp")
    store.record_event(db, "DOWN", "link-lost", "examplecorp")
    events = store.recent_events(db)
    assert events[0].endswith("DOWN link-lost")
    assert events[1].endswith("UP")


def test_an_event_without_a_reason_has_no_trailing_space(db):
    store.record_event(db, "UP")
    assert store.recent_events(db)[0] == store.recent_events(db)[0].rstrip()


def test_events_respect_the_limit(db):
    for _ in range(20):
        store.record_event(db, "UP")
    assert len(store.recent_events(db, limit=5)) == 5


# --- log sessions ----------------------------------------------------------


def test_a_session_keeps_its_lines(db):
    session = store.start_log_session(db, "examplecorp")
    store.append_lines(db, session, ["first", "second"])
    assert store.session_lines(db, session) == ["first", "second"]


def test_a_failed_attempts_log_survives(db):
    """The whole point: the in-memory ring buffer emptied exactly when you wanted to read it."""
    session = store.start_log_session(db, "examplecorp")
    store.append_lines(db, session, ["AUTH_FAILED"])
    store.end_log_session(db, session, "failed")
    assert store.session_lines(db, session) == ["AUTH_FAILED"]
    assert store.recent_sessions(db)[0]["outcome"] == "failed"


def test_lines_are_capped_keeping_the_newest(db):
    session = store.start_log_session(db, None)
    store.append_lines(db, session, [f"line {i}" for i in range(store.MAX_LINES_PER_SESSION + 100)])
    lines = store.session_lines(db, session, limit=10_000)
    assert len(lines) == store.MAX_LINES_PER_SESSION
    assert lines[-1] == f"line {store.MAX_LINES_PER_SESSION + 99}"


def test_appending_nothing_is_a_no_op(db):
    session = store.start_log_session(db, None)
    store.append_lines(db, session, [])
    assert store.session_lines(db, session) == []


def test_session_lines_returns_the_tail_in_order(db):
    session = store.start_log_session(db, None)
    store.append_lines(db, session, [f"line {i}" for i in range(10)])
    assert store.session_lines(db, session, limit=3) == ["line 7", "line 8", "line 9"]


def test_pruning_drops_old_sessions_and_their_lines(db):
    for _ in range(5):
        session = store.start_log_session(db, None)
        store.append_lines(db, session, ["x"])
    assert store.prune_sessions(db, keep=2) == 3
    assert len(store.recent_sessions(db, limit=50)) == 2
    assert db.execute("SELECT COUNT(*) FROM log_lines").fetchone()[0] == 2


def test_recent_sessions_reports_line_counts(db):
    session = store.start_log_session(db, "examplecorp")
    store.append_lines(db, session, ["a", "b", "c"])
    assert store.recent_sessions(db)[0]["lines"] == 3


# --- traffic samples -------------------------------------------------------


def test_samples_round_trip(db):
    session = store.start_log_session(db, "client")
    store.record_sample(db, session, 1000.0, 1024, 512)
    store.record_sample(db, session, 1005.0, 2048, 1024)
    assert store.session_samples(db, session) == [(1000.0, 1024, 512), (1005.0, 2048, 1024)]


def test_samples_are_capped_keeping_the_newest(db, monkeypatch):
    monkeypatch.setattr(store, "MAX_SAMPLES_PER_SESSION", 5)
    session = store.start_log_session(db, None)
    for index in range(12):
        store.record_sample(db, session, float(index), index, index)
    samples = store.session_samples(db, session)
    assert len(samples) == 5
    assert samples[-1] == (11.0, 11, 11)


def test_samples_belong_to_their_session(db):
    first = store.start_log_session(db, None)
    second = store.start_log_session(db, None)
    store.record_sample(db, first, 1.0, 10, 10)
    store.record_sample(db, second, 2.0, 20, 20)
    assert store.session_samples(db, first) == [(1.0, 10, 10)]
    assert store.session_samples(db, second) == [(2.0, 20, 20)]


def test_pruning_takes_the_samples_with_the_session(db):
    """ON DELETE CASCADE, so retention needs no separate sweep for these."""
    for _ in range(4):
        session = store.start_log_session(db, None)
        store.record_sample(db, session, 1.0, 1, 1)
    store.prune_sessions(db, keep=1)
    assert db.execute("SELECT COUNT(*) FROM traffic_samples").fetchone()[0] == 1


# --- dns rules ---------------------------------------------------------------


def test_a_fresh_database_has_no_dns_rules(db):
    assert store.list_dns_rules(db) == []


def test_adding_a_domain_forwarder(db):
    rule = store.add_dns_rule(db, kind="domain", domain="example.corp", address="10.100.53.2")
    assert rule.kind == "domain"
    assert rule.domain == "example.corp"
    assert rule.address == "10.100.53.2"
    assert rule.position is None
    assert store.list_dns_rules(db) == [rule]


def test_re_adding_a_domain_updates_it_in_place(db):
    """A concentrator-IP change should not need delete-then-add."""
    first = store.add_dns_rule(db, kind="domain", domain="example.corp", address="10.100.53.2")
    second = store.add_dns_rule(db, kind="domain", domain="example.corp", address="10.100.53.3")
    assert second.id == first.id
    assert second.address == "10.100.53.3"
    assert len(store.list_dns_rules(db)) == 1


def test_adding_fallback_servers_assigns_increasing_positions(db):
    first = store.add_dns_rule(db, kind="fallback", domain=None, address="8.8.8.8")
    second = store.add_dns_rule(db, kind="fallback", domain=None, address="8.8.4.4")
    assert (first.position, second.position) == (0, 1)


def test_a_duplicate_fallback_address_is_refused(db):
    store.add_dns_rule(db, kind="fallback", domain=None, address="8.8.8.8")
    with pytest.raises(StoreError):
        store.add_dns_rule(db, kind="fallback", domain=None, address="8.8.8.8")
    assert len(store.list_dns_rules(db)) == 1


def test_a_bad_domain_is_refused_before_anything_is_written(db):
    with pytest.raises(store.DnsError):
        store.add_dns_rule(db, kind="domain", domain="/etc/passwd", address="1.2.3.4")
    assert store.list_dns_rules(db) == []


def test_deleting_a_dns_rule(db):
    rule = store.add_dns_rule(db, kind="fallback", domain=None, address="8.8.8.8")
    store.delete_dns_rule(db, rule.id)
    assert store.list_dns_rules(db) == []


def test_deleting_an_unknown_rule_is_refused(db):
    with pytest.raises(StoreError):
        store.delete_dns_rule(db, 999)


def test_moving_a_fallback_rule_up_and_down(db):
    first = store.add_dns_rule(db, kind="fallback", domain=None, address="1.1.1.1")
    second = store.add_dns_rule(db, kind="fallback", domain=None, address="2.2.2.2")
    store.move_fallback_rule(db, second.id, "up")
    rules = {r.id: r.position for r in store.list_dns_rules(db)}
    assert rules[second.id] == first.position
    assert rules[first.id] == second.position


def test_moving_is_clamped_at_the_ends(db):
    """A no-op rather than an error -- the UI need not disable the buttons perfectly."""
    only = store.add_dns_rule(db, kind="fallback", domain=None, address="1.1.1.1")
    store.move_fallback_rule(db, only.id, "up")
    store.move_fallback_rule(db, only.id, "down")
    assert store.list_dns_rules(db)[0].position == only.position
