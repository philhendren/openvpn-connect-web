"""Routes, login and CSRF."""

from __future__ import annotations

import io
import json
from dataclasses import replace

import pytest

from app import create_app
from app.services import store
from app.services.dns_rules import DnsRules
from app.services.openvpn import CONNECTED, VpnError, VpnStatus
from app.services.routing import Route
from tests.conftest import PASSWORD, FakeRunner, _extract_csrf


def test_index_requires_login(client):
    response = client.get("/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_api_requires_login_with_401_not_a_redirect(client):
    response = client.get("/api/status")
    assert response.status_code == 401
    assert response.get_json()["error"]


def test_login_succeeds_and_renders_the_panel(auth_client, stored_connection):
    response = auth_client.get("/")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Enter Authenticator Code" in body
    assert "client" in body


def test_login_rejects_a_wrong_password(client):
    token = _extract_csrf(client.get("/login").get_data(as_text=True))
    response = client.post("/login", data={"password": "nope", "csrf_token": token})
    assert response.status_code == 401
    assert client.get("/").status_code == 302


def test_login_without_csrf_is_rejected(client):
    client.get("/login")
    response = client.post("/login", data={"password": PASSWORD})
    assert response.status_code == 400


def test_login_is_rate_limited(app, config):
    import app.routes.ui as ui

    ui._throttle = None
    test_client = app.test_client()
    token = _extract_csrf(test_client.get("/login").get_data(as_text=True))
    for _ in range(config.LOGIN_MAX_ATTEMPTS):
        test_client.post("/login", data={"password": "nope", "csrf_token": token})
    response = test_client.post("/login", data={"password": PASSWORD, "csrf_token": token})
    assert response.status_code == 429
    ui._throttle = None


def test_setup_page_when_no_password_is_configured(config, fake_controller, app_db, vault_state):
    application = create_app(
        {
            "APP_CONFIG": replace(config, PASSWORD_HASH=""),
            "CONTROLLER": fake_controller,
            "DB": app_db,
            "VAULT": vault_state,
            "TESTING": True,
        }
    )
    response = application.test_client().get("/login")
    assert response.status_code == 503
    assert "set-password" in response.get_data(as_text=True)


def test_status_endpoint_returns_the_snapshot(auth_client, fake_controller):
    fake_controller.status = VpnStatus(state=CONNECTED, tun_ip="10.0.0.2", bytes_in=5)
    payload = auth_client.get("/api/status").get_json()
    assert payload["state"] == CONNECTED
    assert payload["tun_ip"] == "10.0.0.2"
    assert payload["connected"] is True
    assert payload["events"]


def test_connect_endpoint_passes_input_to_the_controller(auth_client, fake_controller):
    response = auth_client.post(
        "/api/connect",
        json={"profile": "client", "otp": "123456"},
        headers={"X-CSRF-Token": auth_client.csrf_token},
    )
    assert response.status_code == 202
    assert fake_controller.connect_calls == [("client", "123456")]


def test_connect_endpoint_reports_controller_errors(auth_client, fake_controller):
    fake_controller.connect_error = VpnError("Authentication rejected")
    response = auth_client.post(
        "/api/connect",
        json={"profile": "client", "otp": "123456"},
        headers={"X-CSRF-Token": auth_client.csrf_token},
    )
    assert response.status_code == 400
    assert response.get_json()["error"] == "Authentication rejected"


@pytest.mark.parametrize("path", ["/api/connect", "/api/disconnect"])
def test_state_changes_require_csrf(auth_client, fake_controller, path):
    response = auth_client.post(path, json={"profile": "client", "otp": "123456"})
    assert response.status_code == 400
    assert fake_controller.connect_calls == []
    assert fake_controller.disconnect_calls == 0


@pytest.mark.parametrize("path", ["/api/connect", "/api/disconnect"])
def test_state_changes_are_not_reachable_by_get(auth_client, path):
    assert auth_client.get(path).status_code == 405


def test_disconnect_endpoint(auth_client, fake_controller):
    response = auth_client.post("/api/disconnect", headers={"X-CSRF-Token": auth_client.csrf_token})
    assert response.status_code == 202
    assert fake_controller.disconnect_calls == 1


def test_logout_clears_the_session(auth_client):
    response = auth_client.post("/logout", data={"csrf_token": auth_client.csrf_token})
    assert response.status_code == 302
    assert auth_client.get("/").status_code == 302


def test_security_headers_are_set(client):
    headers = client.get("/login").headers
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert headers["Cache-Control"] == "no-store"


def test_a_fresh_install_offers_to_add_a_connection(app, app_db):
    """Nothing is configured out of the box, so the panel must say so rather than half-render."""
    test_client = app.test_client()
    token = _extract_csrf(test_client.get("/login").get_data(as_text=True))
    test_client.post("/login", data={"password": PASSWORD, "csrf_token": token})
    body = test_client.get("/").get_data(as_text=True)
    assert "Nothing is set up yet" in body
    assert 'id="connect-form"' not in body
    assert 'id="connection-form"' in body


def test_whois_endpoint_requires_login(client):
    assert client.get("/api/whois?dest=5.20.0.0/14").status_code == 401


def test_whois_endpoint_looks_up_a_current_route(auth_client, fake_controller):
    """5.20.0.0/14 is in FakeController's route list; ask about it and it gets looked up."""
    fake_controller.whois_orgs = {"5.20.0.0/14": "Amazon.com, Inc."}
    response = auth_client.get("/api/whois?dest=5.20.0.0/14")
    assert response.get_json() == {
        "results": [{"destination": "5.20.0.0/14", "org": "Amazon.com, Inc."}]
    }
    assert fake_controller.whois_calls == [["5.20.0.0/14"]]


def test_whois_endpoint_ignores_destinations_the_tunnel_is_not_actually_carrying(
    auth_client, fake_controller
):
    """A signed-in session cannot use this as a general whois relay -- only what /api/routes
    would also show gets passed through, whatever the query string asks for."""
    response = auth_client.get("/api/whois?dest=1.1.1.1&dest=8.8.8.8/32")
    assert response.get_json() == {"results": []}
    assert fake_controller.whois_calls == [[]]


def test_whois_endpoint_only_filters_on_what_is_currently_routed(auth_client, fake_controller):
    """The private/public split is whois.lookup_many's job (covered in tests/test_whois.py) --
    this endpoint's own responsibility is narrower: pass through anything that is a real current
    route, whatever it is, and nothing that is not. 10.99.0.0/23 is on-link and private, but
    it *is* a current route, so it must reach the controller unchanged."""
    fake_controller.whois_orgs = {"10.99.0.0/23": "irrelevant here"}
    response = auth_client.get("/api/whois?dest=10.99.0.0/23")
    assert response.get_json() == {
        "results": [{"destination": "10.99.0.0/23", "org": "irrelevant here"}]
    }
    assert fake_controller.whois_calls == [["10.99.0.0/23"]]


def test_whois_endpoint_caps_the_batch_size(auth_client, fake_controller):
    from app.services.whois import MAX_BATCH

    extra = MAX_BATCH + 10
    fake_controller.route_list = [
        Route(f"5.{i}.0.0/16", "10.99.0.1", "tun0", 101) for i in range(extra)
    ]
    query = "&".join(f"dest=5.{i}.0.0/16" for i in range(extra))
    response = auth_client.get(f"/api/whois?{query}")
    assert len(response.get_json()["results"]) == MAX_BATCH


def test_notify_settings_require_login(client):
    assert client.get("/api/notify").status_code == 401
    assert client.post("/api/notify", json={"topic": "x"}).status_code == 401


def test_notify_settings_are_returned(auth_client, seeded_topic):
    payload = auth_client.get("/api/notify").get_json()
    assert payload["topic"] == "existing-topic"
    assert payload["url"] == "https://ntfy.sh/existing-topic"


def test_notify_topic_can_be_saved(auth_client, app_db, seeded_topic):
    response = auth_client.post(
        "/api/notify",
        json={"topic": "new-alerts"},
        headers={"X-CSRF-Token": auth_client.csrf_token},
    )
    assert response.status_code == 200
    assert response.get_json()["topic"] == "new-alerts"
    assert store.notify_topic(app_db) == "new-alerts"


def test_notify_topic_rejects_shell_metacharacters(auth_client, app_db, seeded_topic):
    response = auth_client.post(
        "/api/notify",
        json={"topic": "evil; rm -rf /"},
        headers={"X-CSRF-Token": auth_client.csrf_token},
    )
    assert response.status_code == 400
    assert store.notify_topic(app_db) == "existing-topic"


def test_notify_save_requires_csrf(auth_client, app_db, seeded_topic):
    assert auth_client.post("/api/notify", json={"topic": "sneaky"}).status_code == 400
    assert store.notify_topic(app_db) == "existing-topic"


def test_page_renders_the_current_topic_and_the_disconnect_modal(
    auth_client, seeded_topic, stored_connection
):
    body = auth_client.get("/").get_data(as_text=True)
    assert 'value="existing-topic"' in body
    assert 'id="disconnect-modal"' in body
    assert 'data-bs-target="#disconnect-modal"' in body


def test_panels_appear_in_the_configured_order(auth_client, stored_connection):
    """Connections, then routes, then events, then log, then notifications."""
    body = auth_client.get("/").get_data(as_text=True)
    order = [
        body.index(f'id="panel-{name}"')
        for name in ("connections", "routes", "events", "log", "notifications")
    ]
    assert order == sorted(order)


def test_every_panel_is_collapsible(auth_client, stored_connection):
    body = auth_client.get("/").get_data(as_text=True)
    for name in ("connections", "routes", "events", "log", "notifications"):
        assert f'data-bs-target="#panel-{name}"' in body


def test_panels_start_collapsed_once_a_connection_exists(auth_client, stored_connection):
    body = auth_client.get("/").get_data(as_text=True)
    for name in ("connections", "routes", "events", "log", "notifications"):
        marker = f'id="panel-{name}"'
        opening = body.rindex('<div class="collapse', 0, body.index(marker))
        assert " show" not in body[opening : body.index(marker)], name


def test_connections_starts_open_when_nothing_is_configured(app):
    """A new operator must land on the form, not on a row of closed headers."""
    test_client = app.test_client()
    token = _extract_csrf(test_client.get("/login").get_data(as_text=True))
    test_client.post("/login", data={"password": PASSWORD, "csrf_token": token})
    body = test_client.get("/").get_data(as_text=True)
    opening = body.rindex('<div class="collapse', 0, body.index('id="panel-connections"'))
    assert " show" in body[opening : body.index('id="panel-connections"')]
    assert 'data-panel-locked="true"' in body


def test_bootstrap_and_the_brand_mark_are_served_locally(auth_client):
    """Vendored, not CDN -- the CSP only allows 'self'."""
    body = auth_client.get("/").get_data(as_text=True)
    assert "/static/vendor/bootstrap/bootstrap.min.css" in body
    assert "cdn.jsdelivr.net" not in body
    assert 'aria-label="OpenVPN"' in body
    for path in ("/static/vendor/bootstrap/bootstrap.bundle.min.js", "/static/img/favicon.svg"):
        response = auth_client.get(path)
        assert response.status_code == 200
        response.close()  # static responses hold an open file handle


def test_favicon_is_served_at_the_root_without_a_login(client):
    """Browsers request /favicon.ico regardless of the <link> tags, and before signing in."""
    response = client.get("/favicon.ico")
    assert response.status_code == 200
    assert "icon" in response.headers["Content-Type"]
    response.close()


def test_every_page_links_the_openvpn_mark(client, auth_client):
    """Signed out (login page) and signed in (panel) alike."""
    for body in (
        client.get("/login").get_data(as_text=True),
        auth_client.get("/").get_data(as_text=True),
    ):
        assert 'href="/static/img/favicon.svg"' in body
        assert 'href="/static/img/favicon-32.png"' in body
        assert 'sizes="192x192"' in body
        assert 'sizes="512x512"' in body
        assert 'rel="apple-touch-icon"' in body


def test_manifest_is_public_and_correctly_typed(client):
    """ChromeOS installs take their icon from here, and fetch it without credentials."""
    response = client.get("/manifest.webmanifest")
    assert response.status_code == 200
    assert response.headers["Content-Type"].startswith("application/manifest+json")
    response.close()


def test_manifest_advertises_installable_icons(client):

    response = client.get("/manifest.webmanifest")
    manifest = json.loads(response.get_data(as_text=True))
    response.close()

    assert manifest["name"] == "OpenVPN Connect"
    assert manifest["display"] == "standalone"
    assert manifest["start_url"] == "/"

    by_size = {(icon["sizes"], icon.get("purpose", "any")) for icon in manifest["icons"]}
    # Chrome needs a 192 and a 512 for an install; the maskable one stops ChromeOS cropping
    # the rounded-square badge into a squircle.
    assert ("192x192", "any") in by_size
    assert ("512x512", "any") in by_size
    assert ("512x512", "maskable") in by_size


def test_every_manifest_icon_is_actually_served(client):

    response = client.get("/manifest.webmanifest")
    manifest = json.loads(response.get_data(as_text=True))
    response.close()

    for icon in manifest["icons"]:
        served = client.get(icon["src"])
        assert served.status_code == 200, icon["src"]
        served.close()


def test_pages_link_the_manifest(client, auth_client):
    for body in (
        client.get("/login").get_data(as_text=True),
        auth_client.get("/").get_data(as_text=True),
    ):
        assert 'rel="manifest"' in body
        assert 'name="theme-color"' in body


def test_routes_endpoint_requires_a_session(client):
    assert client.get("/api/routes").status_code == 401


def test_routes_endpoint_returns_the_controller_view(auth_client):
    payload = auth_client.get("/api/routes").get_json()
    assert payload["device"] == "tun0"
    assert payload["count"] == 2
    assert payload["routes"][0] == {
        "destination": "5.20.0.0/14",
        "gateway": "10.99.0.1",
        "device": "tun0",
        "metric": 101,
        "kind": "tunnel",
        "addresses": 262144,
        "public": True,
    }


def test_routes_endpoint_is_empty_when_the_tunnel_is_down(auth_client, fake_controller):
    fake_controller.route_list = []
    payload = auth_client.get("/api/routes").get_json()
    assert payload["count"] == 0
    assert payload["routes"] == []


def test_status_does_not_carry_the_route_list(auth_client):
    """Routes are deliberately kept off the polled endpoint -- it runs to hundreds of rows."""
    assert "routes" not in auth_client.get("/api/status").get_json()


def test_the_index_page_has_a_routes_table_above_the_log(auth_client):
    html = auth_client.get("/").get_data(as_text=True)
    assert 'id="routes-body"' in html
    assert html.index('id="routes-body"') < html.index('id="log"')


def test_notify_payload_carries_titles_bodies_and_defaults(auth_client):
    payload = auth_client.get("/api/notify").get_json()
    assert set(payload["bodies"]) == {"up", "down_manual", "down_severed"}
    assert payload["titles"]["up"] == "VPN connected"
    assert payload["default_bodies"]["up"]
    assert "{ip}" in payload["placeholders"]


def test_bodies_can_be_saved(auth_client, app_db, seeded_topic):
    response = auth_client.post(
        "/api/notify",
        json={"bodies": {"down_severed": "Died after {duration}."}},
        headers={"X-CSRF-Token": auth_client.csrf_token},
    )
    assert response.status_code == 200
    assert response.get_json()["bodies"]["down_severed"] == "Died after {duration}."
    assert store.notify_bodies(app_db)["down_severed"] == "Died after {duration}."


def test_titles_are_not_writable(auth_client, app_db, seeded_topic):
    """The UI shows titles as labels; nothing in the payload may change them."""
    auth_client.post(
        "/api/notify",
        json={"titles": {"up": "hacked"}, "bodies": {"up": "b"}},
        headers={"X-CSRF-Token": auth_client.csrf_token},
    )
    assert auth_client.get("/api/notify").get_json()["titles"]["up"] == "VPN connected"
    assert store.notify_bodies(app_db)["up"] == "b"


def test_topic_and_bodies_save_together(auth_client, app_db, seeded_topic):
    """The card is one form with one Save button, so one request carries both."""
    auth_client.post(
        "/api/notify",
        json={"topic": "both-at-once", "bodies": {"up": "Up!"}},
        headers={"X-CSRF-Token": auth_client.csrf_token},
    )
    assert store.notify_topic(app_db) == "both-at-once"
    assert store.notify_bodies(app_db)["up"] == "Up!"


def test_a_bad_topic_does_not_save_the_bodies(auth_client, app_db, seeded_topic):
    response = auth_client.post(
        "/api/notify",
        json={"topic": "$(evil)", "bodies": {"up": "Up!"}},
        headers={"X-CSRF-Token": auth_client.csrf_token},
    )
    assert response.status_code == 400
    assert store.notify_bodies(app_db)["up"] != "Up!"
    assert store.notify_topic(app_db) == "existing-topic"


def test_body_save_requires_csrf(auth_client, app_db, seeded_topic):
    assert auth_client.post("/api/notify", json={"bodies": {"up": "no"}}).status_code == 400
    assert store.notify_bodies(app_db)["up"] != "no"


def test_the_page_renders_one_notifications_form_with_three_bodies(auth_client):
    html = auth_client.get("/").get_data(as_text=True)
    assert html.count('id="notify-form"') == 1
    assert 'id="messages-form"' not in html  # the second form is gone
    for kind in ("up", "down_manual", "down_severed"):
        assert f'data-kind="{kind}"' in html
    assert 'data-field="title"' not in html  # titles are labels now, not inputs
    assert "VPN connected" in html and "VPN dropped" in html


def test_test_notification_requires_login(client):
    assert client.post("/api/notify/test").status_code == 401


def test_test_notification_requires_csrf(auth_client, notifier):
    assert auth_client.post("/api/notify/test").status_code == 400
    assert notifier.tests_sent == 0


def test_test_notification_sends(auth_client, notifier, seeded_topic):
    response = auth_client.post(
        "/api/notify/test", headers={"X-CSRF-Token": auth_client.csrf_token}
    )
    assert response.status_code == 200
    assert response.get_json()["url"].endswith("existing-topic")
    assert notifier.tests_sent == 1


def test_a_failed_test_notification_reports_the_reason(auth_client, notifier):
    from app.services.notifications import NotifyDeliveryError

    notifier.test_error = NotifyDeliveryError("could not reach https://ntfy.sh/x: timed out")
    response = auth_client.post(
        "/api/notify/test", headers={"X-CSRF-Token": auth_client.csrf_token}
    )
    assert response.status_code == 502
    assert "could not reach" in response.get_json()["error"]


def test_the_page_offers_a_test_button(auth_client):
    assert 'id="notify-test"' in auth_client.get("/").get_data(as_text=True)


# --- connections API -------------------------------------------------------


def test_connections_require_login(client):
    assert client.get("/api/connections").status_code == 401
    assert client.post("/api/connections").status_code == 401


def test_listing_connections(auth_client, stored_connection):
    payload = auth_client.get("/api/connections").get_json()
    assert payload["count"] == 1
    assert payload["connections"][0]["name"] == "client"


def test_uploading_a_profile_creates_a_connection(auth_client, app_db, vpn_dir):
    """Multipart, as the browser form posts it."""
    response = auth_client.post(
        "/api/connections",
        data={
            "name": "work",
            "label": "Work VPN",
            "username": "alice",
            "password": "s3cret",
            "profile_file": (io.BytesIO(b"client\nremote x 1194 udp\n"), "work.ovpn"),
        },
        content_type="multipart/form-data",
        headers={"X-CSRF-Token": auth_client.csrf_token},
    )
    assert response.status_code == 200
    assert response.get_json()["display_name"] == "Work VPN"
    assert (vpn_dir / "work.ovpn").exists()


def test_the_uploaded_secrets_are_encrypted_at_rest(auth_client, config, vpn_dir):
    auth_client.post(
        "/api/connections",
        data={
            "name": "work",
            "username": "alice",
            "password": "hunter2-plaintext",
            "profile_file": (io.BytesIO(b"<key>PRIVATE-MATERIAL</key>"), "work.ovpn"),
        },
        content_type="multipart/form-data",
        headers={"X-CSRF-Token": auth_client.csrf_token},
    )
    # WAL: a just-written row may still be in the -wal file rather than the database itself.
    raw = config.database.read_bytes()
    wal = config.database.with_name(config.database.name + "-wal")
    if wal.exists():
        raw += wal.read_bytes()
    assert b"hunter2-plaintext" not in raw
    assert b"PRIVATE-MATERIAL" not in raw
    assert b"work" in raw  # the name is not a secret, and is needed while locked


def test_a_profile_can_be_sent_inline_as_json(auth_client, vpn_dir):
    """The same endpoint serves a script, not just the browser form."""
    response = auth_client.post(
        "/api/connections",
        json={"name": "api", "profile": "client\n", "username": "a", "password": "b"},
        headers={"X-CSRF-Token": auth_client.csrf_token},
    )
    assert response.status_code == 200
    assert (vpn_dir / "api.ovpn").read_text() == "client\n"


def test_a_binary_upload_is_refused(auth_client):
    response = auth_client.post(
        "/api/connections",
        data={
            "name": "work",
            "username": "a",
            "password": "b",
            "profile_file": (io.BytesIO(b"\x89PNG\r\n\x1a\n\xff\xfe"), "notaprofile.png"),
        },
        content_type="multipart/form-data",
        headers={"X-CSRF-Token": auth_client.csrf_token},
    )
    assert response.status_code == 400
    assert "not text" in response.get_json()["error"]


def test_a_bad_connection_name_is_refused(auth_client, vpn_dir):
    response = auth_client.post(
        "/api/connections",
        json={"name": "../escape", "profile": "client\n", "username": "a", "password": "b"},
        headers={"X-CSRF-Token": auth_client.csrf_token},
    )
    assert response.status_code == 400
    assert list(vpn_dir.glob("*.ovpn")) == []


def test_saving_a_connection_requires_csrf(auth_client, vpn_dir):
    response = auth_client.post(
        "/api/connections",
        json={"name": "work", "profile": "client\n", "username": "a", "password": "b"},
    )
    assert response.status_code == 400
    assert list(vpn_dir.glob("*.ovpn")) == []


def test_the_default_can_be_moved(auth_client, connections, stored_connection):
    connections.save(name="home", profile="client\n", username="b", password="p")
    response = auth_client.post(
        "/api/connections/home/default", headers={"X-CSRF-Token": auth_client.csrf_token}
    )
    assert response.status_code == 200
    assert connections.default().name == "home"


def test_a_connection_can_be_deleted(auth_client, connections, stored_connection):
    response = auth_client.post(
        "/api/connections/client/delete", headers={"X-CSRF-Token": auth_client.csrf_token}
    )
    assert response.status_code == 200
    assert connections.list() == []


def test_deleting_a_connection_in_use_is_refused(
    auth_client, fake_controller, connections, stored_connection
):
    """Pulling the profile out from under a live attempt would fail it confusingly."""
    fake_controller.status = VpnStatus(state="connecting", profile="client")
    response = auth_client.post(
        "/api/connections/client/delete", headers={"X-CSRF-Token": auth_client.csrf_token}
    )
    assert response.status_code == 409
    assert connections.list() != []


# --- log history -----------------------------------------------------------


def test_logs_endpoint_returns_the_latest_session(auth_client, history):
    history.start_session("client")
    history.append("AUTH_FAILED")
    history.end_session("failed")
    payload = auth_client.get("/api/logs").get_json()
    assert payload["sessions"][0]["outcome"] == "failed"
    assert payload["lines"] == ["AUTH_FAILED"]


def test_logs_endpoint_can_pick_a_session(auth_client, history):
    history.start_session("client")
    history.append("first attempt")
    history.end_session("failed")
    first = auth_client.get("/api/logs").get_json()["session"]
    history.start_session("client")
    history.append("second attempt")
    history.end_session("connected")

    assert auth_client.get(f"/api/logs?session={first}").get_json()["lines"] == ["first attempt"]


def test_logs_require_login(client):
    assert client.get("/api/logs").status_code == 401


# --- a session that outlived the key ---------------------------------------


def _signed_in(app):
    test_client = app.test_client()
    token = _extract_csrf(test_client.get("/login").get_data(as_text=True))
    test_client.post("/login", data={"password": PASSWORD, "csrf_token": token})
    return test_client


def test_a_locked_vault_redirects_a_page_request_to_login(app, vault_state, stored_connection):
    """The cookie is signed and survives a restart; the derived key does not."""
    test_client = _signed_in(app)
    assert test_client.get("/").status_code == 200
    vault_state.lock()  # what a restart looks like to a session that is still holding a cookie
    assert test_client.get("/").status_code == 302


def test_a_locked_vault_tells_an_api_caller_why(app, vault_state, stored_connection):
    """A separate client, because the first blocked request is what carries the explanation --
    it ends the session, so anything after it is a plain 'not signed in'."""
    test_client = _signed_in(app)
    vault_state.lock()
    response = test_client.get("/api/status")
    assert response.status_code == 401
    assert "restarted" in response.get_json()["error"]


def test_signing_in_again_unlocks_it(app, vault_state, stored_connection):
    test_client = _signed_in(app)
    vault_state.lock()
    test_client.get("/")  # consumes the locked session
    assert _signed_in(app).get("/").status_code == 200
    assert vault_state.unlocked


# --- traffic ---------------------------------------------------------------


def test_traffic_requires_login(client):
    assert client.get("/api/traffic").status_code == 401


def test_traffic_with_no_sessions_is_empty_not_an_error(auth_client):
    payload = auth_client.get("/api/traffic").get_json()
    assert payload["session"] is None
    assert payload["points"] == []


def test_traffic_returns_the_latest_session_by_default(auth_client, history):
    history.start_session("client")
    history.record_sample(1024, 512)
    history.record_sample(2048, 1024)
    payload = auth_client.get("/api/traffic").get_json()
    assert payload["session"] == history.session_id
    assert payload["live"] is True
    assert payload["bytes_in"] == 2048


def test_traffic_can_pick_an_older_session(auth_client, history):
    history.start_session("client")
    history.record_sample(10, 10)
    first = history.session_id
    history.end_session("failed")
    history.start_session("client")
    history.record_sample(99, 99)

    payload = auth_client.get(f"/api/traffic?session={first}").get_json()
    assert payload["session"] == first
    assert payload["live"] is False
    assert payload["bytes_in"] == 10


def test_the_traffic_payload_is_bounded(auth_client, history, app_db):
    """However long the tunnel has been up, the browser gets a fixed-size series."""
    from app.services import store as store_module

    history.start_session("client")
    session = history.session_id
    for index in range(1200):
        store_module.record_sample(app_db, session, float(index * 5), index * 5000, index * 500)
    payload = auth_client.get("/api/traffic?points=60").get_json()
    assert len(payload["points"]) == 60


def test_the_traffic_point_count_is_clamped(auth_client, history):
    history.start_session("client")
    assert auth_client.get("/api/traffic?points=999999").status_code == 200
    assert auth_client.get("/api/traffic?points=-5").status_code == 200


def test_the_page_has_a_traffic_panel_after_connections(auth_client, stored_connection):
    body = auth_client.get("/").get_data(as_text=True)
    assert body.index('id="panel-connections"') < body.index('id="panel-traffic"')
    assert body.index('id="panel-traffic"') < body.index('id="panel-routes"')
    assert 'id="traffic-chart"' in body


# --- tunnel scope ----------------------------------------------------------


def test_scope_requires_login(client):
    assert client.get("/api/scope").status_code == 401


def test_scope_reports_the_verdict(auth_client, fake_controller):
    payload = auth_client.get("/api/scope").get_json()
    assert payload["mode"] in {"full", "split", "none"}
    assert "ipv4" in payload and "ipv6" in payload
    assert isinstance(payload["warnings"], list)


def test_the_page_has_a_scope_panel_between_traffic_and_routes(auth_client, stored_connection):
    body = auth_client.get("/").get_data(as_text=True)
    assert body.index('id="panel-traffic"') < body.index('id="panel-scope"')
    assert body.index('id="panel-scope"') < body.index('id="panel-routes"')
    assert 'id="scope-mode"' in body


# --- dns rules ---------------------------------------------------------------


def test_dns_requires_login(client):
    assert client.get("/api/dns").status_code == 401
    body = {"kind": "fallback", "address": "8.8.8.8"}
    assert client.post("/api/dns", json=body).status_code == 401


def test_the_page_has_a_dns_panel_between_routes_and_events(auth_client, stored_connection):
    body = auth_client.get("/").get_data(as_text=True)
    assert body.index('id="panel-routes"') < body.index('id="panel-dns"')
    assert body.index('id="panel-dns"') < body.index('id="panel-events"')


def test_dns_rules_start_empty(auth_client):
    payload = auth_client.get("/api/dns").get_json()
    assert payload["domain_rules"] == []
    assert payload["fallback_rules"] == []
    assert payload["legacy"] is None


def test_adding_a_domain_forwarder(auth_client):
    response = auth_client.post(
        "/api/dns",
        json={"kind": "domain", "domain": "example.corp", "address": "10.100.53.2"},
        headers={"X-CSRF-Token": auth_client.csrf_token},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["rule"]["domain"] == "example.corp"
    assert payload["domain_rules"][0]["address"] == "10.100.53.2"


def test_adding_a_fallback_server(auth_client):
    response = auth_client.post(
        "/api/dns",
        json={"kind": "fallback", "address": "8.8.8.8"},
        headers={"X-CSRF-Token": auth_client.csrf_token},
    )
    assert response.status_code == 200
    assert response.get_json()["fallback_rules"][0]["address"] == "8.8.8.8"


def test_a_bad_domain_is_rejected_before_the_helper_is_ever_called(auth_client, dns_runner):
    response = auth_client.post(
        "/api/dns",
        json={"kind": "domain", "domain": "/etc/passwd", "address": "1.2.3.4"},
        headers={"X-CSRF-Token": auth_client.csrf_token},
    )
    assert response.status_code == 400
    assert dns_runner.calls == []


def test_adding_a_dns_rule_requires_csrf(auth_client):
    response = auth_client.post("/api/dns", json={"kind": "fallback", "address": "8.8.8.8"})
    assert response.status_code == 400


def test_deleting_a_dns_rule(auth_client, dns_rules):
    rule, _ = dns_rules.add(kind="fallback", domain=None, address="8.8.8.8")
    response = auth_client.post(
        f"/api/dns/{rule.id}/delete", headers={"X-CSRF-Token": auth_client.csrf_token}
    )
    assert response.status_code == 200
    assert response.get_json()["fallback_rules"] == []


def test_moving_a_fallback_rule(auth_client, dns_rules):
    dns_rules.add(kind="fallback", domain=None, address="1.1.1.1")
    second, _ = dns_rules.add(kind="fallback", domain=None, address="2.2.2.2")
    response = auth_client.post(
        f"/api/dns/{second.id}/move",
        json={"direction": "up"},
        headers={"X-CSRF-Token": auth_client.csrf_token},
    )
    assert response.status_code == 200
    addresses = [r["address"] for r in response.get_json()["fallback_rules"]]
    assert addresses == ["2.2.2.2", "1.1.1.1"]


def test_a_failed_apply_still_returns_200_with_a_warning_and_persists_the_row(
    auth_client, dns_runner
):
    """A dns-apply failure must not make the save itself look like it failed -- the row is
    already committed by the time the helper is asked to apply it."""
    dns_runner.returncode = 1
    dns_runner.stderr = "dnsmasq rejected the new rules"
    response = auth_client.post(
        "/api/dns",
        json={"kind": "fallback", "address": "8.8.8.8"},
        headers={"X-CSRF-Token": auth_client.csrf_token},
    )
    assert response.status_code == 200
    assert "dnsmasq rejected the new rules" in response.get_json()["warning"]
    follow_up = auth_client.get("/api/dns").get_json()
    assert follow_up["fallback_rules"][0]["address"] == "8.8.8.8"


def test_dns_import_with_nothing_to_import_is_refused(auth_client):
    response = auth_client.post("/api/dns/import", headers={"X-CSRF-Token": auth_client.csrf_token})
    assert response.status_code == 400


def test_dns_import_requires_csrf(auth_client):
    assert auth_client.post("/api/dns/import").status_code == 400


def test_the_legacy_import_banner_and_import_flow(
    app_db, config, vault_state, fake_controller, tmp_path
):
    """The banner only appears while nothing has been saved; importing takes it over in one call
    and retires the legacy file in the same operation the helper performs."""
    legacy = tmp_path / "examplecorp.conf"
    legacy.write_text("server=/example.corp/10.100.53.2\nserver=8.8.8.8\n", encoding="utf-8")
    runner = FakeRunner(stdout="applied")
    dns_config = replace(config, DNS_LEGACY_CONF=legacy)
    dns_service = DnsRules(app_db, dns_config, runner=runner)
    application = create_app(
        {
            "APP_CONFIG": dns_config,
            "CONTROLLER": fake_controller,
            "DB": app_db,
            "VAULT": vault_state,
            "DNS_RULES": dns_service,
            "TESTING": True,
        }
    )
    application.config["WTF_CSRF_ENABLED"] = False
    test_client = application.test_client()
    page = test_client.get("/login")
    token = _extract_csrf(page.get_data(as_text=True))
    test_client.post("/login", data={"password": PASSWORD, "csrf_token": token})
    csrf_token = _extract_csrf(test_client.get("/").get_data(as_text=True))

    preview = test_client.get("/api/dns").get_json()
    assert preview["legacy"]["path"] == str(legacy)
    assert len(preview["legacy"]["rules"]) == 2

    response = test_client.post("/api/dns/import", headers={"X-CSRF-Token": csrf_token})
    assert response.status_code == 200
    result = response.get_json()
    assert result["imported"] == 2
    assert len(result["domain_rules"]) == 1
    assert len(result["fallback_rules"]) == 1

    follow_up = test_client.get("/api/dns").get_json()
    assert follow_up["legacy"] is None


# --- dns status ---------------------------------------------------------------


def test_dns_status_requires_login(client):
    assert client.get("/api/dns/status").status_code == 401


def test_dns_status_reports_the_resolver_state(auth_client, dns_runner):
    payload = auth_client.get("/api/dns/status").get_json()
    # The fake runner returns no usable resolvectl output, which is the tunnel-down case.
    assert payload["mode"] == "down"
    assert payload["link"] is None
    assert payload["headline"]
    assert payload["action_needed"] is False


def test_dns_status_goes_through_the_injected_runner(auth_client, dns_runner):
    """The endpoint must never reach the real systemd-resolved from a test."""
    dns_runner.calls.clear()
    auth_client.get("/api/dns/status")
    assert dns_runner.calls == [["resolvectl", "--json=short", "status", "tun0"]]


def test_dns_status_cross_references_the_saved_rules(auth_client, dns_rules):
    dns_rules.add(kind="domain", domain="example.corp", address="10.100.53.2")
    payload = auth_client.get("/api/dns/status").get_json()
    assert any("example.corp" in note for note in payload["notes"])


# --- ignoring pushed DNS ------------------------------------------------------


def test_toggle_pushed_dns_requires_login(client):
    assert client.post("/api/connections/client/toggle-dns").status_code == 401


def test_toggle_pushed_dns_requires_csrf(auth_client, stored_connection):
    response = auth_client.post("/api/connections/client/toggle-dns")
    assert response.status_code == 400


def test_toggle_pushed_dns_flips_the_flag(auth_client, stored_connection, connections):
    csrf = _extract_csrf(auth_client.get("/").get_data(as_text=True))
    response = auth_client.post(
        "/api/connections/client/toggle-dns", headers={"X-CSRF-Token": csrf}
    )
    assert response.status_code == 200
    assert response.get_json()["ignore_pushed_dns"] is True
    assert connections.get("client").ignore_pushed_dns is True


def test_toggle_pushed_dns_on_an_unknown_connection_is_a_400(auth_client, stored_connection):
    csrf = _extract_csrf(auth_client.get("/").get_data(as_text=True))
    response = auth_client.post("/api/connections/nope/toggle-dns", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 400


def test_the_connection_row_offers_the_dns_toggle(auth_client, stored_connection):
    body = auth_client.get("/").get_data(as_text=True)
    assert 'data-action="toggle-dns"' in body
    assert "Ignore pushed DNS" in body


def test_the_row_shows_the_flag_once_it_is_on(auth_client, stored_connection, connections):
    connections.toggle_ignore_pushed_dns("client")
    body = auth_client.get("/").get_data(as_text=True)
    assert "ignores pushed DNS" in body
    assert "Allow pushed DNS" in body


# --- the deployment self-check ---------------------------------------------


def test_deploy_status_requires_a_login(client):
    assert client.get("/api/deploy").status_code == 401


def test_deploy_status_reports_a_clean_deployment_as_clean(auth_client):
    payload = auth_client.get("/api/deploy").get_json()
    assert payload["clean"] is True
    assert payload["items"] == []


def test_deploy_status_surfaces_a_damaged_env_file(auth_client, config):
    config.VPN_DIR.joinpath("webapp.env").write_text(
        "VPN_CONNECT_PASSWORD_HASH='a'\nVPN_CONNECT_PASSWORD_HASH='b'\n", encoding="utf-8"
    )
    payload = auth_client.get("/api/deploy").get_json()
    assert payload["clean"] is False
    assert [item["kind"] for item in payload["items"]] == ["env"]
