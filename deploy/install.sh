#!/usr/bin/env bash
#
# Installs the root helper, its sudoers rule and the systemd unit.
#
#   sudo ./deploy/install.sh                    # asks where to listen; defaults to 127.0.0.1:5000
#   sudo BIND=0.0.0.0 PORT=5000 ./deploy/install.sh   # setting BIND skips the question
#
# Re-runnable: every step overwrites its previous output.

set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VPN_OWNER="${SUDO_USER:-$USER}"
OWNER_HOME="$(getent passwd "$VPN_OWNER" | cut -d: -f6)"

VPN_DIR="${VPN_DIR:-$OWNER_HOME/.vpn}"
ENV_FILE="${ENV_FILE:-$VPN_DIR/webapp.env}"
RUN_DIR="${RUN_DIR:-/run/vpn-connect}"
HELPER="${HELPER:-/usr/local/sbin/vpn-connect-helper}"
# Only the label the web form shows above the code box. It no longer reaches openvpn: whether a
# code is asked for at all now comes from the profile's own static-challenge line.
CHALLENGE="${CHALLENGE:-Enter Authenticator Code}"
OPENVPN="${OPENVPN:-$(command -v openvpn || echo /usr/sbin/openvpn)}"
DNS_CONF="${DNS_CONF:-/etc/dnsmasq.d/vpn-connect.conf}"
DNS_DIR="$(dirname "$DNS_CONF")"
DNSMASQ_UNIT="${DNSMASQ_UNIT:-dnsmasq}"

# The helper and the app must agree on which legacy file is being retired: the app reads
# VPN_CONNECT_DNS_LEGACY_CONF from the env file, the helper has it baked in at install time. The
# env file is only written on a *first* install, so on a re-run the value would silently fall
# back to empty here while the app still had it -- the app would offer the import, the helper
# would install the new file and never retire the old one, and both would define the same
# domain. Read it back out of the env file when it is not being set explicitly.
if [[ -z "${LEGACY_DNS_CONF:-}" && -f "$ENV_FILE" ]]; then
    LEGACY_DNS_CONF="$(sed -n "s/^VPN_CONNECT_DNS_LEGACY_CONF='\(.*\)'$/\1/p" "$ENV_FILE" | tail -1)"
fi
LEGACY_DNS_CONF="${LEGACY_DNS_CONF:-}"
PORT="${PORT:-5000}"

# --- where the web UI listens ------------------------------------------------
#
# Localhost is the default, and you have to choose to widen it. This panel can rewrite the
# machine's routing and DNS and holds VPN credentials, so the login password is the only thing in
# front of a root-equivalent tool -- that is a decision to make deliberately, not to inherit from
# an installer.
#
# BIND= in the environment always wins and never prompts, so scripted and unattended installs stay
# non-interactive. On a re-run the address already in the installed unit becomes the default, so
# pressing enter never quietly takes away access that is already set up and working.
installed_bind() {
    local unit=/etc/systemd/system/vpn-connect.service
    [[ -f "$unit" ]] || return 1
    sed -n 's/.*--bind \([^ :]*\):[0-9]*.*/\1/p' "$unit" | head -1
}

if [[ -z "${BIND:-}" ]]; then
    BIND="$(installed_bind || true)"
    BIND="${BIND:-127.0.0.1}"
    # Without a terminal there is nobody to ask, and a prompt would hang an unattended install.
    if [[ -t 0 ]]; then
        cat <<EOF

Where should the web UI listen?

  1) 127.0.0.1  this machine only -- reach it with: ssh -L $PORT:localhost:$PORT <host>
  2) 0.0.0.0    every interface, so any device on your LAN can reach the login page

Or type an address to bind just that one, e.g. your tailnet IP.
EOF
        read -r -p "Choice [$BIND]: " answer || answer=""
        case "$answer" in
            "")  ;;  # keep the default
            1)   BIND="127.0.0.1" ;;
            2)   BIND="0.0.0.0" ;;
            *)   BIND="$answer" ;;
        esac
    fi
fi

# Also stops anything with a '|' in it reaching the sed that renders the unit template.
[[ "$BIND" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || {
    echo "BIND must be an IPv4 address, got '$BIND'." >&2
    exit 1
}
UV="${UV:-$(sudo -u "$VPN_OWNER" -H bash -lc 'command -v uv' || true)}"

[[ $EUID -eq 0 ]] || { echo "Run this with sudo." >&2; exit 1; }
[[ -n "$UV" ]] || { echo "Cannot find uv for $VPN_OWNER — set UV=/path/to/uv." >&2; exit 1; }
[[ -x "$OPENVPN" ]] || { echo "openvpn not found at $OPENVPN." >&2; exit 1; }
[[ -d "$VPN_DIR" ]] || { echo "VPN directory $VPN_DIR does not exist." >&2; exit 1; }

# Hashed with the placeholder still in it, so the app can recompute exactly this value from the
# template in the repo without knowing any of the install-time substitutions.
HELPER_VERSION="$(sha256sum "$APP_DIR/deploy/vpn-connect-helper.in" | cut -d' ' -f1)"

render() {
    sed -e "s|@HELPER_VERSION@|$HELPER_VERSION|g" \
        -e "s|@VPN_OWNER@|$VPN_OWNER|g" \
        -e "s|@VPN_DIR@|$VPN_DIR|g" \
        -e "s|@RUN_DIR@|$RUN_DIR|g" \
        -e "s|@HELPER@|$HELPER|g" \
        -e "s|@OPENVPN@|$OPENVPN|g" \
        -e "s|@DNS_CONF@|$DNS_CONF|g" \
        -e "s|@DNS_DIR@|$DNS_DIR|g" \
        -e "s|@LEGACY_DNS_CONF@|$LEGACY_DNS_CONF|g" \
        -e "s|@DNSMASQ_UNIT@|$DNSMASQ_UNIT|g" \
        -e "s|@APP_DIR@|$APP_DIR|g" \
        -e "s|@ENV_FILE@|$ENV_FILE|g" \
        -e "s|@UV@|$UV|g" \
        -e "s|@BIND@|$BIND|g" \
        -e "s|@PORT@|$PORT|g" \
        "$1"
}

echo "==> Installing helper to $HELPER"
render "$APP_DIR/deploy/vpn-connect-helper.in" > "$HELPER.tmp"
install -o root -g root -m 0755 "$HELPER.tmp" "$HELPER"
rm -f "$HELPER.tmp"

echo "==> Installing sudoers rule to /etc/sudoers.d/vpn-connect"
render "$APP_DIR/deploy/vpn-connect.sudoers.in" > /tmp/vpn-connect.sudoers
visudo -cf /tmp/vpn-connect.sudoers >/dev/null
install -o root -g root -m 0440 /tmp/vpn-connect.sudoers /etc/sudoers.d/vpn-connect
rm -f /tmp/vpn-connect.sudoers

echo "==> Installing unit to /etc/systemd/system/vpn-connect.service"
render "$APP_DIR/deploy/vpn-connect.service.in" > /etc/systemd/system/vpn-connect.service
chmod 0644 /etc/systemd/system/vpn-connect.service

if [[ ! -f "$ENV_FILE" ]]; then
    echo "==> Creating $ENV_FILE with a fresh secret key"
    umask 077
    {
        echo "# Environment for vpn-connect.service — keep mode 0600."
        echo "VPN_CONNECT_SECRET_KEY='$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')'"
        echo "VPN_CONNECT_VPN_DIR='$VPN_DIR'"
        echo "VPN_CONNECT_HELPER='$HELPER'"
        echo "VPN_CONNECT_MGMT_SOCKET='$RUN_DIR/mgmt.sock'"
        echo "VPN_CONNECT_STATIC_CHALLENGE='$CHALLENGE'"
        if [[ -n "$LEGACY_DNS_CONF" ]]; then
            echo "VPN_CONNECT_DNS_LEGACY_CONF='$LEGACY_DNS_CONF'"
        fi
        echo "# Add the login hash: uv run flask --app app set-password >> $ENV_FILE"
    } > "$ENV_FILE"
    chown "$VPN_OWNER:$VPN_OWNER" "$ENV_FILE"
    chmod 0600 "$ENV_FILE"
fi

echo "==> Reloading systemd"
systemctl daemon-reload

cat <<EOF

Installed. Remaining steps, as $VPN_OWNER:

  cd $APP_DIR
  uv sync
  uv run flask --app app set-password >> $ENV_FILE   # appends VPN_CONNECT_PASSWORD_HASH
  sudo systemctl enable --now vpn-connect

EOF

if [[ "$BIND" == "0.0.0.0" ]]; then
    cat <<EOF
The UI will be on http://<this-host>:$PORT/ — bound to every interface, so anything on your LAN
reaches the login page and the password is the only barrier in front of a tool that can rewrite
this machine's routing. Re-run with BIND=127.0.0.1 if you would rather use an SSH tunnel.
EOF
else
    cat <<EOF
The UI will be on http://$BIND:$PORT/ — reachable only from that address. If that is 127.0.0.1,
get to it with: ssh -L $PORT:localhost:$PORT <host>
EOF
fi
