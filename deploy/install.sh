#!/usr/bin/env bash
#
# Installs the root helper, its sudoers rule and the systemd unit.
#
#   sudo ./deploy/install.sh                    # asks where to listen; defaults to 127.0.0.1:5000
#   sudo BIND=0.0.0.0 PORT=5000 ./deploy/install.sh   # setting BIND skips the question
#   sudo BIND=0.0.0.0 ALLOW_FROM=127.0.0.0/8,192.168.4.0/22 ./deploy/install.sh   # fully scripted
#   sudo TRUSTED_PROXIES=127.0.0.0/8 ./deploy/install.sh   # something like `tailscale serve` in front
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

# --- who may actually connect ------------------------------------------------
#
# Binding is not a security boundary: 0.0.0.0 listens on *every* interface, and while the VPN is
# up that includes tun0 -- so without this list the network at the far end of the tunnel can
# reach the panel. The app tests every request's source against these CIDRs before authentication.
#
# Named explicitly rather than derived from "is it a private address", because a tun0 address is
# private too. Only the operator knows which private network is theirs.
lan_cidr() {
    local dev
    dev="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')"
    [[ -n "$dev" ]] || return 1
    # The kernel's own on-link route is already the network address, so there is no netmask
    # arithmetic to get wrong here -- 192.168.4.0/22, not the 192.168.4.46/22 that `ip addr` says.
    ip -4 -o route show dev "$dev" scope link proto kernel 2>/dev/null | awk '{print $1; exit}'
}

installed_allow_from() {
    [[ -f "$ENV_FILE" ]] || return 1
    sed -n "s/^VPN_CONNECT_ALLOW_FROM='\(.*\)'$/\1/p" "$ENV_FILE" | tail -1
}

if [[ -z "${ALLOW_FROM:-}" ]]; then
    ALLOW_FROM="$(installed_allow_from || true)"
    if [[ -z "$ALLOW_FROM" ]]; then
        if [[ "$BIND" == "127.0.0.1" ]]; then
            ALLOW_FROM="127.0.0.0/8"
        else
            LAN="$(lan_cidr || true)"
            ALLOW_FROM="127.0.0.0/8${LAN:+,$LAN}"
            # The tailnet range, not this node's address: Tailscale hands out a new one whenever
            # it feels like it, and 100.64.0.0/10 is the whole CGNAT space it draws from.
            ip -o link show tailscale0 >/dev/null 2>&1 && ALLOW_FROM="$ALLOW_FROM,100.64.0.0/10"
        fi
    fi
    if [[ -t 0 && "$BIND" != "127.0.0.1" ]]; then
        cat <<EOF

Listening on $BIND means every interface, including tun0 while the VPN is up.
Which source addresses may reach the panel?

  Detected: $ALLOW_FROM

Press enter to accept, or type a comma-separated list of CIDRs.
EOF
        read -r -p "Allow from [$ALLOW_FROM]: " answer || answer=""
        [[ -n "$answer" ]] && ALLOW_FROM="$answer"
    fi
fi

# Charset only. The app parses this properly at startup and refuses to start on a bad entry
# rather than skipping it; this check exists to catch a typo now instead of at first boot, and to
# keep quotes and shell metacharacters out of the env file.
[[ "$ALLOW_FROM" =~ ^[0-9a-fA-F.:/,]+$ ]] || {
    echo "ALLOW_FROM must be comma-separated addresses or CIDRs, got '$ALLOW_FROM'." >&2
    exit 1
}

# --- reverse proxy, if any ---------------------------------------------------
#
# Only consulted to decide who a request belongs to for the login throttle -- never to decide who
# may connect, which is always the real socket peer. Empty is the right default: with nothing in
# front of the app, X-Forwarded-For is a header a client made up.
#
# Set this to 127.0.0.0/8 when something like `tailscale serve` fronts the app on loopback,
# otherwise every device behind it shares one lockout bucket.
TRUSTED_PROXIES="${TRUSTED_PROXIES:-$(
    [[ -f "$ENV_FILE" ]] &&
        sed -n "s/^VPN_CONNECT_TRUSTED_PROXIES='\(.*\)'$/\1/p" "$ENV_FILE" | tail -1
)}"

[[ -z "$TRUSTED_PROXIES" || "$TRUSTED_PROXIES" =~ ^[0-9a-fA-F.:/,]+$ ]] || {
    echo "TRUSTED_PROXIES must be comma-separated addresses or CIDRs, got '$TRUSTED_PROXIES'." >&2
    exit 1
}
UV="${UV:-$(sudo -u "$VPN_OWNER" -H bash -lc 'command -v uv' || true)}"

[[ $EUID -eq 0 ]] || { echo "Run this with sudo." >&2; exit 1; }
[[ -n "$UV" ]] || { echo "Cannot find uv for $VPN_OWNER — set UV=/path/to/uv." >&2; exit 1; }
if [[ ! -x "$OPENVPN" ]]; then
    echo "openvpn not found at $OPENVPN." >&2
    # Worth saying explicitly: to somebody who has openvpn3 installed, "openvpn not found" reads
    # as a broken installer rather than as a different program.
    if command -v openvpn3 >/dev/null 2>&1; then
        echo "An OpenVPN 3 client ($(command -v openvpn3)) is installed, but this panel drives" >&2
        echo "the classic openvpn client over OpenVPN's management interface, which OpenVPN 3" >&2
        echo "does not provide. They can be installed side by side." >&2
    fi
    echo "Run ./install_prerequisites.sh, or set OPENVPN=/path/to/openvpn." >&2
    exit 1
fi
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
        echo "VPN_CONNECT_ALLOW_FROM='$ALLOW_FROM'"
        echo "VPN_CONNECT_TRUSTED_PROXIES='$TRUSTED_PROXIES'"
        if [[ -n "$LEGACY_DNS_CONF" ]]; then
            echo "VPN_CONNECT_DNS_LEGACY_CONF='$LEGACY_DNS_CONF'"
        fi
        echo "# Add the login hash: uv run flask --app app set-password >> $ENV_FILE"
    } > "$ENV_FILE"
    chown "$VPN_OWNER:$VPN_OWNER" "$ENV_FILE"
    chmod 0600 "$ENV_FILE"
else
    # The heredoc above only ever runs on a first install, so on every re-run this is the only
    # thing that keeps the env file in step with the answers just given. Without it, widening
    # BIND on an existing box would leave the old allowlist in force and lock the operator out
    # of the address they had just asked for.
    #
    # Replaces rather than appends: systemd takes the last of a duplicated key and would behave
    # correctly, but the app's own deployment self-check reports duplicate assignments as drift,
    # so appending would light up the drift banner on every page load.
    upsert_env() {
        local key="$1" value="$2" tmp
        tmp="$(mktemp)"
        grep -v "^${key}=" "$ENV_FILE" > "$tmp" || true
        echo "${key}='${value}'" >> "$tmp"
        install -o "$VPN_OWNER" -g "$VPN_OWNER" -m 0600 "$tmp" "$ENV_FILE"
        rm -f "$tmp"
    }
    echo "==> Updating access settings in $ENV_FILE"
    upsert_env VPN_CONNECT_ALLOW_FROM "$ALLOW_FROM"
    upsert_env VPN_CONNECT_TRUSTED_PROXIES "$TRUSTED_PROXIES"
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
The UI will be on http://<this-host>:$PORT/ — bound to every interface, but only these sources
are allowed to reach it:

  $ALLOW_FROM

Anything else, including the network at the far end of the VPN, gets a 403 before the login form.
Re-run with BIND=127.0.0.1 if you would rather use an SSH tunnel, or ALLOW_FROM=... to change the
list.
EOF
else
    cat <<EOF
The UI will be on http://$BIND:$PORT/ — reachable only from that address. If that is 127.0.0.1,
get to it with: ssh -L $PORT:localhost:$PORT <host>
EOF
fi
