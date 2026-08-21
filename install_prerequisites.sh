#!/usr/bin/env bash
#
# Everything vpn-connect needs before deploy/install.sh can run: the openvpn client, the tools the
# panel reads the system with, and uv.
#
#   ./install_prerequisites.sh                 # asks about dnsmasq, then installs
#   ./install_prerequisites.sh -y              # take the defaults, ask nothing
#   ./install_prerequisites.sh -y --with-dnsmasq --skip-uv
#   ./install_prerequisites.sh --check         # report what is missing, install nothing
#
# Run it as yourself, not with sudo: package installs are individually elevated, and uv has to
# belong to the user the service will run as. Running it under sudo works too -- it installs uv for
# $SUDO_USER -- but plain `./install_prerequisites.sh` is the intended way.
#
# Supported: Debian/Ubuntu (apt), Fedora/RHEL family (dnf), Arch (pacman). On anything else it
# prints the package list and stops rather than guessing.

set -euo pipefail

ASSUME_YES=0
CHECK_ONLY=0
SKIP_UV=0
WANT_DNSMASQ=""   # unset until asked or overridden

usage() {
    sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -y|--yes)         ASSUME_YES=1 ;;
        --check)          CHECK_ONLY=1 ;;
        --skip-uv)        SKIP_UV=1 ;;
        --with-dnsmasq)   WANT_DNSMASQ=1 ;;
        --no-dnsmasq)     WANT_DNSMASQ=0 ;;
        -h|--help)        usage 0 ;;
        *)                echo "Unknown option: $1" >&2; usage 1 ;;
    esac
    shift
done

# --- who are we, and how do we become root -----------------------------------
#
# uv must belong to the account the systemd unit will run as, never to root: deploy/install.sh
# looks it up as that user and the unit calls it by that path. So the one thing this script is
# careful about is which user each step runs as.
if [[ $EUID -eq 0 ]]; then
    TARGET_USER="${SUDO_USER:-root}"
    as_root() { "$@"; }
else
    TARGET_USER="$USER"
    if command -v sudo >/dev/null 2>&1; then
        as_root() { sudo "$@"; }
    else
        as_root() { echo "This needs root and sudo is not installed: $*" >&2; return 1; }
    fi
fi

say()  { printf '\n==> %s\n' "$*"; }
warn() { printf '  ! %s\n' "$*" >&2; }
ok()   { printf '  . %s\n' "$*"; }

confirm() {
    local prompt="$1" default="${2:-y}" answer
    (( ASSUME_YES )) && { [[ "$default" == y ]]; return; }
    [[ -t 0 ]] || { [[ "$default" == y ]]; return; }
    read -r -p "$prompt [$( [[ "$default" == y ]] && echo "Y/n" || echo "y/N" )]: " answer || answer=""
    answer="${answer:-$default}"
    [[ "$answer" =~ ^[Yy] ]]
}

# --- which distribution ------------------------------------------------------
#
# ID first, then ID_LIKE, so derivatives (Linux Mint, Pop!_OS, Rocky, CachyOS...) are handled
# without maintaining a list of every one of them.
FAMILY=""
DISTRO_NAME="this system"
if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_NAME="${PRETTY_NAME:-${NAME:-this system}}"
    for id in "${ID:-}" ${ID_LIKE:-}; do
        case "$id" in
            debian|ubuntu)          FAMILY=debian ;;
            fedora|rhel|centos)     FAMILY=fedora ;;
            arch)                   FAMILY=arch ;;
        esac
        [[ -n "$FAMILY" ]] && break
    done
fi

# --- package names, per family ----------------------------------------------
#
# The differences are small but real: iproute2 is `iproute` on Fedora, and systemd-resolved is a
# separate package on recent Ubuntu and Fedora while it is part of systemd on Arch. Rather than
# encode which release split it out, every optional name is checked against the repositories
# before it is asked for -- see pkg_exists below.
case "$FAMILY" in
    debian)
        PKGS=(openvpn iproute2 whois curl ca-certificates)
        MAYBE=(systemd-resolved)
        DNSMASQ_PKG=dnsmasq
        pkg_exists() { apt-cache show "$1" >/dev/null 2>&1; }
        pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "ok installed"; }
        pkg_install() {
            as_root env DEBIAN_FRONTEND=noninteractive apt-get update
            as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
        }
        ;;
    fedora)
        PKGS=(openvpn iproute whois curl ca-certificates)
        MAYBE=(systemd-resolved)
        DNSMASQ_PKG=dnsmasq
        pkg_exists() { dnf --quiet list --available "$1" >/dev/null 2>&1 || dnf --quiet list --installed "$1" >/dev/null 2>&1; }
        pkg_installed() { rpm -q "$1" >/dev/null 2>&1; }
        pkg_install() { as_root dnf install -y "$@"; }
        ;;
    arch)
        PKGS=(openvpn iproute2 whois curl ca-certificates)
        MAYBE=()          # systemd-resolved ships inside systemd here
        DNSMASQ_PKG=dnsmasq
        pkg_exists() { pacman -Si "$1" >/dev/null 2>&1; }
        pkg_installed() { pacman -Qi "$1" >/dev/null 2>&1; }
        pkg_install() { as_root pacman -S --needed --noconfirm "$@"; }
        ;;
    *)
        cat >&2 <<EOF
Unrecognised distribution ($DISTRO_NAME).

Install these by hand, then run: mkdir -p ~/.vpn && uv sync && sudo ./deploy/install.sh

  openvpn        the client this panel drives
  iproute2       'ip' -- the routes and scope panels read the kernel's tables with it
  whois          route ownership lookups in the routes table
  systemd        the service, the root helper and the DNS report all use systemctl/resolvectl
  dnsmasq        optional; only the DNS rules panel needs it
  uv             https://docs.astral.sh/uv/ -- install as the user the service will run as
EOF
        exit 1
        ;;
esac

say "Prerequisites for vpn-connect on $DISTRO_NAME"
ok "package manager family: $FAMILY"
ok "uv will belong to: $TARGET_USER"

# --- systemd is not optional -------------------------------------------------
if [[ ! -d /run/systemd/system ]]; then
    warn "systemd is not running here. vpn-connect installs a systemd unit and its root helper"
    warn "calls systemctl, so it cannot work on this machine."
    exit 1
fi

# --- work out what is missing ------------------------------------------------
WANTED=("${PKGS[@]}")
for candidate in ${MAYBE[@]+"${MAYBE[@]}"}; do
    if pkg_exists "$candidate"; then
        WANTED+=("$candidate")
    else
        ok "$candidate is not a separate package here (nothing to do)"
    fi
done

# dnsmasq is genuinely optional: without it every panel except DNS rules works, and applying a rule
# reports that dnsmasq is not running rather than failing. Ask rather than assume -- installing a
# second resolver on someone's machine is not a side effect to spring on them.
if [[ -z "$WANT_DNSMASQ" ]]; then
    if pkg_installed "$DNSMASQ_PKG"; then
        WANT_DNSMASQ=1
    elif confirm "Install dnsmasq? Only the DNS rules panel needs it" n; then
        WANT_DNSMASQ=1
    else
        WANT_DNSMASQ=0
    fi
fi
(( WANT_DNSMASQ )) && WANTED+=("$DNSMASQ_PKG")

MISSING=()
for pkg in "${WANTED[@]}"; do
    if pkg_installed "$pkg"; then
        ok "$pkg"
    else
        MISSING+=("$pkg")
    fi
done

if (( CHECK_ONLY )); then
    say "Check only, installing nothing"
    if (( ${#MISSING[@]} )); then
        echo "Missing: ${MISSING[*]}"
    else
        echo "Every package is present."
    fi
    command -v uv >/dev/null 2>&1 || echo "Missing: uv (see https://docs.astral.sh/uv/)"
    exit 0
fi

if (( ${#MISSING[@]} )); then
    say "Installing: ${MISSING[*]}"
    confirm "Proceed?" y || { echo "Nothing installed."; exit 1; }
    pkg_install "${MISSING[@]}"
else
    say "Every package is already present"
fi

# --- uv, as the right user ---------------------------------------------------
#
# Deliberately not from the distribution's repositories even where it has them: deploy/install.sh
# resolves uv as the service account and bakes that path into the unit, and the official installer
# is the one place it is guaranteed to land in that account's ~/.local/bin.
# Run something as the service account -- directly when that is already who we are, so the common
# case (a user running this on their own machine) never asks for a sudo password just to look up
# whether uv exists.
as_target() {
    if [[ "$TARGET_USER" == "$USER" ]]; then
        bash -lc "$1"
    else
        sudo -u "$TARGET_USER" -H bash -lc "$1"
    fi
}

uv_for_target() { as_target 'command -v uv' 2>/dev/null; }

if (( SKIP_UV )); then
    ok "skipping uv (--skip-uv)"
elif [[ "$TARGET_USER" == root ]]; then
    warn "running as root with no SUDO_USER, so there is no account to install uv for."
    warn "Run this script as the user the service will run as, or install uv yourself."
elif uv_path="$(uv_for_target)" && [[ -n "$uv_path" ]]; then
    ok "uv: $uv_path"
else
    say "Installing uv for $TARGET_USER"
    if confirm "Fetch and run the installer from https://astral.sh/uv/install.sh?" y; then
        as_target 'curl -LsSf https://astral.sh/uv/install.sh | sh'
        uv_path="$(uv_for_target || true)"
        if [[ -n "$uv_path" ]]; then
            ok "uv: $uv_path"
        else
            warn "uv installed but is not on $TARGET_USER's PATH yet."
            warn "Open a new shell, or: source \$HOME/.local/bin/env"
        fi
    else
        warn "uv not installed. deploy/install.sh will refuse to run without it."
    fi
fi

# --- what the machine actually reports now -----------------------------------
#
# The same discipline the app itself follows: check what is true rather than trusting that the
# package manager's exit status meant everything works.
say "Checking the tools the panel uses"
for tool in openvpn ip whois systemctl resolvectl; do
    if path="$(command -v "$tool" 2>/dev/null)"; then
        ok "$tool: $path"
    elif [[ "$tool" == whois || "$tool" == resolvectl ]]; then
        # Both of these only feed a report. Missing whois leaves the routes table without owner
        # names; missing resolvectl leaves the DNS card unable to say who resolves what.
        warn "$tool missing -- that panel degrades rather than breaks, but its report will be blank."
    else
        warn "$tool missing -- vpn-connect needs it."
    fi
done

if version="$(openvpn --version 2>/dev/null | head -1)"; then
    ok "$version"
    number="$(sed -n 's/^OpenVPN \([0-9][0-9.]*\).*/\1/p' <<<"$version")"
    major="${number%%.*}"; rest="${number#*.}"; minor="${rest%%.*}"
    if [[ -n "$major" && -n "$minor" ]] && (( major < 2 || (major == 2 && minor < 5) )); then
        warn "OpenVPN $number is older than 2.5; the management interface options this uses may"
        warn "not all exist. 2.6+ is what the DNS behaviour in the README describes."
    fi
fi

if (( WANT_DNSMASQ )); then
    if systemctl is-active --quiet dnsmasq; then
        ok "dnsmasq is running"
    else
        warn "dnsmasq is installed but not running. On a systemd-resolved machine this is usually"
        warn "the two of them wanting port 53: give dnsmasq 'listen-address=127.0.0.1' and"
        warn "'bind-interfaces', then point resolved at it. The DNS panel works either way -- it"
        warn "reports that dnsmasq is not running rather than failing."
    fi
fi

say "Done"
cat <<EOF
Next, from this directory:

  mkdir -p ~/.vpn
  uv sync
  sudo ./deploy/install.sh
  uv run flask --app app set-password >> ~/.vpn/webapp.env
  sudo systemctl enable --now vpn-connect

See README.md for what install.sh asks you and why.
EOF
