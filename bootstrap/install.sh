#!/usr/bin/env bash
# One-command AlterChat bootstrap node installer for Linux servers (systemd).
#
#   curl -fsSL https://raw.githubusercontent.com/onurbaydas/AlterChat/main/bootstrap/install.sh | sudo bash
#
# What it does:
#   1. Installs the alterchat-bootstrap binary to /usr/local/bin
#      (prebuilt release binary, verified with SHA256SUMS; falls back to
#      building from source with cargo if no release asset exists).
#   2. Creates a locked-down system user and /var/lib/alterchat-bootstrap.
#   3. Installs and starts a hardened systemd service.
#   4. Prints the multiaddr to share with AlterChat users.
#
# Environment overrides: ALTERCHAT_BOOTSTRAP_PORT (default 4001), ALTERCHAT_REPO,
# ALTERCHAT_PUBLIC_IP (auto-detected if unset).
set -euo pipefail

REPO="${ALTERCHAT_REPO:-onurbaydas/AlterChat}"
PORT="${ALTERCHAT_BOOTSTRAP_PORT:-4001}"
BIN=/usr/local/bin/alterchat-bootstrap
DATA=/var/lib/alterchat-bootstrap
UNIT=/etc/systemd/system/alterchat-bootstrap.service

log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
command -v systemctl >/dev/null || die "systemd is required"
command -v curl >/dev/null || die "curl is required"

arch="$(uname -m)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

install_prebuilt() {
    [ "$arch" = "x86_64" ] || return 1
    local base="https://github.com/${REPO}/releases/latest/download"
    log "Downloading prebuilt binary from the latest release"
    curl -fsSL "$base/alterchat-bootstrap-linux-x86_64" -o "$tmp/alterchat-bootstrap-linux-x86_64" || return 1
    curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS" || return 1
    (cd "$tmp" && grep ' alterchat-bootstrap-linux-x86_64$' SHA256SUMS | sha256sum -c -) || die "checksum mismatch"
    install -m 0755 "$tmp/alterchat-bootstrap-linux-x86_64" "$BIN"
}

install_from_source() {
    log "No prebuilt binary available; building from source (takes a few minutes)"
    command -v git >/dev/null || die "git is required to build from source"
    if ! command -v cargo >/dev/null; then
        log "Installing a Rust toolchain (rustup, minimal profile)"
        curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal
        # shellcheck disable=SC1091
        . "$HOME/.cargo/env"
    fi
    git clone --depth 1 "https://github.com/${REPO}.git" "$tmp/src"
    (cd "$tmp/src" && cargo build --release -p alterchat-bootstrap)
    install -m 0755 "$tmp/src/target/release/alterchat-bootstrap" "$BIN"
}

install_prebuilt || install_from_source

log "Creating service user and data directory"
id alterchat >/dev/null 2>&1 || useradd --system --home "$DATA" --shell /usr/sbin/nologin alterchat
install -d -m 0700 -o alterchat -g alterchat "$DATA"

# Public address of this server. Cloud VMs usually sit behind 1:1 NAT, so the
# node cannot see its own public IP; without it the relay cannot hand out
# usable reservations.
PUBLIC_IP="${ALTERCHAT_PUBLIC_IP:-$(curl -fsS4 --max-time 5 https://api.ipify.org 2>/dev/null || true)}"
EXTERNAL_ADDRS=""
if [ -n "$PUBLIC_IP" ]; then
    EXTERNAL_ADDRS="/ip4/${PUBLIC_IP}/tcp/${PORT},/ip4/${PUBLIC_IP}/udp/${PORT}/quic-v1"
    log "Public address: ${PUBLIC_IP}"
else
    log "Could not detect the public IP; set ALTERCHAT_PUBLIC_IP and re-run for relay support"
fi

log "Installing systemd service"
cat > "$UNIT" <<EOF
[Unit]
Description=AlterChat bootstrap node
After=network-online.target
Wants=network-online.target

[Service]
User=alterchat
Group=alterchat
Environment=ALTERCHAT_DATA_DIR=${DATA}
Environment=ALTERCHAT_BOOTSTRAP_PORT=${PORT}
Environment=ALTERCHAT_EXTERNAL_ADDRS=${EXTERNAL_ADDRS}
Environment=RUST_LOG=info
ExecStart=${BIN}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=${DATA}
CapabilityBoundingSet=
AmbientCapabilities=
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now alterchat-bootstrap

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    log "Opening port ${PORT}/tcp and ${PORT}/udp in ufw"
    ufw allow "${PORT}/tcp" >/dev/null
    ufw allow "${PORT}/udp" >/dev/null
fi

log "Waiting for the node to start"
peer=""
for _ in $(seq 1 20); do
    peer="$(journalctl -u alterchat-bootstrap --no-pager -o cat 2>/dev/null | sed -n 's/^Bootstrap node id: //p' | tail -1)"
    [ -n "$peer" ] && break
    sleep 1
done
[ -n "$peer" ] || die "service did not start; check: journalctl -u alterchat-bootstrap"

ip="${PUBLIC_IP:-$(hostname -I | awk '{print $1}')}"
echo
log "AlterChat bootstrap node is running."
echo "Share this address with AlterChat users (Settings -> Network -> Bootstrap list):"
echo
echo "    /ip4/${ip}/tcp/${PORT}/p2p/${peer}"
echo "    /ip4/${ip}/udp/${PORT}/quic-v1/p2p/${peer}"
echo
echo "Make sure ${PORT}/tcp and ${PORT}/udp are open in your cloud provider's firewall."
