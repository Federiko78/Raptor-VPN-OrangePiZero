#!/bin/sh
# Snapshot only software/service files; never copy credentials or Tailscale identity.
set -eu
[ "$(id -u)" -eq 0 ] || exit 1
ROOT=/var/backups/tailscale-panel
install -d -m 0700 "$ROOT"
NAME=$(date -u +%Y%m%dT%H%M%SZ)-$$
DIR="$ROOT/$NAME"
install -d -m 0700 "$DIR"
cat > "$DIR/paths.txt" <<'EOF'
opt/tailscale-panel/tailscale_panel.py
opt/tailscale-panel/password_policy.py
opt/tailscale-panel/panel_assets.py
opt/tailscale-panel/panel_i18n.py
opt/tailscale-panel/i18n/en.json
opt/tailscale-panel/i18n/it.json
usr/local/libexec/tailscale-panel-helper
usr/local/libexec/tailscale-panel-net-helper
usr/local/libexec/tailscale-panel-discovery
usr/local/libexec/tailscale-panel-auth
etc/systemd/system/tailscale-panel.service
etc/systemd/system/tailscale-panel.socket
etc/systemd/system/tailscale-panel-net-recovery.service
etc/systemd/system/tailscale-panel-route-guard.service
etc/systemd/system/tailscaled.service.d/20-tspanel-guard.conf
etc/sudoers.d/tailscale-panel
etc/tailscale-panel-lan.conf
etc/sysctl.d/99-tailscale-panel.conf
etc/avahi/services/tailscale-panel.service
EOF
: > "$DIR/existing.txt"
while IFS= read -r path; do
  if [ -f "/$path" ]; then printf '%s\n' "$path" >> "$DIR/existing.txt"; fi
done < "$DIR/paths.txt"
tar -C / -cf "$DIR/previous.tar" -T "$DIR/existing.txt"
chmod 0600 "$DIR"/*.txt "$DIR/previous.tar"
printf '%s\n' "$DIR"
