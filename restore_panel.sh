#!/bin/sh
# Best-effort restore after failed panel update. Does NOT edit VPN credentials,
# DHCP/Netplan, root passwords, or root-owned firewall policies.
set -eu
[ "$(id -u)" -eq 0 ] || exit 1
DIR=${1:-}
case "$DIR" in /var/backups/tailscale-panel/*) ;; *) echo 'Percorso di backup non valido' >&2; exit 1;; esac
[ -f "$DIR/existing.txt" ] && [ -f "$DIR/paths.txt" ] && [ -f "$DIR/previous.tar" ] || exit 1
while IFS= read -r path; do
  if ! grep -Fxq -- "$path" "$DIR/existing.txt"; then
    # Only paths in the fixed root-generated manifest are eligible.
    rm -f -- "/$path"
  fi
done < "$DIR/paths.txt"
tar -C / -xf "$DIR/previous.tar"
systemctl daemon-reload || true
# If an old panel was present, reactivate it; otherwise leave Tailscale alone.
if grep -Fxq 'etc/systemd/system/tailscale-panel.service' "$DIR/existing.txt"; then
  systemctl enable --now tailscale-panel.socket 2>/dev/null || true
  systemctl restart tailscale-panel.service 2>/dev/null || true
else
  systemctl disable --now tailscale-panel.service tailscale-panel.socket 2>/dev/null || true
fi
# Guard chains are deliberately left in fail-closed mode; never open forwarding
# automatically while an installer reports a failure.
echo "Rollback dei file del pannello tentato da $DIR" >&2
