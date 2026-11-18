#!/bin/sh
# Read-only checks. No credentials, keys, peer list or Tailscale identity are printed.
set -u
ok=1
FRESH=false
if [ "${1:-}" = --fresh ]; then FRESH=true; fi
line() { printf '%-42s %s\n' "$1" "$2"; }
expect_active() {
  name=$1
  status=$(timeout 10 systemctl is-active "$name" 2>/dev/null || true)
  if [ "$status" = active ]; then line "$name" 'OK (active)'; else line "$name" "ERRORE ($status)"; ok=0; fi
}
line '===== FACTORY CHECK =====' ''
if python3 -c 'import sys; sys.path.insert(0, "/opt/tailscale-panel"); from password_policy import password_error; assert password_error("Abcdefg1") is None; assert password_error("abcdefg1") is not None; assert password_error("Abcdefgh") is not None' 2>/dev/null; then
  line 'Regole password v1.5.0' 'OK (8-128, maiuscola/minuscola/numero)'
else
  line 'Regole password v1.5.0' 'ERRORE: modulo non presente o policy incoerente'; ok=0
fi
line 'OS' "$(grep '^PRETTY_NAME=' /etc/os-release | cut -d= -f2- | tr -d '"')"
line 'Architettura' "$(dpkg --print-architecture)"
line 'Kernel' "$(uname -r)"
expect_active tailscaled.service
expect_active tailscale-panel.socket
expect_active tailscale-panel.service
expect_active tailscale-panel-route-guard.service
expect_active avahi-daemon.service
if [ "$(systemctl is-enabled tailscale-panel-net-recovery.service 2>/dev/null || true)" = enabled ]; then
  line 'Recovery Ethernet a riavvio' 'OK (enabled)'
else
  line 'Recovery Ethernet a riavvio' 'ERRORE (not enabled)'; ok=0
fi
if [ "$(systemctl show tailscale-panel.service -p ReadWritePaths --value 2>/dev/null)" = /etc/tailscale-panel ]; then
  line 'Fix cambio password' 'OK'
else
  line 'Fix cambio password' 'ERRORE: ReadWritePaths non impostato'; ok=0
fi
if [ -s /etc/tailscale-panel/auth.json ] && \
   [ "$(stat -c '%a' /etc/tailscale-panel/auth.json 2>/dev/null)" = 600 ]; then
  line 'Password Web UI' 'OK (hash salvato, permessi 600)'
else
  line 'Password Web UI' 'ERRORE: credenziali assenti o permessi da correggere'; ok=0
fi
if [ -f /etc/tailscale-panel-lan.conf ] && [ ! -L /etc/tailscale-panel-lan.conf ] && \
   [ "$(stat -c '%U:%G' /etc/tailscale-panel-lan.conf 2>/dev/null)" = root:root ] && \
   grep -Fq "INTERFACE_FILE = '/etc/tailscale-panel-lan.conf'" /usr/local/libexec/tailscale-panel-discovery 2>/dev/null && \
   grep -Fq "INTERFACE_FILE = '/etc/tailscale-panel-lan.conf'" /usr/local/libexec/tailscale-panel-helper 2>/dev/null; then
  line 'Scanner LAN: interfaccia configurata' 'OK'
else
  line 'Scanner LAN: interfaccia configurata' 'ERRORE: configurazione non coerente'; ok=0
fi
if command -v arp-scan >/dev/null 2>&1 && [ -x /usr/local/libexec/tailscale-panel-discovery ]; then
  line 'Scanner LAN (arp-scan)' 'OK'
else
  line 'Scanner LAN (arp-scan)' 'ERRORE'; ok=0
fi
if /usr/sbin/iptables -t mangle -S FORWARD 2>/dev/null | grep -Eq -- '-i tailscale0 -o end0 -j TSPANEL_M_[AB]'; then
  line 'IPv4 mangle/forward pre-Tailscale' 'OK (regola presente)'
else
  line 'IPv4 mangle/forward pre-Tailscale' 'ERRORE (filtro assente)'; ok=0
fi
if /usr/sbin/ip6tables -t mangle -C FORWARD -i tailscale0 -o end0 -j DROP 2>/dev/null; then
  line 'Blocco IPv6 Tailscale -> LAN' 'OK'
else
  line 'Blocco IPv6 Tailscale -> LAN' 'ERRORE (filtro assente)'; ok=0
fi
if [ -r /var/lib/tailscale-panel-guard/policy.json ]; then
  if python3 -c 'import json; d=json.load(open("/var/lib/tailscale-panel-guard/policy.json")); assert d.get("mode") in ("off", "selected", "all")' 2>/dev/null; then
    line 'Policy persistente' 'OK'
  else
    line 'Policy persistente' 'ERRORE (policy non valida)'; ok=0
  fi
fi
if [ "$FRESH" = true ]; then
  if python3 - <<'CHECK_INITIAL'
import json
p='/var/lib/tailscale-panel-guard/policy.json'
d=json.load(open(p,encoding='utf8'))
assert d == {'mode':'off','subnets':'','selected_hosts':[]}, d
CHECK_INITIAL
  then
    line 'Policy Factory iniziale' 'OK (LAN OFF, zero host)'
  else
    line 'Policy Factory iniziale' 'ERRORE (non pulita)'; ok=0
  fi
  # The deny rule must be the default verdict in the active panel chain.
  ACTIVE=$(iptables -t mangle -S FORWARD 2>/dev/null | sed -n 's/.*-i tailscale0 -o end0 -j \(TSPANEL_M_[AB]\).*/\1/p' | head -1)
  if [ -n "$ACTIVE" ] && iptables -t mangle -S "$ACTIVE" 2>/dev/null | grep -Fqx -- "-A $ACTIVE -j DROP"; then
    line 'Mangle Factory fail-closed' 'OK (DROP di default)'
  else
    line 'Mangle Factory fail-closed' 'ERRORE'; ok=0
  fi
fi
if [ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" = 1 ]; then
  line 'IP forwarding IPv4' 'OK'
else
  line 'IP forwarding IPv4' 'ERRORE: disabilitato'; ok=0
fi
line 'Spazio root libero (MiB)' "$(df -Pm / | awk 'NR==2 {print $4}')"
LAN_IP=$(ip -4 -o addr show dev end0 scope global 2>/dev/null | awk 'NR==1 {split($4,a,"/"); print a[1]}')
line 'IP attuale end0' "${LAN_IP:-non assegnato}"
if [ -n "$LAN_IP" ]; then
  STATUS=$(curl --noproxy '*' -sk --connect-timeout 5 --max-time 8 -o /dev/null -w '%{http_code}' "https://$LAN_IP:8443/login" 2>/dev/null || true)
  if [ "$STATUS" = 200 ]; then
    line 'HTTPS /login su Ethernet' 'OK (200)'
  else
    line 'HTTPS /login su Ethernet' "ERRORE (${STATUS:-senza risposta})"; ok=0
  fi
fi
if command -v runuser >/dev/null 2>&1 && [ -x /usr/local/libexec/tailscale-panel-net-helper ]; then
  NET=$(printf '{"action":"status"}' | timeout 12 runuser -u tspanel -- sudo -n /usr/local/libexec/tailscale-panel-net-helper 2>/dev/null || true)
  if printf '%s' "$NET" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(not d.get("ok"))' 2>/dev/null; then
    line 'Netplan helper / sudo' 'OK'
    if printf '%s' "$NET" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(not d["network"].get("supported"))' 2>/dev/null; then
      line 'DHCP/IP statico da GUI' 'Supportato'
    else
      line 'DHCP/IP statico da GUI' 'DA VERIFICARE: file Netplan diversi dal profilo previsto'
    fi
  else
    line 'Netplan helper / sudo' 'ERRORE'; ok=0
  fi
fi
printf '\n'
if [ "$ok" = 1 ]; then
  echo 'VERIFICA FACTORY COMPLETATA (controlli essenziali OK).'
  exit 0
else
  echo 'VERIFICA FACTORY: presenti errori; esaminare prima di mettere in produzione.'
  exit 1
fi
