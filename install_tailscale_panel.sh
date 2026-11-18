#!/bin/sh
# Tailscale Control Panel - installer Debian/Orange Pi Zero (run as root)
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "ERRORE: usare sudo sh ./install_tailscale_panel.sh" >&2
  exit 1
fi

DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
APP=/opt/tailscale-panel
CONFIG=/etc/tailscale-panel
DATA=/var/lib/tailscale-panel
HELPER=/usr/local/libexec/tailscale-panel-helper
NET_HELPER=/usr/local/libexec/tailscale-panel-net-helper
DISCOVERY_HELPER=/usr/local/libexec/tailscale-panel-discovery
PORT=${PORT:-8443}
case "$PORT" in
  ''|*[!0-9]*) echo "PORT deve essere un numero" >&2; exit 1;;
esac
if [ "$PORT" -lt 1024 ] || [ "$PORT" -gt 65535 ]; then
  echo "Scegliere una porta TCP fra 1024 e 65535" >&2; exit 1
fi
for src in tailscale_panel.py tailscale_panel_helper.py tailscale_panel_network.py tailscale_panel_discovery.py password_policy.py; do
  if [ ! -r "$DIR/$src" ]; then
    echo "Manca il file $DIR/$src: trasferire tutti i file nella stessa cartella." >&2
    exit 1
  fi
done
if ! command -v systemctl >/dev/null 2>&1; then
  echo "ERRORE: questo installer richiede Debian con systemd." >&2; exit 1
fi

printf '\n== ORANGE PI ZERO / FACTORY R1.3.2 - WEB UI 1.5.0 ==\n'
printf 'Kernel: '; uname -r
printf 'Architettura: '; uname -m
if [ -r /etc/os-release ]; then . /etc/os-release; echo "Sistema: ${PRETTY_NAME:-Linux}"; fi

# With a 2GB microSD, never run apt update unless a required command is missing.
MISSING_PKGS=''
for item in python3:python3 sudo:sudo openssl:openssl ip:iproute2 curl:curl; do
  binary=${item%%:*}
  package=${item#*:}
  if ! command -v "$binary" >/dev/null 2>&1; then
    MISSING_PKGS="$MISSING_PKGS $package"
  fi
done
if [ -n "$MISSING_PKGS" ]; then
  echo "== Installazione sole dipendenze mancanti: $MISSING_PKGS =="
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y $MISSING_PKGS ca-certificates
else
  echo '== Dipendenze presenti: nessun aggiornamento apt necessario =='
fi
if ! python3 -c 'import sys; assert sys.version_info >= (3,7)' ; then
  echo "ERRORE: Python 3.7 o superiore necessario." >&2; exit 1
fi

if ! timeout 12 systemctl list-units --type=service --no-pager >/dev/null 2>&1; then
  echo 'ERRORE: systemd non risponde. Non installo servizi sul sistema instabile.' >&2
  exit 1
fi

if [ ! -c /dev/net/tun ]; then
  echo "== Verifica interfaccia TUN =="
  modprobe tun 2>/dev/null || true
fi
if [ ! -c /dev/net/tun ]; then
  echo "ERRORE: /dev/net/tun assente. Il kernel deve supportare TUN/TAP per il subnet router." >&2
  echo "Controllare prima kernel/moduli: non modifico il sistema." >&2
  exit 1
fi

if ! command -v tailscale >/dev/null 2>&1; then
  echo "== Installazione Tailscale dal sito ufficiale =="
  TMP=$(mktemp)
  trap 'rm -f "$TMP"' EXIT HUP INT TERM
  curl -fsSL https://tailscale.com/install.sh -o "$TMP"
  sh "$TMP"
  rm -f "$TMP"
  trap - EXIT HUP INT TERM
fi
if [ ! -x /usr/bin/tailscale ]; then
  echo "ERRORE: /usr/bin/tailscale non trovato." >&2; exit 1
fi
if ! systemctl is-active --quiet tailscaled; then
  systemctl enable --now tailscaled
else
  echo "== Tailscale gia attivo: configurazione esistente preservata =="
fi

if ! id tspanel >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin tspanel
fi
install -d -m 755 -o root -g root "$APP" /usr/local/libexec
install -d -m 750 -o tspanel -g tspanel "$CONFIG" "$DATA"

# Preserve previous working source if this is an update.
if [ -r "$APP/tailscale_panel.py" ]; then
  cp -p "$APP/tailscale_panel.py" "$APP/tailscale_panel.py.bak-$(date +%Y%m%d-%H%M%S)"
fi
install -m 644 -o root -g root "$DIR/tailscale_panel.py" "$APP/tailscale_panel.py"
install -m 644 -o root -g root "$DIR/password_policy.py" "$APP/password_policy.py"
install -m 755 -o root -g root "$DIR/tailscale_panel_helper.py" "$HELPER"
install -m 755 -o root -g root "$DIR/tailscale_panel_network.py" "$NET_HELPER"
install -m 755 -o root -g root "$DIR/tailscale_panel_discovery.py" "$DISCOVERY_HELPER"

# Exact command permitted; no arbitrary root commands or arguments.
cat > /etc/sudoers.d/tailscale-panel <<'EOF'
tspanel ALL=(root) NOPASSWD: /usr/local/libexec/tailscale-panel-helper "", /usr/local/libexec/tailscale-panel-net-helper "", /usr/local/libexec/tailscale-panel-discovery ""
EOF
chmod 0440 /etc/sudoers.d/tailscale-panel
if ! visudo -cf /etc/sudoers.d/tailscale-panel >/dev/null; then
  rm -f /etc/sudoers.d/tailscale-panel
  echo "ERRORE: regola sudoers non valida." >&2; exit 1
fi

# Determine Ethernet device once; systemd binds socket to *interface* not IP.
# Orange Pi Zero uses end0; do not mistakenly choose tailscale0 when a VPN
# exit route changes the system default route.
if ip link show dev end0 >/dev/null 2>&1; then
  LAN_DEV=end0
else
  LAN_DEV=$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev" && $(i+1) ~ /^e(th|n|n[p|s])/) {print $(i+1); exit}}')
fi
if [ -z "$LAN_DEV" ] || ! ip link show dev "$LAN_DEV" >/dev/null 2>&1; then
  echo 'ERRORE: nessuna interfaccia Ethernet trovata. Non espongo il pannello sulla VPN.' >&2
  exit 1
fi
case "$LAN_DEV" in
  ''|*[!a-zA-Z0-9_.-]*) echo "ERRORE: nome interfaccia non valido: $LAN_DEV" >&2; exit 1;;
esac
LAN_IP=$(ip -4 -o addr show dev "$LAN_DEV" scope global | awk 'NR==1 {split($4,a,"/"); print a[1]}')
if [ -z "$LAN_IP" ]; then
  echo "ATTENZIONE: al momento l'interfaccia $LAN_DEV non ha un IP DHCP." >&2
fi
HOST=$(hostname -s | tr '[:upper:]' '[:lower:]')
case "$HOST" in
  ''|*[!a-z0-9-]*) HOST=orangepizero;;
esac
DNS_NAME="$HOST.local"
# The two privileged helpers use this root-owned file outside the writable
# web credential directory; the web process cannot redirect a scan to a VPN.
printf '%s\n' "$LAN_DEV" > /etc/tailscale-panel-lan.conf
chmod 0644 /etc/tailscale-panel-lan.conf
chown root:root /etc/tailscale-panel-lan.conf
install -d -m 0700 -o root -g root /var/lib/tailscale-panel-guard
printf 'LAN: interfaccia %s, IP attuale %s, nome %s\n' "$LAN_DEV" "${LAN_IP:-nessuno}" "$DNS_NAME"
if command -v netplan >/dev/null 2>&1; then
  echo '== Netplan già presente: NON modifico il DHCP della rete =='
  if ! grep -Eq 'dhcp4: *(yes|true)' /etc/netplan/*.yaml 2>/dev/null; then
    echo 'ATTENZIONE: verificare DHCP4 nel netplan corrente prima di spostare la scheda.'
  fi
fi

NEW_PASSWORD=no
if [ ! -s "$CONFIG/auth.json" ]; then
  NEW_PASSWORD=yes
  echo "== Scelta password amministratore Web UI (non visualizzata) =="
  if [ ! -t 0 ]; then
    echo 'ERRORE: installazione interattiva richiesta per impostare la password Web UI.' >&2
    echo 'Aprire una sessione SSH con terminale e rilanciare lo script.' >&2
    exit 1
  fi
  python3 "$APP/tailscale_panel.py" --configure-password
  chown tspanel:tspanel "$CONFIG/auth.json"
  chmod 600 "$CONFIG/auth.json"
fi

# Keep existing credentials. Create a stable hostname SAN (not an ephemeral LAN IP).
GENERATE_CERT=no
if [ ! -s "$CONFIG/key.pem" ] || [ ! -s "$CONFIG/cert.pem" ]; then
  GENERATE_CERT=yes
elif ! openssl x509 -in "$CONFIG/cert.pem" -noout -ext subjectAltName 2>/dev/null | grep -F "DNS:$DNS_NAME" >/dev/null 2>&1; then
  echo '== Aggiornamento certificato per il nome mDNS (salvo il precedente) =='
  cp -p "$CONFIG/cert.pem" "$CONFIG/cert.pem.bak-$(date +%Y%m%d-%H%M%S)"
  cp -p "$CONFIG/key.pem" "$CONFIG/key.pem.bak-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
  GENERATE_CERT=yes
fi
if [ "$GENERATE_CERT" = yes ]; then
  SSL_CONF=$(mktemp)
  trap 'rm -f "$SSL_CONF"' EXIT HUP INT TERM
  cat > "$SSL_CONF" <<EOF
[req]
prompt = no
distinguished_name = dn
x509_extensions = ext
[dn]
CN = $DNS_NAME
[ext]
basicConstraints = critical,CA:FALSE
keyUsage = digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:$DNS_NAME${LAN_IP:+,IP:$LAN_IP}
EOF
  openssl req -x509 -nodes -newkey rsa:2048 -sha256 -days 730 \
      -keyout "$CONFIG/key.pem" -out "$CONFIG/cert.pem" \
      -config "$SSL_CONF" >/dev/null 2>&1
  rm -f "$SSL_CONF"
  trap - EXIT HUP INT TERM
  chown tspanel:tspanel "$CONFIG/key.pem" "$CONFIG/cert.pem"
  chmod 600 "$CONFIG/key.pem"
  chmod 644 "$CONFIG/cert.pem"
fi

cat > /etc/sysctl.d/99-tailscale-panel.conf <<'EOF'
# Forward IPv4 packets for Tailscale subnet routing.
net.ipv4.ip_forward = 1
EOF
sysctl -p /etc/sysctl.d/99-tailscale-panel.conf

# Backup working systemd units before migrating to v1.5.0.
for unit in tailscale-panel.service tailscale-panel.socket tailscale-panel-route-guard.service; do
  path="/etc/systemd/system/$unit"
  if [ -f "$path" ]; then
    cp -p "$path" "$path.bak-$(date +%Y%m%d-%H%M%S)"
  fi
done

# Stop v1.1 server bound to the old IP, leaving SSH and tailscaled untouched.
systemctl stop tailscale-panel.service 2>/dev/null || true
systemctl disable tailscale-panel.service 2>/dev/null || true

# Interface-level binding survives any DHCP IP change (SO_BINDTODEVICE).
cat > /etc/systemd/system/tailscale-panel.socket <<EOF
[Unit]
Description=Tailscale Panel v1.5.0 HTTPS socket on $LAN_DEV (DHCP-independent)

[Socket]
ListenStream=0.0.0.0:$PORT
BindToDevice=$LAN_DEV
Service=tailscale-panel.service
NoDelay=true

[Install]
WantedBy=sockets.target
EOF

cat > /etc/systemd/system/tailscale-panel.service <<EOF
[Unit]
Description=Tailscale Control Panel v1.5.0 HTTPS / Orange Pi Zero
Requires=tailscale-panel.socket tailscaled.service
After=tailscale-panel.socket network.target tailscaled.service

[Service]
Type=simple
User=tspanel
Group=tspanel
WorkingDirectory=$APP
Environment=PANEL_PORT=$PORT
Environment=PANEL_LAN_DEV=$LAN_DEV
ExecStart=/usr/bin/python3 $APP/tailscale_panel.py
Restart=on-failure
RestartSec=3
UMask=0077
ProtectSystem=full
# Allow writing updated web credentials while keeping the rest of /etc read-only.
ReadWritePaths=/etc/tailscale-panel
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
# Hardening aggiuntivo. NoNewPrivileges NON va impostato: il servizio avvia gli
# helper root tramite sudo (setuid) e verrebbe bloccato. RestrictAddressFamilies
# e' omesso di proposito: arp-scan usa socket AF_PACKET.
ProtectKernelLogs=true
ProtectClock=true
ProtectHostname=true
LockPersonality=true
RestrictRealtime=true
SystemCallArchitectures=native
MemoryMax=160M
TasksMax=96

[Install]
WantedBy=multi-user.target
EOF

# Recovery at boot: if power is lost during an unconfirmed network change,
# restore the previously working Netplan files after networkd starts.
cat > /etc/systemd/system/tailscale-panel-net-recovery.service <<EOF
[Unit]
Description=Restore pending Tailscale Panel network configuration after boot
After=systemd-networkd.service
Before=tailscale-panel.service

[Service]
Type=oneshot
ExecStart=$NET_HELPER --recover
TimeoutStartSec=110

[Install]
WantedBy=multi-user.target
EOF

# Restore panel's forwarding filter BEFORE tailscaled starts on next boot.
# Use a dedicated chain; never flush client-defined firewall tables or rules.
cat > /etc/systemd/system/tailscale-panel-route-guard.service <<EOF
[Unit]
Description=Restore Tailscale Panel selective LAN access guard
DefaultDependencies=yes
Before=tailscaled.service
Wants=network-online.target
After=local-fs.target network-online.target

[Service]
Type=oneshot
ExecStart=$HELPER --restore
RemainAfterExit=yes
TimeoutStartSec=50

[Install]
WantedBy=multi-user.target
EOF
install -d -m 0755 /etc/systemd/system/tailscaled.service.d
# Preserve the user's existing tailsscaled drop-in, if any.
if [ -f /etc/systemd/system/tailscaled.service.d/20-tspanel-guard.conf ]; then
 cp -p /etc/systemd/system/tailscaled.service.d/20-tspanel-guard.conf \
   /etc/systemd/system/tailscaled.service.d/20-tspanel-guard.conf.bak-$(date +%Y%m%d-%H%M%S)
fi
cat > /etc/systemd/system/tailscaled.service.d/20-tspanel-guard.conf <<EOF
[Unit]
Requires=tailscale-panel-route-guard.service
After=tailscale-panel-route-guard.service
EOF

systemctl daemon-reload
systemctl enable tailscale-panel-route-guard.service
systemctl restart tailscale-panel-route-guard.service
systemctl enable tailscale-panel-net-recovery.service
systemctl enable --now tailscale-panel.socket
systemctl restart tailscale-panel.service
sleep 1
if ! systemctl is-active --quiet tailscale-panel.socket || \
   ! systemctl is-active --quiet tailscale-panel.service; then
  echo 'ERRORE: pannello o socket non attivo. Diagnostica:' >&2
  echo 'journalctl -u tailscale-panel.service -u tailscale-panel.socket -n 60 --no-pager' >&2
  exit 1
fi

# Avahi is optional to panel operation; it announces hostname.local on a LAN
# where mDNS is allowed. Avoid heavy upgrades on tiny SD cards.
if ! command -v avahi-daemon >/dev/null 2>&1; then
  FREE_MB=$(df -Pm / | awk 'NR==2{print $4}')
  if [ "$FREE_MB" -ge 180 ]; then
    echo '== Installazione leggera Avahi per risoluzione .local =='
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends avahi-daemon; then
      echo 'AVVISO: Avahi non installato; il pannello funziona con IP DHCP.' >&2
    fi
  else
    echo 'AVVISO: spazio insufficiente per aggiungere Avahi in sicurezza.' >&2
  fi
fi
if command -v avahi-daemon >/dev/null 2>&1; then
  systemctl enable --now avahi-daemon.service 2>/dev/null || true
  install -d -m 755 /etc/avahi/services
  cat > /etc/avahi/services/tailscale-panel.service <<EOF
<?xml version="1.0" standalone='no'?>
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<service-group>
  <name replace-wildcards="yes">Tailscale Panel su %h</name>
  <service><type>_https._tcp</type><port>$PORT</port></service>
</service-group>
EOF
  systemctl try-restart avahi-daemon.service 2>/dev/null || true
fi

echo
echo '=========================================================='
echo ' INSTALLAZIONE FACTORY v1.5.0 COMPLETATA'
echo '=========================================================='
echo "Dashboard : https://$DNS_NAME:$PORT (se mDNS disponibile)"
echo "IP DHCP   : https://${LAN_IP:-IP-ASSEGNATO}:$PORT"
echo "Socket    : BindToDevice=$LAN_DEV, nessun IP fissato nel servizio"
echo "Servizio  : tailscale-panel.service"
echo 'Accesso   : password amministratore, modificabile da GUI > Sicurezza'
if [ "$NEW_PASSWORD" = no ]; then
  echo 'Password  : mantenuta la password della precedente installazione'
fi
echo 'Tailscale : se non autenticato, eseguire sudo tailscale up'
echo 'Discovery : scanner ARP locale, IP/MAC/hostname, pubblicazione /32'
echo 'Guard     : forwarding LAN filtrato per host in modalità selettiva'
echo 'Info      : approvare le rotte su Tailscale Admin > Machines'
echo 'Rete      : DHCP e IP statico via GUI, conferma entro 150 s o tentativo rollback'
echo 'Recovery  : servizio di ripristino al riavvio abilitato'
echo 'Avviso    : certificato locale autofirmato; browser potrebbe segnalare un avviso'
echo 'Sicurezza : socket HTTPS solo su interfaccia Ethernet; non aprire porte Internet'
echo '=========================================================='
