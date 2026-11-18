#!/bin/sh
# Raptor VPN - accesso di servizio: Wi-Fi che annuncia l'IP della scheda.
#
#   sh install_access.sh                          chiede cosa fare (sessione SSH interattiva)
#   sh install_access.sh --ap on|off              attiva / disattiva il Wi-Fi che annuncia l'IP
#
# Richiede il pannello gia' installato (install_tailscale_panel.sh). Si puo' rilanciare.
# La configurazione sta SOLO sulla scheda (/etc/raptor-ap.conf).
set -eu
export LC_ALL=C

say() { printf '\n== %s ==\n' "$*"; }
die() { printf '\nERRORE: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die 'Eseguire come root: sh ./install_access.sh'
BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
NET_HELPER=/usr/local/libexec/tailscale-panel-net-helper
AP_BIN=/usr/local/libexec/raptor-ap
AP_CONF=/etc/raptor-ap.conf
AP_UNIT=/etc/systemd/system/raptor-ap.service

AP=""
while [ $# -gt 0 ]; do
  case "$1" in
    --ap) [ $# -ge 2 ] || die '--ap richiede on oppure off'; AP=$2; shift 2 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) die "Argomento sconosciuto: $1" ;;
  esac
done
case "$AP" in ''|on|off) ;; *) die '--ap: usare on oppure off' ;; esac

[ -x "$NET_HELPER" ] || die 'Pannello non installato: eseguire prima install_tailscale_panel.sh'

# ---------------------------------------------------------------------------
say 'Wi-Fi che annuncia l’indirizzo IP (Raptor VPN - <IP>)'
if [ -z "$AP" ]; then
  if [ -t 0 ]; then
    cat <<'TEXT'
Dopo ogni avvio la scheda apre per circa 3 minuti una rete Wi-Fi chiamata "Raptor VPN - <IP>"
(non e' collegabile: serve solo a leggere l'IP dal telefono). Chiunque sia nel raggio Wi-Fi
puo' leggere quell'IP in quei minuti: se non vuoi, rispondi n.
TEXT
    printf 'Attivare il Wi-Fi che annuncia l’IP? [S/n]: '
    IFS= read -r ANSWER || die 'Impossibile leggere la scelta dal terminale'
    case "$ANSWER" in ''|s|S|si|SI|Si|y|Y|yes) AP=on ;; n|N|no|NO|No) AP=off ;; *) die 'Risposta non riconosciuta' ;; esac
  else
    AP=on
  fi
fi

if [ "$AP" = on ]; then
  [ -s "$BASE/raptor_ap.py" ] || die 'File mancante nel pacchetto: raptor_ap.py'
  python3 - "$BASE/raptor_ap.py" <<'PYCOMPILE' || die 'Errore di sintassi in raptor_ap.py'
import ast, sys
with open(sys.argv[1], encoding='utf-8') as fd:
    ast.parse(fd.read(), filename=sys.argv[1])
PYCOMPILE
  [ -e /sys/class/net/wlan0 ] || echo 'AVVISO: wlan0 non presente ora (driver non caricato?): il servizio verra'"'"' installato comunque.' >&2
  if ! command -v hostapd >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends hostapd rfkill || die 'Installazione hostapd non riuscita'
  fi
  # Il servizio standard di Debian resta spento: usiamo hostapd solo tramite raptor-ap.service.
  systemctl mask hostapd.service >/dev/null 2>&1 || true
  install -d -m 0755 -o root -g root /usr/local/libexec
  install -m 0755 -o root -g root "$BASE/raptor_ap.py" "$AP_BIN"
  if [ ! -e "$AP_CONF" ]; then
    cat > "$AP_CONF" <<'EOF'
# Raptor VPN - Wi-Fi che annuncia l'IP. Modifica e poi: systemctl restart raptor-ap
ENABLED=1      # 0 = mai
DURATION=180   # secondi di vita della rete (20-300)
CHANNEL=6      # canale 1-11
IFACE=wlan0
WAIT_IP=90     # secondi massimi di attesa dell'IP prima di annunciare "nessun IP"
EOF
    chmod 0644 "$AP_CONF"
  fi
  # Mai scrivere "attraverso" una unit mascherata (collegamento a /dev/null) o rimasta vuota:
  # la si toglie prima e si ricrea da zero.
  systemctl unmask raptor-ap.service >/dev/null 2>&1 || true
  rm -f "$AP_UNIT"
  cat > "$AP_UNIT" <<EOF
[Unit]
Description=Raptor VPN - Wi-Fi temporaneo che annuncia l'indirizzo IP
After=systemd-networkd.service wpa_supplicant.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 $AP_BIN
RuntimeDirectory=raptor-ap
RuntimeDirectoryMode=0700
TimeoutStopSec=20
Restart=no
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectControlGroups=yes

[Install]
WantedBy=multi-user.target
EOF
  chmod 0644 "$AP_UNIT"
  [ -s "$AP_UNIT" ] && [ ! -L "$AP_UNIT" ] || die "Unit $AP_UNIT non scritta correttamente"
  systemctl daemon-reload
  systemctl enable raptor-ap.service >/dev/null 2>&1 || die 'Impossibile abilitare raptor-ap.service'
  [ "$(systemctl is-enabled raptor-ap.service 2>/dev/null || true)" = enabled ] || die 'raptor-ap.service non risulta abilitato (mascherato?): controllare systemctl status raptor-ap'
  systemctl restart --no-block raptor-ap.service || true
  echo 'Wi-Fi annuncio-IP installato: parte ad ogni avvio, dopo il DHCP, per circa 3 minuti.'
  echo 'Prova subito: sul telefono cerca la rete "Raptor VPN - <IP>" (per ~3 minuti).'
  echo 'Se la scheda si bloccasse con il Wi-Fi attivo: ENABLED=0 in /etc/raptor-ap.conf.'
elif [ "$AP" = off ]; then
  if [ -e "$AP_UNIT" ]; then
    systemctl disable --now raptor-ap.service >/dev/null 2>&1 || true
    echo 'Wi-Fi annuncio-IP disattivato (il servizio resta installato, spento).'
  else
    echo 'Wi-Fi annuncio-IP: non installato.'
  fi
fi
# Scrive tutto sulla microSD: se si stacca l'alimentazione subito dopo, i file non restano vuoti.
sync
printf '\nFatto.\n'
