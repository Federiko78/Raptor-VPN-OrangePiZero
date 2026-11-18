#!/bin/sh
# Raptor VPN - accesso di servizio: indirizzo IP di recupero + Wi-Fi che annuncia l'IP.
#
#   sh install_access.sh                          chiede cosa fare (sessione SSH interattiva)
#   sh install_access.sh --recovery-ip IP         IP di recupero 169.254.X.Y scelto da te
#   sh install_access.sh --recovery-ip random     ne genera uno casuale
#   sh install_access.sh --recovery-ip none       toglie l'IP di recupero
#   sh install_access.sh --ap on|off              attiva / disattiva il Wi-Fi che annuncia l'IP
#
# Richiede il pannello gia' installato (install_tailscale_panel.sh). Si puo' rilanciare:
# senza opzioni, in modo non interattivo, conserva l'IP di recupero esistente.
# Le configurazioni stanno SOLO sulla scheda (/etc/raptor-recovery.conf, /etc/raptor-ap.conf).
set -eu
export LC_ALL=C

say() { printf '\n== %s ==\n' "$*"; }
die() { printf '\nERRORE: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die 'Eseguire come root: sh ./install_access.sh'
BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
NET_HELPER=/usr/local/libexec/tailscale-panel-net-helper
RECOVERY_CONF=/etc/raptor-recovery.conf
AP_BIN=/usr/local/libexec/raptor-ap
AP_CONF=/etc/raptor-ap.conf
AP_UNIT=/etc/systemd/system/raptor-ap.service

RECOVERY=""
AP=""
while [ $# -gt 0 ]; do
  case "$1" in
    --recovery-ip) [ $# -ge 2 ] || die '--recovery-ip richiede un valore'; RECOVERY=$2; shift 2 ;;
    --ap) [ $# -ge 2 ] || die '--ap richiede on oppure off'; AP=$2; shift 2 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) die "Argomento sconosciuto: $1" ;;
  esac
done
case "$AP" in ''|on|off) ;; *) die '--ap: usare on oppure off' ;; esac

[ -x "$NET_HELPER" ] || die 'Pannello non installato: eseguire prima install_tailscale_panel.sh'

# ---------------------------------------------------------------------------
say 'Indirizzo IP di recupero'
CURRENT=""
if [ -r "$RECOVERY_CONF" ]; then
  CURRENT=$(sed -n 's/^RECOVERY_IP=//p' "$RECOVERY_CONF" | head -n 1)
fi
if [ -z "$RECOVERY" ]; then
  if [ -t 0 ]; then
    cat <<'TEXT'
Serve a rientrare nella scheda anche se non conosci piu' il suo IP, se la rete e' stata
configurata male o se Tailscale e' spento: la scheda risponde SEMPRE anche a un indirizzo
tutto tuo, della forma 169.254.X.Y (X e Y da 1 a 254), sulla stessa rete locale.
Non e' una porta aperta senza password: il pannello chiede sempre la password.
Scegli un valore che solo tu conosci (es. 169.254.77.12). Funziona solo se il tuo PC e'
collegato alla stessa LAN della scheda (stesso switch/router), non da Internet.
TEXT
    if [ -n "$CURRENT" ]; then
      printf 'Indirizzo attuale: %s\nNuovo IP, "random", "none" oppure INVIO per tenerlo: ' "$CURRENT"
    else
      printf 'IP di recupero (INVIO = ne genero uno casuale, "none" = nessuno): '
    fi
    IFS= read -r RECOVERY || die 'Impossibile leggere la scelta dal terminale'
    if [ -z "$RECOVERY" ]; then
      if [ -n "$CURRENT" ]; then RECOVERY=keep; else RECOVERY=random; fi
    fi
  elif [ -n "$CURRENT" ]; then
    RECOVERY=keep
  else
    RECOVERY=random
  fi
fi

RIP="$CURRENT"
if [ "$RECOVERY" = keep ]; then
  echo "IP di recupero: invariato (${CURRENT:-non configurato})."
else
  OUT=$("$NET_HELPER" --set-recovery "$RECOVERY" 2>&1) || die "IP di recupero non impostato: $OUT"
  RIP=$(printf '%s' "$OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("recovery_ip") or "")') \
    || die "Risposta inattesa dall'helper di rete: $OUT"
fi

if [ -n "$RIP" ]; then
  cat <<TEXT

  +--------------------------------------------------------------+
    INDIRIZZO DI RECUPERO:  $RIP
    Annotalo in un posto sicuro. NON compare nel pannello e non
    e' nel repository: sta solo in $RECOVERY_CONF.
  +--------------------------------------------------------------+
  Per usarlo dal PC Windows (stessa LAN della scheda), come amministratore:
      powershell -ExecutionPolicy Bypass -File recupero_windows.ps1 $RIP
  e si apre https://$RIP:8443 (accetta l'avviso del certificato; serve la password).
TEXT
else
  echo 'IP di recupero: non configurato.'
fi

# ---------------------------------------------------------------------------
say 'Wi-Fi che annuncia l’indirizzo IP (Raptor VPN - <IP>)'
if [ -z "$AP" ]; then
  if [ -t 0 ]; then
    cat <<'TEXT'
Dopo ogni avvio la scheda apre per circa 1 minuto una rete Wi-Fi chiamata "Raptor VPN - <IP>"
(non e' collegabile: serve solo a leggere l'IP dal telefono). Chiunque sia nel raggio Wi-Fi
puo' leggere quell'IP durante il minuto: se non vuoi, rispondi n.
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
DURATION=60    # secondi di vita della rete (20-300)
CHANNEL=6      # canale 1-11
IFACE=wlan0
WAIT_IP=90     # secondi massimi di attesa dell'IP prima di annunciare "nessun IP"
EOF
    chmod 0644 "$AP_CONF"
  fi
  cat > "$AP_UNIT" <<EOF
[Unit]
Description=Raptor VPN - Wi-Fi temporaneo che annuncia l'indirizzo IP
After=systemd-networkd.service

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
  systemctl daemon-reload
  systemctl enable raptor-ap.service >/dev/null 2>&1 || die 'Impossibile abilitare raptor-ap.service'
  systemctl restart --no-block raptor-ap.service || true
  echo 'Wi-Fi annuncio-IP installato: parte ad ogni avvio, dopo il DHCP, per circa 1 minuto.'
  echo 'Prova subito: sul telefono cerca la rete "Raptor VPN - <IP>" (per ~1 minuto).'
  echo 'Se la scheda si bloccasse con il Wi-Fi attivo: ENABLED=0 in /etc/raptor-ap.conf.'
elif [ "$AP" = off ]; then
  if [ -e "$AP_UNIT" ]; then
    systemctl disable --now raptor-ap.service >/dev/null 2>&1 || true
    echo 'Wi-Fi annuncio-IP disattivato (il servizio resta installato, spento).'
  else
    echo 'Wi-Fi annuncio-IP: non installato.'
  fi
fi
printf '\nFatto.\n'
