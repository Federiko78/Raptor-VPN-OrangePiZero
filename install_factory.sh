#!/bin/sh
# Tailscale Control Panel FACTORY R1.3.2 (app 1.5.0), Orange Pi Zero, Armbian Trixie Minimal.
# Fresh installation. No auth/Tailscale state is copied from another device.
set -eu
export LC_ALL=C

say() { printf '\n== %s ==\n' "$*"; }
die() { printf '\nERRORE: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die 'Eseguire come root: sh ./install_factory.sh'
[ -t 0 ] || die 'Lanciare l’installer in una sessione SSH interattiva (TTY): verrà chiesta la password Web UI.'
BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$BASE"
command -v python3 >/dev/null 2>&1 || die 'python3 mancante: eseguire  apt-get update && apt-get install -y python3  (oppure usare bootstrap.sh)'
for f in install_tailscale_panel.sh install_access.sh raptor_ap.py tailscale_panel.py tailscale_panel_helper.py tailscale_panel_network.py tailscale_panel_discovery.py password_policy.py check_installation.sh backup_panel.sh restore_panel.sh; do
  [ -s "$f" ] || die "File mancante nel pacchetto: $f"
done
if [ -f SHA256SUMS ]; then
  say 'Verifica integrità file del pacchetto'
  sha256sum -c SHA256SUMS || die 'Verifica SHA256 non superata: file danneggiati'
fi

say 'Preflight sorgenti (senza modifiche)'
for module in tailscale_panel.py tailscale_panel_helper.py tailscale_panel_network.py tailscale_panel_discovery.py password_policy.py raptor_ap.py; do
  python3 - "$module" <<'PYCOMPILE' || die "Errore di sintassi in $module"
import ast, sys
with open(sys.argv[1], encoding='utf-8') as fd:
    ast.parse(fd.read(), filename=sys.argv[1])
PYCOMPILE
done
for script in install_factory.sh install_tailscale_panel.sh install_access.sh check_installation.sh backup_panel.sh restore_panel.sh; do
  sh -n "$script" || die "Errore sintassi Shell: $script"
done

say 'Prerequisiti Armbian Minimal / Orange Pi Zero'
[ -r /etc/os-release ] || die '/etc/os-release mancante'
. /etc/os-release
[ "${ID:-}" = debian ] && [ "${VERSION_CODENAME:-}" = trixie ] || die 'Supportato solo Debian 13 Trixie Armbian Minimal'
[ "$(dpkg --print-architecture)" = armhf ] || die 'La release Factory è stata collaudata logicamente per ARM32 armhf'
[ "$(ps -p 1 -o comm= | tr -d ' ')" = systemd ] || die 'systemd non è il processo PID 1'
command -v timeout >/dev/null 2>&1 || die 'Comando timeout non trovato'
if ! timeout 12 systemctl list-units --no-pager >/dev/null 2>&1; then
  die 'systemd non risponde; fermarsi e riparare il blocco console prima dell’installer'
fi
[ -e /sys/class/net/end0 ] || die 'Interfaccia Ethernet end0 assente'
[ -c /dev/net/tun ] || die '/dev/net/tun assente: verificare il kernel'
command -v netplan >/dev/null 2>&1 || die 'Netplan assente: immagine non corrispondente ad Armbian Minimal'
if [ "$(systemctl is-active systemd-networkd.service 2>/dev/null || true)" != active ]; then
  die 'systemd-networkd non attivo: questa GUI supporta Armbian Minimal, non NetworkManager'
fi
FREE_MB=$(df -Pm / | awk 'NR==2 {print $4}')
case "$FREE_MB" in ''|*[!0-9]*) die 'Impossibile misurare lo spazio libero';; esac
printf 'Sistema: %s\nKernel: %s\nArchitettura: %s\nSpazio libero: %s MiB\n' "${PRETTY_NAME:-Debian}" "$(uname -r)" "$(dpkg --print-architecture)" "$FREE_MB"
if [ "$FREE_MB" -lt 450 ]; then
  die 'Spazio insufficiente (<450 MiB). Usare preferibilmente una microSD da almeno 16 GB.'
fi
if [ ! -f /etc/netplan/10-dhcp-all-interfaces.yaml ]; then
  echo 'AVVISO: manca il Netplan DHCP standard Armbian. Il pannello potrebbe inibire la modifica IP per sicurezza.' >&2
fi

say 'Preflight Factory pulita: nessuna configurazione precedente da sovrascrivere'
for marker in /opt/tailscale-panel/tailscale_panel.py /etc/tailscale-panel/auth.json \
    /var/lib/tailscale-panel-guard/policy.json /var/lib/tailscale/tailscaled.state \
    /etc/systemd/system/tailscale-panel.service /etc/systemd/system/tailscale-panel.socket; do
  if [ -e "$marker" ]; then
    die "Trovata installazione/configurazione preesistente: $marker. Questa Factory è SOLO per Armbian pulito; non azzero dati o rotte attuali."
  fi
done

say 'Backup preventivo dei componenti del pannello'
BACKUP_DIR=$(sh "$BASE/backup_panel.sh") || die 'Impossibile creare backup preinstallazione'
printf 'Backup software: %s\n' "$BACKUP_DIR"

say 'Credenziali del sistema Linux / SSH'
echo 'Armbian richiede il cambio password root al primo login (password iniziale standard: 1234).'
echo 'Se hai già completato il primo accesso, NON serve cambiarla una seconda volta.'
printf 'Vuoi cambiare nuovamente la password Linux dell’utente root? [s/N]: '
IFS= read -r CONFIRM_ROOT || die 'Impossibile leggere la scelta dal terminale'
case "$CONFIRM_ROOT" in
  s|S|si|SI|Si|sI|y|Y|yes|YES)
    echo 'Inserire due volte la nuova password Linux (minimo 12, maiuscola, minuscola e numero).'
    python3 "$BASE/password_policy.py" --set-linux-root || die 'Cambio password Linux non riuscito: installazione interrotta'
    ;;
  ''|n|N|no|NO|No)
    echo 'Password Linux già gestita al primo login: non modificata.'
    ;;
  *)
    die 'Risposta non riconosciuta: nessuna password Linux modificata. Rilanciare.'
    ;;
esac
printf '\n'
echo 'Durante l’installazione verrà richiesta SEPARATAMENTE la password della Web UI (12-128 caratteri; maiuscola, minuscola e numero).'

say 'Installazione dipendenze Debian'
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl python3 sudo openssl iproute2 netplan.io avahi-daemon avahi-utils arp-scan iptables || die 'Installazione dipendenze non riuscita'

say 'Repository ufficiale Stable Tailscale per Debian Trixie'
install -d -m 0755 /usr/share/keyrings /etc/apt/sources.list.d
KEY_TMP=$(mktemp)
LIST_TMP=$(mktemp)
trap 'rm -f "$KEY_TMP" "$LIST_TMP"' EXIT HUP INT TERM
curl --fail --silent --show-error --location --retry 2 --max-time 45 \
  https://pkgs.tailscale.com/stable/debian/trixie.noarmor.gpg -o "$KEY_TMP" || die 'Download chiave repository non riuscito'
curl --fail --silent --show-error --location --retry 2 --max-time 45 \
  https://pkgs.tailscale.com/stable/debian/trixie.tailscale-keyring.list -o "$LIST_TMP" || die 'Download sorgente repository non riuscito'
[ -s "$KEY_TMP" ] && [ -s "$LIST_TMP" ] || die 'File repository vuoti'
if ! grep -q 'pkgs.tailscale.com/stable/debian' "$LIST_TMP"; then
  die 'Lista repository ricevuta inattesa'
fi
install -m 0644 "$KEY_TMP" /usr/share/keyrings/tailscale-archive-keyring.gpg
install -m 0644 "$LIST_TMP" /etc/apt/sources.list.d/tailscale.list
rm -f "$KEY_TMP" "$LIST_TMP"
trap - EXIT HUP INT TERM
apt-get update
if command -v tailscale >/dev/null 2>&1; then
  echo 'Tailscale già presente: conservo la versione installata e l’identità VPN.'
else
  apt-get install -y --no-install-recommends tailscale || die 'Installazione Tailscale non riuscita'
fi
# Only enable here: the web installer applies the fail-closed mangle guard
# and systemd ordering BEFORE any service can start tailscaled.
timeout 20 systemctl enable tailscaled.service || die 'Non riesco ad abilitare tailscaled'

say 'Verifica disponibilità filtri mangle IPv4 e IPv6'
command -v iptables >/dev/null 2>&1 && command -v ip6tables >/dev/null 2>&1 || die 'iptables/ip6tables non disponibili'
timeout 12 iptables -t mangle -S FORWARD >/dev/null || die 'Filtro mangle IPv4 non disponibile sul kernel'
timeout 12 ip6tables -t mangle -S FORWARD >/dev/null || die 'Filtro mangle IPv6 non disponibile sul kernel'

say 'Policy Factory iniziale: LAN OFF, nessun host, nessuna rotta'
install -d -o root -g root -m 0700 /var/lib/tailscale-panel-guard
printf '%s\n' '{"mode":"off","subnets":"","selected_hosts":[]}' > /var/lib/tailscale-panel-guard/policy.json
chmod 0600 /var/lib/tailscale-panel-guard/policy.json

say 'Gestione console USB non utilizzata'
# The audit machine showed a /dev/console deadlock with ttyGS0 and ttyS0.
# Keep the physical debug UART ttyS0. Only disable the USB gadget LOGIN service.
if systemctl list-unit-files --no-legend 'serial-getty@.service' 2>/dev/null | grep -q 'serial-getty@'; then
  if [ "$(timeout 8 systemctl is-active serial-getty@ttyGS0.service 2>/dev/null || true)" = active ]; then
    echo 'Console USB ttyGS0 attiva: la disabilito, preservando ttyS0 e SSH.'
    timeout 15 systemctl disable --now serial-getty@ttyGS0.service || die 'Non riesco a fermare ttyGS0'
    timeout 10 systemctl mask serial-getty@ttyGS0.service || die 'Impossibile mascherare ttyGS0'
  fi
fi

say 'Installazione applicazione e servizi web v1.5.0'
if ! sh "$BASE/install_tailscale_panel.sh"; then
  sh "$BASE/restore_panel.sh" "$BACKUP_DIR" || true
  die 'Installer dell’applicazione non riuscito: tentato ripristino del pannello precedente'
fi

say 'Accesso di servizio: IP di recupero e Wi-Fi che annuncia l’IP'
# Non fatale: il pannello e' gia' installato e funzionante; si puo' rilanciare a parte.
sh "$BASE/install_access.sh" || printf 'AVVISO: accesso di servizio non completato. Rilanciare: sh install_access.sh\n' >&2

# Scrive tutto sulla microSD: i clienti staccano la presa senza spegnere, e un file nuovo non
# ancora scritto su disco resterebbe vuoto.
sync

say 'Verifica finale Factory'
if ! sh "$BASE/check_installation.sh" --fresh; then
  sh "$BASE/restore_panel.sh" "$BACKUP_DIR" || true
  die 'Autoverifica non superata: tentato ripristino del pannello precedente'
fi

printf '\n=====================================================\n'
printf ' TAILSCALE CONTROL PANEL FACTORY R1.3.2 - INSTALLATO\n'
printf '=====================================================\n'
printf '1) Usa la password Web UI scelta durante l’installazione (non visualizzata).\n'
printf '2) Autentica il nuovo dispositivo: tailscale up\n'
printf '3) Apri https://IP-ETHERNET:8443 sul PC nella LAN.\n'
printf '4) LAN OFF, nessun host scelto, nessuna rotta. Configura solo quando pronto.\n'
printf '5) Prima di pubblicare subnet: regole tailnet + approvazione rotta.\n'
printf '6) Non aprire TCP 8443 verso Internet.\n'
printf '7) IP di recupero e Wi-Fi "Raptor VPN - <IP>": vedi ACCESSO_DI_SERVIZIO.md.\n'
printf '=====================================================\n'
