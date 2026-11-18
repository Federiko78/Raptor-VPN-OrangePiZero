#!/bin/bash
# Raptor VPN - hardening di sistema per Orange Pi (Armbian Debian 13).
#
#   harden_system.sh                 mostra cosa farebbe (nessuna modifica)
#   harden_system.sh --apply         applica tutto
#   harden_system.sh --apply --skip-updates     come sopra, senza installare unattended-upgrades
#
# Tre interventi, ognuno in un solo file di configurazione facilmente rimovibile:
#  1. systemd-resolved: spegne LLMNR e mDNS di resolved (porte 5355/5353 aperte sulla LAN
#     del cliente). Il nome orangepizero.local continua a funzionare tramite avahi.
#  2. Aggiornamenti automatici SOLO di sicurezza Debian (unattended-upgrades): niente
#     kernel, niente pacchetti Armbian o Tailscale, mai riavvii automatici.
#  3. Watchdog hardware: se il sistema si blocca, la scheda si riavvia da sola.
set -eu

APPLY=0; SKIP_UPDATES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1; shift ;;
    --skip-updates) SKIP_UPDATES=1; shift ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "Argomento sconosciuto: $1" >&2; exit 1 ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "ERRORE: eseguire come root" >&2; exit 1; }

# put FILE: legge il contenuto da stdin; lo scrive solo con --apply.
put() {
  echo "== $1"
  if [ "$APPLY" -eq 1 ]; then
    install -d -m 755 "$(dirname "$1")"
    cat > "$1"; chmod 644 "$1"
  else
    sed 's/^/   | /'
  fi
}

# --- 1. resolved ---------------------------------------------------------------
put /etc/systemd/resolved.conf.d/50-raptor.conf <<'CONF'
# Gestito da Raptor VPN: niente risoluzione multicast sulla LAN del cliente.
[Resolve]
LLMNR=no
MulticastDNS=no
CONF
if [ "$APPLY" -eq 1 ]; then systemctl restart systemd-resolved; fi

# --- 2. aggiornamenti di sicurezza ---------------------------------------------
if [ "$SKIP_UPDATES" -eq 0 ]; then
  put /etc/apt/apt.conf.d/52raptor-unattended-upgrades <<'CONF'
// Gestito da Raptor VPN: solo aggiornamenti di sicurezza Debian.
// Kernel, pacchetti Armbian e Tailscale restano sotto il tuo controllo.
#clear Unattended-Upgrade::Origins-Pattern;
Unattended-Upgrade::Origins-Pattern {
        "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
        "origin=Debian,codename=${distro_codename},label=Debian-Security";
};
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
CONF
  if [ "$APPLY" -eq 1 ]; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends unattended-upgrades
    systemctl enable --now unattended-upgrades.service apt-daily-upgrade.timer 2>/dev/null || true
    echo "   Verifica a secco: unattended-upgrade --dry-run --debug | tail"
  fi
else
  echo "== aggiornamenti automatici: saltati (--skip-updates)"
fi

# --- 3. watchdog hardware ------------------------------------------------------
if [ -c /dev/watchdog ]; then
  # Il watchdog dell'Allwinner H2+/H3 accetta al massimo circa 16 s: 15 s e' il limite sicuro.
  put /etc/systemd/system.conf.d/10-raptor-watchdog.conf <<'CONF'
# Gestito da Raptor VPN: se systemd non risponde, il watchdog hardware riavvia la scheda.
[Manager]
RuntimeWatchdogSec=15
RebootWatchdogSec=2min
CONF
  if [ "$APPLY" -eq 1 ]; then
    systemctl daemon-reexec
    echo "   Watchdog attivo: $(systemctl show -p RuntimeWatchdogUSec --value)"
  fi
else
  echo "== watchdog: /dev/watchdog non presente, saltato"
fi

echo
if [ "$APPLY" -eq 1 ]; then
  echo "Applicato. Controlli: resolvectl status | grep -i -E 'LLMNR|mDNS'   e   systemctl show -p RuntimeWatchdogUSec"
else
  echo "Nessuna modifica fatta. Per applicare: $0 --apply"
fi
