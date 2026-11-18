#!/bin/sh
# Raptor VPN - aggiorna una scheda GIA' installata all'ultima versione del ramo in uso.
#
#   cd ~/Raptor-VPN-OrangePiZero && sh update.sh
#
# Scarica le modifiche (git pull), verifica i file, aggiorna pannello, registro eventi e, se gia'
# installato, il Wi-Fi annuncio-IP. NON tocca: password del pannello, identita' Tailscale,
# configurazione di rete, IP di recupero e rotte scelte.
set -eu
export LC_ALL=C

say() { printf '\n== %s ==\n' "$*"; }
die() { printf '\nERRORE: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die 'Eseguire come root: sh ./update.sh'
BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$BASE"
[ -d .git ] || die 'Questa cartella non e'"'"' una copia git del progetto: usare bootstrap.sh'
[ -x /usr/local/libexec/tailscale-panel-net-helper ] || die 'Pannello non installato: usare install_factory.sh'

say 'Download'
git pull --ff-only || die 'git pull non riuscito (modifiche locali o rete?).'
sha256sum -c SHA256SUMS >/dev/null || die 'Verifica SHA256 non superata: file danneggiati'

say 'Pannello'
sh ./install_tailscale_panel.sh || die 'Aggiornamento del pannello non riuscito.'

say 'Registro eventi'
sh ./install_eventlog.sh || die 'Installazione del registro eventi non riuscita.'

if [ -x /usr/local/libexec/raptor-ap ]; then
  say 'Wi-Fi annuncio-IP'
  sh ./install_access.sh --recovery-ip keep --ap on || die 'Aggiornamento del Wi-Fi non riuscito.'
fi

sync
say 'Verifica'
sh ./check_installation.sh --fresh 2>&1 | grep -E 'ERRORE|DA VERIFICARE|VERIFICA' || true
