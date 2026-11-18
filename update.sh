#!/bin/sh
# Raptor VPN - aggiorna una scheda GIA' installata all'ultima versione del ramo in uso.
#
#   cd ~/Raptor-VPN-OrangePiZero && sh update.sh
#
# Scarica le modifiche (git pull), verifica i file, aggiorna pannello, registro eventi e, se gia'
# installato, il Wi-Fi annuncio-IP. NON tocca: password del pannello, identita' Tailscale,
# configurazione di rete e rotte scelte.
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
# Niente "git pull": la copia e' superficiale (--depth 1) e il ramo puo' non avere un ramo remoto associato
# (e' cosi' dopo "git checkout -B ramo FETCH_HEAD"). Si scarica l'ultimo commit del ramo e si passa a quello.
BRANCH=$(git symbolic-ref --short -q HEAD || true)
case "$BRANCH" in ''|*[!A-Za-z0-9._/-]*) die 'Nessun ramo attivo: rifare il download con bootstrap.sh' ;; esac
[ -z "$(git status --porcelain --untracked-files=no)" ] || die 'File del progetto modificati a mano: annullare con "git checkout -- ." oppure rifare il download con bootstrap.sh'
git fetch --depth 1 origin "$BRANCH" || die "Download del ramo $BRANCH non riuscito (rete? il ramo esiste su GitHub?)."
git checkout -q -B "$BRANCH" FETCH_HEAD || die 'Aggiornamento dei file non riuscito.'
echo "Versione: $(git log --oneline -1)"
sha256sum -c SHA256SUMS >/dev/null || die 'Verifica SHA256 non superata: file danneggiati'

say 'Pulizia IP di recupero (funzione rimossa)'
# Le schede installate con le versioni precedenti possono avere un indirizzo 169.254.X.Y di recupero
# (alias su end0, riga nel Netplan del pannello, /etc/raptor-recovery.conf). La funzione e' stata tolta:
# si rimuove qui con l'helper GIA' INSTALLATO, prima che l'installazione del pannello lo sostituisca con
# la versione nuova, che non conosce piu' quel comando. Il lease DHCP e le sessioni SSH non si toccano.
RECOVERY_CONF=/etc/raptor-recovery.conf
if [ -e "$RECOVERY_CONF" ]; then
  OUT=$(/usr/local/libexec/tailscale-panel-net-helper --set-recovery none 2>&1) \
    || die "IP di recupero non rimosso (modifica di rete in sospeso?): $OUT. Il pannello non e' stato aggiornato: riprova con sh update.sh quando la rete e' a posto."
  rm -f /var/lib/tailscale-panel-network/backup-recovery-*.json
  echo 'IP di recupero rimosso (indirizzo, Netplan e configurazione).'
else
  echo 'Nessun IP di recupero da togliere.'
fi

say 'Pannello'
sh ./install_tailscale_panel.sh || die 'Aggiornamento del pannello non riuscito.'

say 'Registro eventi'
sh ./install_eventlog.sh || die 'Installazione del registro eventi non riuscita.'

if [ -x /usr/local/libexec/raptor-ap ]; then
  say 'Wi-Fi annuncio-IP'
  sh ./install_access.sh --ap on || die 'Aggiornamento del Wi-Fi non riuscito.'
fi

sync
say 'Verifica'
# Niente --fresh: quel controllo e' per una scheda appena installata (pretende policy iniziale con LAN spenta e zero host)
# e su una scheda gia' in servizio, con rotte pubblicate, darebbe un falso errore.
sh ./check_installation.sh 2>&1 | grep -E 'ERRORE|DA VERIFICARE|VERIFICA' || true
