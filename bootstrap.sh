#!/bin/sh
# Raptor VPN - avvio rapido su una Orange Pi Zero appena installata
# (Armbian Debian 13 Trixie Minimal, armhf, collegata a Internet via Ethernet).
#
# Da root, in una sessione SSH:
#   curl -fsSL https://raw.githubusercontent.com/Federiko78/Raptor-VPN-OrangePiZero/main/bootstrap.sh | sh
#
# Fa, in ordine: installa git e python3, scarica il progetto in /root/Raptor-VPN-OrangePiZero
# e lancia install_factory.sh (che chiede le password e le scelte, quindi serve il terminale).
# Si puo' rilanciare: se la cartella esiste la aggiorna.
#
# Variabili facoltative:  RAPTOR_BRANCH (predefinito: main)   RAPTOR_DIR   RAPTOR_REPO
#   curl -fsSL <url>/bootstrap.sh | RAPTOR_BRANCH=sicurezza sh
#
# Tutto e' dentro main(): la shell legge lo script da una pipe e, senza questa precauzione,
# dopo il cambio di input continuerebbe a leggere i comandi dalla tastiera.
set -eu

die() { printf '\nERRORE: %s\n' "$*" >&2; exit 1; }
say() { printf '\n== %s ==\n' "$*"; }

main() {
  REPO=${RAPTOR_REPO:-https://github.com/Federiko78/Raptor-VPN-OrangePiZero.git}
  BRANCH=${RAPTOR_BRANCH:-main}
  DEST=${RAPTOR_DIR:-/root/Raptor-VPN-OrangePiZero}

  [ "$(id -u)" -eq 0 ] || die 'Eseguire come root.'
  case "$BRANCH" in ''|*[!A-Za-z0-9._/-]*) die "Nome ramo non valido: $BRANCH" ;; esac

  # L'installer fa domande (password, IP di recupero): serve la tastiera anche se lo script
  # arriva da una pipe.
  if [ ! -t 0 ]; then
    ( : < /dev/tty ) 2>/dev/null || die 'Serve una sessione interattiva (SSH con terminale).'
    exec < /dev/tty
  fi

  say 'Pacchetti di base (git, python3)'
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends git python3 ca-certificates || die 'Installazione pacchetti non riuscita.'

  say "Download del progetto (ramo $BRANCH)"
  if [ -d "$DEST/.git" ]; then
    git -C "$DEST" fetch --depth 1 origin "$BRANCH" || die 'Aggiornamento non riuscito.'
    git -C "$DEST" checkout -q -f -B "$BRANCH" FETCH_HEAD || die 'Aggiornamento non riuscito.'
  elif [ -e "$DEST" ]; then
    die "$DEST esiste ma non e' una copia del progetto: spostala o cancellala."
  else
    git clone --depth 1 --branch "$BRANCH" "$REPO" "$DEST" || die 'Download non riuscito.'
  fi

  cd "$DEST"
  say 'Installazione'
  exec sh ./install_factory.sh
}

main "$@"
