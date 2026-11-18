#!/bin/bash
# Raptor VPN - hardening di SSH per una Orange Pi lasciata in rete di un cliente.
#
#   harden_ssh.sh [--user NOME]            mostra cosa farebbe (nessuna modifica)
#   harden_ssh.sh [--user NOME] --apply    applica
#   harden_ssh.sh --revert                 rimuove la configurazione (torna ai default)
#
# Cosa fa: disattiva il login di root e l'accesso con password, consente solo
# l'utente amministratore con CHIAVE SSH, riduce i tentativi e il tempo di login.
# Scrive un solo file: /etc/ssh/sshd_config.d/00-raptor-hardening.conf
#
# SICUREZZA ANTI-BLOCCO: si rifiuta di procedere se l'utente scelto non ha almeno
# una chiave in ~/.ssh/authorized_keys, e controlla la configurazione con "sshd -t"
# prima di ricaricare il servizio. Le sessioni gia' aperte non vengono chiuse.
set -eu

DROPIN=/etc/ssh/sshd_config.d/00-raptor-hardening.conf
APPLY=0; REVERT=0; ADMIN=""
while [ $# -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1; shift ;;
    --revert) REVERT=1; shift ;;
    --user) [ $# -ge 2 ] || { echo "--user richiede un nome" >&2; exit 1; }; ADMIN="$2"; shift 2 ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "Argomento sconosciuto: $1" >&2; exit 1 ;;
  esac
done

die() { echo "ERRORE: $*" >&2; exit 1; }
reload_ssh() { systemctl reload ssh 2>/dev/null || systemctl reload sshd; }

[ "$(id -u)" -eq 0 ] || die "eseguire come root"

if [ "$REVERT" -eq 1 ]; then
  rm -f "$DROPIN"
  command -v sshd >/dev/null 2>&1 && sshd -t || die "sshd -t non riuscito dopo la rimozione: controllare /etc/ssh"
  reload_ssh
  echo "Configurazione rimossa: SSH torna ai valori predefiniti."
  exit 0
fi

# Utente amministratore: il primo con UID >= 1000 nel gruppo sudo, se non indicato.
if [ -z "$ADMIN" ]; then
  ADMIN=$(getent group sudo | cut -d: -f4 | tr ',' '\n' | while read -r u; do
            [ -n "$u" ] && [ "$(id -u "$u" 2>/dev/null || echo 0)" -ge 1000 ] && { echo "$u"; break; }
          done)
fi
[ -n "$ADMIN" ] || die "nessun utente amministratore (UID>=1000 nel gruppo sudo): usare --user NOME"
id "$ADMIN" >/dev/null 2>&1 || die "utente inesistente: $ADMIN"
getent group sudo | cut -d: -f4 | tr ',' '\n' | grep -qx "$ADMIN" || die "$ADMIN non e' nel gruppo sudo: dopo il blocco di root non potresti amministrare il sistema"

HOME_DIR=$(getent passwd "$ADMIN" | cut -d: -f6)
KEYS="$HOME_DIR/.ssh/authorized_keys"
NKEYS=0
if [ -f "$KEYS" ]; then
  NKEYS=$(ssh-keygen -lf "$KEYS" 2>/dev/null | wc -l)
fi
if [ "$NKEYS" -lt 1 ]; then
  cat >&2 <<MSG
ERRORE: $ADMIN non ha nessuna chiave SSH in $KEYS.
Senza chiave, disattivare la password ti taglierebbe fuori. Prima aggiungi la tua chiave:

  1. Sul PC Windows apri PuTTYgen, "Generate", salva la chiave privata (.ppk)
     e copia il testo nel riquadro "Public key for pasting into OpenSSH authorized_keys file".
  2. Sulla Orange Pi:
       install -d -m 700 -o $ADMIN -g $ADMIN $HOME_DIR/.ssh
       nano $KEYS            (incolla la riga, salva)
       chown $ADMIN:$ADMIN $KEYS; chmod 600 $KEYS
  3. In PuTTY: Connection > SSH > Auth > Credentials > Private key file = il tuo .ppk,
     e verifica di poter entrare come $ADMIN SENZA password. Poi rilancia questo script.
MSG
  exit 1
fi

grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config 2>/dev/null \
  || die "/etc/ssh/sshd_config non include sshd_config.d/*.conf: configurazione non standard, intervenire a mano"

CONFIG=$(cat <<CONF
# Gestito da Raptor VPN (harden_ssh.sh). Il primo valore letto da sshd vince: questo file
# si chiama 00-* per precedere gli altri. Per annullare: harden_ssh.sh --revert
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
AllowUsers $ADMIN
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
MaxStartups 5:50:20
ClientAliveInterval 60
ClientAliveCountMax 3
CONF
)

echo "Utente amministratore : $ADMIN ($NKEYS chiave/i trovate)"
echo "File che verra' scritto: $DROPIN"
echo "----------------------------------------"
echo "$CONFIG"
echo "----------------------------------------"
if [ "$APPLY" -ne 1 ]; then
  echo "Nessuna modifica fatta. Per applicare: $0 --user $ADMIN --apply"
  exit 0
fi

command -v sshd >/dev/null 2>&1 || die "sshd non trovato"
BACKUP=""
if [ -f "$DROPIN" ]; then BACKUP=$(mktemp); cp -p "$DROPIN" "$BACKUP"; fi
printf '%s\n' "$CONFIG" > "$DROPIN"
chmod 644 "$DROPIN"
if ! sshd -t; then
  echo "ERRORE: sshd -t ha rifiutato la configurazione: ripristino." >&2
  if [ -n "$BACKUP" ]; then cp -p "$BACKUP" "$DROPIN"; else rm -f "$DROPIN"; fi
  exit 1
fi
[ -z "$BACKUP" ] || rm -f "$BACKUP"
reload_ssh
cat <<DONE

Applicato. NON CHIUDERE questa sessione: apri una NUOVA sessione PuTTY con la chiave
(utente $ADMIN, niente password) e verifica che entri. Poi usa "sudo -i" per diventare root.
Se qualcosa non va, da questa sessione:  $0 --revert
DONE
