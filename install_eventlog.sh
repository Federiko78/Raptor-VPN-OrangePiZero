#!/bin/sh
# Raptor VPN - registro eventi persistente (avvii, spegnimenti, mancanza di corrente).
#
#   sh install_eventlog.sh            installa e attiva
#   sh install_eventlog.sh --remove   toglie servizi e programma (il file degli eventi resta)
#
# Il registro sta in /var/lib/raptor-events/events.jsonl (un evento JSON per riga) e si vede nel
# pannello, sezione "Eventi". Scrive solo root; il pannello lo legge e basta.
set -eu
export LC_ALL=C

say() { printf '\n== %s ==\n' "$*"; }
die() { printf '\nERRORE: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die 'Eseguire come root: sh ./install_eventlog.sh'
BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BIN=/usr/local/libexec/raptor-eventlog
UNITS=/etc/systemd/system
MAIN=$UNITS/raptor-eventlog.service
BEAT=$UNITS/raptor-eventlog-heartbeat.service
TIMER=$UNITS/raptor-eventlog-heartbeat.timer

if [ "${1:-}" = --remove ]; then
  systemctl disable --now raptor-eventlog-heartbeat.timer raptor-eventlog.service >/dev/null 2>&1 || true
  rm -f "$MAIN" "$BEAT" "$TIMER" "$BIN"
  systemctl daemon-reload
  echo 'Registro eventi disinstallato (il file /var/lib/raptor-events resta).'
  exit 0
fi
[ $# -eq 0 ] || die "Argomento sconosciuto: $1"

say 'Registro eventi'
[ -s "$BASE/raptor_eventlog.py" ] || die 'File mancante nel pacchetto: raptor_eventlog.py'
python3 - "$BASE/raptor_eventlog.py" <<'PYCOMPILE' || die 'Errore di sintassi in raptor_eventlog.py'
import ast, sys
with open(sys.argv[1], encoding='utf-8') as fd:
    ast.parse(fd.read(), filename=sys.argv[1])
PYCOMPILE

install -d -m 0755 -o root -g root /usr/local/libexec
install -m 0755 -o root -g root "$BASE/raptor_eventlog.py" "$BIN"

# Le unit si riscrivono sempre da zero: mai "attraverso" un collegamento a /dev/null o un file vuoto.
for unit in raptor-eventlog.service raptor-eventlog-heartbeat.service raptor-eventlog-heartbeat.timer; do
  systemctl unmask "$unit" >/dev/null 2>&1 || true
  rm -f "$UNITS/$unit"
done

cat > "$MAIN" <<EOF
[Unit]
Description=Raptor VPN - registro eventi (avvii e spegnimenti)
After=local-fs.target dbus.socket

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 $BIN --boot
ExecStop=/usr/bin/python3 $BIN --shutdown
StateDirectory=raptor-events
StateDirectoryMode=0755
TimeoutStopSec=20
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

cat > "$BEAT" <<EOF
[Unit]
Description=Raptor VPN - battito del registro eventi (ultimo istante in cui la scheda era viva)
After=raptor-eventlog.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 $BIN --heartbeat
StateDirectory=raptor-events
StateDirectoryMode=0755
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
EOF

cat > "$TIMER" <<EOF
[Unit]
Description=Raptor VPN - battito ogni 5 minuti

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
EOF
chmod 0644 "$MAIN" "$BEAT" "$TIMER"
for f in "$MAIN" "$BEAT" "$TIMER"; do
  [ -s "$f" ] && [ ! -L "$f" ] || die "Unit $f non scritta correttamente"
done

systemctl daemon-reload
systemctl enable raptor-eventlog.service raptor-eventlog-heartbeat.timer >/dev/null 2>&1 || die 'Impossibile abilitare i servizi del registro eventi'
[ "$(systemctl is-enabled raptor-eventlog.service 2>/dev/null || true)" = enabled ] || die 'raptor-eventlog.service non risulta abilitato: controllare systemctl status raptor-eventlog'
# Avvio subito: registra l'avvio in corso (e come era finito il precedente, se lo stato esiste).
systemctl restart raptor-eventlog.service || die 'raptor-eventlog.service non e'"'"' partito: journalctl -u raptor-eventlog'
systemctl start raptor-eventlog-heartbeat.timer
# Scrive tutto sulla microSD: se si stacca la presa subito dopo, i file non restano vuoti.
sync

echo 'Registro eventi attivo. Ultimi eventi registrati:'
tail -n 3 /var/lib/raptor-events/events.jsonl 2>/dev/null || echo '(nessuno)'
echo 'Si vede nel pannello, sezione "Eventi · Riavvii e stato del sistema".'
