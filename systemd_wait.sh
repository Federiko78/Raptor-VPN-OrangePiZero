# Funzioni condivise da install_factory.sh e install_tailscale_panel.sh (si includono con:  . "$DIR/systemd_wait.sh").
# Non si esegue da solo.
#
# Il blocco noto di /dev/console: due (agetty) di console seriale (per esempio ttyS0 e ttyGS0) restano a meta'
# avvio, uno tiene il lock di /dev/console e l'altro lo aspetta; PID 1 (systemd) ci si mette in coda dietro, si ferma
# e systemctl non risponde piu'. Si riconosce da PID 1 fermo in "locks_lock_inode_wait" e dai lock su /dev/console
# tenuti da processi ancora chiamati "(agetty)" (il nome tra parentesi vuol dire che non hanno ancora fatto exec).
#
# RAPTOR_PROC serve solo ai test (percorso finto al posto di /proc).

# unblock_console: termina quegli (agetty) bloccati. Esce 0 solo se ne ha terminato almeno uno.
unblock_console() {
  proc=${RAPTOR_PROC:-/proc}
  [ "$(cat "$proc/1/wchan" 2>/dev/null || true)" = locks_lock_inode_wait ] || return 1
  command -v lslocks >/dev/null 2>&1 || return 1
  console_unblocked=1
  for console_pid in $(lslocks -n -r -o PID,PATH 2>/dev/null | awk '$2 == "/dev/console" && $1 != 1 { print $1 }'); do
    [ "$(cat "$proc/$console_pid/comm" 2>/dev/null || true)" = '(agetty)' ] || continue
    [ "$(awk '/^PPid:/ { print $2 }' "$proc/$console_pid/status" 2>/dev/null || true)" = 1 ] || continue
    kill -9 "$console_pid" 2>/dev/null || continue
    echo "Console bloccata: terminato il processo $console_pid ((agetty) fermo a meta' avvio)."
    console_unblocked=0
  done
  return "$console_unblocked"
}

# wait_for_systemd: aspetta che systemd risponda. Subito dopo l'avvio o dopo apt la scheda puo' essere occupata e
# systemctl lenta: si riprova per circa 2 minuti. Se vede il blocco della console lo toglie. Imposta
# systemd_ready (yes/no), systemd_rc e systemd_err (il motivo vero, che prima era nascosto). Esce 0 se risponde.
wait_for_systemd() {
  systemd_ready=no
  systemd_err=
  systemd_rc=0
  for systemd_try in 1 2 3 4 5 6; do
    if systemd_err=$(timeout 15 systemctl list-units --no-pager 2>&1 >/dev/null); then
      systemd_ready=yes
      return 0
    else
      systemd_rc=$?
    fi
    if unblock_console; then
      sleep 3
      continue
    fi
    [ "$systemd_try" -lt 6 ] || break
    printf 'systemd occupato o lento (tentativo %s di 6): attendo...\n' "$systemd_try"
    sleep 5
  done
  return 1
}
