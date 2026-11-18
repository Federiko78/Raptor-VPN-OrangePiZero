#!/usr/bin/env python3
"""Raptor VPN - registro eventi persistente (avvii, spegnimenti, mancanza di corrente).

Scrive /var/lib/raptor-events/events.jsonl: un evento JSON per riga (JSON Lines). Se la corrente
manca mentre si scrive, si perde al massimo l'ultima riga e il resto resta leggibile. Il pannello
web lo legge soltanto: a scrivere e' solo questo programma, che gira come root.

Voci di comando (le lancia systemd, vedi install_eventlog.sh):
  --boot       all'avvio: registra l'avvio e come e' finito l'avvio precedente
  --shutdown   allo spegnimento: segna lo spegnimento come pulito (solo se il sistema si sta
               davvero fermando, non con un semplice "systemctl stop")
  --heartbeat  ogni 5 minuti: aggiorna "ultimo istante in cui la scheda era viva" e registra
               quando l'orologio viene sincronizzato

Come si capisce che la corrente e' mancata: all'avvio, se lo stato dell'avvio precedente NON
porta il segno di spegnimento pulito, la scheda e' stata spenta di colpo (corrente, blocco,
watchdog). L'ultimo "battito" dice entro quando (al massimo 5 minuti prima dell'accensione).

Tipi di evento:  boot, shutdown, unclean_shutdown, clock_synced
Gli orari sono secondi Unix UTC ("epoch"). Senza batteria la scheda parte con l'orologio indietro
finche' non si sincronizza: l'evento boot porta clock_synced=false, poi arriva clock_synced.
"""
import contextlib
import fcntl
import json
import os
import pathlib
import subprocess
import sys
import time

DIR = pathlib.Path('/var/lib/raptor-events')
EVENTS = DIR / 'events.jsonl'
STATE = DIR / 'state.json'
BOOT_ID_FILE = pathlib.Path('/proc/sys/kernel/random/boot_id')
UPTIME_FILE = pathlib.Path('/proc/uptime')
TIMESYNC_FILE = pathlib.Path('/run/systemd/timesync/synchronized')
MAX_BYTES = 400 * 1024      # oltre questa dimensione, all'avvio si tengono solo gli ultimi eventi
KEEP_LINES = 1000
LATE_SECONDS = 180          # avvio registrato piu' di 3 minuti dopo l'accensione = installazione a caldo
SHUTDOWN_KINDS = {'reboot.target': 'reboot', 'kexec.target': 'reboot',
                  'poweroff.target': 'poweroff', 'halt.target': 'halt'}


def run(args, timeout=10):
    try:
        done = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return done.stdout.strip() if done.returncode == 0 else None


def uptime_seconds():
    try:
        return float(UPTIME_FILE.read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return 0.0


def boot_id():
    try:
        return BOOT_ID_FILE.read_text().strip()
    except OSError:
        return ''


def clock_synced():
    answer = run(['timedatectl', 'show', '-p', 'NTPSynchronized', '--value'])
    if answer in ('yes', 'no'):
        return answer == 'yes'
    return TIMESYNC_FILE.exists()


def system_is_stopping():
    return run(['systemctl', 'is-system-running']) == 'stopping'


def shutdown_kind():
    jobs = run(['systemctl', 'list-jobs', '--no-legend']) or ''
    for target, kind in SHUTDOWN_KINDS.items():
        if target in jobs:
            return kind
    return 'unknown'


# --- scrittura sicura ---------------------------------------------------------------------
def fsync_dir():
    try:
        fd = os.open(str(DIR), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def write_state(state):
    DIR.mkdir(parents=True, exist_ok=True)
    tmp = DIR / '.state.json.tmp'
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(fd, 'w') as stream:
        stream.write(json.dumps(state, sort_keys=True))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(str(tmp), str(STATE))
    fsync_dir()


def read_state():
    """None se non esiste (primo avvio); {'corrupt': True} se esiste ma non e' leggibile."""
    try:
        text = STATE.read_text()
    except FileNotFoundError:
        return None
    except OSError:
        return {'corrupt': True}
    try:
        state = json.loads(text)
    except ValueError:
        return {'corrupt': True}
    return state if isinstance(state, dict) else {'corrupt': True}


def append_event(event):
    DIR.mkdir(parents=True, exist_ok=True)
    line = (json.dumps(event, sort_keys=True, separators=(',', ':')) + '\n').encode()
    fd = os.open(str(EVENTS), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        os.write(fd, line)
        os.fsync(fd)
    finally:
        os.close(fd)
    fsync_dir()


def trim_events():
    """Tiene il file piccolo (protegge la microSD): oltre MAX_BYTES restano gli ultimi eventi."""
    try:
        if EVENTS.stat().st_size <= MAX_BYTES:
            return False
        lines = EVENTS.read_text(errors='replace').splitlines()[-KEEP_LINES:]
    except OSError:
        return False
    tmp = DIR / '.events.jsonl.tmp'
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(fd, 'w') as stream:
        stream.write('\n'.join(lines) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(str(tmp), str(EVENTS))
    fsync_dir()
    return True


@contextlib.contextmanager
def locked():
    """Un solo comando alla volta: evita che un battito sovrascriva il segno di spegnimento pulito."""
    DIR.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(DIR / '.lock'), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


# --- comandi ------------------------------------------------------------------------------
def classify_previous(previous):
    """Come e' finito l'avvio precedente, secondo lo stato salvato."""
    if previous is None:
        return 'first_boot'
    if previous.get('corrupt'):
        return 'unknown'
    if previous.get('clean') is True:
        return 'clean_' + str(previous.get('shutdown_kind') or 'unknown')
    return 'unclean'


def cmd_boot():
    now = int(time.time())
    up = uptime_seconds()
    this_boot = boot_id()
    previous = read_state()
    if previous and previous.get('boot_id') == this_boot and this_boot:
        return {'ok': True, 'note': 'avvio gia registrato'}          # rilancio manuale: niente doppioni
    trim_events()
    boot_epoch = int(now - up)
    synced = clock_synced()
    how = classify_previous(previous)
    event = {'type': 'boot', 'epoch': boot_epoch, 'boot_id': this_boot, 'previous': how,
             'clock_synced': synced, 'kernel': os.uname().release}
    if previous and previous.get('last_seen_epoch'):
        event['previous_last_seen_epoch'] = int(previous['last_seen_epoch'])
    if up > LATE_SECONDS:
        event['logged_late'] = True                                 # installato quando la scheda era gia' accesa
        event['logged_epoch'] = now
    if how == 'unclean':
        append_event({'type': 'unclean_shutdown', 'epoch': boot_epoch, 'boot_id': this_boot,
                      'last_seen_epoch': int(previous.get('last_seen_epoch') or 0) or None,
                      'detected_epoch': now})
    append_event(event)
    # Solo DOPO aver letto il vecchio stato: da qui in poi lo spegnimento e' "non ancora pulito".
    write_state({'version': 1, 'boot_id': this_boot, 'boot_epoch': boot_epoch, 'boot_uptime': up,
                 'clean': False, 'shutdown_kind': None, 'last_seen_epoch': now, 'clock_synced': synced})
    return {'ok': True, 'previous': how}


def cmd_shutdown():
    if not system_is_stopping():
        return {'ok': True, 'note': 'non e\' uno spegnimento del sistema: ignorato'}
    state = read_state()
    if not state or state.get('corrupt'):
        state = {'version': 1, 'boot_id': boot_id()}
    kind = shutdown_kind()
    now = int(time.time())
    append_event({'type': 'shutdown', 'epoch': now, 'boot_id': state.get('boot_id', ''), 'kind': kind,
                  'clock_synced': clock_synced()})
    state.update({'clean': True, 'shutdown_kind': kind, 'last_seen_epoch': now})
    write_state(state)
    return {'ok': True, 'kind': kind}


def cmd_heartbeat():
    state = read_state()
    if state is None or state.get('corrupt'):
        return {'ok': True, 'note': 'nessuno stato valido: attendere --boot'}
    now = int(time.time())
    if state.get('clean'):
        return {'ok': True, 'note': 'spegnimento in corso'}
    if state.get('clock_synced') is False and clock_synced():
        expected = state.get('boot_epoch', now) + uptime_seconds()      # orario se l'orologio non fosse saltato
        append_event({'type': 'clock_synced', 'epoch': now, 'boot_id': state.get('boot_id', ''),
                      'jump_seconds': int(round(now - expected))})
        state['clock_synced'] = True
    state['last_seen_epoch'] = now
    write_state(state)
    return {'ok': True}


COMMANDS = {'--boot': cmd_boot, '--shutdown': cmd_shutdown, '--heartbeat': cmd_heartbeat}


def main(argv):
    if len(argv) != 2 or argv[1] not in COMMANDS:
        print(__doc__)
        return 2
    if os.geteuid() != 0:
        print('Serve root.', file=sys.stderr)
        return 1
    try:
        with locked():
            result = COMMANDS[argv[1]]()
        print(json.dumps(result))
    except OSError as error:
        print(json.dumps({'ok': False, 'error': str(error)[:300]}))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
