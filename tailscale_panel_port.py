#!/usr/bin/env python3
"""Restricted root controller for the HTTPS port of the panel.

Public sudo entry: no command line arguments, JSON on stdin.
Internal entry points (--apply / --rollback / --recover) are started only by systemd.
From a root shell, `--set-port N` changes the port at once (recovery use, see PORTA_PANNELLO.md).

The change is never final until it is confirmed from the NEW port: if the customer's network
does not let the new port through, nobody can confirm and the previous port comes back by itself
(timer, and also at boot if the power was lost in the meantime).

What is rewritten (exact lines only, nothing else in those files is touched):
  tailscale-panel.socket          ListenStream=0.0.0.0:PORT
  tailscale-panel.service         Environment=PANEL_PORT=PORT
  avahi service file              <port>PORT</port>                       (if present)
  /etc/raptor-input-guard.conf    PANEL_PORT=PORT, then the rules are reapplied (if the guard is active)
"""
import base64
import fcntl
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import time
import uuid

DEFAULT_PORT = 8443
MIN_PORT = 1024
MAX_PORT = 65535
# Ports that other parts of the system already use (Tailscale, mDNS): never offered to the panel.
RESERVED = frozenset({5353, 41641})
WAIT_SECONDS = 150       # time allowed to confirm from the new port
APPLY_DELAY = 4          # lets the browser receive the reply before the panel moves
LISTEN_WAIT = 10         # seconds to wait for the new port to be listening

SOCKET_UNIT = pathlib.Path('/etc/systemd/system/tailscale-panel.socket')
SERVICE_UNIT = pathlib.Path('/etc/systemd/system/tailscale-panel.service')
AVAHI = pathlib.Path('/etc/avahi/services/tailscale-panel.service')
GUARD_CONF = pathlib.Path('/etc/raptor-input-guard.conf')
GUARD_BIN = pathlib.Path('/usr/local/libexec/raptor-input-guard')
# Root-only directory, outside anything the panel user can write.
STATE = pathlib.Path('/var/lib/tailscale-panel-port')
PENDING = STATE / 'pending.json'
LOCK = pathlib.Path('/run/lock/tailscale-panel-port.lock')
SELF = pathlib.Path('/usr/local/libexec/tailscale-panel-port-helper')

SOCKET_RE = re.compile(r'(?m)^ListenStream=0\.0\.0\.0:(\d{1,5})$')
SERVICE_RE = re.compile(r'(?m)^Environment=PANEL_PORT=\d{1,5}$')
AVAHI_RE = re.compile(r'<port>\d{1,5}</port>')
GUARD_RE = re.compile(r'(?m)^PANEL_PORT=\d{1,5}$')


def shell(args, timeout=15):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def atomic_write(path, data, mode=0o644):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name('.' + path.name + '.tmp-' + uuid.uuid4().hex[:12])
    fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(str(temp), str(path))
        os.chmod(str(path), mode)
    finally:
        if temp.exists():
            temp.unlink()


def locked(fn):
    with open(LOCK, 'a+') as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        return fn()


def read_pending():
    try:
        return json.loads(PENDING.read_text())
    except FileNotFoundError:
        return None


def validate_port(value):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError('The port must be a whole number.')
    if value < MIN_PORT or value > MAX_PORT:
        raise ValueError('The port must be between 1024 and 65535.')
    if value in RESERVED:
        raise ValueError('This port is reserved for other services: choose another one.')
    return value


def current_port():
    """Port of the socket unit as written on disk (the single source of truth)."""
    try:
        found = SOCKET_RE.findall(SOCKET_UNIT.read_text())
    except OSError:
        raise RuntimeError('Panel socket unit not found.')
    if len(found) != 1:
        raise RuntimeError('Panel socket unit not recognised: automatic change blocked.')
    return int(found[0])


def listening_ports():
    out = shell(['ss', '-H', '-ltn'], 10)
    if out.returncode:
        raise RuntimeError('Unable to check which ports are in use.')
    ports = set()
    for line in out.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 4 and ':' in fields[3]:
            tail = fields[3].rsplit(':', 1)[1]
            if tail.isdigit():
                ports.add(int(tail))
    return ports


def rewrite(kind, text, port):
    """Replace the single port line of a known file. Anything unexpected stops the change."""
    pattern, new = {
        'socket': (SOCKET_RE, 'ListenStream=0.0.0.0:%d' % port),
        'service': (SERVICE_RE, 'Environment=PANEL_PORT=%d' % port),
        'avahi': (AVAHI_RE, '<port>%d</port>' % port),
        'guard': (GUARD_RE, 'PANEL_PORT=%d' % port),
    }[kind]
    result, count = pattern.subn(new, text)
    if count != 1:
        raise RuntimeError('File not recognised, automatic change blocked: %s' % kind)
    return result


# kind -> (path, must exist). Optional files are changed only when they are there.
MANAGED = (('socket', SOCKET_UNIT, True), ('service', SERVICE_UNIT, True),
           ('avahi', AVAHI, False), ('guard', GUARD_CONF, False))


def snapshot():
    files = {}
    for kind, path, _ in MANAGED:
        files[str(path)] = base64.b64encode(path.read_bytes()).decode() if path.exists() else None
    return files


def restore(files):
    allowed = {str(path) for _, path, _ in MANAGED}
    for path, content in files.items():
        if path not in allowed:
            raise RuntimeError('Backup path not allowed.')
        if content is not None:
            file = pathlib.Path(path)
            mode = stat.S_IMODE(file.stat().st_mode) if file.exists() else 0o644
            atomic_write(file, base64.b64decode(content), mode)


def write_port(port):
    """All new contents are computed first, so a file that does not match changes nothing."""
    plan = []
    for kind, path, required in MANAGED:
        if not path.exists():
            if required:
                raise RuntimeError('File missing, automatic change blocked: %s' % path.name)
            continue
        plan.append((path, stat.S_IMODE(path.stat().st_mode), rewrite(kind, path.read_text(), port)))
    for path, mode, text in plan:
        atomic_write(path, text.encode(), mode)


def guard_active():
    if not GUARD_CONF.exists() or not GUARD_BIN.exists():
        return False
    return shell(['iptables', '-w', '5', '-S', 'RAPTOR_IN'], 10).returncode == 0


def wait_listening(port):
    deadline = time.monotonic() + LISTEN_WAIT
    while True:
        if port in listening_ports():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.5)


def activate(port):
    """Makes the files on disk take effect: firewall first (new port open), then the socket moves."""
    if guard_active():
        applied = shell([str(GUARD_BIN), 'apply'], 30)
        if applied.returncode:
            raise RuntimeError('Unable to update the incoming firewall: ' + applied.stderr[-200:])
    reloaded = shell(['systemctl', 'daemon-reload'], 30)
    if reloaded.returncode:
        raise RuntimeError('systemd reload failed: ' + reloaded.stderr[-200:])
    restarted = shell(['systemctl', 'restart', 'tailscale-panel.socket'], 30)
    if restarted.returncode:
        raise RuntimeError('Unable to restart the panel socket: ' + restarted.stderr[-200:])
    if not wait_listening(port):
        raise RuntimeError('The panel is not listening on the port.')


def cancel_timers(sid):
    for prefix in ('tspanel-port-rollback', 'tspanel-port-apply'):
        shell(['systemctl', 'stop', prefix + '-' + sid + '.timer'], 8)


def summary(pending):
    return {'id': pending['id'], 'old_port': pending['old_port'], 'new_port': pending['new_port'],
            'expires_at': pending['expires_at'], 'state': pending.get('state', 'scheduled')}


def get_current():
    out = {'supported': True, 'min': MIN_PORT, 'max': MAX_PORT, 'pending': None}
    try:
        out['current'] = current_port()
    except (RuntimeError, OSError) as err:
        out['supported'] = False
        out['current'] = DEFAULT_PORT
        out['reason'] = str(err)[:250]
    pending = read_pending()
    if pending:
        out['pending'] = summary(pending)
    return out


def rollback(sid):
    def run_rollback():
        pending = read_pending()
        if not pending or pending['id'] != sid:
            return {'ok': True, 'note': 'No change to restore.'}
        restore(pending['snapshot'])
        try:
            activate(pending['old_port'])
        except RuntimeError as err:
            # Files are back: the pending record stays so the next boot tries again.
            raise RuntimeError('Previous port restored on disk, but the panel did not restart: ' + str(err)[:200])
        PENDING.unlink(missing_ok=True)
        return {'ok': True, 'rolled_back': True, 'port': pending['old_port']}
    return locked(run_rollback)


def start(port):
    def perform():
        validate_port(port)
        if read_pending():
            raise RuntimeError('Previous change still pending. Confirm it or wait for the restore.')
        old = current_port()
        if port == old:
            raise ValueError('The panel already uses this port.')
        if port in listening_ports():
            raise ValueError('This port is already used by another service: choose another one.')
        snap = snapshot()
        for kind, path, required in MANAGED:     # refuse early, before any timer exists
            if path.exists():
                rewrite(kind, path.read_text(), port)
            elif required:
                raise RuntimeError('File missing, automatic change blocked: %s' % path.name)
        sid = uuid.uuid4().hex[:14]
        pending = {'id': sid, 'old_port': old, 'new_port': port, 'snapshot': snap,
                   'expires_at': int(time.time()) + WAIT_SECONDS, 'state': 'scheduled'}
        # Nothing is applied if the persistent restore timer cannot be created.
        timer = shell(['systemd-run', '--quiet', '--unit=tspanel-port-rollback-' + sid,
                       '--on-active=%ds' % WAIT_SECONDS, str(SELF), '--rollback', sid], 20)
        if timer.returncode:
            raise RuntimeError('Unable to create the restore timer: ' + timer.stderr[-200:])
        atomic_write(STATE / ('backup-' + sid + '.json'), json.dumps(snap).encode(), 0o600)
        atomic_write(PENDING, json.dumps(pending).encode(), 0o600)
        apply_timer = shell(['systemd-run', '--quiet', '--unit=tspanel-port-apply-' + sid,
                             '--on-active=%ds' % APPLY_DELAY, str(SELF), '--apply', sid], 20)
        if apply_timer.returncode:
            PENDING.unlink(missing_ok=True)
            cancel_timers(sid)
            raise RuntimeError('Unable to start the port change: ' + apply_timer.stderr[-200:])
        return {'ok': True, 'id': sid, 'old_port': old, 'new_port': port, 'expires_at': pending['expires_at']}
    return locked(perform)


def apply(sid):
    def prepare():
        pending = read_pending()
        if not pending or pending['id'] != sid or pending.get('state') != 'scheduled':
            return None
        try:
            write_port(pending['new_port'])
        except (RuntimeError, OSError):
            restore(pending['snapshot'])
            PENDING.unlink(missing_ok=True)
            cancel_timers(sid)
            raise
        pending['state'] = 'applying'
        atomic_write(PENDING, json.dumps(pending).encode(), 0o600)
        return pending
    pending = locked(prepare)
    if pending is None:
        return {'ok': True, 'note': 'Change already completed.'}
    try:
        activate(pending['new_port'])
    except RuntimeError:
        rollback(sid)
        raise

    def mark():
        current = read_pending()
        if current and current['id'] == sid:
            current['state'] = 'applied'
            atomic_write(PENDING, json.dumps(current).encode(), 0o600)
    locked(mark)
    return {'ok': True, 'applied': True}


def confirm(sid, port):
    def run_confirm():
        pending = read_pending()
        if not pending or pending['id'] != sid:
            raise ValueError('No pending change with this identifier.')
        if pending.get('state') != 'applied':
            raise ValueError('Change not applied yet: wait and try again.')
        # The request must have arrived on the NEW port: that is the whole point of the confirmation.
        if port != pending['new_port']:
            raise ValueError('Open the panel on the new port to confirm.')
        if pending['new_port'] not in listening_ports():
            raise ValueError('The new port is not active yet: not confirming.')
        PENDING.unlink(missing_ok=True)
        return {'ok': True, 'confirmed': True, 'port': pending['new_port']}
    result = locked(run_confirm)
    cancel_timers(sid)
    return result


def set_port(port):
    """Root-only, from the command line (SSH/console): immediate change without confirmation.

    For when the panel cannot be reached any more (for instance the customer's router started to
    block the port after the change had been confirmed). Not reachable from the web: sudoers allows
    the helper without arguments only.
    """
    def perform():
        validate_port(port)
        if read_pending():
            raise RuntimeError('Previous change still pending. Confirm it or wait for the restore.')
        old = current_port()
        if port == old:
            return None, old
        if port in listening_ports():
            raise ValueError('This port is already used by another service: choose another one.')
        snap = snapshot()
        write_port(port)
        return snap, old
    snap, old = locked(perform)
    if snap is None:
        return {'ok': True, 'port': port, 'note': 'The panel already uses this port.'}
    try:
        activate(port)
    except RuntimeError:
        restore(snap)
        activate(old)
        raise
    return {'ok': True, 'port': port}


def api():
    data = sys.stdin.buffer.read(4097)
    if len(data) > 4096:
        raise ValueError('Request too large')
    payload = json.loads(data)
    if not isinstance(payload, dict):
        raise ValueError('Invalid request')
    action = payload.get('action')
    if action == 'status' and set(payload) == {'action'}:
        return {'ok': True, 'port': get_current()}
    if action == 'start' and set(payload) == {'action', 'port'}:
        return start(payload['port'])
    if action == 'confirm' and set(payload) == {'action', 'id', 'port'}:
        sid = payload['id']
        if not isinstance(sid, str) or not re.fullmatch('[0-9a-f]{14}', sid):
            raise ValueError('Invalid confirmation ID')
        return confirm(sid, payload['port'])
    raise ValueError('Action or parameters not allowed.')


def main():
    if os.geteuid() != 0:
        raise ValueError('Port access not authorised')
    os.umask(0o077)
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(STATE, 0o700)
    if len(sys.argv) == 2 and sys.argv[1] == '--recover':
        pending = read_pending()
        result = rollback(pending['id']) if pending else {'ok': True, 'note': 'No restore needed.'}
    elif len(sys.argv) == 3 and sys.argv[1] == '--set-port':
        result = set_port(int(sys.argv[2]))
    elif len(sys.argv) == 3 and sys.argv[1] in ('--apply', '--rollback'):
        sid = sys.argv[2]
        if not re.fullmatch('[0-9a-f]{14}', sid):
            raise ValueError('Invalid internal ID')
        result = apply(sid) if sys.argv[1] == '--apply' else rollback(sid)
    elif len(sys.argv) == 1:
        result = api()
    else:
        raise ValueError('Arguments not allowed.')
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        print(json.dumps({'ok': False, 'error': str(e)[:500]}))
        sys.exit(1)
