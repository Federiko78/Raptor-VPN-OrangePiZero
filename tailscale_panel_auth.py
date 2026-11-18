#!/usr/bin/env python3
"""Raptor VPN - accesso a Tailscale dal pannello (programma root, chiamato dal pannello con sudo -n).

Legge UNA richiesta JSON da stdin e risponde con UNA riga JSON. Azioni:

  {"action": "login_url", "hostname": "nome-facoltativo"}
      Avvia l'accesso con link: restituisce l'indirizzo da aprire con un browser e un account Tailscale.
  {"action": "login_key", "key": "tskey-auth-...", "tags": ["tag:cliente"], "hostname": "..."}
      Accesso senza browser con una chiave di autenticazione (e, se serve, i tag). La chiave passa
      da un file 0600 su /run (memoria, mai sulla microSD) e non compare mai tra gli argomenti dei
      programmi ne' nelle risposte.
  {"action": "connect"}
      Riattiva una scheda gia' autenticata ma ferma ("tailscale down"), senza cambiare impostazioni.
  {"action": "logout"}
      Scollega la scheda dall'account (dopo, serve un nuovo accesso).

Ogni campo e' controllato con espressioni rigide prima di arrivare alla riga di comando.
"""
import fcntl
import json
import os
import re
import subprocess
import sys
import tempfile
import time

TAILSCALE = '/usr/bin/tailscale'
RUN_DIR = '/run'
LOCK_PATH = '/run/raptor-tsauth.lock'
MAX_BODY = 2048

KEY_RE = re.compile(r'^tskey-(auth|client)-[A-Za-z0-9_-]{6,200}$')
TAG_RE = re.compile(r'^tag:[a-z][a-z0-9-]{0,62}$')
HOST_RE = re.compile(r'^[a-z0-9][a-z0-9-]{0,62}$')
URL_RE = re.compile(r'https://[A-Za-z0-9.-]+\.tailscale\.com/a/[A-Za-z0-9_-]{4,64}')
MAX_TAGS = 5

LOGIN_URL_WAIT = '15s'
LOGIN_KEY_WAIT = '45s'
CONNECT_RUN_SECONDS = 25    # limite per "tailscale up" (senza opzioni: niente --timeout, vedi connect())
CONNECT_SETTLE = 8.0        # dopo "up" lo stato puo' impiegare qualche istante a diventare Running


class Refused(Exception):
    """Richiesta non valida o non consentita: il testo e' pensato per essere mostrato all'operatore."""


def check_hostname(value):
    if value in (None, ''):
        return ''
    if not isinstance(value, str) or not HOST_RE.match(value) or value.endswith('-'):
        raise Refused('Invalid board name: lowercase letters, numbers and hyphens only (max 63).')
    return value


def check_tags(value):
    if value in (None, []):
        return []
    if not isinstance(value, list) or len(value) > MAX_TAGS:
        raise Refused('Invalid tags (at most %d).' % MAX_TAGS)
    tags = []
    for tag in value:
        if not isinstance(tag, str) or not TAG_RE.match(tag):
            raise Refused('Invalid tag: use the format tag:name (lowercase, numbers, hyphens).')
        if tag not in tags:
            tags.append(tag)
    return tags


def check_key(value):
    if not isinstance(value, str) or not KEY_RE.match(value.strip()):
        raise Refused('Invalid key: it must start with tskey-auth- (or tskey-client-).')
    return value.strip()


def validate(body):
    """Ritorna (azione, parametri) oppure solleva Refused."""
    if not isinstance(body, dict) or not isinstance(body.get('action'), str):
        raise Refused('Invalid request.')
    action = body['action']
    allowed = {'login_url': {'action', 'hostname'},
               'login_key': {'action', 'key', 'tags', 'hostname'},
               'connect': {'action'},
               'down': {'action'},
               'logout': {'action'}}.get(action)
    if allowed is None or not set(body) <= allowed:
        raise Refused('Invalid request.')
    if action in ('logout', 'connect', 'down'):
        return action, {}
    params = {'hostname': check_hostname(body.get('hostname'))}
    if action == 'login_key':
        params['key'] = check_key(body.get('key'))
        params['tags'] = check_tags(body.get('tags'))
    return action, params


def run(argv, timeout):
    """Esegue un programma senza shell, con ambiente minimo. Ritorna (codice, testo)."""
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
    try:
        done = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=timeout, env=env, check=False)
        return done.returncode, done.stdout.decode('utf-8', 'replace')
    except subprocess.TimeoutExpired as exc:
        return 124, (exc.stdout or b'').decode('utf-8', 'replace')
    except OSError as exc:
        return 127, str(exc)


def backend_state():
    """Stato di Tailscale e, se c'e', l'indirizzo di accesso in attesa."""
    code, text = run([TAILSCALE, 'status', '--json'], 10)
    try:
        data = json.loads(text)
    except ValueError:
        return None, ''
    if not isinstance(data, dict):
        return None, ''
    url = data.get('AuthURL')
    url = url if isinstance(url, str) and URL_RE.fullmatch(url) else ''
    state = data.get('BackendState')
    return (state if isinstance(state, str) else None), url


def scrub(text, secret=''):
    """Testo di errore breve e mai con la chiave dentro."""
    if secret:
        text = text.replace(secret, '***')
    text = re.sub(r'tskey-[A-Za-z0-9_-]+', 'tskey-***', text)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return ' '.join(lines)[:240]


def common_flags(params):
    flags = []
    if params.get('hostname'):
        flags.append('--hostname=' + params['hostname'])
    return flags


def login_url(params):
    state, _ = backend_state()
    if state == 'Running':
        raise Refused('The board is already connected to Tailscale: disconnect it before switching account.')
    code, text = run([TAILSCALE, 'login', '--timeout=' + LOGIN_URL_WAIT] + common_flags(params), 40)
    found = URL_RE.search(text)
    url = found.group(0) if found else ''
    if not url:
        state, url = backend_state()
        if state == 'Running':
            return {'ok': True, 'connected': True}
    if not url:
        raise Refused('Tailscale did not return the login link. ' + scrub(text))
    return {'ok': True, 'auth_url': url}


def login_key(params):
    state, _ = backend_state()
    if state == 'Running':
        raise Refused('The board is already connected to Tailscale: disconnect it before using a key.')
    fd, path = tempfile.mkstemp(prefix='tskey-', dir=RUN_DIR)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(params['key'] + '\n')
        argv = [TAILSCALE, 'login', '--auth-key=file:' + path, '--timeout=' + LOGIN_KEY_WAIT]
        if params['tags']:
            argv.append('--advertise-tags=' + ','.join(params['tags']))
        argv += common_flags(params)
        code, text = run(argv, 70)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    if code != 0:
        state, _ = backend_state()
        if state != 'Running':
            raise Refused('Key login failed: ' + (scrub(text, params['key']) or 'no answer from Tailscale.'))
    return {'ok': True, 'connected': True}


def connect(_params):
    state, _ = backend_state()
    if state == 'Running':
        return {'ok': True, 'connected': True}
    # "tailscale up" SENZA NESSUN FLAG e' la ripresa semplice: riaccende e basta, e rotte, DNS e il resto restano come sono.
    # Con qualunque flag, anche solo --timeout, tailscale controlla invece che si citino tutte le impostazioni non
    # predefinite e si ferma con "changing settings via 'tailscale up' requires mentioning all non-default flags".
    # Per questo il limite di tempo e' del processo (run), non di tailscale.
    code, text = run([TAILSCALE, 'up'], CONNECT_RUN_SECONDS)
    deadline = time.monotonic() + (CONNECT_SETTLE if code == 0 else 0)
    while True:
        state, url = backend_state()
        if state == 'Running':
            return {'ok': True, 'connected': True}
        if url or time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    found = URL_RE.search(text)
    url = url or (found.group(0) if found else '')
    if url:
        return {'ok': True, 'auth_url': url}
    raise Refused('Unable to reactivate Tailscale: ' + (scrub(text) or 'no answer.'))


def down(_params):
    """Spegne Tailscale (tailscale down): resta autenticata, si riaccende con "connect" senza un nuovo accesso."""
    code, text = run([TAILSCALE, 'down'], 30)
    state, _ = backend_state()
    if state == 'Stopped' or (code == 0 and state != 'Running'):
        return {'ok': True}
    raise Refused('Unable to turn Tailscale off: ' + (scrub(text) or 'no answer.'))


def logout(_params):
    code, text = run([TAILSCALE, 'logout'], 30)
    if code != 0:
        raise Refused('Disconnect failed: ' + (scrub(text) or 'no answer from Tailscale.'))
    return {'ok': True}


ACTIONS = {'login_url': login_url, 'login_key': login_key, 'connect': connect, 'down': down, 'logout': logout}


def main():
    try:
        if os.geteuid() != 0:
            raise Refused('This program must run as root.')
        if len(sys.argv) != 1:
            raise Refused('Arguments not allowed.')
        raw = sys.stdin.buffer.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raise Refused('Request too large.')
        try:
            body = json.loads(raw.decode('utf-8'))
        except ValueError:
            raise Refused('Invalid request.')
        action, params = validate(body)
        with open(LOCK_PATH, 'a+') as lock:
            os.fchmod(lock.fileno(), 0o600)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise Refused('A login is already in progress: wait a few seconds.')
            result = ACTIONS[action](params)
    except Refused as exc:
        result = {'ok': False, 'error': str(exc)}
    except Exception:      # nessun dettaglio interno verso il pannello
        result = {'ok': False, 'error': 'Internal error while logging in to Tailscale.'}
    sys.stdout.write(json.dumps(result, ensure_ascii=False) + '\n')
    return 0 if result.get('ok') else 1


if __name__ == '__main__':
    sys.exit(main())
