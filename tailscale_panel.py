#!/usr/bin/env python3
"""Raptor VPN - pannello Tailscale 1.6.0: accesso Tailscale, host LAN selezionati, DHCP/IP statico, HTTPS."""
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import string
import shutil
import ssl
import subprocess
import tempfile
import sys
import threading
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from password_policy import password_error, POLICY_DESCRIPTION
from panel_assets import EYE_B64

AUTH_PATH = '/etc/tailscale-panel/auth.json'
STATE_PATH = '/var/lib/tailscale-panel/settings.json'
# Registro eventi scritto SOLO da raptor-eventlog (root): il pannello lo legge e basta.
EVENTS_PATH = '/var/lib/raptor-events/events.jsonl'
EVENTS_TAIL_BYTES = 128 * 1024     # si legge solo la coda del file
EVENTS_LIMIT = 200                 # eventi restituiti (i piu' recenti)
EVENT_TYPES = ('boot', 'shutdown', 'unclean_shutdown', 'clock_synced')
CERT_PATH = '/etc/tailscale-panel/cert.pem'
KEY_PATH = '/etc/tailscale-panel/key.pem'
HELPER = '/usr/local/libexec/tailscale-panel-helper'
NET_HELPER = '/usr/local/libexec/tailscale-panel-net-helper'
DISCOVERY_HELPER = '/usr/local/libexec/tailscale-panel-discovery'
AUTH_HELPER = '/usr/local/libexec/tailscale-panel-auth'
# Link di accesso Tailscale: ammesso solo https verso *.tailscale.com/a/<codice>.
AUTH_URL_RE = re.compile(r'https://[A-Za-z0-9.-]+\.tailscale\.com/a/[A-Za-z0-9_-]{4,64}')
TAG_RE = re.compile(r'tag:[a-z][a-z0-9-]{0,62}')
PORT = int(os.environ.get('PANEL_PORT', '8443'))
LAN_DEV = os.environ.get('PANEL_LAN_DEV', 'end0')
SESSIONS = {}
FAILURES = {}
LOCK = threading.Lock()
# Limiti di robustezza: la scheda ha circa 512 MB di RAM ed e' esposta alla LAN del cliente.
MAX_CONNECTIONS = 24         # connessioni simultanee; oltre, la connessione viene chiusa subito
HANDSHAKE_TIMEOUT = 10       # secondi concessi per completare l'handshake TLS
REQUEST_DEADLINE = 120       # durata massima di una connessione (anti slowloris)
FAILURE_WINDOW = 900         # finestra di conteggio dei login falliti (15 minuti)
LOGIN_FAILURES_PER_IP = 5
LOGIN_FAILURES_GLOBAL = 20   # tutti gli IP insieme: frena il brute force da piu' indirizzi
HASH_SLOTS = threading.Semaphore(2)  # al massimo 2 PBKDF2 in parallelo, FUORI dal LOCK globale
DEFAULTS = {'subnets':'', 'advertise':False, 'mode':'off', 'selected_hosts':[],
            'snat':True, 'accept_routes':False, 'accept_dns':True, 'auto_update':False}


def run(args, timeout=6, input_text=None):
    return subprocess.run(args, input=input_text, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, universal_newlines=True, timeout=timeout)


def read_json(path, fallback=None):
    try:
        with open(path, encoding='utf-8') as handle:
            return json.load(handle)
    except (IOError, OSError, ValueError):
        return fallback


def password_record(password):
    # Preserve the existing PBKDF2-SHA256 password format for upgrades.
    salt = os.urandom(16)
    iterations = 220000
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    return {'salt': base64.b64encode(salt).decode('ascii'),
            'digest': base64.b64encode(digest).decode('ascii'),
            'iterations': iterations}


def write_password(password):
    """Safely replace only the password file; never truncate the working hash."""
    directory = os.path.dirname(AUTH_PATH)
    os.makedirs(directory, mode=0o750, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.auth-', suffix='.tmp', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(password_record(password), handle, separators=(',', ':'))
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, AUTH_PATH)
        # Persist the rename when possible; failure here must not destroy the file.
        directory_fd = os.open(directory, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def password_version():
    """Tie sessions to the current credential file, including CLI resets."""
    try:
        with open(AUTH_PATH, 'rb') as handle:
            return hashlib.sha256(handle.read(4096)).digest()
    except OSError:
        return None


def make_password():
    # Random reset passwords satisfy the same policy without reducing entropy.
    chars = [secrets.choice(string.ascii_uppercase),
             secrets.choice(string.ascii_lowercase),
             secrets.choice(string.digits)]
    pool = string.ascii_letters + string.digits + '-_'
    chars.extend(secrets.choice(pool) for _ in range(21))
    secrets.SystemRandom().shuffle(chars)
    password = ''.join(chars)
    write_password(password)
    return password


def verify_password(password):
    auth = read_json(AUTH_PATH)
    if not auth or not isinstance(password, str):
        return False
    try:
        salt = base64.b64decode(auth['salt'])
        expected = base64.b64decode(auth['digest'])
        iterations = int(auth['iterations'])
        if not 100000 <= iterations <= 1000000:
            return False
        actual = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
        return hmac.compare_digest(expected, actual)
    except (KeyError, ValueError, TypeError):
        return False


def saved_state():
    state = read_json(STATE_PATH, {})
    if not isinstance(state, dict):
        state = {}
    if 'mode' not in state:  # migrate R1.2 state without changing active routes
        state['mode'] = 'all' if state.get('advertise') else 'off'
    return dict(DEFAULTS, **{key: state[key] for key in DEFAULTS if key in state})


def save_state(payload):
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    path = STATE_PATH + '.tmp'
    with open(path, 'w', encoding='utf-8') as out:
        json.dump(payload, out)
        out.write('\n')
    os.replace(path, STATE_PATH)


def pref(flag):
    """Return real active CLI preference, or None when CLI cannot read it."""
    try:
        cmd = run(['/usr/bin/tailscale', 'get', '--json', flag])
        if cmd.returncode:
            return None
        data = json.loads(cmd.stdout)
        if isinstance(data, dict):
            data = data.get(flag, data.get(flag.replace('-', '_'), None))
        return data
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def lan_details():
    """Read the *actual* Ethernet address on every API request; never cache it."""
    details = {'device':LAN_DEV, 'ip':'-', 'subnet':'', 'gateway':'-',
               'dhcp':'Non verificato', 'web_name':socket.gethostname()+'.local'}
    try:
        ip_cmd = shutil.which('ip') or '/usr/bin/ip'
        response = run([ip_cmd, '-j', '-4', 'addr', 'show', 'dev', LAN_DEV])
        if response.returncode:
            return details
        interfaces = json.loads(response.stdout)
        for iface in interfaces:
            for addr in iface.get('addr_info', []):
                if addr.get('family') != 'inet' or addr.get('scope') != 'global':
                    continue
                ip = addr.get('local','')
                if ip.startswith('169.254.'):
                    continue  # indirizzo di recupero (link-local): mai mostrato come IP LAN
                mask = addr.get('prefixlen', 24)
                network = ipaddress.ip_network('%s/%s' % (ip,mask), strict=False)
                if not isinstance(network, ipaddress.IPv4Network):
                    continue
                details['ip'] = ip
                details['subnet'] = str(network)
                # Kernel marks DHCP-leased IP addresses as dynamic.
                if addr.get('dynamic') is True or 'dynamic' in addr.get('flags', []):
                    details['dhcp'] = 'Attivo (indirizzo dinamico)'
                break
        route = run([ip_cmd, '-j', '-4', 'route', 'show', 'default'])
        if route.returncode == 0:
            for entry in json.loads(route.stdout):
                if entry.get('dev') == LAN_DEV:
                    details['gateway'] = entry.get('gateway', '-')
                    if entry.get('protocol') == 'dhcp':
                        details['dhcp'] = 'Attivo'
                    break
        # IP addresses without a dynamic flag can still originate from DHCP;
        # show unknown rather than incorrectly claiming that DHCP is off.
        return details
    except (OSError, ValueError, subprocess.TimeoutExpired, TypeError, KeyError):
        return details


def _event_int(value):
    """Intero ragionevole (secondi Unix tra il 2001 e il 2100) oppure None."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 1_000_000_000 <= value <= 4_102_444_800 else None


def events_data(path=None, now=None):
    """Registro eventi per l'interfaccia: sola lettura, ogni campo controllato (mai HTML grezzo)."""
    path = path or EVENTS_PATH
    now = time.time() if now is None else now
    try:
        with open(path, 'rb') as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - EVENTS_TAIL_BYTES))
            raw = handle.read(EVENTS_TAIL_BYTES + 1)
    except FileNotFoundError:
        return {'available': False, 'reason': 'Registro eventi non ancora attivo su questa scheda (installare raptor-eventlog).'}
    except OSError:
        return {'available': False, 'reason': 'Registro eventi non leggibile.'}
    lines = raw.decode('utf-8', 'replace').splitlines()
    if size > EVENTS_TAIL_BYTES and lines:
        lines = lines[1:]                      # la prima riga della coda puo' essere tagliata a meta'
    events = []
    for line in lines:
        try:
            item = json.loads(line)
        except ValueError:
            continue                          # ultima riga rovinata da uno spegnimento di colpo
        if not isinstance(item, dict) or item.get('type') not in EVENT_TYPES:
            continue
        epoch = _event_int(item.get('epoch'))
        if epoch is None:
            continue
        clean = {'type': item['type'], 'epoch': epoch}
        for key in ('previous', 'kind'):
            value = item.get(key)
            if isinstance(value, str) and 0 < len(value) <= 32 and all(c.islower() or c == '_' for c in value):
                clean[key] = value
        for key in ('clock_synced', 'logged_late'):
            if isinstance(item.get(key), bool):
                clean[key] = item[key]
        for key in ('last_seen_epoch', 'previous_last_seen_epoch', 'detected_epoch'):
            value = _event_int(item.get(key))
            if value is not None:
                clean[key] = value
        jump = item.get('jump_seconds')
        if isinstance(jump, int) and not isinstance(jump, bool) and abs(jump) < 10 ** 9:
            clean['jump_seconds'] = jump
        events.append(clean)
    try:
        with open('/proc/uptime') as handle:
            uptime = int(float(handle.read().split()[0]))
    except (OSError, ValueError, IndexError):
        uptime = 0
    month_ago = now - 30 * 86400
    recent = [e for e in events if e['epoch'] >= month_ago]
    unclean = [e for e in events if e['type'] == 'unclean_shutdown']
    return {'available': True,
            'events': events[-EVENTS_LIMIT:][::-1],            # piu' recenti per primi (ordine di scrittura)
            'summary': {'now': int(now), 'uptime_seconds': uptime, 'boot_epoch': int(now - uptime),
                        'boots_30d': sum(1 for e in recent if e['type'] == 'boot'),
                        'unclean_30d': sum(1 for e in recent if e['type'] == 'unclean_shutdown'),
                        'last_unclean_epoch': unclean[-1]['epoch'] if unclean else None,
                        'total': len(events)}}


def status_data():
    result = {'backend':'Non disponibile', 'tailscale_ip':'-', 'hostname':'-',
              'tailnet':'-', 'error':'', 'version':'-', 'lan':lan_details(),
              'forwarding':False, 'settings':saved_state(), 'cli_read_ok':False,
              'auth_url':'', 'tags':[]}
    try:
        p = run(['/usr/bin/tailscale', 'status', '--json'])
        if p.returncode:
            result['error'] = (p.stderr or p.stdout).strip()[:250]
        else:
            s = json.loads(p.stdout)
            self_node = s.get('Self') or {}
            result['backend'] = s.get('BackendState', 'Sconosciuto')
            result['hostname'] = self_node.get('HostName') or '-'
            result['tailscale_ip'] = ', '.join(self_node.get('TailscaleIPs') or []) or '-'
            tailnet = s.get('CurrentTailnet') or {}
            result['tailnet'] = tailnet.get('Name', '-')
            url = s.get('AuthURL')
            if isinstance(url, str) and AUTH_URL_RE.fullmatch(url):
                result['auth_url'] = url
            tags = self_node.get('Tags')
            if isinstance(tags, list):
                result['tags'] = [t for t in tags[:10] if isinstance(t, str) and TAG_RE.fullmatch(t)]
        v = run(['/usr/bin/tailscale', 'version'])
        if v.returncode == 0:
            result['version'] = v.stdout.splitlines()[0].strip()
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        result['error'] = str(exc)[:250]
    try:
        with open('/proc/sys/net/ipv4/ip_forward') as stream:
            result['forwarding'] = stream.read().strip() == '1'
    except OSError:
        pass
    settings = result['settings']
    routes = pref('advertise-routes')
    if routes is not None:
        if isinstance(routes, (list, str)):
            actual = [str(r).strip() for r in routes] if isinstance(routes, list) else [r.strip() for r in routes.split(',') if r.strip()]
            settings['advertise'] = bool(actual)
            result['cli_read_ok'] = True
            if not actual:
                settings['mode'] = 'off'
            elif all(r.endswith('/32') for r in actual):
                settings['mode'] = 'selected'
                settings['selected_hosts'] = [r.rsplit('/',1)[0] for r in actual]
            else:
                settings['mode'] = 'all'
                settings['subnets'] = ', '.join(actual)
    for flag, key in [('snat-subnet-routes','snat'),
                      ('accept-routes','accept_routes'), ('accept-dns','accept_dns'),
                      ('auto-update','auto_update')]:
        value = pref(flag)
        if isinstance(value, bool):
            settings[key] = value
    try:
        proc=run(['/usr/bin/sudo','-n',NET_HELPER], timeout=9,
                 input_text=json.dumps({'action':'status'}))
        net_status=read_json_from_string(proc.stdout)
        result['network'] = net_status.get('network', {'supported':False, 'reason':proc.stderr.strip()[:250] or 'Gestione Ethernet non disponibile'})
    except (OSError, subprocess.TimeoutExpired) as err:
        result['network']={'supported':False, 'reason':str(err)[:250]}
    return result


def tailscale_auth(request):
    """Chiede al programma root di fare login/logout/connect. Risposta ripulita: mai testo non controllato."""
    try:
        proc = run(['/usr/bin/sudo', '-n', AUTH_HELPER], timeout=85, input_text=json.dumps(request))
    except subprocess.TimeoutExpired:
        return {'ok':False, 'error':'Tailscale non ha risposto in tempo: controlla lo stato e riprova.'}
    except OSError as exc:
        return {'ok':False, 'error':'Programma di accesso non disponibile: %s' % str(exc)[:120]}
    reply = read_json_from_string(proc.stdout)
    if proc.returncode == 0 and reply.get('ok') is True:
        out = {'ok':True}
        if reply.get('connected') is True:
            out['connected'] = True
        url = reply.get('auth_url')
        if isinstance(url, str) and AUTH_URL_RE.fullmatch(url):
            out['auth_url'] = url
        return out
    error = reply.get('error')
    if not isinstance(error, str) or not error.strip():
        error = 'Operazione non riuscita: programma di accesso non installato o non autorizzato (rilancia install_tailscale_panel.sh).'
    return {'ok':False, 'error':error.strip()[:300]}


STYLE = '''
:root{color-scheme:dark;--bg:#090d11;--panel:#10161c;--panel2:#151c23;--edge:#29323b;--edge2:#34404b;--text:#e9eef3;--muted:#94a1ad;--gold:#f5bd12;--gold-hi:#ffd84a;--green:#00e58a;--red:#ff3658;--blue:#5aa9ff;--radius:10px;--focus:0 0 0 2px #090d11,0 0 0 4px #f5bd12}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
[hidden],.hidden{display:none!important}
body{margin:0;min-height:100vh;background:radial-gradient(ellipse at 0 0,rgba(245,189,18,.07),transparent 42%),radial-gradient(ellipse at 100% 100%,rgba(90,169,255,.045),transparent 40%),var(--bg);color:var(--text);font:15px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
:focus-visible{outline:none;box-shadow:var(--focus)}
button,input,select{font:inherit;color:inherit}
h1,h2{margin:0}
.top{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:24px;padding:8px 20px;background:linear-gradient(180deg,#10161c,#0c1116);border-bottom:1px solid var(--edge);box-shadow:0 5px 20px rgba(0,0,0,.22)}
.brand{display:flex;align-items:center;gap:12px;color:inherit;text-decoration:none;flex-shrink:0}
.eye{width:46px;height:39px;background:url(data:image/png;base64,__EYE__) center/contain no-repeat;filter:drop-shadow(0 0 8px rgba(245,189,18,.18))}
.word{display:block;font-size:21px;font-weight:800;letter-spacing:5px;line-height:1;text-transform:uppercase}
.word b{color:var(--gold)}
.tag{display:block;margin-top:5px;font-size:9px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:var(--muted)}
.tabs{display:flex;gap:2px;align-self:stretch;min-width:0;overflow-x:auto;scrollbar-width:none}
.tabs::-webkit-scrollbar{display:none}
.tab{display:flex;align-items:center;min-height:48px;padding:0 11px;border-bottom:3px solid transparent;font-size:12.5px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;white-space:nowrap;color:#a6b0bb;text-decoration:none}
.tab:hover{color:#f2f5f7;border-bottom-color:var(--edge2)}
.top-right{margin-left:auto;display:flex;align-items:center;gap:10px}
.top-right form{margin:0}
.pill{padding:3px 10px;border:1px solid var(--edge2);border-radius:999px;font-size:12px;font-weight:700;letter-spacing:.4px;color:var(--muted);white-space:nowrap}
main{max-width:1100px;margin:0 auto;padding:26px 20px 70px}
section[id]{scroll-margin-top:76px}
.shell{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:0 0 16px}
.card{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--edge);border-radius:var(--radius);padding:20px 22px;box-shadow:0 8px 28px rgba(0,0,0,.32)}
.card .meta{font-size:11px;font-weight:800;letter-spacing:1.5px;text-transform:uppercase;color:var(--muted)}
.big{margin:10px 0 6px;font-size:20px;font-weight:750;overflow-wrap:anywhere}
small,.muted{color:var(--muted)}
.dot{display:inline-block;width:9px;height:9px;margin-right:8px;border-radius:50%;background:var(--gold);box-shadow:0 0 10px rgba(245,189,18,.45)}
.dot.good{background:var(--green);box-shadow:0 0 10px rgba(0,229,138,.5)}
.dot.bad{background:var(--red);box-shadow:0 0 10px rgba(255,54,88,.5)}
.columns{display:grid;grid-template-columns:1.7fr 1fr;gap:16px;margin-top:16px}
.accountcard,.networkcard,.discoverycard,.securitycard,.eventscard{margin-top:16px}
.shell+.accountcard{margin-top:0}
.subhead{position:relative;margin:0 0 8px;padding-left:12px;font-size:18px;font-weight:800;letter-spacing:.2px}
.subhead:before{content:"";position:absolute;left:0;top:3px;bottom:3px;width:3px;border-radius:2px;background:var(--gold)}
p{color:#a9b4bf;line-height:1.6}
a{color:var(--gold-hi)}
a:hover{color:#fff0a8}
.field{margin:18px 0}
.field label{display:block;margin-bottom:7px;font-size:11px;font-weight:800;letter-spacing:1.1px;text-transform:uppercase;color:#c2ccd6}
input[type=text],input[type=password],input[type=number],select{width:100%;padding:12px 13px;border:1px solid var(--edge2);border-radius:6px;background:#0b1117;color:var(--text);outline:none}
input[type=text]::placeholder,input[type=password]::placeholder,input[type=number]::placeholder{color:#66727e}
input[type=text]:focus,input[type=password]:focus,input[type=number]:focus,select:focus{border-color:var(--gold);box-shadow:0 0 0 2px rgba(245,189,18,.1)}
input[type=radio],input[type=checkbox]{accent-color:var(--gold)}
.formgrid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.formgrid .field{margin:8px 0}
.netmessage{font-size:14px;line-height:1.5}
.buttonrow{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-top:12px}
.radioopts{display:flex;gap:22px;flex-wrap:wrap;padding:14px 0}
.radioopts label{cursor:pointer}
.dangerlabel{color:#ff8da1}
.tgl{display:flex;align-items:center;justify-content:space-between;gap:18px;padding:16px 0;border-bottom:1px solid var(--edge)}
.tgl:last-of-type{border-bottom:0}
.tgl strong{display:block;margin-bottom:3px}
.tgl span{color:var(--muted);font-size:13px}
.switch{appearance:none;-webkit-appearance:none;position:relative;flex-shrink:0;width:47px;height:27px;border-radius:20px;background:#3a4650;cursor:pointer;transition:.2s}
.switch:before{content:'';position:absolute;top:4px;left:4px;width:19px;height:19px;border-radius:50%;background:#fff;transition:.2s}
.switch:checked{background:var(--gold)}
.switch:checked:before{left:24px;background:#10141a}
.action{padding:11px 20px;border:1px solid #ffe25f;border-radius:6px;background:linear-gradient(180deg,#ffd638,#f1bb13);color:#090b0e;font-size:13px;font-weight:900;letter-spacing:.9px;text-transform:uppercase;cursor:pointer;box-shadow:0 8px 22px rgba(240,196,25,.12)}
.action:hover{filter:brightness(1.06)}
.action:disabled{opacity:.5;cursor:wait;filter:none}
.quiet{padding:10px 15px;border:1px solid var(--edge2);border-radius:6px;background:transparent;color:#cbd4dd;font-size:13px;font-weight:700;letter-spacing:.4px;cursor:pointer}
.quiet:hover{border-color:var(--gold);color:var(--gold-hi)}
.quiet:disabled{opacity:.5;cursor:wait}
.danger{padding:10px 15px;border:1px solid rgba(255,54,88,.55);border-radius:6px;background:rgba(255,54,88,.1);color:#ff8da1;font-size:13px;font-weight:800;letter-spacing:.4px;cursor:pointer}
.danger:hover{background:rgba(255,54,88,.2)}
.footer{display:flex;align-items:center;gap:15px;margin-top:20px;flex-wrap:wrap}
#message{font-weight:600}
.ok{color:var(--green)}
.err{color:#ff8da1}
.devlist{margin-top:14px;display:grid;gap:8px}
.device{display:flex;gap:12px;align-items:flex-start;padding:13px;border:1px solid var(--edge);border-radius:8px;background:#0e141a}
.device:hover{border-color:var(--edge2)}
.device input{margin-top:5px}
.deviceinfo{min-width:0}
.deviceinfo strong{display:block}
.deviceinfo small{display:block;margin-top:3px;overflow-wrap:anywhere}
.scanmeta{margin-top:10px;color:var(--muted);font-size:13px}
.passwordinfo{margin-top:8px;font-size:13px;color:var(--muted)}
.notice{margin-top:15px;padding:13px 16px;border:1px solid rgba(245,189,18,.28);border-left:3px solid var(--gold);border-radius:8px;background:rgba(245,189,18,.05);color:#d4d9bd;line-height:1.6}
.notice.warnnotice{border-color:rgba(255,54,88,.4);border-left-color:var(--red);background:rgba(255,54,88,.06);color:#f1c9d0}
.value{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:14px;color:#dbe6f0;overflow-wrap:anywhere}
.device.alertrow{border-color:rgba(255,54,88,.45);background:rgba(255,54,88,.07)}
.device.alertrow strong{color:#ff8da1}
.evtime{font-variant-numeric:tabular-nums}
.authlink{display:block;margin:8px 0;padding:10px 12px;border:1px dashed var(--edge2);border-radius:6px;background:#0b1117;overflow-wrap:anywhere}
ul{padding-left:20px;color:#b4c0cc;line-height:1.9}
.authwrap{min-height:100vh;max-width:none;display:flex;align-items:center;justify-content:center;padding:18px}
.auth{position:relative;width:min(470px,100%);padding:20px 32px 24px;border:1px solid rgba(240,196,25,.72);border-radius:7px;background:linear-gradient(155deg,rgba(13,20,27,.985),rgba(5,10,15,.97));box-shadow:0 26px 78px rgba(0,0,0,.64),0 0 30px rgba(240,196,25,.07);clip-path:polygon(14px 0,calc(100% - 20px) 0,100% 18px,100% calc(100% - 14px),calc(100% - 16px) 100%,0 100%,0 14px)}
.auth:before{content:"";position:absolute;left:22px;right:22px;top:0;height:1px;background:linear-gradient(90deg,transparent,#f0c419 35%,#ffe36a 50%,#f0c419 65%,transparent);opacity:.68;box-shadow:0 0 16px rgba(240,196,25,.4)}
.auth .eye{width:92px;height:79px;margin:0 auto 4px}
.authbrand{text-align:center;font-size:30px;font-weight:800;letter-spacing:8px;text-transform:uppercase}
.authbrand b{color:var(--gold)}
.authsub{margin:16px 0 0;text-align:center;font-size:14px;font-weight:700;letter-spacing:5px;text-transform:uppercase;color:#edf2f6}
.authsub b{color:#f0c419}
.authtag{margin-top:7px;text-align:center;font-size:8px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#a5afb9}
.authrule{position:relative;width:68%;height:1px;margin:14px auto 18px;background:linear-gradient(90deg,transparent,#59616a 24%,#59616a 76%,transparent)}
.authrule:after{content:"";position:absolute;left:50%;top:-1px;width:38px;height:3px;transform:translateX(-50%);border-radius:3px;background:#f0c419;box-shadow:0 0 14px rgba(240,196,25,.35)}
.authform{display:flex;flex-direction:column;gap:12px}
.authform label{display:flex;flex-direction:column;gap:6px;font-size:10px;font-weight:900;letter-spacing:1.7px;color:#e5eaf0}
.authform input{height:44px;padding:0 14px;border:1px solid #536170;border-radius:6px;background:rgba(5,11,16,.84);color:#f2f5f7;font-size:15px}
.authform input:focus{border-color:#f0c419;box-shadow:0 0 0 2px rgba(240,196,25,.1),0 0 24px rgba(240,196,25,.07)}
.authform button{height:50px;margin-top:4px;border:1px solid #ffe25f;border-radius:4px;background:linear-gradient(180deg,#ffd638,#f1bb13);color:#090b0e;font-size:15px;font-weight:900;letter-spacing:1.4px;cursor:pointer;box-shadow:0 10px 28px rgba(240,196,25,.16),0 0 0 1px rgba(255,255,255,.18) inset;clip-path:polygon(9px 0,calc(100% - 9px) 0,100% 9px,100% calc(100% - 9px),calc(100% - 9px) 100%,9px 100%,0 calc(100% - 9px),0 9px)}
.authform button:after{content:"  →"}
.authform button:hover{filter:brightness(1.06)}
.authmsg{margin:14px 0 0;padding:8px 10px;border:1px solid #8e3636;border-radius:6px;background:rgba(58,23,23,.92);color:#ff9898;font-size:12px;font-weight:800}
.authfoot{margin-top:16px;text-align:center;font-size:9px;letter-spacing:1.7px;text-transform:uppercase;color:#6d7781}
.authfoot:before{content:"◆";margin-right:9px;color:#f0c419}
@media(max-width:900px){.top{position:static;gap:14px;padding:8px 12px;flex-wrap:wrap}.tabs{order:3;flex-basis:100%}.tab{min-height:40px}}
@media(max-width:480px){.pill{display:none}}
@media(max-width:770px){.formgrid{grid-template-columns:1fr}.shell{grid-template-columns:1fr}.columns{grid-template-columns:1fr}main{padding:18px 14px 60px}.word{font-size:18px;letter-spacing:4px}.authwrap .auth{padding:16px 18px 20px}.authform input{font-size:16px}}
'''


def page(body, extra=''):
    icon = 'data:image/png;base64,' + EYE_B64
    return ('<!doctype html><html lang="it"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta name="theme-color" content="#090d11"><meta name="color-scheme" content="dark">'
            '<title>Raptor VPN</title><link rel="icon" type="image/png" href="' + icon + '">'
            '<style>' + STYLE.replace('__EYE__', EYE_B64) + '</style></head><body>' + body + extra + '</body></html>')


LOGIN = '''<main class="authwrap"><section class="auth"><div class="eye" role="img" aria-label="Raptor"></div>
<div class="authbrand">Raptor <b>VPN</b></div>
<h1 class="authsub">Accesso <b>protetto</b></h1><div class="authtag">Gestione Tailscale · Orange Pi Zero</div><div class="authrule"></div>
__MSG__<form method="post" action="/login" class="authform"><label for="password">PASSWORD<input id="password" name="password" type="password" autocomplete="current-password" required autofocus></label>
<button type="submit">ACCEDI</button></form>
<div class="authfoot">Connessione HTTPS locale protetta</div></section></main>'''


def login_page(message=''):
    """Pagina di accesso; il messaggio (testo fisso, mai dati dell'utente) compare dentro la scheda."""
    box = '<div class="authmsg" role="alert">%s</div>' % message if message else ''
    return page(LOGIN.replace('__MSG__', box))


DASH = '''<header class="top"><a class="brand" href="#top"><span class="eye" role="img" aria-label="Raptor"></span><span><span class="word">Raptor <b>VPN</b></span><span class="tag">Tailscale · Orange Pi Zero</span></span></a>
<nav class="tabs" aria-label="Sezioni"><a class="tab" href="#account">Account</a><a class="tab" href="#routes">Rotte</a><a class="tab" href="#lanDiscovery">Dispositivi</a><a class="tab" href="#ethernet">Ethernet</a><a class="tab" href="#events">Eventi</a><a class="tab" href="#security">Sicurezza</a></nav>
<div class="top-right"><span class="pill">Web UI v1.6.0</span><form method="post" action="/logout"><input type="hidden" name="csrf" value="__CSRF__"><button class="quiet">Esci</button></form></div></header>
<main id="top">
<div class="shell"><div class="card"><div class="meta">Connessione Tailscale</div><div class="big" id="backend">Verifica...</div><small id="tailnet">-</small></div><div class="card"><div class="meta">Indirizzo Tailscale</div><div class="big value" id="tsip">-</div><small id="hostname">-</small></div><div class="card"><div class="meta">Rete locale</div><div class="big value" id="lanip">-</div><small id="interface">-</small></div></div>
<section class="card accountcard" id="account"><h2 class="subhead">Account Tailscale</h2>
<div id="accNote" class="netmessage" role="status"></div>
<div id="accDown" class="notice warnnotice" hidden><strong>Tailscale non risponde.</strong> Il servizio potrebbe essere fermo o in avvio: attendi qualche secondo e premi “Aggiorna stato”. <span id="accDownWhy"></span></div>
<div id="accConnected" hidden>
<p>La scheda è collegata alla rete Tailscale <strong id="accTailnet">-</strong> con il nome <strong id="accHost">-</strong>.</p>
<p id="accTagsRow" hidden><strong>Tag:</strong> <span class="value" id="accTags">-</span></p>
<div class="buttonrow"><button class="danger" id="accLogout" type="button">Scollega da Tailscale</button></div>
<div id="accLogoutBox" class="notice warnnotice" hidden><strong>Scollegare questa scheda dall’account?</strong> Le rotte pubblicate smettono di funzionare e la scheda non sarà più raggiungibile da remoto finché non la ricolleghi da qui (serve di nuovo un link o una chiave).
<div class="buttonrow"><button class="danger" id="accLogoutYes" type="button">Sì, scollega</button><button class="quiet" id="accLogoutNo" type="button">Annulla</button></div></div></div>
<div id="accStopped" hidden><p>La scheda è autenticata ma Tailscale è <strong>fermo</strong> (disattivato).</p><div class="buttonrow"><button class="action" id="accConnect" type="button">Riattiva Tailscale</button></div></div>
<div id="accWait" class="notice" hidden>La scheda ha chiesto l’accesso e attende l’<strong>approvazione</strong> nella console di Tailscale (<a href="https://login.tailscale.com/admin/machines" target="_blank" rel="noopener noreferrer">Admin → Machines</a>). Questa pagina si aggiorna da sola.</div>
<div id="accLogin" hidden>
<p>La scheda non è ancora collegata a un account Tailscale. Scegli come collegarla: tutto si fa da qui, senza SSH.</p>
<div class="radioopts"><label><input type="radio" name="accMode" id="accModeUrl" value="url" checked> Accedi con link</label><label><input type="radio" name="accMode" id="accModeKey" value="key"> Accedi con chiave e tag</label></div>
<form id="accForm" autocomplete="off"><div class="formgrid"><div class="field"><label for="accName">Nome della scheda (facoltativo)</label><input id="accName" type="text" placeholder="raptor-cliente" spellcheck="false" maxlength="63" autocomplete="off"></div></div>
<div id="accKeyFields" class="hidden"><div class="formgrid"><div class="field"><label for="accKey">Chiave di autenticazione</label><input id="accKey" type="password" placeholder="tskey-auth-..." autocomplete="off" spellcheck="false" maxlength="220"></div>
<div class="field"><label for="accTagsIn">Tag (facoltativi, separati da virgola)</label><input id="accTagsIn" type="text" placeholder="tag:cliente" spellcheck="false" autocomplete="off"></div></div>
<p class="passwordinfo">Crea la chiave in <a href="https://login.tailscale.com/admin/settings/keys" target="_blank" rel="noopener noreferrer">Tailscale Admin → Settings → Keys</a>. Per usare dei tag, la chiave deve essere creata con gli stessi tag e quei tag devono esistere nella policy (tagOwners). La chiave non viene salvata sulla scheda.</p></div>
<div class="buttonrow"><button class="action" id="accGo" type="submit">Ottieni il link di accesso</button><span id="accMsg" class="netmessage" role="status"></span></div></form>
<div id="accLink" class="notice" hidden><strong>Apri questo link</strong> con un browser (anche dal telefono), accedi al tuo account Tailscale e approva la scheda. Questa pagina si aggiorna da sola.
<a class="authlink value" id="accLinkA" target="_blank" rel="noopener noreferrer" href="#"></a><div class="buttonrow"><button class="quiet" id="accCopy" type="button">Copia link</button></div></div>
</div></section>
<div class="columns"><section class="card" id="routes"><h2 class="subhead">Configurazione di rete</h2><p>Configura le rotte pubblicate su Tailscale. La configurazione dell’indirizzo Ethernet (DHCP o IP statico) è gestita nella sezione dedicata qui sotto.</p>
<form id="settings"><strong>Modalità di pubblicazione</strong>
<div class="radioopts"><label><input name="routeMode" type="radio" id="routeOff" value="off" checked> Nessuna LAN</label>
<label><input name="routeMode" type="radio" id="routeAll" value="all"> Intera subnet</label>
<label><input name="routeMode" type="radio" id="routeSelected" value="selected"> Solo dispositivi selezionati</label></div>
<div class="field"><label for="subnets">Subnet IPv4 (CIDR) — modalità Intera subnet</label><input id="subnets" type="text" spellcheck="false" placeholder="192.168.1.0/24"><small>Massimo 4 subnet private. Nella modalità Dispositivi vengono pubblicati soltanto i singoli IP /32 scelti sotto.</small></div>
<div class="tgl"><div><strong>SNAT / Masquerading</strong><span>Consigliato: i dispositivi LAN vedono l'IP dell'Orange Pi</span></div><input class="switch" id="snat" type="checkbox" aria-label="SNAT"></div>
<div class="tgl"><div><strong>Accetta rotte da Tailscale</strong><span>Abilita l'utilizzo di subnet pubblicate da altri nodi</span></div><input class="switch" id="accept_routes" type="checkbox" aria-label="Accetta rotte"></div>
<div class="tgl"><div><strong>Utilizza DNS di Tailscale</strong><span>Applica a questo Orange Pi le impostazioni DNS della tailnet</span></div><input class="switch" id="accept_dns" type="checkbox" aria-label="DNS Tailscale"></div>
<div class="tgl"><div><strong>Aggiornamenti automatici</strong><span>Consenti a Tailscale di aggiornarsi automaticamente (canale corrente)</span></div><input class="switch" id="auto_update" type="checkbox" aria-label="Aggiornamenti automatici Tailscale"></div>
<div class="footer"><button id="save" class="action" type="submit">Salva configurazione</button><span id="message" role="status"></span></div></form></section>
<aside class="card"><h2 class="subhead">Stato e informazioni</h2><p>La modifica delle rotte non interrompe il collegamento Tailscale del dispositivo. In modalità selettiva il firewall LAN blocca il forwarding verso gli IP non scelti.</p>
<p><strong>IP forwarding:</strong> <span id="forwarding">-</span></p><p><strong>Versione:</strong> <span id="version">-</span></p>
<p><strong>Modalità Ethernet (Armbian):</strong> <span class="value" id="dhcp">-</span></p>
   <p><strong>Gateway LAN:</strong> <span class="value" id="gateway">-</span></p>
   <p><strong>Nome locale:</strong><br><span class="value" id="webname">-</span></p>
   <p><strong>Subnet rilevata:</strong><br><span class="value" id="detected">-</span></p>
   <button class="quiet" id="useDetected" type="button">Usa subnet rilevata</button>
<button class="quiet" id="refresh" type="button">Aggiorna stato</button>
<div class="notice">Dopo aver pubblicato una subnet, verifica l'approvazione su <a href="https://login.tailscale.com/admin/machines" target="_blank" rel="noopener noreferrer">Tailscale Admin → Machines</a>. Senza approvazione la rete non diventa raggiungibile.</div>
<div class="notice">Questo pannello non è destinato a Internet pubblico: non aprire la porta TCP 8443 sul router.</div></aside></div>
<section class="card discoverycard" id="lanDiscovery"><h2 class="subhead">LAN Device Discovery</h2>
<p>Scanner ARP della sola rete Ethernet locale: rileva IP, MAC, produttore e hostname se risolvibile. Seleziona i dispositivi da pubblicare come rotte /32. La scansione non modifica le rotte.</p>
<div class="buttonrow"><button class="quiet" id="scanLan" type="button">Scansiona dispositivi LAN</button><span id="scanMsg" class="netmessage" role="status"></span></div>
<div id="scanMeta" class="scanmeta">Nessuna scansione eseguita.</div>
<div id="deviceList" class="devlist"></div>
<div class="notice">La selezione è basata sull’<strong>IP</strong>: MAC e hostname servono solo per riconoscere il dispositivo. Per NVR/RAPTOR usa IP statici o prenotazioni DHCP. Le rotte /32 richiedono approvazione Tailscale; per il controllo completo degli accessi servono anche le regole Grants/ACL.</div>
</section>
<section class="card networkcard" id="ethernet"><h2 class="subhead">Rete Ethernet · DHCP / IP statico</h2>
<p>Configurazione persistente di <strong>end0</strong>. Un cambiamento di IP può interrompere temporaneamente SSH e questa pagina. Devi riconnetterti e premere <strong>Conferma configurazione</strong> entro 150 secondi, altrimenti viene tentato il ripristino automatico della configurazione precedente.</p>
<form id="networkForm"><div class="radioopts"><label><input type="radio" name="netmode" id="modeDhcp" value="dhcp" checked> DHCP automatico</label><label><input type="radio" name="netmode" id="modeStatic" value="static"> IP statico</label></div>
<div id="staticFields" class="hidden"><div class="formgrid">
<div class="field"><label for="staticIp">Indirizzo IP Orange Pi</label><input type="text" id="staticIp" placeholder="192.168.1.200" spellcheck="false"></div>
<div class="field"><label for="staticPrefix">Prefisso subnet (CIDR)</label><input id="staticPrefix" type="number" min="8" max="30" value="24"></div>
<div class="field"><label for="staticGateway">Gateway / Router</label><input id="staticGateway" type="text" placeholder="192.168.1.1" spellcheck="false"></div>
<div class="field"><label for="staticDns">DNS (separati da virgola)</label><input id="staticDns" type="text" placeholder="192.168.1.1, 1.1.1.1" spellcheck="false"></div>
</div></div><div class="buttonrow"><button class="action" type="submit" id="applyNetwork">Applica modifica rete</button><span id="networkMessage" class="netmessage" role="status"></span></div></form>
<div id="pendingBox" class="notice hidden"><strong class="dangerlabel">Modifica temporanea da confermare.</strong>
<p>Apri nuovamente il pannello dal nuovo indirizzo e premi il pulsante qui sotto. Se il browser non trova la rete, attendi il ripristino automatico.</p>
<p><strong>Nuovo indirizzo previsto:</strong> <a id="newAddress" href="#" target="_blank" rel="noopener noreferrer"></a></p>
<p><strong>Scadenza:</strong> <span id="pendingCountdown">-</span></p>
<button id="confirmNetwork" type="button" class="action">Conferma configurazione</button>
</div>
<div class="notice">Prima di impostare un IP statico, scegli un indirizzo <strong>libero e fuori dal pool DHCP</strong> del router del cliente, per evitare conflitti. Dopo il cambio, Tailscale ristabilisce la connessione; la pubblicazione di una subnet differente va aggiornata e approvata separatamente.</div>
</section>
<section class="card securitycard" id="security"><h2 class="subhead">Sicurezza · Cambia password</h2>
<p>Modifica la password di accesso alla Web UI. La password attuale è obbligatoria. Dopo il cambio tutte le sessioni aperte (anche su altri dispositivi) vengono chiuse e dovrai effettuare nuovamente l’accesso.</p>
<form id="passwordForm" autocomplete="on"><div class="formgrid">
<div class="field"><label for="oldPassword">Password attuale</label><input id="oldPassword" type="password" autocomplete="current-password" required></div>
<div class="field"><label for="newPassword">Nuova password</label><input id="newPassword" type="password" autocomplete="new-password" minlength="12" maxlength="128" required></div>
<div class="field"><label for="repeatPassword">Conferma nuova password</label><input id="repeatPassword" type="password" autocomplete="new-password" minlength="12" maxlength="128" required></div>
</div><div class="passwordinfo">Minimo 12 caratteri, con almeno una maiuscola, una minuscola e un numero. Simboli facoltativi. È consigliata una password lunga e univoca.</div>
<div class="footer"><button class="action" id="changePassword" type="submit">Cambia password</button><span id="passwordMessage" role="status"></span></div>
</form></section>
<section class="card eventscard" id="events"><h2 class="subhead">Eventi · Riavvii e stato del sistema</h2>
<p>Registro conservato sulla scheda (anche dopo uno spegnimento): avvii, spegnimenti regolari e <strong>spegnimenti anomali</strong>, cioè mancanza di corrente o blocco. Gli orari sono quelli del tuo computer.</p>
<div id="eventsSummary" class="scanmeta">Caricamento...</div>
<div class="buttonrow"><button class="quiet" id="refreshEvents" type="button">Aggiorna eventi</button><span id="eventsMsg" class="netmessage" role="status"></span></div>
<div id="eventsList" class="devlist"></div>
<div class="notice">Senza batteria la scheda parte con l’orologio indietro finché non si sincronizza con Internet: finché non compare “Orologio sincronizzato”, gli orari dell’ultimo avvio possono essere sbagliati. Dopo una mancanza di corrente, l’ultimo segno di vita indica entro quando è avvenuta (al massimo 5 minuti prima).</div>
</section></main>
<script>
const csrf = '__CSRF__';
const $ = id => document.getElementById(id);
const boolFields = ['snat','accept_routes','accept_dns','auto_update'];
let selectedHosts = new Set();
let discovered = [];
let initialMode = 'off';
let detectedSubnet = '';
let first = true;
async function refresh(){
 try {
  const response=await fetch('/api/status',{cache:'no-store'}); if(!response.ok)throw Error('Sessione scaduta: ricarica la pagina');
  const data=await response.json(); const s=data.settings;
  renderAccount(data);
  $('tailnet').textContent=data.tailnet;
  $('tsip').textContent=data.tailscale_ip; $('hostname').textContent=data.hostname;
  $('lanip').textContent=data.lan.ip; $('interface').textContent=data.lan.device;
  detectedSubnet=data.lan.subnet||'';
  $('detected').textContent=detectedSubnet||'Non rilevata';
  $('dhcp').textContent=(data.network && data.network.mode==='static')?'IP statico':(data.lan.dhcp||'DHCP (da verificare)');
  $('gateway').textContent=data.lan.gateway||'-';
  $('webname').textContent=data.lan.web_name||'-';
  if (s.mode==='all' && detectedSubnet && s.subnets && !s.subnets.split(',').map(x=>x.trim()).includes(detectedSubnet))
    msg('Attenzione: la rete pubblicata non coincide con la LAN corrente. Verifica prima di salvare.',true);
  $('forwarding').textContent=data.forwarding?'Attivo':'Non attivo'; $('version').textContent=data.version;
  if(first){
    boolFields.forEach(id=>$(id).checked=!!s[id]);
    $('subnets').value=s.subnets||data.lan.subnet;
    initialMode=['off','all','selected'].includes(s.mode)?s.mode:'off';
    $(initialMode==='all'?'routeAll':initialMode==='selected'?'routeSelected':'routeOff').checked=true;
    selectedHosts=new Set(Array.isArray(s.selected_hosts)?s.selected_hosts:[]);
    renderDevices();first=false;
  }
  netData(data.network,data.lan);
  if(data.error)msg(data.error,true);
 } catch(e){msg(e.message,true)}
}
function escapeHtml(t){return String(t).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function msg(t,error){$('message').textContent=t;$('message').className=error?'err':'ok'}
$('settings').addEventListener('submit',async e=>{
 e.preventDefault();$('save').disabled=true;msg('Applicazione in corso...',false);
 const payload=Object.fromEntries(boolFields.map(id=>[id,$(id).checked]));
 payload.mode=$('routeAll').checked?'all':$('routeSelected').checked?'selected':'off';
 payload.subnets=$('subnets').value.trim();payload.selected_hosts=[...selectedHosts];
 if(payload.mode==='selected' && !payload.selected_hosts.length){msg('Seleziona almeno un dispositivo dalla scansione LAN.',true);$('save').disabled=false;return;}
 try {const response=await fetch('/api/apply',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify(payload)});
 const result=await response.json();if(!response.ok)throw Error(result.error||'Errore non specificato');
 msg('Impostazioni applicate. Controlla le rotte nel pannello Tailscale.',false);
 first=true;await refresh();
 }catch(error){msg(error.message,true)}finally{$('save').disabled=false;}
});
function renderDevices(){
 const list=$('deviceList');list.replaceChildren();
 const seen=new Set(discovered.map(d=>d.ip));
 const rows=[...discovered];
 for(const ip of selectedHosts){if(!seen.has(ip))rows.push({ip,hostname:'Non rilevato nell’ultima scansione',mac:'-',vendor:'-'});}
 for(const d of rows){
   const row=document.createElement('label');row.className='device';
   const check=document.createElement('input');check.type='checkbox';check.checked=selectedHosts.has(d.ip);
   check.addEventListener('change',()=>{if(check.checked)selectedHosts.add(d.ip);else selectedHosts.delete(d.ip);renderScanMeta();});
   const info=document.createElement('div');info.className='deviceinfo';
   const title=document.createElement('strong');title.textContent=d.hostname&&d.hostname!=='-'?d.hostname:'Dispositivo LAN';
   const address=document.createElement('small');address.textContent='IP '+d.ip+' · MAC '+(d.mac||'-');
   const vendor=document.createElement('small');vendor.textContent='Produttore: '+(d.vendor||'-');
   info.append(title,address,vendor);row.append(check,info);list.append(row);
 }
 renderScanMeta();
}
function renderScanMeta(){
 $('scanMeta').textContent=discovered.length+' dispositivi rilevati · '+selectedHosts.size+' selezionati';
}
$('scanLan').addEventListener('click', async()=>{
 $('scanLan').disabled=true;$('scanMsg').textContent='Scansione in corso...';$('scanMsg').className='netmessage';
 try{
   const resp=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({action:'scan'})});
   const data=await resp.json();if(!resp.ok)throw Error(data.error||'Scansione non riuscita');
   discovered=data.devices||[];renderDevices();
   $('scanMsg').textContent='Scansione completata: '+data.subnet;
   if(data.limited||data.hostname_limited)$('scanMsg').textContent+=' (alcuni risultati o nomi limitati)';
   $('scanMsg').className='netmessage ok';
 }catch(error){$('scanMsg').textContent=error.message;$('scanMsg').className='netmessage err';}
 finally{$('scanLan').disabled=false;}
});
$('useDetected').onclick=()=>{
 if(!detectedSubnet){msg('Nessuna subnet Ethernet rilevata.',true);return;}
 $('subnets').value=detectedSubnet;
 msg('Rete rilevata inserita: premi Salva configurazione per applicarla.',false);
};
$('refresh').onclick=()=>{first=true;refresh()};
let netLoaded=false;
let pendingId='';
function netMsg(t, error){$('networkMessage').textContent=t;$('networkMessage').className=error?'netmessage err':'netmessage ok';}
function showNetFields(){$('staticFields').classList.toggle('hidden',!$('modeStatic').checked)}
$('modeDhcp').onchange=showNetFields;
$('modeStatic').onchange=showNetFields;
function showPending(p){
  $('pendingBox').classList.toggle('hidden',!p);
  if(p){pendingId=p.id;
    const url=p.mode==='static'?'https://'+p.ip+':8443':'https://orangepizero.local:8443';
    $('newAddress').textContent=url;$('newAddress').href=url;
    $('pendingCountdown').textContent=Math.max(0,p.expires_at-Math.floor(Date.now()/1000))+' secondi';
  }else pendingId='';
}
function netData(n,lan){
  if(!n)return;
  $('applyNetwork').disabled=!n.supported||!!n.pending;
  if(!n.supported)netMsg('Modifica IP non disponibile: '+(n.reason||'gestore di rete non compatibile'),true);
  if(!netLoaded){
    $('modeDhcp').checked=n.mode!=='static';$('modeStatic').checked=n.mode==='static';
    $('staticIp').value=n.ip||(lan && lan.ip!=='-'?lan.ip:'');$('staticPrefix').value=n.mode==='static'?n.prefix:((lan && lan.subnet)?Number(lan.subnet.split('/')[1]):24);
    $('staticGateway').value=n.gateway||(lan && lan.gateway!=='-'?lan.gateway:'');$('staticDns').value=(n.dns&&n.dns.length?n.dns:[(lan&&lan.gateway&&lan.gateway!=='-'?lan.gateway:'')]).filter(Boolean).join(', ');
    showNetFields();netLoaded=true;
  }
  showPending(n.pending);
}
$('networkForm').addEventListener('submit',async e=>{
  e.preventDefault();
  const mode=$('modeStatic').checked?'static':'dhcp';
  const payload={mode,ip:$('staticIp').value.trim(),prefix:Number($('staticPrefix').value),
    gateway:$('staticGateway').value.trim(),dns:$('staticDns').value.split(',').map(x=>x.trim()).filter(Boolean)};
  if(!window.confirm('Modificare ora la configurazione Ethernet? La connessione potrebbe interrompersi. Senza conferma entro 150 secondi verrà tentato il ripristino automatico.'))return;
  $('applyNetwork').disabled=true;
  try{
    const resp=await fetch('/api/network/start',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify(payload)});
    const data=await resp.json();if(!resp.ok)throw Error(data.error||'Errore modifica');
    netMsg('Modifica programmata. Ricollegati dal nuovo indirizzo e premi Conferma.',false);
    showPending({id:data.id,mode,ip:payload.ip,expires_at:data.expires_at});
  }catch(e){netMsg(e.message,true);$('applyNetwork').disabled=false;}
});
$('confirmNetwork').onclick=async()=>{
  if(!pendingId)return;
  try{
    const resp=await fetch('/api/network/confirm',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({id:pendingId})});
    const data=await resp.json();if(!resp.ok)throw Error(data.error||'Conferma fallita');
    showPending(null);netMsg('Configurazione Ethernet confermata e salvata.',false);netLoaded=false;await refresh();
  }catch(e){netMsg(e.message,true);}
};
$('passwordForm').addEventListener('submit',async e=>{
 e.preventDefault();
 const oldPassword=$('oldPassword').value, newPassword=$('newPassword').value, confirmPassword=$('repeatPassword').value;
 const message=$('passwordMessage');
 message.className='';
 if(newPassword!==confirmPassword){message.className='err';message.textContent='Le nuove password non corrispondono.';return;}
 if(newPassword.length<12||newPassword.length>128||!/[A-Z]/.test(newPassword)||!/[a-z]/.test(newPassword)||!/[0-9]/.test(newPassword)){message.className='err';message.textContent='Usa 12-128 caratteri con una maiuscola, una minuscola e un numero.';return;}
 if(!window.confirm('Confermi il cambio della password? Tutte le sessioni verranno disconnesse.'))return;
 $('changePassword').disabled=true;
 try{
  const response=await fetch('/api/password',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({current_password:oldPassword,new_password:newPassword,confirm_password:confirmPassword})});
  const result=await response.json();
  if(!response.ok)throw Error(result.error||'Cambio password non riuscito.');
  $('passwordForm').reset();message.className='ok';message.textContent='Password aggiornata. Accesso nuovamente richiesto.';
  window.location.replace('/login');
 }catch(error){message.className='err';message.textContent=error.message;}
 finally{$('changePassword').disabled=false;}
});
setInterval(()=>{if(pendingId){refresh();}},6000);
const BACKEND_LABELS={Running:'Collegato',NeedsLogin:'Accesso richiesto',NeedsMachineAuth:'In attesa di approvazione',Stopped:'Fermo',Starting:'Avvio in corso',NoState:'Avvio in corso'};
let accWaiting=false;
function safeAuthUrl(u){try{const x=new URL(u);return x.protocol==='https:'&&/(^|[.])tailscale[.]com$/.test(x.hostname)&&x.pathname.startsWith('/a/')&&!x.username&&!x.password&&!x.port;}catch(e){return false;}}
function accNote(t,error){$('accNote').textContent=t;$('accNote').className='netmessage '+(error?'err':'ok');}
function accMsg(t,error){$('accMsg').textContent=t;$('accMsg').className='netmessage '+(error?'err':'ok');}
async function postJson(url,body){
 const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify(body)});
 let d={};try{d=await r.json();}catch(e){}
 if(!r.ok||d.ok===false)throw Error(d.error||'Operazione non riuscita.');
 return d;
}
function showLink(url){
 const ok=safeAuthUrl(url);$('accLink').hidden=!ok;
 if(ok){$('accLinkA').href=url;$('accLinkA').textContent=url;}
 return ok;
}
function renderAccount(d){
 const st=d.backend,down=st==='Non disponibile',connected=st==='Running',stopped=st==='Stopped';
 const needsLogin=st==='NeedsLogin'||st==='NoState'||st==='Starting';
 $('accDown').hidden=!down;$('accDownWhy').textContent=down&&d.error?d.error:'';
 $('accConnected').hidden=!connected;$('accStopped').hidden=!stopped;
 $('accWait').hidden=st!=='NeedsMachineAuth';$('accLogin').hidden=!needsLogin;
 if(connected){
  $('accTailnet').textContent=d.tailnet;$('accHost').textContent=d.hostname;
  const tags=Array.isArray(d.tags)?d.tags:[];$('accTagsRow').hidden=!tags.length;$('accTags').textContent=tags.join(', ');
 }
 const pending=needsLogin&&showLink(d.auth_url);
 if(!pending&&!needsLogin)$('accLink').hidden=true;
 accWaiting=pending||st==='NeedsMachineAuth'||st==='Starting';
 $('backend').innerHTML='<span class="dot '+(connected?'good':(down?'bad':''))+'"></span>'+escapeHtml(BACKEND_LABELS[st]||st);
}
for(const id of ['accModeUrl','accModeKey'])$(id).addEventListener('change',()=>{
 const key=$('accModeKey').checked;$('accKeyFields').classList.toggle('hidden',!key);
 $('accGo').textContent=key?'Collega con la chiave':'Ottieni il link di accesso';accMsg('',false);
});
$('accForm').addEventListener('submit',async e=>{
 e.preventDefault();const key=$('accModeKey').checked;
 const body={mode:key?'key':'url',hostname:$('accName').value.trim()};
 if(key){
  body.key=$('accKey').value.trim();body.tags=$('accTagsIn').value.split(',').map(x=>x.trim()).filter(Boolean);
  if(!body.key){accMsg('Inserisci la chiave di autenticazione.',true);return;}
 }
 $('accGo').disabled=true;accMsg(key?'Collegamento in corso: può richiedere fino a un minuto...':'Richiesta del link in corso...',false);
 try{
  const r=await postJson('/api/tailscale/login',body);
  if(r.auth_url){showLink(r.auth_url);accMsg('Link pronto: aprilo per completare l’accesso.',false);accWaiting=true;}
  else{accMsg('Scheda collegata a Tailscale.',false);}
  if(key)$('accKey').value='';
  await refresh();
 }catch(error){accMsg(error.message,true);}
 finally{$('accGo').disabled=false;}
});
$('accCopy').addEventListener('click',async()=>{
 try{await navigator.clipboard.writeText($('accLinkA').textContent);$('accCopy').textContent='Copiato';}
 catch(e){$('accCopy').textContent='Seleziona e copia a mano';}
 setTimeout(()=>{$('accCopy').textContent='Copia link';},2500);
});
$('accLogout').addEventListener('click',()=>{$('accLogoutBox').hidden=false;$('accLogout').hidden=true;});
$('accLogoutNo').addEventListener('click',()=>{$('accLogoutBox').hidden=true;$('accLogout').hidden=false;});
$('accLogoutYes').addEventListener('click',async()=>{
 $('accLogoutYes').disabled=true;
 try{await postJson('/api/tailscale/logout',{});$('accLogoutBox').hidden=true;$('accLogout').hidden=false;await refresh();}
 catch(error){accNote(error.message,true);}
 finally{$('accLogoutYes').disabled=false;}
});
$('accConnect').addEventListener('click',async()=>{
 $('accConnect').disabled=true;
 try{const r=await postJson('/api/tailscale/connect',{});if(r.auth_url)showLink(r.auth_url);await refresh();}
 catch(error){accNote(error.message,true);}
 finally{$('accConnect').disabled=false;}
});
setInterval(()=>{if(accWaiting)refresh();},4000);
const EVENT_LABELS={boot:'Avvio',shutdown:'Spegnimento',unclean_shutdown:'Spegnimento anomalo (corrente mancata o blocco)',clock_synced:'Orologio sincronizzato'};
const PREV_LABELS={first_boot:'primo avvio registrato',clean_reboot:'dopo un riavvio regolare',clean_poweroff:'dopo uno spegnimento regolare',clean_halt:'dopo un arresto regolare',clean_unknown:'dopo uno spegnimento regolare',unclean:'dopo uno spegnimento anomalo',unknown:'stato precedente non leggibile'};
const KIND_LABELS={reboot:'riavvio',poweroff:'spegnimento',halt:'arresto',unknown:'tipo non rilevato'};
const fmtDate=e=>new Date(e*1000).toLocaleString('it-IT');
function fmtSpan(s){const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return (d?d+' g ':'')+(h||d?h+' h ':'')+m+' min';}
function eventDetail(e){
 const parts=[];
 if(e.type==='boot'){parts.push(PREV_LABELS[e.previous]||'stato precedente sconosciuto');
  if(e.clock_synced===false)parts.push('orario non ancora sincronizzato');
  if(e.logged_late)parts.push('registrato a scheda già accesa (installazione)');}
 if(e.type==='shutdown')parts.push(KIND_LABELS[e.kind]||'tipo non rilevato');
 if(e.type==='unclean_shutdown'&&e.last_seen_epoch)parts.push('ultimo segno di vita: '+fmtDate(e.last_seen_epoch));
 if(e.type==='clock_synced'&&typeof e.jump_seconds==='number')parts.push('correzione dell’orologio: '+e.jump_seconds+' s');
 return parts.join(' · ');
}
async function loadEvents(){
 const list=$('eventsList'),sum=$('eventsSummary'),msg=$('eventsMsg');
 $('refreshEvents').disabled=true;msg.textContent='';
 try{
  const response=await fetch('/api/events',{cache:'no-store'});
  if(!response.ok)throw Error('Sessione scaduta: ricarica la pagina');
  const data=await response.json();list.replaceChildren();
  if(!data.available){sum.textContent=data.reason||'Registro non disponibile.';return;}
  const s=data.summary;
  sum.textContent='In funzione da '+fmtSpan(s.uptime_seconds)+' (avvio: '+fmtDate(s.boot_epoch)+') · Avvii negli ultimi 30 giorni: '+s.boots_30d+' · Spegnimenti anomali negli ultimi 30 giorni: '+s.unclean_30d+(s.last_unclean_epoch?' (ultimo: '+fmtDate(s.last_unclean_epoch)+')':'');
  if(!data.events.length){sum.textContent+=' · Nessun evento registrato.';}
  for(const e of data.events){
   const row=document.createElement('div');row.className='device'+(e.type==='unclean_shutdown'?' alertrow':'');
   const info=document.createElement('div');info.className='deviceinfo';
   const title=document.createElement('strong');title.textContent=EVENT_LABELS[e.type]||e.type;
   const when=document.createElement('small');when.className='evtime';when.textContent=fmtDate(e.epoch);
   const detail=document.createElement('small');detail.textContent=eventDetail(e);
   info.append(title,when);if(detail.textContent)info.append(detail);row.append(info);list.append(row);
  }
 }catch(error){msg.textContent=error.message;msg.className='netmessage err';}
 finally{$('refreshEvents').disabled=false;}
}
$('refreshEvents').addEventListener('click',loadEvents);
refresh();
loadEvents();
</script>'''


def _abort_connection(sock):
    """Chiude una connessione che ha superato REQUEST_DEADLINE."""
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


def _purge_expired(now):
    """Elimina sessioni scadute e login falliti fuori finestra. Chiamare con LOCK preso."""
    cutoff = now - FAILURE_WINDOW
    for ip in list(FAILURES):
        FAILURES[ip] = [t for t in FAILURES[ip] if t > cutoff]
        if not FAILURES[ip]:
            del FAILURES[ip]
    for key in [k for k, s in SESSIONS.items() if s['expires'] <= now]:
        del SESSIONS[key]


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16
    _slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

    def process_request(self, request, client_address):
        # Oltre il limite la connessione viene chiusa subito: nessun thread in piu'.
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def finish_request(self, request, client_address):
        # L'handshake TLS si fa QUI, nel thread della richiesta e con un timeout.
        # Se lo facesse accept() (do_handshake_on_connect=True) una sola connessione
        # TCP muta bloccherebbe l'intero pannello a tempo indeterminato.
        if hasattr(request, 'do_handshake'):
            try:
                request.settimeout(HANDSHAKE_TIMEOUT)
                request.do_handshake()
            except OSError:  # include ssl.SSLError e timeout
                return
        timer = threading.Timer(REQUEST_DEADLINE, _abort_connection, (request,))
        timer.daemon = True
        timer.start()
        try:
            self.RequestHandlerClass(request, client_address, self)
        finally:
            timer.cancel()

    def handle_error(self, request, client_address):
        # Client scomparsi, reset e timeout non sono errori del pannello: niente rumore nel journal.
        if isinstance(sys.exc_info()[1], OSError):
            return
        super().handle_error(request, client_address)


class Handler(BaseHTTPRequestHandler):
    server_version = 'RaptorVPNPanel/1.6.0'
    sys_version = ''

    def setup(self):
        super().setup()
        self.connection.settimeout(12)

    def log_message(self, fmt, *args):
        # Prevent passwords and tokens from being written into the journal.
        if self.path.split('?')[0] not in ('/login', '/api/apply', '/api/password'):
            super().log_message(fmt, *args)

    def _send(self, code, body, content='text/html; charset=utf-8', headers=None):
        data = body.encode('utf-8') if isinstance(body, str) else body
        self.send_response(code)
        self.send_header('Content-Type', content)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; img-src data:; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        for k,v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False), 'application/json; charset=utf-8')

    def _session(self):
        try:
            raw = cookies.SimpleCookie()
            raw.load(self.headers.get('Cookie', ''))
            key = raw['tspanel'].value
        except (KeyError, cookies.CookieError):
            return None
        now = time.time()
        version = password_version()
        with LOCK:
            session = SESSIONS.get(key)
            if session is not None and session['expires'] > now and version is not None and hmac.compare_digest(session.get('auth_version', b''), version):
                return session
            SESSIONS.pop(key, None)
        return None

    def _body(self):
        length = int(self.headers.get('Content-Length', '0'))
        if length <= 0 or length > 8192:
            raise ValueError('Dimensione della richiesta non valida.')
        return self.rfile.read(length)

    def _csrf(self, session, token):
        return bool(session and isinstance(token, str) and
                    hmac.compare_digest(session['csrf'], token))

    def do_GET(self):
        path = urlparse(self.path).path
        if path == '/login':
            return self._send(200, login_page())
        if path == '/':
            session = self._session()
            if not session:
                return self._send(303, b'', headers={'Location':'/login'})
            return self._send(200, page(DASH.replace('__CSRF__', session['csrf'])))
        if path == '/api/status':
            if not self._session():
                return self._json(401, {'error':'Accesso richiesto'})
            return self._json(200, status_data())
        if path == '/api/events':
            if not self._session():
                return self._json(401, {'error':'Accesso richiesto'})
            return self._json(200, events_data())
        return self._send(404, 'Non trovato', 'text/plain; charset=utf-8')

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            body = self._body()
            if path == '/login':
                client_ip = self.client_address[0]
                with LOCK:
                    _purge_expired(time.time())
                    limited = (len(FAILURES.get(client_ip, [])) >= LOGIN_FAILURES_PER_IP or
                               sum(len(v) for v in FAILURES.values()) >= LOGIN_FAILURES_GLOBAL)
                if limited:
                    return self._send(429, login_page('Troppi tentativi. Riprova più tardi.'))
                form = parse_qs(body.decode('utf-8'))
                password = (form.get('password') or [''])[0]
                # PBKDF2 (220.000 iterazioni) e' lento su Cortex-A7: va eseguito FUORI dal
                # LOCK globale, altrimenti ogni login blocca tutte le altre richieste.
                current_version = password_version()
                with HASH_SLOTS:
                    valid = bool(current_version) and verify_password(password)
                authenticated = False
                with LOCK:
                    if valid and hmac.compare_digest(current_version, password_version() or b''):
                        token = secrets.token_urlsafe(32)
                        session = {'csrf':secrets.token_urlsafe(32), 'expires':time.time()+8*3600,
                                   'auth_version':current_version, 'password_attempts':[]}
                        SESSIONS[token] = session
                        FAILURES.pop(client_ip, None)
                        authenticated = True
                    else:
                        FAILURES.setdefault(client_ip, []).append(time.time())
                if authenticated:
                    cookie = 'tspanel=%s; Path=/; Max-Age=28800; HttpOnly; Secure; SameSite=Strict' % token
                    return self._send(303, b'', headers={'Location':'/', 'Set-Cookie':cookie})
                return self._send(401, login_page('Password non valida.'))
            session = self._session()
            if not session:
                return self._json(401, {'error':'Sessione scaduta. Eseguire il login.'})
            if path == '/logout':
                form = parse_qs(body.decode('utf-8'))
                if not self._csrf(session, (form.get('csrf') or [''])[0]):
                    return self._send(403, 'CSRF non valido', 'text/plain')
                jar = cookies.SimpleCookie()
                jar.load(self.headers.get('Cookie', ''))
                with LOCK:
                    SESSIONS.pop(jar['tspanel'].value, None)
                return self._send(303, b'', headers={'Location':'/login',
                    'Set-Cookie':'tspanel=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict'})
            if path == '/api/password':
                if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                    return self._json(415, {'error':'Content-Type non supportato'})
                if not self._csrf(session, self.headers.get('X-CSRF-Token', '')):
                    return self._json(403, {'error':'CSRF non valido'})
                payload = json.loads(body.decode('utf-8'))
                if not isinstance(payload, dict) or set(payload) != {'current_password','new_password','confirm_password'}:
                    raise ValueError('Campi password non validi.')
                old = payload['current_password']
                new = payload['new_password']
                confirm = payload['confirm_password']
                if not all(isinstance(x, str) for x in (old, new, confirm)):
                    raise ValueError('Valori password non validi.')
                policy_error = password_error(new)
                if policy_error:
                    raise ValueError(policy_error)
                if new != confirm:
                    raise ValueError('Le nuove password non coincidono.')
                with LOCK:
                    now = time.time()
                    attempts = [t for t in session['password_attempts'] if t > now - 900]
                    session['password_attempts'] = attempts
                    if len(attempts) >= 5:
                        return self._json(429, {'error':'Troppi tentativi. Riprova fra 15 minuti.'})
                # Come per il login: l'hash lento si calcola fuori dal LOCK globale.
                version_before = password_version()
                with HASH_SLOTS:
                    old_is_valid = verify_password(old)
                with LOCK:
                    now = time.time()
                    if not old_is_valid:
                        session['password_attempts'].append(now)
                        return self._json(403, {'error':'Password attuale non corretta.'})
                    if version_before is None or not hmac.compare_digest(version_before, password_version() or b''):
                        return self._json(409, {'error':'La password è stata modificata nel frattempo: accedi di nuovo.'})
                    if hmac.compare_digest(old.encode('utf-8'), new.encode('utf-8')):
                        raise ValueError('La nuova password deve essere diversa da quella attuale.')
                    # Write first; revoke all sessions only if the new hash is saved.
                    write_password(new)
                    SESSIONS.clear()
                    FAILURES.clear()
                return self._send(200, json.dumps({'ok':True,'reauth':True}),
                                  'application/json; charset=utf-8',
                                  headers={'Set-Cookie':'tspanel=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict'})
            if path in ('/api/network/start','/api/network/confirm'):
                if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                    return self._json(415, {'error':'Content-Type non supportato'})
                if not self._csrf(session, self.headers.get('X-CSRF-Token', '')):
                    return self._json(403, {'error':'CSRF non valido'})
                payload = json.loads(body.decode('utf-8'))
                if not isinstance(payload,dict):
                    raise ValueError('Richiesta rete non valida.')
                if path.endswith('/start'):
                    if set(payload) != {'mode','ip','prefix','gateway','dns'}:
                        raise ValueError('Campi rete non validi.')
                    req={'action':'start','config':payload}
                else:
                    if set(payload) != {'id'}:
                        raise ValueError('Conferma non valida.')
                    req={'action':'confirm','id':payload['id']}
                proc=run(['/usr/bin/sudo','-n',NET_HELPER], timeout=28,
                         input_text=json.dumps(req))
                result=read_json_from_string(proc.stdout)
                if proc.returncode or not result.get('ok'):
                    return self._json(400, {'error':str(result.get('error') or proc.stderr.strip() or 'Errore rete')[:500]})
                return self._json(200,result)
            if path in ('/api/tailscale/login', '/api/tailscale/logout', '/api/tailscale/connect'):
                if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                    return self._json(415, {'error':'Content-Type non supportato'})
                if not self._csrf(session, self.headers.get('X-CSRF-Token', '')):
                    return self._json(403, {'error':'CSRF non valido'})
                payload = json.loads(body.decode('utf-8'))
                if not isinstance(payload, dict):
                    raise ValueError('JSON non valido')
                if path == '/api/tailscale/login':
                    mode = payload.get('mode')
                    if mode not in ('url', 'key') or not set(payload) <= {'mode', 'hostname', 'key', 'tags'}:
                        raise ValueError('Richiesta di accesso non valida.')
                    request = {'action':'login_' + mode, 'hostname':payload.get('hostname', '')}
                    if mode == 'key':
                        request['key'] = payload.get('key')
                        request['tags'] = payload.get('tags', [])
                    elif set(payload) - {'mode', 'hostname'}:
                        raise ValueError('Richiesta di accesso non valida.')
                else:
                    if payload:
                        raise ValueError('Richiesta non valida.')
                    request = {'action':path.rsplit('/', 1)[1]}
                result = tailscale_auth(request)
                return self._json(200 if result['ok'] else 400, result)
            if path == '/api/scan':
                if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                    return self._json(415, {'error':'Content-Type non supportato'})
                if not self._csrf(session, self.headers.get('X-CSRF-Token', '')):
                    return self._json(403, {'error':'CSRF non valido'})
                payload = json.loads(body.decode('utf-8'))
                if payload != {'action':'scan'}:
                    raise ValueError('Comando di scansione non valido')
                with LOCK:
                    now = time.monotonic()
                    if now - session.get('last_scan',-1000) < 15:
                        return self._json(429, {'error':'Attendere 15 secondi tra le scansioni.'})
                    session['last_scan'] = now
                proc=run(['/usr/bin/sudo','-n',DISCOVERY_HELPER], timeout=34,
                         input_text=json.dumps(payload))
                response=read_json_from_string(proc.stdout)
                if proc.returncode or not response.get('ok'):
                    return self._json(400, {'error':str(response.get('error') or proc.stderr.strip() or 'Errore scanner')[:450]})
                return self._json(200, response)
            if path == '/api/apply':
                if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                    return self._json(415, {'error':'Content-Type non supportato'})
                if not self._csrf(session, self.headers.get('X-CSRF-Token', '')):
                    return self._json(403, {'error':'CSRF non valido'})
                payload = json.loads(body.decode('utf-8'))
                if not isinstance(payload, dict):
                    raise ValueError('JSON non valido')
                proc = run(['/usr/bin/sudo', '-n', HELPER], timeout=30,
                           input_text=json.dumps(payload))
                response = read_json_from_string(proc.stdout)
                if proc.returncode:
                    return self._json(400, {'error':str(response.get('error') or proc.stderr.strip() or 'Errore applicazione')[:500]})
                save_state(payload)
                return self._json(200, {'ok':True, 'result':response})
        except (ValueError, KeyError, TypeError, UnicodeError, subprocess.TimeoutExpired, OSError) as exc:
            return self._json(400, {'error':str(exc)[:350]})
        return self._send(404, 'Non trovato', 'text/plain; charset=utf-8')


def read_json_from_string(text):
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else {}
    except ValueError:
        return {}


def main():
    if len(sys.argv) == 2 and sys.argv[1] == '--configure-password':
        # First installation: choose the web password without echoing it,
        # passing it as a CLI argument, or storing it in environment variables.
        if os.geteuid() != 0:
            sys.exit('Eseguire come root: sudo python3 ... --configure-password')
        import getpass
        if not os.isatty(0):
            sys.exit('Serve un terminale interattivo SSH (TTY) per impostare la password.')
        for attempt in range(3):
            try:
                password = getpass.getpass('Nuova password Web UI (minimo 12; maiuscola, minuscola e numero): ')
                confirmation = getpass.getpass('Conferma password Web UI: ')
            except (EOFError, KeyboardInterrupt):
                sys.exit('\nImpostazione password annullata, nessuna credenziale modificata.')
            if password != confirmation:
                print('Le password non coincidono. Riprova.')
                continue
            policy_error = password_error(password)
            if policy_error:
                print(policy_error)
                continue
            write_password(password)
            try:
                import pwd
                ident = pwd.getpwnam('tspanel')
                os.chown(AUTH_PATH, ident.pw_uid, ident.pw_gid)
            except KeyError:
                sys.exit('Errore: utente di servizio tspanel non trovato')
            os.chmod(AUTH_PATH, 0o600)
            print('Password Web UI impostata correttamente (non visualizzata).')
            return
        sys.exit('Troppi tentativi: credenziali non modificate.')
    if len(sys.argv) == 2 and sys.argv[1] == '--reset-password':
        if os.geteuid() != 0:
            sys.exit('Eseguire come root: sudo python3 ... --reset-password')
        password = make_password()
        try:
            import pwd
            ident = pwd.getpwnam('tspanel')
            os.chown(AUTH_PATH, ident.pw_uid, ident.pw_gid)
        except KeyError:
            pass
        print('Nuova password amministratore (salvare): ' + password)
        return
    if len(sys.argv) != 1:
        sys.exit('Argomento non valido')
    # Service must be launched by a systemd socket bound to the Ethernet device.
    # Never bind a stand-alone 0.0.0.0 socket which would expose the admin UI
    # through tailscale0, Wi-Fi, or other interfaces.
    if os.environ.get('LISTEN_FDS') != '1' or os.environ.get('LISTEN_PID') != str(os.getpid()):
        sys.exit('Il pannello deve essere avviato dal socket systemd tailscale-panel.socket')
    inherited = socket.socket(fileno=3)
    if inherited.family != socket.AF_INET or inherited.type & socket.SOCK_STREAM != socket.SOCK_STREAM:
        sys.exit('Socket systemd incompatibile')
    httpd = Server(('0.0.0.0', PORT), Handler, bind_and_activate=False)
    httpd.socket.close()
    httpd.socket = inherited
    httpd.server_address = inherited.getsockname()
    httpd.server_name = socket.getfqdn(httpd.server_address[0])
    httpd.server_port = httpd.server_address[1]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if hasattr(ssl, 'TLSVersion'):
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=CERT_PATH, keyfile=KEY_PATH)
    # L'handshake NON si fa in accept(): lo esegue Server.finish_request con un timeout.
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True, do_handshake_on_connect=False)
    print('Tailscale Panel HTTPS socket Ethernet %s:%s pronto' % (LAN_DEV, PORT), flush=True)
    httpd.serve_forever()


if __name__ == '__main__':
    main()
