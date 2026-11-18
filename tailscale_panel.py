#!/usr/bin/env python3
"""Tailscale Control Panel 1.5.0 - Selected LAN hosts, DHCP/static IP, HTTPS."""
import base64
import hashlib
import hmac
import ipaddress
import json
import os
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
              'forwarding':False, 'settings':saved_state(), 'cli_read_ok':False}
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


STYLE = '''
:root{color-scheme:dark;font:15px system-ui,-apple-system,Segoe UI,Arial,sans-serif;background:#0b1020;color:#e7edff}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 5% 0%,#142846 0,transparent 45%),#0b1020;min-height:100vh}
main{max-width:1050px;margin:0 auto;padding:40px 22px 65px}
.head{display:flex;justify-content:space-between;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:28px}
.logo{display:flex;align-items:center;gap:13px}.emblem{background:linear-gradient(135deg,#24c4b3,#4378e9);padding:12px;border-radius:15px;font-weight:800;color:#06131a}
h1{font-size:26px;margin:0;letter-spacing:-.6px}.uiversion{font-size:12px;color:#7adacb;margin-top:4px;font-weight:600}small,.muted{color:#94a6c2}button,input{font:inherit}
.shell{display:grid;grid-template-columns:repeat(3,1fr);gap:15px;margin:22px 0}.card{background:#141d30;border:1px solid #263551;border-radius:18px;padding:22px;box-shadow:0 10px 35px #0002}
.card .meta{font-size:12px;letter-spacing:.09em;color:#93a6c4;text-transform:uppercase}.big{font-size:20px;font-weight:750;margin:10px 0;overflow-wrap:anywhere}
.dot{display:inline-block;height:9px;width:9px;border-radius:50%;background:#efab58;margin-right:8px}.dot.good{background:#34d7a1}
.columns{display:grid;grid-template-columns:1.7fr 1fr;gap:15px}.subhead{font-size:19px;font-weight:760;margin:0 0 7px}p{color:#a7b6d1;line-height:1.6}
.field{margin:20px 0}.field label{display:block;margin-bottom:8px;font-weight:650}input[type=text],input[type=password],input[type=number],select{width:100%;padding:13px;border:1px solid #3a4b69;background:#0d1627;color:#eaf2ff;border-radius:11px;outline:none}input:focus,select:focus{border-color:#62badf}.formgrid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.formgrid .field{margin:8px 0}.hidden{display:none!important}.networkcard{margin-top:16px}.netmessage{font-size:14px;line-height:1.5}.buttonrow{display:flex;gap:12px;flex-wrap:wrap;margin-top:12px}.radioopts{display:flex;gap:22px;flex-wrap:wrap;padding:14px 0}.radioopts label{cursor:pointer}.dangerlabel{color:#ffc084}
.tgl{display:flex;align-items:center;justify-content:space-between;gap:18px;padding:17px 0;border-bottom:1px solid #293650}.tgl:last-of-type{border-bottom:0}
.tgl strong{display:block;margin-bottom:3px}.tgl span{color:#9eafc9;font-size:13px}.switch{appearance:none;width:47px;height:27px;border-radius:20px;background:#45516a;position:relative;cursor:pointer;flex-shrink:0;transition:.2s}.switch:before{content:'';position:absolute;top:4px;left:4px;width:19px;height:19px;border-radius:50%;background:#fff;transition:.2s}.switch:checked{background:#25b8a9}.switch:checked:before{left:24px}
.action{background:linear-gradient(120deg,#21bda8,#3289dd);border:none;padding:12px 19px;border-radius:11px;color:#061d2c;font-weight:800;cursor:pointer}
.action:disabled{opacity:.5;cursor:wait}.quiet{background:transparent;border:1px solid #395072;color:#bdd3ef;padding:10px 14px;border-radius:10px;cursor:pointer}
.footer{display:flex;align-items:center;gap:15px;margin-top:20px;flex-wrap:wrap}#message{font-weight:600}.ok{color:#41dbb4}.err{color:#ff9ba1}
.discoverycard{margin-top:16px}.devlist{margin-top:14px;display:grid;gap:8px}.device{display:flex;gap:12px;align-items:flex-start;padding:13px;border:1px solid #293b58;border-radius:12px;background:#101b2d}.device input{margin-top:5px;accent-color:#28c4ac}.deviceinfo{min-width:0}.deviceinfo strong{display:block}.deviceinfo small{display:block;margin-top:3px;overflow-wrap:anywhere}.scanmeta{margin-top:10px;color:#9eafc9;font-size:13px}.securitycard{margin-top:16px}.passwordinfo{font-size:13px;color:#9eafc9;margin-top:8px}.notice{padding:13px 16px;border:1px solid #395275;border-radius:11px;background:#13243a;color:#b6d0ee;line-height:1.6;margin-top:15px}.value{font-family:ui-monospace,Consolas,monospace;font-size:14px;color:#dbe8fa;overflow-wrap:anywhere}
.eventscard{margin-top:16px}.device.alertrow{border-color:#8a5a2c;background:#2a1d10}.device.alertrow strong{color:#ffc084}.evtime{font-variant-numeric:tabular-nums}
a{color:#7cd6ef}.login{max-width:435px;margin:12vh auto;padding:32px}.login h1{margin:15px 0}ul{padding-left:20px;color:#b4c6dd;line-height:1.9}
@media(max-width:770px){.formgrid{grid-template-columns:1fr}.shell{grid-template-columns:1fr}.columns{grid-template-columns:1fr}main{padding:24px 15px}h1{font-size:22px}}
'''


def page(body, extra=''):
    return ('''<!doctype html><html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Tailscale Control Panel</title><style>''' + STYLE + '''</style></head><body>''' + body + extra + '</body></html>')


LOGIN = '''<main><section class="card login"><div class="emblem" style="display:inline-block">TS</div>
<h1>Orange Pi · Tailscale</h1><p>Accedi al pannello di amministrazione della rete.</p>
<form method="post" action="/login"><div class="field"><label for="password">Password amministratore</label>
<input id="password" name="password" type="password" autocomplete="current-password" required autofocus></div>
<button class="action" type="submit">Accedi al pannello</button></form><p style="font-size:12px">Connessione HTTPS locale protetta.</p></section></main>'''

DASH = '''<main><header class="head"><div class="logo"><div class="emblem">TS</div><div><h1>Tailscale Control Panel</h1><small>Orange Pi Zero · Subnet Router</small><div class="uiversion">Web User Interface v1.5.0</div></div></div><form method="post" action="/logout"><input type="hidden" name="csrf" value="__CSRF__"><button class="quiet">Esci</button></form></header>
<div class="shell"><div class="card"><div class="meta">Connessione Tailscale</div><div class="big" id="backend">Verifica...</div><small id="tailnet">-</small></div><div class="card"><div class="meta">Indirizzo Tailscale</div><div class="big value" id="tsip">-</div><small id="hostname">-</small></div><div class="card"><div class="meta">Rete locale</div><div class="big value" id="lanip">-</div><small id="interface">-</small></div></div>
<div class="columns"><section class="card"><h2 class="subhead">Configurazione di rete</h2><p>Configura le rotte pubblicate su Tailscale. La configurazione dell’indirizzo Ethernet (DHCP o IP statico) è gestita nella sezione dedicata qui sotto.</p>
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
  $('backend').innerHTML='<span class="dot '+(data.backend==='Running'?'good':'')+'"></span>'+escapeHtml(data.backend);
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
    server_version = 'TailscalePanel/1.5.0'
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
        self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
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
            return self._send(200, page(LOGIN))
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
                    return self._send(429, page(LOGIN + '<p>Troppi tentativi. Riprova più tardi.</p>'))
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
                return self._send(401, page(LOGIN + '<p class="err">Password non valida.</p>'))
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
