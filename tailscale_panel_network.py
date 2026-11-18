#!/usr/bin/env python3
"""Restricted root Netplan controller for Orange Pi Zero / Armbian Minimal.

Public sudo entry: no command line arguments, JSON stdin.
Internal entry points (--apply/--rollback) are invoked only by systemd timers.
"""
import base64
import fcntl
import ipaddress
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import time
import uuid

DEV = 'end0'
NETDIR = pathlib.Path('/etc/netplan')
DEFAULT = NETDIR / '10-dhcp-all-interfaces.yaml'
CUSTOM = NETDIR / '90-tailscale-panel-end0.yaml'
# Root-only directory, outside tspanel-writable /var/lib/tailscale-panel.
STATE = pathlib.Path('/var/lib/tailscale-panel-network')
PENDING = STATE / 'pending.json'
LOCK = pathlib.Path('/run/lock/tailscale-panel-network.lock')
SELF = pathlib.Path('/usr/local/libexec/tailscale-panel-net-helper')
WAIT_SECONDS = 150


def shell(args, timeout=15):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def atomic_write(path, data, mode=0o600):
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


def read_pending():
    try:
        return json.loads(PENDING.read_text())
    except FileNotFoundError:
        return None


def locked(fn):
    with open(LOCK, 'a+') as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        return fn()


def ipv4(value):
    try:
        return ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, TypeError):
        raise ValueError('Indirizzo IPv4 non valido: %s' % value)


def private_lan(ip):
    return any(ip in x for x in [ipaddress.ip_network('10.0.0.0/8'), ipaddress.ip_network('172.16.0.0/12'), ipaddress.ip_network('192.168.0.0/16')])


def validate(body):
    if not isinstance(body, dict) or set(body) != {'mode','ip','prefix','gateway','dns'}:
        raise ValueError('Campi di configurazione rete non validi.')
    mode = body['mode']
    if mode not in ('dhcp','static'):
        raise ValueError('Modalita non valida: usare DHCP o statico.')
    if mode == 'dhcp':
        return {'mode':'dhcp','ip':'','prefix':24,'gateway':'','dns':[]}
    try:
        prefix = int(body['prefix'])
    except (TypeError, ValueError):
        raise ValueError('Prefisso CIDR non valido.')
    if not 8 <= prefix <= 30:
        raise ValueError('Prefisso IPv4 consentito: da /8 a /30.')
    address = ipv4(body['ip'])
    gateway = ipv4(body['gateway'])
    network = ipaddress.IPv4Network('%s/%s' % (address,prefix), strict=False)
    if not private_lan(address) or not private_lan(gateway):
        raise ValueError('Sono consentiti solo IP e gateway delle reti LAN private.')
    if address in (network.network_address, network.broadcast_address):
        raise ValueError('IP statico non utilizzabile: rete o broadcast.')
    if gateway not in network or gateway == address:
        raise ValueError('Il gateway deve stare nella stessa subnet ed essere diverso dall’IP Orange Pi.')
    if not isinstance(body['dns'], list) or not 1 <= len(body['dns']) <= 3:
        raise ValueError('Inserire da 1 a 3 server DNS IPv4.')
    dns = []
    for item in body['dns']:
        addr = ipv4(item)
        if addr.is_multicast or addr.is_unspecified or addr.is_loopback or addr.is_link_local:
            raise ValueError('Server DNS non utilizzabile.')
        if str(addr) not in dns:
            dns.append(str(addr))
    return {'mode':'static','ip':str(address),'prefix':prefix,'gateway':str(gateway),'dns':dns}


def known_default(content):
    """Fail closed if the supposed default file has unexpected settings."""
    s = content.decode('utf-8')
    return ('all-eth-interfaces:' in s and 'dhcp4:' in s and 'name: "e*"' in s and
            not any(k in s for k in ('addresses:', 'routes:', 'gateway4:', 'nameservers:')))


def assert_platform():
    if not shutil.which('netplan'):
        raise RuntimeError('Netplan non installato: gestione rete non supportata.')
    if shell(['systemctl','is-active','systemd-networkd'], 8).stdout.strip() != 'active':
        raise RuntimeError('Questo pannello richiede Armbian Minimal con systemd-networkd attivo.')
    if not pathlib.Path('/sys/class/net/' + DEV).exists():
        raise RuntimeError('Interfaccia Ethernet end0 non presente.')
    if not NETDIR.exists():
        raise RuntimeError('Cartella /etc/netplan mancante.')
    if not DEFAULT.exists() and not CUSTOM.exists():
        raise RuntimeError('Configurazione Netplan preesistente non riconosciuta: verifica /etc/netplan.')
    if DEFAULT.exists() and not known_default(DEFAULT.read_bytes()):
        raise RuntimeError('Netplan personalizzato: intervenire manualmente, modifica automatica bloccata.')
    # Refuse unknown netplan files: an unrelated eth profile could override end0.
    other = [f.name for f in NETDIR.iterdir() if f.suffix in ('.yaml','.yml') and f not in (DEFAULT,CUSTOM)]
    if other:
        raise RuntimeError('Profili Netplan aggiuntivi (%s): modifica automatica bloccata per sicurezza.' % ', '.join(other)[:160])
    if CUSTOM.exists() and 'Managed by Tailscale Panel' not in CUSTOM.read_text():
        raise RuntimeError('File Netplan del pannello modificato esternamente: rifiuto la sovrascrittura.')


def get_current():
    out = {'supported':False,'reason':'','mode':'dhcp','ip':'','prefix':24,'gateway':'','dns':[], 'pending':None}
    try:
        assert_platform()
        out['supported'] = True
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as e:
        out['reason'] = str(e)
    if CUSTOM.exists():
        # Proprietary comment at top allows read-only state without yaml dependency.
        for line in CUSTOM.read_text().splitlines():
            if line.startswith('# TSPANEL-CONFIG:'):
                try:
                    config = json.loads(line.split(':',1)[1].strip())
                    out.update(config)
                except (ValueError, TypeError):
                    pass
                break
    pending = read_pending()
    if pending:
        out['pending'] = {'id':pending['id'],'mode':pending['config']['mode'],
                          'ip':pending['config']['ip'], 'expires_at':pending['expires_at'],
                          'state':pending.get('state','scheduled')}
    return out


def render(config):
    tag = '# TSPANEL-CONFIG: ' + json.dumps(config, ensure_ascii=True, sort_keys=True, separators=(',',':'))
    output = ['# Managed by Tailscale Panel - do not edit manually', tag,
              'network:', '  version: 2', '  renderer: networkd', '  ethernets:',
              '    end0:', '      dhcp6: ' + ('true' if config['mode']=='dhcp' else 'false'), '      dhcp4: ' + ('true' if config['mode']=='dhcp' else 'false')]
    if config['mode'] == 'static':
        output += ['      addresses:', '        - '+ config['ip'] + '/' + str(config['prefix']),
                   '      routes:', '        - to: default', '          via: '+config['gateway'],
                   '      nameservers:', '        addresses: ['+', '.join(config['dns'])+']']
    return ('\n'.join(output)+'\n').encode()


def snapshot():
    files = {}
    for file in (DEFAULT,CUSTOM):
        files[str(file)] = (base64.b64encode(file.read_bytes()).decode() if file.exists() else None)
    return files


def restore(files):
    for path, content in files.items():
        if path not in (str(DEFAULT),str(CUSTOM)):
            raise RuntimeError('Percorso backup non consentito.')
        file = pathlib.Path(path)
        if content is None:
            if file.exists():
                file.unlink()
        else:
            atomic_write(file, base64.b64decode(content), 0o600)


def cancel_timers(id):
    for prefix in ('tspanel-rollback','tspanel-apply'):
        shell(['systemctl','stop', prefix+'-'+id+'.timer'],timeout=8)


def rollback(id):
    def run_rollback():
        pending = read_pending()
        if not pending or pending['id'] != id:
            return {'ok':True,'note':'Nessuna modifica da ripristinare.'}
        restore(pending['snapshot'])
        generate = shell(['netplan','generate'], 20)
        if generate.returncode:
            raise RuntimeError('Ripristino configurazione su disco, ma netplan generate non riuscito: '+generate.stderr[-200:])
        applied = shell(['netplan','apply'],75)
        if applied.returncode:
            raise RuntimeError('Ripristino su disco riuscito ma applicazione fallita: '+applied.stderr[-200:])
        PENDING.unlink(missing_ok=True)
        return {'ok':True,'rolled_back':True}
    return locked(run_rollback)


def start(config):
    def perform():
        assert_platform()
        if read_pending():
            raise RuntimeError('Modifica precedente ancora in sospeso. Confermala o attendi il ripristino.')
        space = shutil.disk_usage('/').free
        if space < 30 * 1024 * 1024:
            raise RuntimeError('Spazio libero insufficiente per una modifica di rete sicura.')
        sid = uuid.uuid4().hex[:14]
        pending = {'id':sid,'config':config,'snapshot':snapshot(),
                   'expires_at':int(time.time())+WAIT_SECONDS,'state':'scheduled'}
        # Apply nothing if creating the persistent rollback timer fails.
        rollback_timer = shell(['systemd-run','--quiet','--unit=tspanel-rollback-'+sid,
                                '--on-active=%ds' % WAIT_SECONDS,
                                str(SELF),'--rollback',sid],20)
        if rollback_timer.returncode:
            raise RuntimeError('Impossibile creare timer ripristino: '+rollback_timer.stderr[-200:])
        # Durable, root-only copy of the original Netplan files for manual recovery.
        atomic_write(STATE / ('backup-'+sid+'.json'),json.dumps(pending['snapshot']).encode())
        atomic_write(PENDING, json.dumps(pending).encode())
        apply_timer = shell(['systemd-run','--quiet','--unit=tspanel-apply-'+sid,
                             '--on-active=4s',str(SELF),'--apply',sid],20)
        if apply_timer.returncode:
            PENDING.unlink(missing_ok=True)
            cancel_timers(sid)
            raise RuntimeError('Impossibile avviare modifica rete: '+apply_timer.stderr[-200:])
        return {'ok':True,'id':sid,'expires_at':pending['expires_at'],
                'new_url':'https://'+ (config['ip'] if config['mode']=='static' else 'orangepizero.local')+':8443',
                'host_url':'https://orangepizero.local:8443'}
    return locked(perform)


def apply(id):
    def run_apply():
        pending = read_pending()
        if not pending or pending['id'] != id:
            return {'ok':True,'note':'Modifica gia conclusa.'}
        config = pending['config']
        if DEFAULT.exists():
            DEFAULT.unlink()
        atomic_write(CUSTOM, render(config), 0o600)
        generate = shell(['netplan','generate'],20)
        if generate.returncode:
            restore(pending['snapshot'])
            shell(['netplan','generate'],20)
            PENDING.unlink(missing_ok=True)
            raise RuntimeError('Netplan generate fallito: '+generate.stderr[-300:])
        pending['state'] = 'applying'
        atomic_write(PENDING,json.dumps(pending).encode())
        return {'ok':True}
    locked(run_apply)
    # Don't hold lock while netplan reconfigures network.
    applied = shell(['netplan','apply'],75)
    if applied.returncode:
        return rollback(id)
    def mark():
        pending = read_pending()
        if pending and pending['id']==id:
            pending['state']='applied'
            atomic_write(PENDING,json.dumps(pending).encode())
    locked(mark)
    return {'ok':True,'applied':True}


def confirm(id):
    def run_confirm():
        p = read_pending()
        if not p or p['id'] != id:
            raise ValueError('Nessuna configurazione in attesa con questo identificativo.')
        if p.get('state') != 'applied':
            raise ValueError('Modifica non ancora applicata: attendere e riprovare.')
        current = shell(['ip','-j','-4','addr','show','dev',DEV],10)
        ips = json.loads(current.stdout) if current.returncode==0 else []
        assigned = {a.get('local') for d in ips for a in d.get('addr_info',[])}
        desired = p['config']['ip']
        if desired and desired not in assigned:
            raise ValueError('L’IP statico non e ancora attivo: non confermo.')
        if not assigned:
            raise ValueError('Nessun IP assegnato su end0: non confermo.')
        PENDING.unlink(missing_ok=True)
        return {'ok':True,'confirmed':True}
    result = locked(run_confirm)
    cancel_timers(id)
    return result


def api():
    data = sys.stdin.buffer.read(8193)
    if len(data)>8192:
        raise ValueError('Richiesta troppo grande')
    payload = json.loads(data)
    if not isinstance(payload,dict):
        raise ValueError('Richiesta non valida')
    action=payload.get('action')
    if action=='status' and set(payload)=={'action'}:
        return {'ok':True,'network':get_current()}
    if action=='start' and set(payload)=={'action','config'}:
        return start(validate(payload['config']))
    if action=='confirm' and set(payload)=={'action','id'}:
        id=payload['id']
        if not isinstance(id,str) or not re.fullmatch('[0-9a-f]{14}',id):
            raise ValueError('ID conferma non valido')
        return confirm(id)
    raise ValueError('Azione o parametri non consentiti.')


def main():
    os.umask(0o077)
    STATE.mkdir(parents=True, exist_ok=True,mode=0o700)
    os.chmod(STATE,0o700)
    if len(sys.argv)==2 and sys.argv[1]=='--recover':
        pending=read_pending()
        result=rollback(pending['id']) if pending else {'ok':True,'note':'Nessun ripristino necessario.'}
    elif len(sys.argv)==3 and sys.argv[1] in ('--apply','--rollback'):
        sid=sys.argv[2]
        if not re.fullmatch('[0-9a-f]{14}',sid):
            raise ValueError('ID interno non valido')
        result = apply(sid) if sys.argv[1]=='--apply' else rollback(sid)
    elif len(sys.argv)==1:
        result=api()
    else:
        raise ValueError('Argomenti non consentiti.')
    print(json.dumps(result))

if __name__=='__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        print(json.dumps({'ok':False,'error':str(e)[:500]}))
        sys.exit(1)
