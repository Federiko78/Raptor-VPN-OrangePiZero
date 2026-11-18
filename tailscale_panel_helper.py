#!/usr/bin/env python3
"""Restricted root helper: Tailscale routes + early fail-closed LAN forward guard.

Only accepts a fixed JSON schema over stdin, with no argv (except --restore
when launched directly by a root-owned systemd oneshot). No shell execution.
The firewall guard filters FORWARDED IPv4 packets from tailscale0 to Ethernet;
it does not replace tailnet grants/ACLs or control other subnet routers.
"""
import fcntl
import ipaddress
import json
import os
import shlex
import subprocess
import sys
import tempfile
import time

BASE = '/var/lib/tailscale-panel-guard'
POLICY = BASE + '/policy.json'
LOCK = BASE + '/lock'
INTERFACE_FILE = '/etc/tailscale-panel-lan.conf'
CHAIN_A = 'TSPANEL_M_A'
CHAIN_B = 'TSPANEL_M_B'
MAX_SELECTED = 64
RFC1918 = [ipaddress.ip_network(c) for c in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
BOOLEAN_KEYS = ('snat', 'accept_routes', 'accept_dns', 'auto_update')
EXPECTED = {'mode', 'subnets', 'selected_hosts', *BOOLEAN_KEYS}


def run(argv, timeout=20, check=True):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError((result.stderr or result.stdout or 'Comando non riuscito').strip()[:350])
    return result


def lan_interface():
    try:
        with open(INTERFACE_FILE, encoding='ascii') as fd:
            dev = fd.read(80).strip()
    except OSError:
        dev = 'end0'
    if not (1 <= len(dev) <= 15 and all(c.isalnum() or c in '._-' for c in dev)):
        raise ValueError('Interfaccia LAN non valida')
    return dev


def current_lan():
    dev = lan_interface()
    result = json.loads(run(['/usr/sbin/ip' if os.path.exists('/usr/sbin/ip') else '/usr/bin/ip',
                             '-j', '-4', 'addr', 'show', 'dev', dev]).stdout)
    for interface in result:
        for addr in interface.get('addr_info', []):
            if addr.get('family') == 'inet' and addr.get('scope') == 'global':
                local = ipaddress.IPv4Address(addr['local'])
                net = ipaddress.IPv4Network('%s/%s' % (local, addr['prefixlen']), strict=False)
                if not local.is_private or net.num_addresses < 4:
                    break
                return dev, local, net
    raise ValueError('Nessun IP IPv4 privato sulla porta Ethernet')


def validate_networks(value):
    if not isinstance(value, str) or len(value) > 255:
        raise ValueError('Subnet IPv4 non valide')
    parts = [v.strip() for v in value.split(',') if v.strip()]
    if not 1 <= len(parts) <= 4:
        raise ValueError('Inserire da 1 a 4 subnet IPv4 private')
    valid = []
    for part in parts:
        try:
            net = ipaddress.ip_network(part, strict=True)
        except ValueError:
            raise ValueError('Subnet non valida: %s (esempio 192.168.1.0/24)' % part)
        if not isinstance(net, ipaddress.IPv4Network) or not any(net.subnet_of(x) for x in RFC1918):
            raise ValueError('Sono consentite soltanto subnet IPv4 private RFC1918')
        if str(net) not in valid:
            valid.append(str(net))
    return valid


def validate_selected(values, local, network):
    if not isinstance(values, list) or len(values) > MAX_SELECTED:
        raise ValueError('Selezionare al massimo 64 indirizzi IPv4')
    selected = []
    for raw in values:
        if not isinstance(raw, str):
            raise ValueError('Indirizzo dispositivo non valido')
        try:
            ip = ipaddress.IPv4Address(raw)
        except ipaddress.AddressValueError:
            raise ValueError('Indirizzo dispositivo non valido: %s' % raw[:50])
        if ip not in network or ip in (local, network.network_address, network.broadcast_address):
            raise ValueError('Il dispositivo %s non appartiene alla LAN o è l’Orange Pi' % ip)
        if str(ip) not in selected:
            selected.append(str(ip))
    return sorted(selected, key=lambda ip: int(ipaddress.IPv4Address(ip)))


def validate(data):
    if not isinstance(data, dict) or set(data) != EXPECTED:
        raise ValueError('Parametri non consentiti')
    if data['mode'] not in ('off', 'all', 'selected'):
        raise ValueError('Modalità non valida')
    for key in BOOLEAN_KEYS:
        if type(data[key]) is not bool:
            raise ValueError('Valore booleano non valido: ' + key)
    dev, local, net = current_lan()
    if not isinstance(data['subnets'], str):
        raise ValueError('Subnet IPv4 non valide')
    networks = validate_networks(data['subnets']) if data['subnets'].strip() else []
    # Disabling access must remain possible even when old selected IPs refer
    # to a different customer's network. Validate their shape/size, but only
    # require LAN membership when selective routing is actually requested.
    raw_hosts = data['selected_hosts']
    if not isinstance(raw_hosts, list) or len(raw_hosts) > MAX_SELECTED or not all(
            isinstance(v, str) and len(v) <= 15 for v in raw_hosts):
        raise ValueError('Elenco dispositivi non valido (massimo 64 IP)')
    selected = validate_selected(raw_hosts, local, net) if data['mode'] == 'selected' else []
    if data['mode'] == 'all' and not networks:
        raise ValueError('Inserire una subnet da pubblicare')
    if data['mode'] == 'selected' and not selected:
        raise ValueError('Selezionare almeno un dispositivo')
    # Scan/selected mode operates only on the directly connected local subnet.
    return {'mode': data['mode'], 'subnets': ', '.join(networks),
            'selected_hosts': selected, **{key:data[key] for key in BOOLEAN_KEYS}}, dev


def read_policy():
    """A missing/malformed policy NEVER imports a preexisting route.

    A fresh Factory starts OFF. Existing policies are preserved only by
    a separate, explicitly authorized migration/upgrade process.
    """
    try:
        with open(POLICY, encoding='utf-8') as fd:
            data = json.load(fd)
        if not isinstance(data, dict) or data.get('mode') not in ('off','all','selected'):
            return {'mode':'off','subnets':'','selected_hosts':[]}
        return data
    except (OSError, ValueError):
        return {'mode':'off', 'subnets':'', 'selected_hosts':[]}


def save_policy(data):
    os.makedirs(BASE, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=BASE, prefix='.policy-')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as out:
            os.fchmod(out.fileno(), 0o600)
            json.dump({key:data[key] for key in ('mode','subnets','selected_hosts')}, out)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, POLICY)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


def ipt(*args, check=True):
    # mangle FORWARD is evaluated before Tailscale's filter/FORWARD chain.
    # Do not insert a guard into the latter: Tailscale may reorder its jump.
    return run(['/usr/sbin/iptables', '-w', '5', '-t', 'mangle', *args],
               timeout=12, check=check)


def ip6t(*args, check=True):
    # UI supports only IPv4 subnet routes. Do not allow IPv6 forwarding
    # from the tailnet into Ethernet through another routing mechanism.
    return run(['/usr/sbin/ip6tables', '-w', '5', '-t', 'mangle', *args],
               timeout=12, check=check)


def fwd_rules():
    p = ipt('-S', 'FORWARD')
    matches = []
    for line in p.stdout.splitlines():
        tokens = shlex.split(line)
        if len(tokens) >= 4 and tokens[:2] == ['-A', 'FORWARD']:
            if '-j' in tokens:
                target = tokens[tokens.index('-j')+1]
                if target in (CHAIN_A, CHAIN_B):
                    matches.append(tokens[2:])
    return matches


def guard_ip6(interface):
    args = ('-i', 'tailscale0', '-o', interface, '-j', 'DROP')
    if ip6t('-C', 'FORWARD', *args, check=False).returncode != 0:
        ip6t('-I', 'FORWARD', '1', *args)
    if ip6t('-C', 'FORWARD', *args, check=False).returncode != 0:
        raise RuntimeError('Protezione IPv6 non installata')


def apply_guard(mode, selected, interface, subnets=''):
    """Build new mangle chain and swap its jump without a fail-open window.

    Both IPv4 and IPv6 are controlled before filter/FORWARD, regardless of
    changes Tailscale makes to ts-forward. Only IPv4 routes are configurable;
    IPv6 tailnet -> LAN forwarding is always blocked.
    """
    guard_ip6(interface)
    attached = fwd_rules()
    active = None
    for rule in attached:
        if '-j' in rule:
            target = rule[rule.index('-j')+1]
            if target in (CHAIN_A, CHAIN_B):
                active = target
                break
    target = CHAIN_B if active == CHAIN_A else CHAIN_A
    # Never flush a chain that is still referenced after an interrupted swap.
    # Leave the earlier restrictive rules intact and require reconciliation.
    if attached and any('-j' in rule and rule[rule.index('-j')+1] == target for rule in attached):
        raise RuntimeError('Catene mangle duplicate: necessario controllo prima di aggiornare')
    if not attached:
        # First establish DENY before preparing anything that might allow LAN.
        ipt('-N', CHAIN_B, check=False)
        ipt('-F', CHAIN_B)
        ipt('-A', CHAIN_B, '-j', 'DROP')
        ipt('-I', 'FORWARD', '1', '-i', 'tailscale0', '-o', interface, '-j', CHAIN_B)
        active, target = CHAIN_B, CHAIN_A
    result = ipt('-N', target, check=False)
    if result.returncode not in (0,1):
        raise RuntimeError('Impossibile creare la catena mangle')
    ipt('-F', target)
    if mode == 'selected':
        for address in selected:
            ipt('-A', target, '-d', address + '/32', '-j', 'RETURN')
    elif mode == 'all':
        for prefix in validate_networks(subnets):
            ipt('-A', target, '-d', prefix, '-j', 'RETURN')
    elif mode != 'off':
        raise ValueError('Modalità firewall non supportata')
    ipt('-A', target, '-j', 'DROP')
    ipt('-I', 'FORWARD', '1', '-i', 'tailscale0', '-o', interface, '-j', target)
    # The new jump is first; remove only older jumps to panel-owned chains.
    for rule in fwd_rules()[1:]:
        ipt('-D', 'FORWARD', *rule)
    actual = fwd_rules()
    if not actual or actual[0][-1] != target:
        raise RuntimeError('Impossibile verificare il filtro mangle')


def active_routes(data):
    if data['mode'] == 'off':
        return ''
    if data['mode'] == 'selected':
        return ','.join(ip+'/32' for ip in data['selected_hosts'])
    return ','.join(validate_networks(data['subnets']))


def apply_tailscale(data):
    cmd = ['/usr/bin/tailscale', 'set', '--advertise-routes=' + active_routes(data)]
    cmd += ['--snat-subnet-routes=' + str(data['snat']).lower(),
            '--accept-routes=' + str(data['accept_routes']).lower(),
            '--accept-dns=' + str(data['accept_dns']).lower(),
            '--auto-update=' + str(data['auto_update']).lower()]
    run(cmd, timeout=30)


def main():
    if len(sys.argv) == 2 and sys.argv[1] == '--restore' and os.geteuid() == 0:
        action = 'restore'
    elif len(sys.argv) == 1:
        raw = sys.stdin.buffer.read(8193)
        if len(raw) > 8192: raise ValueError('Richiesta troppo grande')
        body = json.loads(raw.decode('utf-8'))
        if not isinstance(body, dict) or set(body) != EXPECTED:
            raise ValueError('Schema JSON non valido')
        action = 'apply'
    else:
        raise ValueError('Argomenti non consentiti')
    if os.geteuid() != 0:
        raise ValueError('Il modulo di routing deve essere eseguito con privilegi root')
    os.makedirs(BASE, mode=0o700, exist_ok=True)
    with open(LOCK, 'a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if action == 'restore':
            fresh = not os.path.exists(POLICY)
            previous = read_policy()
            dev = lan_interface()
            mode, hosts = 'off', []
            # Apply a DENY guard immediately, BEFORE waiting for DHCP.
            apply_guard('off', [], dev)
            # At boot IPv4 may not yet be leased; allow up to 15 s to restore
            # the previous policy without unnecessarily leaving LAN blocked.
            for attempt in range(16):
                try:
                    dev, local, network = current_lan()
                    # On a new customer LAN, never authorize the old LAN.
                    if previous.get('mode') == 'selected':
                        saved = previous.get('selected_hosts', [])
                        hosts = validate_selected(saved, local, network)
                        mode = 'selected' if hosts and len(hosts) == len(saved) else 'off'
                    elif previous.get('mode') == 'all':
                        routes = validate_networks(previous.get('subnets',''))
                        mode = 'all' if any(local in ipaddress.IPv4Network(route) for route in routes) else 'off'
                    break
                except (ValueError, TypeError, RuntimeError):
                    if attempt < 15: time.sleep(1)
            if mode != 'off':
                apply_guard(mode, hosts, dev, previous.get('subnets', ''))
            if fresh:  # Capture previously running R1.2 policy before reboot.
                save_policy(previous)
            return print(json.dumps({'ok':True,'guard_mode':mode}))
        data, dev = validate(body)
        previous = read_policy()
        # Stage on persistent storage BEFORE updating network configuration.
        # A disk error must not leave successfully changed routes without a
        # matching boot guard policy.
        save_policy(data)
        try:
            apply_guard(data['mode'], data['selected_hosts'], dev, data['subnets'])
            apply_tailscale(data)
        except (RuntimeError, subprocess.TimeoutExpired, OSError, ValueError) as err:
            try:
                save_policy(previous)
                apply_guard(previous.get('mode','off'), previous.get('selected_hosts',[]), dev, previous.get('subnets',''))
                apply_tailscale({**data, **previous})
            except Exception:
                pass  # Prefer an existing restrictive guard to removing it.
            raise err
        print(json.dumps({'ok':True, 'mode':data['mode'],
                          'advertised':active_routes(data).split(',') if active_routes(data) else []}))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, OSError, KeyError, TypeError,
            subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        print(json.dumps({'ok':False,'error':str(exc)[:500]}))
        sys.exit(1)
