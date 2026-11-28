#!/usr/bin/env python3
"""Restricted root helper: Tailscale routes + early fail-closed LAN forward guard.

Only accepts a fixed JSON schema over stdin, with no argv (except --restore
when launched directly by a root-owned systemd oneshot). No shell execution.
The firewall guard filters FORWARDED IPv4 packets from tailscale0 to Ethernet;
it does not replace tailnet grants/ACLs or control other subnet routers.

Mode "alias": no route is published at all. Everything that reaches the Orange Pi's
own Tailscale address is forwarded (DNAT) to ONE LAN device, which therefore appears
to the tailnet under the Pi's 100.x address. The LAN address of the device never
leaves the customer's network, so it cannot clash with the addresses of the remote site.

Mode "translated": the LAN is published under ANOTHER network of the same size (for example
192.168.1.0/24 seen as 192.168.2.0/24). Packets from the tailnet for 192.168.2.N are rewritten
(NETMAP for the whole network, DNAT for chosen devices) to 192.168.1.N and masqueraded, so the
remote site can use addresses that do not clash with its own. The Pi itself is never translated.
The "subnets" field carries the translated network; "selected_hosts" (optional) the real devices.
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
CHAIN_ALIAS_PRE = 'TSPANEL_ALIAS_PRE'
CHAIN_ALIAS_POST = 'TSPANEL_ALIAS_POST'
TAILNET = '100.64.0.0/10'
MAX_SELECTED = 64
RFC1918 = [ipaddress.ip_network(c) for c in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
BOOLEAN_KEYS = ('snat', 'accept_routes', 'accept_dns', 'auto_update')
EXPECTED = {'mode', 'subnets', 'selected_hosts', *BOOLEAN_KEYS}
MODES = ('off', 'all', 'selected', 'alias', 'translated')
NETMAP_MISSING = 'Whole-network translation is not available on this Orange Pi: choose the devices to translate'


def run(argv, timeout=20, check=True):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError((result.stderr or result.stdout or 'Command failed').strip()[:350])
    return result


def lan_interface():
    try:
        with open(INTERFACE_FILE, encoding='ascii') as fd:
            dev = fd.read(80).strip()
    except OSError:
        dev = 'end0'
    if not (1 <= len(dev) <= 15 and all(c.isalnum() or c in '._-' for c in dev)):
        raise ValueError('Invalid LAN interface')
    return dev


def ip_binary():
    return '/usr/sbin/ip' if os.path.exists('/usr/sbin/ip') else '/usr/bin/ip'


def current_lan():
    dev = lan_interface()
    result = json.loads(run([ip_binary(), '-j', '-4', 'addr', 'show', 'dev', dev]).stdout)
    for interface in result:
        for addr in interface.get('addr_info', []):
            if addr.get('family') == 'inet' and addr.get('scope') == 'global':
                if str(addr.get('local', '')).startswith('169.254.'):
                    continue  # indirizzo link-local: non e' la LAN del cliente
                local = ipaddress.IPv4Address(addr['local'])
                net = ipaddress.IPv4Network('%s/%s' % (local, addr['prefixlen']), strict=False)
                if not local.is_private or net.num_addresses < 4:
                    break
                return dev, local, net
    raise ValueError('No private IPv4 address on the Ethernet port')


def validate_networks(value):
    if not isinstance(value, str) or len(value) > 255:
        raise ValueError('Invalid IPv4 subnets')
    parts = [v.strip() for v in value.split(',') if v.strip()]
    if not 1 <= len(parts) <= 4:
        raise ValueError('Enter 1 to 4 private IPv4 subnets')
    valid = []
    for part in parts:
        try:
            net = ipaddress.ip_network(part, strict=True)
        except ValueError:
            raise ValueError('Invalid subnet: %s (example 192.168.1.0/24)' % part)
        if not isinstance(net, ipaddress.IPv4Network) or not any(net.subnet_of(x) for x in RFC1918):
            raise ValueError('Only private RFC1918 IPv4 subnets are allowed')
        if str(net) not in valid:
            valid.append(str(net))
    return valid


def local_networks():
    """Networks the Orange Pi is directly connected to (main routing table, default route left out).

    Only a sanity check for the translated network: if the list cannot be read, nothing is excluded.
    """
    found = []
    try:
        routes = json.loads(run([ip_binary(), '-j', '-4', 'route', 'show']).stdout)
        for route in routes if isinstance(routes, list) else []:
            dst = route.get('dst') if isinstance(route, dict) else None
            if isinstance(dst, str) and dst != 'default':
                found.append(ipaddress.ip_network(dst, strict=False))
    except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired):
        pass
    return found


def validate_translated(value, network):
    """The one network under which the LAN is published: same size, private, free."""
    nets = validate_networks(value) if isinstance(value, str) and value.strip() else []
    if len(nets) != 1:
        raise ValueError('Enter exactly one translated network (example 192.168.2.0/24)')
    trans = ipaddress.IPv4Network(nets[0])
    if trans.prefixlen != network.prefixlen:
        raise ValueError('The translated network must be the same size as the LAN network (/%d)' % network.prefixlen)
    if trans.overlaps(network):
        raise ValueError('The translated network must be different from the LAN network')
    for used in local_networks():
        if trans.overlaps(used):
            raise ValueError('The translated network overlaps a network already used by this Orange Pi: %s' % used)
    return trans


def map_address(ip, lan, trans):
    """The address under which the LAN device `ip` is seen through the translated network."""
    return str(ipaddress.IPv4Address(int(trans.network_address) + int(ipaddress.IPv4Address(ip)) - int(lan.network_address)))


def translation(policy, lan, local):
    """What the firewall steps need for the translated mode; None if the policy is not for this LAN or not translated."""
    if not isinstance(policy, dict) or policy.get('mode') != 'translated' or policy.get('lan') != lan:
        return None
    try:
        nets = validate_networks(policy.get('subnets', ''))
    except ValueError:
        return None
    return {'net': nets[0], 'lan': lan, 'local': local} if len(nets) == 1 else None


def validate_selected(values, local, network):
    if not isinstance(values, list) or len(values) > MAX_SELECTED:
        raise ValueError('Select at most 64 IPv4 addresses')
    selected = []
    for raw in values:
        if not isinstance(raw, str):
            raise ValueError('Invalid device address')
        try:
            ip = ipaddress.IPv4Address(raw)
        except ipaddress.AddressValueError:
            raise ValueError('Invalid device address: %s' % raw[:50])
        if ip not in network or ip in (local, network.network_address, network.broadcast_address):
            raise ValueError('Device %s is not on the LAN or is the Orange Pi itself' % ip)
        if str(ip) not in selected:
            selected.append(str(ip))
    return sorted(selected, key=lambda ip: int(ipaddress.IPv4Address(ip)))


def validate(data):
    if not isinstance(data, dict) or set(data) != EXPECTED:
        raise ValueError('Parameters not allowed')
    if data['mode'] not in MODES:
        raise ValueError('Invalid mode')
    for key in BOOLEAN_KEYS:
        if type(data[key]) is not bool:
            raise ValueError('Invalid boolean value: ' + key)
    dev, local, net = current_lan()
    if not isinstance(data['subnets'], str):
        raise ValueError('Invalid IPv4 subnets')
    networks = validate_networks(data['subnets']) if data['subnets'].strip() else []
    # Disabling access must remain possible even when old selected IPs refer
    # to a different customer's network. Validate their shape/size, but only
    # require LAN membership when selective routing is actually requested.
    raw_hosts = data['selected_hosts']
    if not isinstance(raw_hosts, list) or len(raw_hosts) > MAX_SELECTED or not all(
            isinstance(v, str) and len(v) <= 15 for v in raw_hosts):
        raise ValueError('Invalid device list (maximum 64 IPs)')
    selected = validate_selected(raw_hosts, local, net) if data['mode'] in ('selected', 'alias', 'translated') else []
    if data['mode'] == 'all' and not networks:
        raise ValueError('Enter a subnet to publish')
    if data['mode'] == 'selected' and not selected:
        raise ValueError('Select at least one device')
    if data['mode'] == 'alias' and len(selected) != 1:
        raise ValueError('Choose exactly one device for the Tailscale alias')
    if data['mode'] == 'translated':
        # No device chosen = the whole LAN is translated; devices chosen = only those.
        networks = [str(validate_translated(data['subnets'], net))]
    # Scan/selected mode operates only on the directly connected local subnet.
    # "lan" and "local" describe the LAN seen now; only "lan" of the translated mode is saved.
    return {'mode': data['mode'], 'subnets': ', '.join(networks),
            'selected_hosts': selected, **{key:data[key] for key in BOOLEAN_KEYS},
            'lan': str(net), 'local': str(local)}, dev


def read_policy():
    """A missing/malformed policy NEVER imports a preexisting route.

    A fresh Factory starts OFF. Existing policies are preserved only by
    a separate, explicitly authorized migration/upgrade process.
    """
    try:
        with open(POLICY, encoding='utf-8') as fd:
            data = json.load(fd)
        if not isinstance(data, dict) or data.get('mode') not in MODES:
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
            saved = {key:data[key] for key in ('mode','subnets','selected_hosts')}
            if data['mode'] == 'translated':
                saved['lan'] = data.get('lan', '')  # the translation only ever applies to the LAN it was set up on
            json.dump(saved, out)
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
        raise RuntimeError('IPv6 protection not installed')


def apply_guard(mode, selected, interface, subnets='', lan=''):
    """Build new mangle chain and swap its jump without a fail-open window.

    Both IPv4 and IPv6 are controlled before filter/FORWARD, regardless of
    changes Tailscale makes to ts-forward. Only IPv4 routes are configurable;
    IPv6 tailnet -> LAN forwarding is always blocked.

    Mode "translated": the destination is checked AFTER the translation (mangle FORWARD
    comes after the nat PREROUTING), so the real LAN addresses are listed, and only for
    packets that really went through the translation (conntrack state DNAT): a packet for a
    real LAN address that was not translated (for example the Pi's own) never gets through.
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
        raise RuntimeError('Duplicate mangle chains: check needed before updating')
    if not attached:
        # First establish DENY before preparing anything that might allow LAN.
        ipt('-N', CHAIN_B, check=False)
        ipt('-F', CHAIN_B)
        ipt('-A', CHAIN_B, '-j', 'DROP')
        ipt('-I', 'FORWARD', '1', '-i', 'tailscale0', '-o', interface, '-j', CHAIN_B)
        active, target = CHAIN_B, CHAIN_A
    result = ipt('-N', target, check=False)
    if result.returncode not in (0,1):
        raise RuntimeError('Unable to create the mangle chain')
    ipt('-F', target)
    if mode in ('selected', 'alias'):
        for address in selected:
            ipt('-A', target, '-d', address + '/32', '-j', 'RETURN')
    elif mode == 'all':
        for prefix in validate_networks(subnets):
            ipt('-A', target, '-d', prefix, '-j', 'RETURN')
    elif mode == 'translated':
        reachable = [address + '/32' for address in selected] or validate_networks(lan)[:1]
        for destination in reachable:
            ipt('-A', target, '-d', destination, '-m', 'conntrack', '--ctstate', 'DNAT', '-j', 'RETURN')
    elif mode != 'off':
        raise ValueError('Unsupported firewall mode')
    ipt('-A', target, '-j', 'DROP')
    ipt('-I', 'FORWARD', '1', '-i', 'tailscale0', '-o', interface, '-j', target)
    # The new jump is first; remove only older jumps to panel-owned chains.
    for rule in fwd_rules()[1:]:
        ipt('-D', 'FORWARD', *rule)
    actual = fwd_rules()
    if not actual or actual[0][-1] != target:
        raise RuntimeError('Unable to verify the mangle filter')


def ipt_nat(*args, check=True):
    return run(['/usr/sbin/iptables', '-w', '5', '-t', 'nat', *args], timeout=12, check=check)


def alias_jumps(hook):
    """Rules of a nat hook chain that jump to the alias chains (as iptables -S prints them)."""
    rules = []
    for line in ipt_nat('-S', hook).stdout.splitlines():
        tokens = shlex.split(line)
        if tokens[:2] == ['-A', hook] and '-j' in tokens and tokens[tokens.index('-j') + 1] in (CHAIN_ALIAS_PRE, CHAIN_ALIAS_POST):
            rules.append(tokens[2:])
    return rules


def alias_chain(chain):
    if ipt_nat('-S', chain, check=False).returncode != 0:
        ipt_nat('-N', chain)
    ipt_nat('-F', chain)


def alias_jump(hook, wanted):
    """Make `wanted` the only jump to an alias chain in the hook; the new one is added before removing old ones."""
    if wanted not in alias_jumps(hook):
        ipt_nat('-I', hook, '1', *wanted)
    for rule in alias_jumps(hook):
        if rule != wanted:
            ipt_nat('-D', hook, *rule)
    if alias_jumps(hook) != [wanted]:
        raise RuntimeError('Unable to verify the alias rules')


def apply_alias(host, interface):
    """Forward everything sent to the Pi's own Tailscale address to `host`, and nothing else.

    Called AFTER the mangle guard, which already lets only `host` through to the LAN.
    DNAT matches the Pi's local addresses on tailscale0 (so a changed Tailscale address
    needs nothing); the MASQUERADE makes the device answer to the Pi whatever the
    "snat" setting says, because the device does not know the 100.x network.
    """
    ipaddress.IPv4Address(host)
    install_nat([['-m', 'addrtype', '--dst-type', 'LOCAL', '-j', 'DNAT', '--to-destination', host]],
                [['-s', TAILNET, '-d', host + '/32', '-j', 'MASQUERADE']], interface)


def install_nat(pre_rules, post_rules, interface):
    """Fill the two panel nat chains, and only then hook them in (alias and translated mode share them)."""
    alias_chain(CHAIN_ALIAS_PRE)
    for rule in pre_rules:
        try:
            ipt_nat('-A', CHAIN_ALIAS_PRE, *rule)
        except RuntimeError:
            if 'NETMAP' in rule:  # the kernel of this board has no NETMAP: leave nothing half done
                clear_alias()
                raise RuntimeError(NETMAP_MISSING)
            raise
    alias_chain(CHAIN_ALIAS_POST)
    for rule in post_rules:
        ipt_nat('-A', CHAIN_ALIAS_POST, *rule)
    alias_jump('PREROUTING', ['-i', 'tailscale0', '-j', CHAIN_ALIAS_PRE])
    alias_jump('POSTROUTING', ['-o', interface, '-j', CHAIN_ALIAS_POST])


def apply_translated(trans, hosts, interface):
    """Show the LAN (or only `hosts`) to the tailnet under the translated network.

    trans = {'net': translated network, 'lan': the real network, 'local': the Pi's own LAN address}.
    Called AFTER the mangle guard. The MASQUERADE makes the devices answer to the Pi whatever the
    "snat" setting says, because they do not know the 100.x network.
    """
    lan = ipaddress.IPv4Network(trans['lan'], strict=True)
    net = ipaddress.IPv4Network(trans['net'], strict=True)
    local = ipaddress.IPv4Address(trans['local'])
    if net.prefixlen != lan.prefixlen or net.overlaps(lan) or local not in lan:
        raise ValueError('Invalid translated network')
    if not isinstance(hosts, list) or any(ipaddress.IPv4Address(host) not in lan for host in hosts):
        raise ValueError('Invalid device address')
    pre, post = [], []
    if hosts:
        for host in hosts:
            pre.append(['-d', map_address(host, lan, net) + '/32', '-j', 'DNAT', '--to-destination', host])
            post.append(['-s', TAILNET, '-d', host + '/32', '-j', 'MASQUERADE'])
    else:
        # The Pi itself and the network/broadcast address are never translated: untouched, the guard drops them.
        for special in (local, lan.network_address, lan.broadcast_address):
            pre.append(['-d', map_address(str(special), lan, net) + '/32', '-j', 'RETURN'])
        pre.append(['-d', str(net), '-j', 'NETMAP', '--to', str(lan)])
        post.append(['-s', TAILNET, '-d', str(lan), '-j', 'MASQUERADE'])
    install_nat(pre, post, interface)


def clear_alias():
    """Remove every alias rule (jumps first, then the chains). Nothing to do if there never was one."""
    for hook in ('PREROUTING', 'POSTROUTING'):
        for rule in alias_jumps(hook):
            ipt_nat('-D', hook, *rule)
    for chain in (CHAIN_ALIAS_PRE, CHAIN_ALIAS_POST):
        if ipt_nat('-S', chain, check=False).returncode == 0:
            ipt_nat('-F', chain)
            ipt_nat('-X', chain)


def apply_nat(mode, selected, interface, trans=None):
    if mode == 'alias' and len(selected) == 1:
        apply_alias(selected[0], interface)
    elif mode == 'translated' and trans:
        apply_translated(trans, selected, interface)
    else:
        clear_alias()


def active_routes(data):
    if data['mode'] in ('off', 'alias'):
        return ''
    if data['mode'] == 'selected':
        return ','.join(ip+'/32' for ip in data['selected_hosts'])
    if data['mode'] == 'translated' and data['selected_hosts']:
        lan = ipaddress.IPv4Network(data['lan'])
        net = ipaddress.IPv4Network(validate_networks(data['subnets'])[0])
        return ','.join(map_address(ip, lan, net) + '/32' for ip in data['selected_hosts'])
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
        if len(raw) > 8192: raise ValueError('Request too large')
        body = json.loads(raw.decode('utf-8'))
        if not isinstance(body, dict) or set(body) != EXPECTED:
            raise ValueError('Invalid JSON schema')
        action = 'apply'
    else:
        raise ValueError('Arguments not allowed')
    if os.geteuid() != 0:
        raise ValueError('The routing module must run with root privileges')
    os.makedirs(BASE, mode=0o700, exist_ok=True)
    with open(LOCK, 'a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if action == 'restore':
            fresh = not os.path.exists(POLICY)
            previous = read_policy()
            dev = lan_interface()
            mode, hosts, trans, lan_text = 'off', [], None, ''
            # Apply a DENY guard immediately, BEFORE waiting for DHCP.
            apply_guard('off', [], dev)
            # At boot IPv4 may not yet be leased; allow up to 15 s to restore
            # the previous policy without unnecessarily leaving LAN blocked.
            for attempt in range(16):
                try:
                    dev, local, network = current_lan()
                    # On a new customer LAN, never authorize the old LAN.
                    if previous.get('mode') in ('selected', 'alias'):
                        saved = previous.get('selected_hosts', [])
                        hosts = validate_selected(saved, local, network)
                        wanted = 1 if previous['mode'] == 'alias' else None
                        ok = bool(hosts) and len(hosts) == len(saved) and (wanted is None or len(hosts) == wanted)
                        mode = previous['mode'] if ok else 'off'
                    elif previous.get('mode') == 'all':
                        routes = validate_networks(previous.get('subnets',''))
                        mode = 'all' if any(local in ipaddress.IPv4Network(route) for route in routes) else 'off'
                    elif previous.get('mode') == 'translated':
                        # Only on the very LAN it was set up on, and only if everything still fits.
                        trans = translation(previous, str(network), str(local))
                        if trans is not None:
                            validate_translated(trans['net'], network)
                            saved = previous.get('selected_hosts', [])
                            hosts = validate_selected(saved, local, network) if saved else []
                            if len(hosts) == len(saved):
                                mode, lan_text = 'translated', str(network)
                    break
                except (ValueError, TypeError, RuntimeError):
                    if attempt < 15: time.sleep(1)
            if mode != 'off':
                apply_guard(mode, hosts, dev, previous.get('subnets', ''), lan_text)
            try:
                apply_nat(mode, hosts if mode in ('alias', 'translated') else [], dev, trans if mode == 'translated' else None)
            except (RuntimeError, subprocess.TimeoutExpired, OSError, ValueError):
                if mode in ('alias', 'translated'):  # without the forward it would silently do nothing: stay closed
                    apply_guard('off', [], dev)
                    mode = 'off'
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
            apply_guard(data['mode'], data['selected_hosts'], dev, data['subnets'], data['lan'])
            apply_nat(data['mode'], data['selected_hosts'], dev, translation(data, data['lan'], data['local']))
            apply_tailscale(data)
        except (RuntimeError, subprocess.TimeoutExpired, OSError, ValueError) as err:
            try:
                save_policy(previous)
                apply_guard(previous.get('mode','off'), previous.get('selected_hosts',[]), dev, previous.get('subnets',''), previous.get('lan',''))
                apply_nat(previous.get('mode','off'), previous.get('selected_hosts',[]), dev, translation(previous, data['lan'], data['local']))
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
