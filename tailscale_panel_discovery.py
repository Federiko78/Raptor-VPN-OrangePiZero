#!/usr/bin/env python3
"""Narrow privileged ARP inventory for the currently connected Ethernet LAN.

Only one fixed action is permitted. No arbitrary target/network/ports can be
provided by the browser. No TCP service probes, no remote VLAN/subnet probing.
"""
import ipaddress
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

INTERFACE_FILE = '/etc/tailscale-panel-lan.conf'
IP_PATTERN = re.compile(r'^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})(?:\s+(.*))?$')


def call(argv, timeout):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                          env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})


def discover_network():
    with open(INTERFACE_FILE, encoding='ascii') as fd:
        dev = fd.read(80).strip()
    if not dev or len(dev) > 15 or any(not(c.isalnum() or c in '._-') for c in dev):
        raise ValueError('Interfaccia Ethernet non valida')
    result = call(['/usr/sbin/ip' if os.path.exists('/usr/sbin/ip') else '/usr/bin/ip',
                   '-j','-4','addr','show','dev',dev], timeout=4)
    if result.returncode:
        raise ValueError('Impossibile leggere la porta Ethernet')
    interfaces = json.loads(result.stdout)
    for iface in interfaces:
        for item in iface.get('addr_info',[]):
            if item.get('family') == 'inet' and item.get('scope') == 'global':
                local = ipaddress.IPv4Address(item['local'])
                net = ipaddress.IPv4Network('%s/%s' % (local,item['prefixlen']),strict=False)
                if not net.is_private or net.num_addresses > 1024:
                    raise ValueError('Scansione limitata a LAN private fino a /22 (1024 indirizzi)')
                return dev,local,net
    raise ValueError('Nessun indirizzo IPv4 Ethernet rilevato')


def hostname(address):
    # Reverse DNS: bounded subprocess instead of unbounded Python resolver.
    # mDNS when Avahi is present, with a separate short timeout.
    for command in ([ '/usr/bin/avahi-resolve-address','-4',address ],
                    [ '/usr/bin/getent','hosts',address ]):
        if not os.path.exists(command[0]): continue
        try:
            result = call(command, timeout=0.9)
            if result.returncode == 0 and result.stdout.strip():
                fields=result.stdout.split()
                if len(fields)>=2:
                    name=fields[1].rstrip('.')
                    if 0 < len(name)<=128 and all(c.isalnum() or c in '._-' for c in name):
                        return name
        except (subprocess.TimeoutExpired, OSError):
            continue
    return '-'


def main():
    if len(sys.argv)!=1 or os.geteuid()!=0:
        raise ValueError('Accesso al discovery non autorizzato')
    raw=sys.stdin.buffer.read(129)
    if len(raw)>128 or json.loads(raw.decode('utf-8'))!={'action':'scan'}:
        raise ValueError('Richiesta di scansione non valida')
    dev,local,net=discover_network()
    cmd=['/usr/sbin/arp-scan','--interface='+dev,'--plain','--retry=1',
         '--timeout=300','--interval=3',str(net)]
    outcome=call(cmd,timeout=22)
    # arp-scan returns 0 if successful. Never pretend the scan is empty on error.
    if outcome.returncode:
        raise RuntimeError('arp-scan: '+(outcome.stderr or 'scansione non riuscita').strip()[:220])
    entries={}
    for line in outcome.stdout.splitlines():
        found=IP_PATTERN.match(line)
        if not found: continue
        ip,mac,vendor=found.groups()
        addr=ipaddress.IPv4Address(ip)
        if addr not in net or addr in (local,net.network_address,net.broadcast_address): continue
        entries[str(addr)]={'ip':str(addr),'mac':mac.upper(),
                            'vendor':(vendor or '').strip()[:90] or '-', 'hostname':'-'}
    devices=sorted(entries.values(),key=lambda d:int(ipaddress.IPv4Address(d['ip'])))[:256]
    # Limit DNS lookups to protect low-memory ARM32 hardware; all IP/MAC entries
    # are displayed even if a hostname cannot be resolved.
    with ThreadPoolExecutor(max_workers=6) as pool:
        pending={pool.submit(hostname,d['ip']):d for d in devices[:64]}
        for future in as_completed(pending):
            try: pending[future]['hostname']=future.result()
            except Exception: pass
    print(json.dumps({'ok':True,'interface':dev,'subnet':str(net),'devices':devices,
                      'limited':len(entries)>256,'hostname_limited':len(devices)>64}))

if __name__ == '__main__':
    try:
        main()
    except (ValueError,OSError,RuntimeError,TypeError,KeyError,
            subprocess.TimeoutExpired,json.JSONDecodeError) as exc:
        print(json.dumps({'ok':False,'error':str(exc)[:400]}))
        sys.exit(1)
