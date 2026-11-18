#!/usr/bin/env python3
"""Raptor VPN - Wi-Fi temporaneo che annuncia l'indirizzo IP della scheda.

Dopo l'avvio, appena la porta Ethernet ha un IP (DHCP o statico), la scheda apre per circa un
minuto una rete Wi-Fi chiamata "Raptor VPN - <IP>". L'installatore legge l'IP dall'elenco delle
reti Wi-Fi del telefono, senza collegarsi a nulla.

Non e' un punto di accesso utilizzabile, di proposito:
  - password WPA2 casuale, generata a ogni avvio e mai mostrata ne' salvata;
  - in piu' hostapd rifiuta ogni dispositivo (lista MAC ammessi vuota);
  - nessun server DHCP, nessun IP su wlan0, nessun inoltro verso la LAN, nessuna socket di controllo.
Passato il minuto l'AP si spegne e l'interfaccia viene messa giu'.

Configurazione opzionale in /etc/raptor-ap.conf (ENABLED, DURATION, CHANNEL, IFACE, WAIT_IP).
Il servizio e' raptor-ap.service; per rilanciarlo a mano:  systemctl restart raptor-ap
"""
import ipaddress
import json
import os
import pathlib
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time

CONF = pathlib.Path('/etc/raptor-ap.conf')
LAN_CONF = pathlib.Path('/etc/tailscale-panel-lan.conf')
RUN_DIR = pathlib.Path('/run/raptor-ap')
PREFIX = 'Raptor VPN - '
NO_IP = 'nessun IP'
DEFAULTS = {'ENABLED': 1, 'DURATION': 60, 'CHANNEL': 6, 'IFACE': 'wlan0', 'WAIT_IP': 90}
STOP = threading.Event()


def log(message):
    print('raptor-ap: ' + message, flush=True)


def parse_conf(text):
    """Legge KEY=VALUE; valori fuori range o strani tornano al predefinito."""
    conf = dict(DEFAULTS)
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = (x.strip() for x in line.split('=', 1))
        if key == 'ENABLED' and value in ('0', '1'):
            conf[key] = int(value)
        elif key == 'DURATION' and value.isdigit() and 20 <= int(value) <= 300:
            conf[key] = int(value)
        elif key == 'WAIT_IP' and value.isdigit() and 5 <= int(value) <= 300:
            conf[key] = int(value)
        elif key == 'CHANNEL' and value.isdigit() and 1 <= int(value) <= 11:
            conf[key] = int(value)
        elif key == 'IFACE' and re.fullmatch(r'[a-z][a-z0-9]{0,14}', value):
            conf[key] = value
    return conf


def load_conf():
    try:
        return parse_conf(CONF.read_text())
    except OSError:
        return dict(DEFAULTS)


def lan_device():
    try:
        name = LAN_CONF.read_text().strip()
        if re.fullmatch(r'[A-Za-z0-9._-]{1,15}', name):
            return name
    except OSError:
        pass
    return 'end0'


def pick_ip(addr_json):
    """Primo IPv4 "vero" della porta: scarta loopback e 169.254.x.x (IP di recupero)."""
    try:
        interfaces = json.loads(addr_json)
    except (TypeError, ValueError):
        return None
    for iface in interfaces if isinstance(interfaces, list) else []:
        infos = iface.get('addr_info') if isinstance(iface, dict) else None
        for addr in infos if isinstance(infos, list) else []:
            if not isinstance(addr, dict) or addr.get('family') != 'inet' or addr.get('scope') != 'global':
                continue
            try:
                ip = ipaddress.IPv4Address(addr.get('local', ''))
            except ValueError:
                continue
            if ip.is_link_local or ip.is_loopback or ip.is_unspecified or ip.is_multicast:
                continue
            return str(ip)
    return None


def current_ip(dev):
    try:
        done = subprocess.run(['ip', '-j', '-4', 'addr', 'show', 'dev', dev],
                              capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return pick_ip(done.stdout) if done.returncode == 0 else None


def make_ssid(ip):
    ssid = PREFIX + (str(ipaddress.IPv4Address(ip)) if ip else NO_IP)
    assert len(ssid.encode()) <= 32 and ssid.isascii()
    return ssid


def make_passphrase():
    return secrets.token_hex(24)   # 48 caratteri: dentro il limite WPA2 (8-63)


def hostapd_conf(iface, ssid, passphrase, channel, accept_file):
    return '\n'.join([
        'interface=' + iface,
        'driver=nl80211',
        'ssid=' + ssid,
        'hw_mode=g',
        'channel=%d' % channel,
        'ieee80211n=0',
        'auth_algs=1',
        'wpa=2',
        'wpa_key_mgmt=WPA-PSK',
        'rsn_pairwise=CCMP',
        'wpa_passphrase=' + passphrase,
        # 1 = ammessi solo i MAC elencati nel file, che e' vuoto: nessuno puo' associarsi.
        'macaddr_acl=1',
        'accept_mac_file=' + str(accept_file),
        'logger_syslog=-1',
        'logger_syslog_level=2',
        '',
    ])


def wait_for_ip(dev, seconds):
    deadline = time.monotonic() + seconds
    while True:
        ip = current_ip(dev)
        if ip or STOP.is_set() or time.monotonic() >= deadline:
            return ip
        STOP.wait(2)


def free_wifi(iface):
    """Ferma wpa_supplicant (non serve: la scheda usa solo Ethernet) e sblocca la radio."""
    for unit in ('wpa_supplicant.service', 'wpa_supplicant@%s.service' % iface):
        subprocess.run(['systemctl', 'stop', unit], capture_output=True, timeout=20)
    if shutil.which('rfkill'):
        subprocess.run(['rfkill', 'unblock', 'wifi'], capture_output=True, timeout=10)


def run_ap(conf):
    iface = conf['IFACE']
    if not pathlib.Path('/sys/class/net/' + iface).exists():
        log('interfaccia %s assente: niente AP' % iface)
        return 0
    hostapd = shutil.which('hostapd')
    if not hostapd:
        log('hostapd non installato: niente AP')
        return 0
    ip = wait_for_ip(lan_device(), conf['WAIT_IP'])
    if STOP.is_set():
        return 0
    ssid = make_ssid(ip)
    log('IP %s -> rete "%s" per %d s' % (ip or 'assente', ssid, conf['DURATION']))
    RUN_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    accept = RUN_DIR / 'accept.mac'
    accept.write_text('')
    config = RUN_DIR / 'hostapd.conf'
    fd = os.open(str(config), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(hostapd_conf(iface, ssid, make_passphrase(), conf['CHANNEL'], accept))
    proc = None
    try:
        free_wifi(iface)
        proc = subprocess.Popen([hostapd, str(config)], stdin=subprocess.DEVNULL)
        end = time.monotonic() + conf['DURATION']
        while time.monotonic() < end and not STOP.is_set():
            if proc.poll() is not None:
                log('hostapd terminato in anticipo (codice %s)' % proc.returncode)
                break
            STOP.wait(1)
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(8)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(5)
        subprocess.run(['ip', 'link', 'set', iface, 'down'], capture_output=True, timeout=10)
        for leftover in (config, accept):
            leftover.unlink(missing_ok=True)
    log('AP spento')
    return 0


def main():
    conf = load_conf()
    if not conf['ENABLED']:
        log('disattivato in %s' % CONF)
        return 0
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: STOP.set())
    if os.geteuid() != 0:
        log('serve root')
        return 1
    return run_ap(conf)


if __name__ == '__main__':
    sys.exit(main())
