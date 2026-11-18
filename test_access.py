#!/usr/bin/env python3
"""Test dell'accesso di servizio.

- gli indirizzi link-local 169.254.x.x non vengono mai scambiati per l'IP della LAN del cliente;
- l'IP di recupero (alias 169.254.X.Y su end0) e' una funzione RIMOSSA: nessuna traccia nel codice
  del pannello, negli installer e nel Netplan generato (la pulizia delle schede gia' installate sta
  in update.sh ed e' provata da test_update.py).

Nessun test tocca la rete o /etc: file e comandi di sistema sono sostituiti da finti.
"""
import importlib.util
import ipaddress
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

DIR = pathlib.Path(__file__).resolve().parent
sys.dont_write_bytecode = True


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, DIR / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


n = load('netcfg', 'tailscale_panel_network.py')
r = load('routes2', 'tailscale_panel_helper.py')
d = load('discover2', 'tailscale_panel_discovery.py')
p = load('panel2', 'tailscale_panel.py')

DHCP = {'mode': 'dhcp', 'ip': '', 'prefix': 24, 'gateway': '', 'dns': []}
STATIC = {'mode': 'static', 'ip': '192.168.1.50', 'prefix': 24, 'gateway': '192.168.1.1', 'dns': ['1.1.1.1']}
DEFAULT_YAML = ('network:\n  version: 2\n  renderer: networkd\n  ethernets:\n    all-eth-interfaces:\n'
                '      match:\n        name: "e*"\n      dhcp4: yes\n      dhcp6: yes\n')


class Fake:
    """Sostituisce shell(): registra i comandi e restituisce esiti configurabili."""
    def __init__(self, fail=()):
        self.calls, self.fail = [], set(fail)

    def __call__(self, args, timeout=15):
        self.calls.append(list(args))
        code = 1 if args[0] in self.fail or ' '.join(args[:2]) in self.fail else 0
        return subprocess.CompletedProcess(args, code, '', 'errore finto' if code else '')


class Sandbox(unittest.TestCase):
    """Cartelle temporanee al posto di /etc/netplan e dello stato."""
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = pathlib.Path(tmp.name)
        (root / 'netplan').mkdir()
        self.paths = {
            'NETDIR': root / 'netplan',
            'DEFAULT': root / 'netplan' / '10-dhcp-all-interfaces.yaml',
            'CUSTOM': root / 'netplan' / '90-tailscale-panel-end0.yaml',
            'STATE': root / 'state',
            'PENDING': root / 'state' / 'pending.json',
            'LOCK': root / 'lock',
        }
        for key, value in self.paths.items():
            patcher = patch.object(n, key, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        n.STATE.mkdir()
        n.DEFAULT.write_text(DEFAULT_YAML)


class RemovedFeatureTests(Sandbox):
    """L'IP di recupero non esiste piu': il Netplan generato non contiene alias e il pannello non lo espone."""

    def test_dhcp_render_has_no_addresses(self):
        text = n.render(DHCP).decode()
        self.assertNotIn('addresses:', text)
        self.assertNotIn('169.254', text)
        self.assertIn('dhcp4: true', text)

    def test_static_render_has_only_the_chosen_address(self):
        text = n.render(STATIC).decode()
        self.assertIn('      addresses:\n        - 192.168.1.50/24\n      routes:', text)
        self.assertEqual(text.count('addresses:'), 2)  # end0 + nameservers
        self.assertNotIn('169.254', text)

    def test_status_does_not_mention_recovery(self):
        with patch.object(n, 'assert_platform'):
            status = n.get_current()
        self.assertFalse([k for k in status if 'recover' in k.lower()], status)

    def test_helper_has_no_recovery_entry_points(self):
        for name in ('set_recovery', 'recovery_ip', 'valid_recovery', 'RECOVERY_CONF', 'RECOVERY_PREFIX'):
            with self.subTest(name=name):
                self.assertFalse(hasattr(n, name))
        self.assertNotIn('--set-recovery', (DIR / 'tailscale_panel_network.py').read_text())

    def test_helper_rejects_the_old_command_line(self):
        with patch.object(n.sys, 'argv', ['helper', '--set-recovery', 'none']), \
             patch.object(n, 'STATE', pathlib.Path(tempfile.mkdtemp())), patch.object(n.os, 'chmod'), \
             patch.object(n, 'assert_platform'):
            with self.assertRaises(Exception):
                n.main()


class PackageTests(unittest.TestCase):
    def test_windows_script_is_gone(self):
        self.assertFalse((DIR / 'recupero_windows.ps1').exists())
        self.assertNotIn('recupero_windows', (DIR / 'SHA256SUMS').read_text())

    def test_installers_and_panel_have_no_recovery_ip_code(self):
        # Solo update.sh (pulizia) e check_installation.sh (segnalazione del residuo) la nominano.
        for name in ('install_access.sh', 'install_factory.sh', 'install_tailscale_panel.sh', 'bootstrap.sh',
                     'tailscale_panel.py', 'tailscale_panel_helper.py', 'tailscale_panel_discovery.py',
                     'tailscale_panel_network.py', 'raptor_ap.py'):
            with self.subTest(name=name):
                text = (DIR / name).read_text()
                self.assertNotIn('raptor-recovery', text)
                self.assertNotIn('--recovery-ip', text)
                self.assertNotIn('RECOVERY_IP', text)

    def test_access_installer_refuses_the_old_option(self):
        text = (DIR / 'install_access.sh').read_text()
        self.assertNotIn('recovery', text.lower())
        self.assertIn("*) die \"Argomento sconosciuto: $1\"", text)

    def test_cleanup_is_still_available_for_old_boards(self):
        update = (DIR / 'update.sh').read_text()
        self.assertIn('--set-recovery none', update)
        # ...e avviene PRIMA che l'installazione del pannello sostituisca l'helper vecchio.
        self.assertLess(update.index('--set-recovery none'), update.index('sh ./install_tailscale_panel.sh'))

    def test_check_flags_a_leftover(self):
        text = (DIR / 'check_installation.sh').read_text()
        self.assertIn('/etc/raptor-recovery.conf', text)
        self.assertIn('DA VERIFICARE', text[text.index('/etc/raptor-recovery.conf'):][:300])


class LanSelectionTests(unittest.TestCase):
    """Un indirizzo link-local 169.254.x.x non deve mai essere scambiato per l'IP della LAN del cliente."""
    ADDRS = [{'family': 'inet', 'scope': 'global', 'local': '169.254.77.12', 'prefixlen': 16},
             {'family': 'inet', 'scope': 'global', 'local': '192.168.1.57', 'prefixlen': 24, 'dynamic': True}]

    def reply(self):
        return subprocess.CompletedProcess([], 0, json.dumps([{'addr_info': self.ADDRS}]), '')

    def test_panel_shows_the_lan_address(self):
        with patch.object(p, 'run', return_value=self.reply()):
            details = p.lan_details()
        self.assertEqual(details['ip'], '192.168.1.57')
        self.assertEqual(details['subnet'], '192.168.1.0/24')

    def test_route_helper_uses_the_lan_address(self):
        with patch.object(r, 'run', return_value=self.reply()), patch.object(r, 'lan_interface', return_value='end0'):
            dev, local, net = r.current_lan()
        self.assertEqual((str(local), str(net)), ('192.168.1.57', '192.168.1.0/24'))

    def test_scanner_uses_the_lan_address(self):
        with patch.object(d, 'call', return_value=self.reply()), \
             patch('builtins.open', create=True) as f:
            import io
            f.return_value.__enter__.return_value = io.StringIO('end0')
            dev, local, net = d.discover_network()
        self.assertEqual((str(local), str(net)), ('192.168.1.57', '192.168.1.0/24'))

    def test_only_link_local_address_means_no_lan(self):
        self.ADDRS = self.ADDRS[:1]
        with patch.object(r, 'run', return_value=self.reply()), patch.object(r, 'lan_interface', return_value='end0'):
            with self.assertRaises(ValueError):
                r.current_lan()


if __name__ == '__main__':
    unittest.main()
