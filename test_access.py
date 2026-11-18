#!/usr/bin/env python3
"""Test dell'indirizzo di recupero (alias 169.254.X.Y su end0).

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
    """Cartelle temporanee al posto di /etc/netplan, /etc/raptor-recovery.conf e dello stato."""
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
            'RECOVERY_CONF': root / 'raptor-recovery.conf',
        }
        for key, value in self.paths.items():
            patcher = patch.object(n, key, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        n.STATE.mkdir()
        n.DEFAULT.write_text(DEFAULT_YAML)


class ValidationTests(unittest.TestCase):
    def test_accepts_link_local_range(self):
        for ip in ('169.254.77.12', '169.254.1.1', '169.254.254.254', ' 169.254.10.20 '):
            with self.subTest(ip=ip):
                self.assertEqual(n.valid_recovery(ip), ip.strip())

    def test_rejects_everything_else(self):
        for ip in ('192.168.1.5', '10.0.0.1', '169.253.1.1', '169.254.0.5', '169.254.255.5',
                   '169.254.5.0', '169.254.5.255', '169.254.1', '', 'abc', '169.254.1.1/16', None, '169.254.1.1; reboot'):
            with self.subTest(ip=ip):
                with self.assertRaises(ValueError):
                    n.valid_recovery(ip)


class RenderTests(Sandbox):
    def test_without_recovery_nothing_changes(self):
        text = n.render(DHCP).decode()
        self.assertNotIn('addresses:', text)
        self.assertIn('dhcp4: true', text)

    def test_dhcp_with_recovery(self):
        n.RECOVERY_CONF.write_text('RECOVERY_IP=169.254.77.12\n')
        text = n.render(DHCP).decode()
        self.assertIn('dhcp4: true', text)
        self.assertIn('      addresses:\n        - 169.254.77.12/16\n', text)
        self.assertNotIn('routes:', text)

    def test_static_with_recovery_keeps_both(self):
        n.RECOVERY_CONF.write_text('RECOVERY_IP=169.254.77.12\n')
        text = n.render(STATIC).decode()
        self.assertIn('        - 192.168.1.50/24\n        - 169.254.77.12/16\n', text)
        self.assertIn('dhcp4: false', text)
        self.assertIn('via: 192.168.1.1', text)
        self.assertEqual(text.count('addresses:'), 2)  # end0 + nameservers

    def test_invalid_conf_is_ignored(self):
        n.RECOVERY_CONF.write_text('RECOVERY_IP=8.8.8.8\n')
        self.assertIsNone(n.recovery_ip())
        self.assertNotIn('8.8.8.8', n.render(DHCP).decode())

    def test_status_reports_state_but_not_the_value(self):
        n.RECOVERY_CONF.write_text('RECOVERY_IP=169.254.77.12\n')
        with patch.object(n, 'assert_platform'):
            status = n.get_current()
        self.assertTrue(status['recovery_active'])
        self.assertNotIn('169.254.77.12', json.dumps(status))


class SetRecoveryTests(Sandbox):
    def run_set(self, value, fake=None):
        fake = fake or Fake()
        with patch.object(n, 'shell', fake), patch.object(n, 'assert_platform'), patch.object(n.os, 'geteuid', return_value=0):
            return n.set_recovery(value), fake

    def test_requires_root(self):
        with patch.object(n.os, 'geteuid', return_value=1000):
            with self.assertRaises(RuntimeError):
                n.set_recovery('169.254.5.5')

    def test_sets_persists_and_activates_without_reapplying_netplan(self):
        result, fake = self.run_set('169.254.77.12')
        self.assertEqual(result, {'ok': True, 'recovery_ip': '169.254.77.12', 'persistent': True})
        self.assertIn('RECOVERY_IP=169.254.77.12', n.RECOVERY_CONF.read_text())
        self.assertEqual(oct(n.RECOVERY_CONF.stat().st_mode & 0o777), '0o600')
        self.assertFalse(n.DEFAULT.exists())
        custom = n.CUSTOM.read_text()
        self.assertIn('Managed by Tailscale Panel', custom)
        self.assertIn('169.254.77.12/16', custom)
        self.assertIn('dhcp4: true', custom)
        self.assertIn(['netplan', 'generate'], fake.calls)
        self.assertIn(['ip', 'addr', 'replace', '169.254.77.12/16', 'dev', 'end0', 'scope', 'link'], fake.calls)
        self.assertNotIn(['netplan', 'apply'], fake.calls)   # il lease DHCP non va toccato
        self.assertTrue(list(n.STATE.glob('backup-recovery-*.json')))

    def test_keeps_existing_static_configuration(self):
        n.DEFAULT.unlink()
        n.CUSTOM.write_bytes(n.render(STATIC))
        self.run_set('169.254.9.9')
        text = n.CUSTOM.read_text()
        self.assertIn('192.168.1.50/24', text)
        self.assertIn('169.254.9.9/16', text)
        self.assertIn('dhcp4: false', text)

    def test_change_removes_old_address(self):
        self.run_set('169.254.1.1')
        _, fake = self.run_set('169.254.2.2')
        self.assertIn(['ip', 'addr', 'del', '169.254.1.1/16', 'dev', 'end0'], fake.calls)
        self.assertNotIn('169.254.1.1', n.CUSTOM.read_text())

    def test_random_is_valid_and_different_calls_stay_valid(self):
        for _ in range(30):
            result, _ = self.run_set('random')
            self.assertEqual(n.valid_recovery(result['recovery_ip']), result['recovery_ip'])

    def test_none_removes_it_but_keeps_panel_netplan(self):
        self.run_set('169.254.1.1')
        result, fake = self.run_set('none')
        self.assertIsNone(result['recovery_ip'])
        self.assertFalse(n.RECOVERY_CONF.exists())
        self.assertNotIn('169.254', n.CUSTOM.read_text())
        self.assertIn(['ip', 'addr', 'del', '169.254.1.1/16', 'dev', 'end0'], fake.calls)

    def test_none_on_clean_system_changes_nothing(self):
        before = n.DEFAULT.read_text()
        self.run_set('none')
        self.assertEqual(n.DEFAULT.read_text(), before)
        self.assertFalse(n.CUSTOM.exists())

    def test_invalid_value_touches_nothing(self):
        before = n.DEFAULT.read_text()
        for bad in ('192.168.1.5', 'boh', '169.254.0.1'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.run_set(bad)
        self.assertEqual(n.DEFAULT.read_text(), before)
        self.assertFalse(n.CUSTOM.exists())
        self.assertFalse(n.RECOVERY_CONF.exists())

    def test_netplan_generate_failure_restores_everything(self):
        before = n.DEFAULT.read_text()
        with self.assertRaises(RuntimeError):
            self.run_set('169.254.5.5', Fake(fail=['netplan']))
        self.assertEqual(n.DEFAULT.read_text(), before)
        self.assertFalse(n.CUSTOM.exists())
        self.assertFalse(n.RECOVERY_CONF.exists())

    def test_refused_while_a_network_change_is_pending(self):
        n.PENDING.write_text(json.dumps({'id': 'a' * 14, 'config': DHCP, 'snapshot': {}, 'expires_at': 1}))
        with self.assertRaises(RuntimeError):
            self.run_set('169.254.5.5')

    def test_not_reachable_through_the_sudo_entry_point(self):
        # Il pannello (utente tspanel) puo' lanciare l'helper solo senza argomenti.
        sudoers = (DIR / 'install_tailscale_panel.sh').read_text()
        line = next(x for x in sudoers.splitlines() if x.startswith('tspanel ALL='))
        self.assertIn('tailscale-panel-net-helper ""', line)
        self.assertNotIn('--set-recovery', line)


class LanSelectionTests(unittest.TestCase):
    """L'alias di recupero non deve mai essere scambiato per l'IP della LAN del cliente."""
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

    def test_only_recovery_address_means_no_lan(self):
        self.ADDRS = self.ADDRS[:1]
        with patch.object(r, 'run', return_value=self.reply()), patch.object(r, 'lan_interface', return_value='end0'):
            with self.assertRaises(ValueError):
                r.current_lan()


if __name__ == '__main__':
    unittest.main()
