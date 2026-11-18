#!/usr/bin/env python3
"""Test del Wi-Fi temporaneo "Raptor VPN - <IP>". Non toccano radio, rete o servizi."""
import importlib.util
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

DIR = pathlib.Path(__file__).resolve().parent
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('ap', DIR / 'raptor_ap.py')
ap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ap)


def addrs(*pairs):
    return json.dumps([{'addr_info': [
        {'family': 'inet', 'scope': scope, 'local': ip, 'prefixlen': 24} for ip, scope in pairs]}])


class ConfTests(unittest.TestCase):
    def test_defaults(self):
        self.assertEqual(ap.parse_conf(''), ap.DEFAULTS)

    def test_valid_values(self):
        conf = ap.parse_conf('ENABLED=0\nDURATION=90\nCHANNEL=11\nIFACE=wlan1\nWAIT_IP=30\n# commento\n')
        self.assertEqual(conf, {'ENABLED': 0, 'DURATION': 90, 'CHANNEL': 11, 'IFACE': 'wlan1', 'WAIT_IP': 30})

    def test_bad_values_fall_back(self):
        text = 'ENABLED=si\nDURATION=5\nCHANNEL=14\nIFACE=wlan0; reboot\nWAIT_IP=-1\nSTRANO\n'
        self.assertEqual(ap.parse_conf(text), ap.DEFAULTS)
        self.assertEqual(ap.parse_conf('DURATION=100000')['DURATION'], 60)
        self.assertEqual(ap.parse_conf('IFACE=../etc')['IFACE'], 'wlan0')


class IpAndSsidTests(unittest.TestCase):
    def test_picks_lan_address_not_recovery(self):
        data = addrs(('169.254.77.12', 'global'), ('192.168.1.57', 'global'))
        self.assertEqual(ap.pick_ip(data), '192.168.1.57')

    def test_ignores_link_scope_and_loopback(self):
        self.assertIsNone(ap.pick_ip(addrs(('169.254.77.12', 'link'), ('127.0.0.1', 'host'))))
        self.assertIsNone(ap.pick_ip(addrs(('169.254.77.12', 'global'))))

    def test_garbage_input(self):
        for bad in ('', 'non json', '{}', '[1,2]', 'null', None):
            with self.subTest(bad=bad):
                self.assertIsNone(ap.pick_ip(bad))

    def test_ssid_format_and_length(self):
        self.assertEqual(ap.make_ssid('192.168.1.57'), 'Raptor VPN - 192.168.1.57')
        self.assertEqual(ap.make_ssid(None), 'Raptor VPN - nessun IP')
        longest = ap.make_ssid('255.255.255.255')
        self.assertLessEqual(len(longest.encode()), 32)

    def test_ssid_rejects_non_ip(self):
        with self.assertRaises(ValueError):
            ap.make_ssid('192.168.1.5\nchannel=1')

    def test_current_ip_handles_command_failure(self):
        with patch.object(ap.subprocess, 'run', side_effect=FileNotFoundError):
            self.assertIsNone(ap.current_ip('end0'))
        with patch.object(ap.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'err')):
            self.assertIsNone(ap.current_ip('end0'))


class HostapdConfTests(unittest.TestCase):
    def conf(self, **kw):
        args = dict(iface='wlan0', ssid='Raptor VPN - 10.0.0.5', passphrase=ap.make_passphrase(),
                    channel=6, accept_file='/run/raptor-ap/accept.mac')
        args.update(kw)
        return ap.hostapd_conf(**args)

    def test_wpa2_only_and_nobody_may_join(self):
        text = self.conf()
        for needle in ('wpa=2', 'wpa_key_mgmt=WPA-PSK', 'rsn_pairwise=CCMP', 'macaddr_acl=1',
                       'accept_mac_file=/run/raptor-ap/accept.mac', 'ssid=Raptor VPN - 10.0.0.5'):
            self.assertIn(needle, text.splitlines())
        self.assertNotIn('ignore_broadcast_ssid=1', text)   # l'XR819 non supporta AP nascosti
        self.assertNotIn('ctrl_interface', text)             # nessuna socket di controllo

    def test_passphrase_is_random_and_valid(self):
        seen = {ap.make_passphrase() for _ in range(50)}
        self.assertEqual(len(seen), 50)
        for p in seen:
            self.assertTrue(8 <= len(p) <= 63 and re.fullmatch(r'[0-9a-f]+', p))

    def test_passphrase_is_never_logged(self):
        with patch('builtins.print') as out:
            ap.log('IP 1.2.3.4 -> rete "x" per 60 s')
        self.assertNotIn('wpa_passphrase', str(out.call_args))


class RunTests(unittest.TestCase):
    """Flusso completo con hostapd e comandi finti."""
    def setUp(self):
        ap.STOP.clear()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.run_dir = pathlib.Path(tmp.name) / 'raptor-ap'
        for target, value in (('RUN_DIR', self.run_dir),):
            patcher = patch.object(ap, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.conf = dict(ap.DEFAULTS, DURATION=20)
        self.commands = []
        self.proc = MagicMock()
        self.proc.poll.return_value = None
        self.proc.returncode = 0
        self.written = {}

        def fake_run(args, **kw):
            self.commands.append(list(args))
            return subprocess.CompletedProcess(args, 0, '', '')
        self.patches = [
            patch.object(ap.subprocess, 'run', side_effect=fake_run),
            patch.object(ap.subprocess, 'Popen', side_effect=self.fake_popen),
            patch.object(ap.shutil, 'which', side_effect=lambda x: '/usr/sbin/' + x),
            patch.object(ap, 'wait_for_ip', return_value='192.168.1.57'),
            patch.object(ap.pathlib.Path, 'exists', lambda self_: str(self_) == '/sys/class/net/wlan0' or pathlib.Path.is_file(self_)),
        ]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def fake_popen(self, args, **kw):
        # hostapd legge la configurazione: la conserviamo prima che venga cancellata.
        self.written['conf'] = pathlib.Path(args[1]).read_text()
        self.written['mode'] = oct(pathlib.Path(args[1]).stat().st_mode & 0o777)
        self.written['args'] = args
        return self.proc

    def test_full_cycle(self):
        # Il "minuto" scade subito: simuliamo con STOP dopo il primo giro.
        with patch.object(ap.STOP, 'wait', side_effect=lambda t=None: ap.STOP.set()):
            self.assertEqual(ap.run_ap(self.conf), 0)
        self.assertIn('ssid=Raptor VPN - 192.168.1.57', self.written['conf'])
        self.assertEqual(self.written['mode'], '0o600')
        self.assertEqual(self.written['args'][0], '/usr/sbin/hostapd')
        self.proc.terminate.assert_called_once()
        self.assertIn(['ip', 'link', 'set', 'wlan0', 'down'], self.commands)
        self.assertIn(['systemctl', 'stop', 'wpa_supplicant.service'], self.commands)
        self.assertEqual(list(self.run_dir.iterdir()), [])     # niente passphrase lasciata su disco

    def test_hostapd_early_exit_is_handled(self):
        self.proc.poll.return_value = 1
        self.proc.returncode = 1
        self.assertEqual(ap.run_ap(self.conf), 0)
        self.assertIn(['ip', 'link', 'set', 'wlan0', 'down'], self.commands)
        self.proc.terminate.assert_not_called()

    def test_no_ip_still_announces_it(self):
        with patch.object(ap, 'wait_for_ip', return_value=None), \
             patch.object(ap.STOP, 'wait', side_effect=lambda t=None: ap.STOP.set()):
            ap.run_ap(self.conf)
        self.assertIn('ssid=Raptor VPN - nessun IP', self.written['conf'])

    def test_missing_interface_or_hostapd_does_nothing(self):
        with patch.object(ap, 'IFACE_WAIT', 0), patch.object(ap.pathlib.Path, 'exists', lambda self_: False):
            self.assertEqual(ap.run_ap(self.conf), 0)
        self.assertEqual(self.commands, [])
        with patch.object(ap.shutil, 'which', return_value=None):
            self.assertEqual(ap.run_ap(self.conf), 0)

    def test_interface_that_appears_late_at_boot_still_gets_the_ap(self):
        # Regressione: all'avvio wlan0 puo' comparire dopo il servizio. Prima si usciva subito.
        seen = {'exists': 0, 'waits': 0}

        def late(self_):
            if str(self_) == '/sys/class/net/wlan0':
                seen['exists'] += 1
                return seen['exists'] > 3          # assente per le prime 3 verifiche
            return pathlib.Path.is_file(self_)

        def wait(timeout=None):
            seen['waits'] += 1
            if seen['waits'] >= 6:                 # dopo l'attesa dell'interfaccia, chiude l'AP
                ap.STOP.set()
        with patch.object(ap.pathlib.Path, 'exists', late), patch.object(ap.STOP, 'wait', side_effect=wait):
            ap.run_ap(dict(self.conf, DURATION=20))
        self.assertGreaterEqual(seen['exists'], 4)
        self.assertIn('ssid=Raptor VPN - 192.168.1.57', self.written['conf'])

    def test_wait_for_iface_gives_up(self):
        with patch.object(ap.pathlib.Path, 'exists', lambda self_: False), \
             patch.object(ap.STOP, 'wait', side_effect=lambda t=None: None):
            self.assertFalse(ap.wait_for_iface('wlan0', 0))

    def test_disabled_by_config(self):
        with patch.object(ap, 'load_conf', return_value=dict(ap.DEFAULTS, ENABLED=0)), \
             patch.object(ap, 'run_ap') as run_ap:
            self.assertEqual(ap.main(), 0)
        run_ap.assert_not_called()

    def test_stop_signal_before_start_means_no_ap(self):
        ap.STOP.set()
        self.assertEqual(ap.run_ap(self.conf), 0)
        self.assertNotIn('conf', self.written)


if __name__ == '__main__':
    unittest.main()
