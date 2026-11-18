#!/usr/bin/env python3
"""Test del programma root che cambia la porta del pannello (tailscale_panel_port.py).

Nessun test tocca systemd, il firewall o /etc: i file stanno in una cartella temporanea e
systemctl, ss, iptables e systemd-run sono sostituiti da un sistema finto che ne simula gli effetti
(per esempio "restart tailscale-panel.socket" legge davvero il file e mette la nuova porta in ascolto).
"""
import importlib.util
import io
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


p = load('porthelper', 'tailscale_panel_port.py')

SOCKET = ('[Unit]\nDescription=Tailscale Panel v1.6.0 HTTPS socket on end0 (DHCP-independent)\n\n[Socket]\n'
          'ListenStream=0.0.0.0:%d\nBindToDevice=end0\nService=tailscale-panel.service\nNoDelay=true\n\n'
          '[Install]\nWantedBy=sockets.target\n')
SERVICE = ('[Unit]\nDescription=Tailscale Control Panel\n\n[Service]\nUser=tspanel\nEnvironment=PANEL_PORT=%d\n'
           'Environment=PANEL_LAN_DEV=end0\nExecStart=/usr/bin/python3 /opt/tailscale-panel/tailscale_panel.py\n')
AVAHI = ('<?xml version="1.0" standalone=\'no\'?>\n<service-group>\n  <name replace-wildcards="yes">Tailscale Panel su %%h</name>\n'
         '  <service><type>_https._tcp</type><port>%d</port></service>\n</service-group>\n')
GUARD = '# Gestito da input_firewall.sh\nPANEL_PORT=%d\nSSH_LAN=1\n'


class FakeSystem:
    """systemctl / ss / iptables / systemd-run finti. Registra i comandi nell'ordine in cui arrivano."""

    def __init__(self, box):
        self.box = box
        self.calls = []
        self.listening = {22, box.port_before}
        self.chain_active = True
        self.fail = set()          # prefissi di comando che devono fallire sempre, es. 'systemctl restart'
        self.fail_once = set()     # prefissi che falliscono solo la prima volta
        self.refuse_binds = 0      # quanti "restart" del socket non mettono nulla in ascolto

    def __call__(self, args, timeout=15):
        args = [str(a) for a in args]
        self.calls.append(args)
        text = ' '.join(args)
        once = next((f for f in self.fail_once if text.startswith(f)), None)
        if once:
            self.fail_once.discard(once)
            return subprocess.CompletedProcess(args, 1, '', 'errore finto')
        if any(text.startswith(f) for f in self.fail):
            return subprocess.CompletedProcess(args, 1, '', 'errore finto')
        if args[:3] == ['ss', '-H', '-ltn']:
            out = ''.join('LISTEN 0 4096 0.0.0.0:%d 0.0.0.0:*\n' % port for port in sorted(self.listening))
            return subprocess.CompletedProcess(args, 0, out + 'LISTEN 0 128 [::]:22 [::]:*\n', '')
        if args[:2] == ['systemctl', 'restart'] and args[2] == 'tailscale-panel.socket':
            wanted = int(p.SOCKET_RE.findall(p.SOCKET_UNIT.read_text())[0])
            self.listening.discard(self.box.panel_port)
            if self.refuse_binds:
                self.refuse_binds -= 1
            else:
                self.listening.add(wanted)
                self.box.panel_port = wanted
        if args[:4] == ['iptables', '-w', '5', '-S']:
            return subprocess.CompletedProcess(args, 0 if self.chain_active else 1, '', '')
        return subprocess.CompletedProcess(args, 0, '', '')

    def names(self):
        return [' '.join(c[:3]) if c[0] != 'systemd-run' else 'systemd-run ' + c[2] for c in self.calls]

    def index(self, prefix):
        return next(i for i, c in enumerate(self.calls) if ' '.join(c).startswith(prefix))


class Sandbox(unittest.TestCase):
    port_before = 8443

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = pathlib.Path(tmp.name)
        (root / 'avahi').mkdir()
        self.port_before = 8443
        self.panel_port = 8443
        self.files = {
            'SOCKET_UNIT': root / 'tailscale-panel.socket',
            'SERVICE_UNIT': root / 'tailscale-panel.service',
            'AVAHI': root / 'avahi' / 'tailscale-panel.service',
            'GUARD_CONF': root / 'raptor-input-guard.conf',
            'GUARD_BIN': root / 'raptor-input-guard',
            'STATE': root / 'state',
            'PENDING': root / 'state' / 'pending.json',
            'LOCK': root / 'lock',
        }
        p_files = dict(self.files)
        for key, value in p_files.items():
            patcher = patch.object(p, key, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        # MANAGED e' costruito all'import con i percorsi veri: va rifatto con quelli di prova.
        managed = (('socket', p.SOCKET_UNIT, True), ('service', p.SERVICE_UNIT, True),
                   ('avahi', p.AVAHI, False), ('guard', p.GUARD_CONF, False))
        patcher = patch.object(p, 'MANAGED', managed)
        patcher.start()
        self.addCleanup(patcher.stop)
        p.STATE.mkdir()
        self.write_all(8443)
        p.GUARD_BIN.write_text('#!/bin/sh\n')
        p.GUARD_BIN.chmod(0o755)
        self.sys = FakeSystem(self)
        for target, value in (('shell', self.sys), ('LISTEN_WAIT', 0)):
            patcher = patch.object(p, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(p.time, 'sleep', lambda s: None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write_all(self, port):
        p.SOCKET_UNIT.write_text(SOCKET % port)
        p.SERVICE_UNIT.write_text(SERVICE % port)
        p.AVAHI.write_text(AVAHI % port)
        p.GUARD_CONF.write_text(GUARD % port)
        for path in (p.SOCKET_UNIT, p.SERVICE_UNIT, p.AVAHI, p.GUARD_CONF):
            path.chmod(0o644)

    def state_of_files(self):
        return {k: v.read_text() for k, v in (('socket', p.SOCKET_UNIT), ('service', p.SERVICE_UNIT),
                                             ('avahi', p.AVAHI), ('guard', p.GUARD_CONF)) if v.exists()}

    def started(self, port=5000):
        result = p.start(port)
        self.assertTrue(result['ok'])
        return result

    def applied(self, port=5000):
        sid = self.started(port)['id']
        p.apply(sid)
        return sid


class ValidationTests(unittest.TestCase):
    def test_accepts_the_allowed_range(self):
        for port in (1024, 5000, 8080, 9443, 65535):
            with self.subTest(port=port):
                self.assertEqual(p.validate_port(port), port)

    def test_rejects_everything_else(self):
        for port in (0, 22, 80, 443, 1023, 65536, 70000, -1, 5353, 41641, '5000', '', None, True, 5000.5, [5000]):
            with self.subTest(port=port):
                with self.assertRaises(ValueError):
                    p.validate_port(port)


class RewriteTests(unittest.TestCase):
    def test_only_the_port_line_changes(self):
        for kind, template in (('socket', SOCKET), ('service', SERVICE), ('avahi', AVAHI), ('guard', GUARD)):
            with self.subTest(kind=kind):
                new = p.rewrite(kind, template % 8443, 5000)
                self.assertEqual(new, template % 5000)

    def test_unexpected_files_are_refused(self):
        for kind, text in (('socket', '[Socket]\nListenStream=127.0.0.1:8443\n'),
                           ('socket', SOCKET % 8443 + 'ListenStream=0.0.0.0:9\n'),
                           ('service', '[Service]\nUser=x\n'),
                           ('avahi', '<service-group/>'),
                           ('guard', 'SSH_LAN=1\n')):
            with self.subTest(kind=kind):
                with self.assertRaises(RuntimeError):
                    p.rewrite(kind, text, 5000)


class StatusTests(Sandbox):
    def test_reports_the_port_written_in_the_unit(self):
        status = p.get_current()
        self.assertEqual((status['supported'], status['current'], status['pending']), (True, 8443, None))
        self.assertEqual((status['min'], status['max']), (1024, 65535))

    def test_unrecognised_unit_means_not_supported_and_gives_a_reason(self):
        p.SOCKET_UNIT.write_text('[Socket]\nListenStream=8443\n')
        status = p.get_current()
        self.assertFalse(status['supported'])
        self.assertIn('not recognised', status['reason'])

    def test_missing_unit(self):
        p.SOCKET_UNIT.unlink()
        self.assertFalse(p.get_current()['supported'])

    def test_pending_is_shown_without_the_snapshot(self):
        self.started()
        pending = p.get_current()['pending']
        self.assertEqual((pending['old_port'], pending['new_port'], pending['state']), (8443, 5000, 'scheduled'))
        self.assertNotIn('snapshot', pending)


class StartTests(Sandbox):
    def test_schedules_but_changes_nothing_yet(self):
        before = self.state_of_files()
        result = self.started(5000)
        self.assertEqual((result['old_port'], result['new_port']), (8443, 5000))
        self.assertEqual(self.state_of_files(), before)
        self.assertNotIn('systemctl daemon-reload', [' '.join(c) for c in self.sys.calls])
        timers = [c for c in self.sys.calls if c[0] == 'systemd-run']
        self.assertEqual(len(timers), 2)
        rollback = next(c for c in timers if '--rollback' in c)
        apply = next(c for c in timers if '--apply' in c)
        self.assertIn('--on-active=150s', rollback)
        self.assertIn('--on-active=4s', apply)
        self.assertEqual(rollback[-1], result['id'])
        self.assertEqual(oct(p.PENDING.stat().st_mode & 0o777), '0o600')
        self.assertTrue(list(p.STATE.glob('backup-*.json')))

    def test_the_restore_timer_is_created_before_the_apply_timer(self):
        self.started()
        runs = [c for c in self.sys.calls if c[0] == 'systemd-run']
        self.assertIn('--rollback', runs[0])
        self.assertIn('--apply', runs[1])

    def test_refusals_leave_no_trace(self):
        cases = [(8443, 'already uses'), (22, 'between'), (80, 'between'), (5353, 'reserved'), ('5000', 'whole number')]
        for port, text in cases:
            with self.subTest(port=port):
                with self.assertRaises(ValueError) as ctx:
                    p.start(port)
                self.assertIn(text, str(ctx.exception))
        self.assertFalse(p.PENDING.exists())
        self.assertFalse([c for c in self.sys.calls if c[0] == 'systemd-run'])

    def test_port_used_by_another_service_is_refused(self):
        self.sys.listening.add(5000)
        with self.assertRaises(ValueError) as ctx:
            p.start(5000)
        self.assertIn('already used', str(ctx.exception))
        self.assertFalse(p.PENDING.exists())

    def test_checking_ports_failing_closes_the_door(self):
        self.sys.fail.add('ss')
        with self.assertRaises(RuntimeError):
            p.start(5000)
        self.assertFalse(p.PENDING.exists())

    def test_second_change_is_refused_while_one_is_pending(self):
        self.started(5000)
        with self.assertRaises(RuntimeError):
            p.start(6000)

    def test_unrecognised_files_stop_it_before_any_timer(self):
        p.SERVICE_UNIT.write_text('[Service]\nUser=tspanel\n')
        with self.assertRaises(RuntimeError):
            p.start(5000)
        self.assertFalse([c for c in self.sys.calls if c[0] == 'systemd-run'])
        self.assertFalse(p.PENDING.exists())

    def test_failing_restore_timer_means_nothing_is_scheduled(self):
        self.sys.fail.add('systemd-run --quiet --unit=tspanel-port-rollback')
        with self.assertRaises(RuntimeError):
            p.start(5000)
        self.assertFalse(p.PENDING.exists())

    def test_failing_apply_timer_removes_the_pending_record(self):
        self.sys.fail.add('systemd-run --quiet --unit=tspanel-port-apply')
        with self.assertRaises(RuntimeError):
            p.start(5000)
        self.assertFalse(p.PENDING.exists())
        sid = next(c for c in self.sys.calls if c[0] == 'systemd-run')[-1]
        self.assertIn(['systemctl', 'stop', 'tspanel-port-rollback-%s.timer' % sid], self.sys.calls)


class ApplyTests(Sandbox):
    def test_rewrites_exactly_the_port_lines_and_moves_the_socket(self):
        self.applied(5000)
        self.assertEqual(self.state_of_files(), {'socket': SOCKET % 5000, 'service': SERVICE % 5000,
                                                 'avahi': AVAHI % 5000, 'guard': GUARD % 5000})
        for path in (p.SOCKET_UNIT, p.SERVICE_UNIT, p.AVAHI, p.GUARD_CONF):
            self.assertEqual(oct(path.stat().st_mode & 0o777), '0o644')
        self.assertEqual(self.panel_port, 5000)
        self.assertEqual(p.get_current()['current'], 5000)
        self.assertEqual(p.read_pending()['state'], 'applied')

    def test_the_firewall_opens_the_new_port_before_the_socket_moves(self):
        self.applied(5000)
        order = [self.sys.index(x) for x in (str(p.GUARD_BIN) + ' apply', 'systemctl daemon-reload', 'systemctl restart tailscale-panel.socket')]
        self.assertEqual(order, sorted(order))
        self.assertEqual(len(set(order)), 3)

    def test_without_the_firewall_nothing_firewall_related_runs(self):
        p.GUARD_CONF.unlink()
        self.applied(5000)
        self.assertFalse([c for c in self.sys.calls if c[0] == 'iptables' or c[0] == str(p.GUARD_BIN)])

    def test_firewall_installed_but_not_active_is_left_alone(self):
        self.sys.chain_active = False
        self.applied(5000)
        self.assertFalse([c for c in self.sys.calls if c[0] == str(p.GUARD_BIN)])
        self.assertIn('PANEL_PORT=5000', p.GUARD_CONF.read_text())   # il file e' comunque coerente

    def test_without_avahi_the_rest_still_works(self):
        p.AVAHI.unlink()
        self.applied(5000)
        self.assertFalse(p.AVAHI.exists())
        self.assertEqual(self.panel_port, 5000)

    def test_unrecognised_optional_file_stops_the_apply_and_restores_everything(self):
        sid = self.started(5000)['id']
        p.AVAHI.write_text('<service-group/>')        # cambiato dopo lo start
        with self.assertRaises(RuntimeError):
            p.apply(sid)
        self.assertEqual(p.SOCKET_UNIT.read_text(), SOCKET % 8443)
        self.assertFalse(p.PENDING.exists())

    def test_a_failing_socket_restart_puts_the_old_port_back(self):
        sid = self.started(5000)['id']
        original = self.state_of_files()
        # il primo restart (nuova porta) fallisce, quello del ripristino riesce
        real = self.sys.__call__
        state = {'n': 0}

        def flaky(args, timeout=15):
            if list(args)[:3] == ['systemctl', 'restart', 'tailscale-panel.socket']:
                state['n'] += 1
                if state['n'] == 1:
                    self.sys.calls.append([str(a) for a in args])
                    return subprocess.CompletedProcess(args, 1, '', 'bind failed')
            return real(args, timeout)
        with patch.object(p, 'shell', flaky):
            with self.assertRaises(RuntimeError):
                p.apply(sid)
        self.assertEqual(self.state_of_files(), original)
        self.assertEqual(self.panel_port, 8443)
        self.assertFalse(p.PENDING.exists())

    def test_the_panel_not_listening_on_the_new_port_means_automatic_restore(self):
        sid = self.started(5000)['id']
        self.sys.refuse_binds = 1
        original = self.state_of_files()
        with self.assertRaises(RuntimeError):
            p.apply(sid)
        self.assertEqual(self.state_of_files(), original)
        self.assertFalse(p.PENDING.exists())

    def test_firewall_failure_restores_before_the_socket_ever_moved(self):
        sid = self.started(5000)['id']
        original = self.state_of_files()
        self.sys.fail_once.add(str(p.GUARD_BIN) + ' apply')
        with self.assertRaises(RuntimeError):
            p.apply(sid)
        self.assertEqual(self.state_of_files(), original)
        self.assertFalse(p.PENDING.exists())
        self.assertEqual(self.panel_port, 8443)

    def test_if_even_the_restore_cannot_restart_the_panel_the_record_stays_for_the_next_boot(self):
        sid = self.started(5000)['id']
        self.sys.fail.add(str(p.GUARD_BIN) + ' apply')      # il firewall non risponde nemmeno per la porta vecchia
        with self.assertRaises(RuntimeError):
            p.apply(sid)
        self.assertEqual(p.SOCKET_UNIT.read_text(), SOCKET % 8443)    # i file sono comunque tornati indietro
        self.assertTrue(p.PENDING.exists())

    def test_apply_twice_or_with_a_wrong_id_does_nothing(self):
        sid = self.applied(5000)
        calls = len(self.sys.calls)
        self.assertIn('note', p.apply(sid))
        self.assertIn('note', p.apply('0' * 14))
        self.assertEqual(len(self.sys.calls), calls)


class ConfirmTests(Sandbox):
    def test_confirm_from_the_new_port_makes_it_final(self):
        sid = self.applied(5000)
        result = p.confirm(sid, 5000)
        self.assertEqual(result, {'ok': True, 'confirmed': True, 'port': 5000})
        self.assertFalse(p.PENDING.exists())
        self.assertIn(['systemctl', 'stop', 'tspanel-port-rollback-%s.timer' % sid], self.sys.calls)
        self.assertIn(['systemctl', 'stop', 'tspanel-port-apply-%s.timer' % sid], self.sys.calls)
        self.assertEqual(p.get_current()['current'], 5000)
        self.assertIsNone(p.get_current()['pending'])

    def test_confirm_from_the_old_port_is_refused(self):
        sid = self.applied(5000)
        with self.assertRaises(ValueError) as ctx:
            p.confirm(sid, 8443)
        self.assertIn('new port', str(ctx.exception))
        self.assertTrue(p.PENDING.exists())

    def test_confirm_before_the_change_is_applied_is_refused(self):
        sid = self.started(5000)['id']
        with self.assertRaises(ValueError):
            p.confirm(sid, 5000)

    def test_the_state_is_checked_even_if_something_already_listens_on_the_new_port(self):
        sid = self.started(5000)['id']
        self.sys.listening.add(5000)
        with self.assertRaises(ValueError) as ctx:
            p.confirm(sid, 5000)
        self.assertIn('not applied yet', str(ctx.exception))
        self.assertTrue(p.PENDING.exists())

    def test_confirm_with_unknown_id(self):
        self.applied(5000)
        with self.assertRaises(ValueError):
            p.confirm('1' * 14, 5000)

    def test_confirm_refused_if_nothing_listens_on_the_new_port(self):
        sid = self.applied(5000)
        self.sys.listening.discard(5000)
        with self.assertRaises(ValueError):
            p.confirm(sid, 5000)
        self.assertTrue(p.PENDING.exists())

    def test_a_string_port_is_not_a_confirmation(self):
        sid = self.applied(5000)
        with self.assertRaises(ValueError):
            p.confirm(sid, '5000')


class RollbackTests(Sandbox):
    def test_unconfirmed_change_comes_back_to_the_old_port(self):
        original = self.state_of_files()
        sid = self.applied(5000)
        result = p.rollback(sid)
        self.assertEqual(result, {'ok': True, 'rolled_back': True, 'port': 8443})
        self.assertEqual(self.state_of_files(), original)
        self.assertEqual(self.panel_port, 8443)
        self.assertFalse(p.PENDING.exists())
        # il firewall viene riapplicato con la porta vecchia
        self.assertGreaterEqual(sum(1 for c in self.sys.calls if c == [str(p.GUARD_BIN), 'apply']), 2)

    def test_rollback_after_confirmation_does_nothing(self):
        sid = self.applied(5000)
        p.confirm(sid, 5000)
        calls = len(self.sys.calls)
        self.assertIn('note', p.rollback(sid))
        self.assertEqual(len(self.sys.calls), calls)
        self.assertEqual(p.get_current()['current'], 5000)

    def test_if_the_restart_fails_the_record_stays_so_the_next_boot_retries(self):
        sid = self.applied(5000)
        self.sys.fail.add('systemctl restart tailscale-panel.socket')
        with self.assertRaises(RuntimeError):
            p.rollback(sid)
        self.assertEqual(p.SOCKET_UNIT.read_text(), SOCKET % 8443)    # i file sono gia' tornati indietro
        self.assertTrue(p.PENDING.exists())
        self.sys.fail.clear()
        with patch.object(p.sys, 'argv', ['helper', '--recover']), patch.object(p.os, 'geteuid', return_value=0), \
             patch('sys.stdout', new_callable=io.StringIO):
            p.main()
        self.assertFalse(p.PENDING.exists())
        self.assertEqual(self.panel_port, 8443)

    def test_restore_refuses_paths_outside_the_managed_files(self):
        with self.assertRaises(RuntimeError):
            p.restore({'/etc/passwd': 'eA=='})


class SetPortTests(Sandbox):
    """`--set-port N` da una shell root: cambio immediato, senza conferma, per quando il pannello non si raggiunge piu'."""

    def run_main(self, *argv):
        out = io.StringIO()
        with patch.object(p.sys, 'argv', ['helper', *argv]), patch.object(p.os, 'geteuid', return_value=0), \
             patch('sys.stdout', out), patch.object(p.os, 'chmod'):
            p.main()
        return json.loads(out.getvalue())

    def test_changes_everything_at_once_and_leaves_no_pending_record(self):
        result = self.run_main('--set-port', '5000')
        self.assertEqual(result, {'ok': True, 'port': 5000})
        self.assertEqual(self.state_of_files(), {'socket': SOCKET % 5000, 'service': SERVICE % 5000,
                                                 'avahi': AVAHI % 5000, 'guard': GUARD % 5000})
        self.assertEqual(self.panel_port, 5000)
        self.assertFalse(p.PENDING.exists())
        self.assertFalse([c for c in self.sys.calls if c[0] == 'systemd-run'])

    def test_same_port_changes_nothing(self):
        calls = len(self.sys.calls)
        result = self.run_main('--set-port', '8443')
        self.assertIn('already uses', result['note'])
        self.assertEqual(self.state_of_files()['socket'], SOCKET % 8443)
        self.assertNotIn(['systemctl', 'daemon-reload'], self.sys.calls[calls:])

    def test_refusals(self):
        for argv in (('--set-port', '80'), ('--set-port', '5353'), ('--set-port', 'abc'), ('--set-port', '5000.5')):
            with self.subTest(argv=argv):
                with self.assertRaises(ValueError):
                    self.run_main(*argv)
        self.sys.listening.add(6000)
        with self.assertRaises(ValueError):
            self.run_main('--set-port', '6000')
        self.started(7000)
        with self.assertRaises(RuntimeError):
            self.run_main('--set-port', '5000')
        self.assertEqual(self.state_of_files()['socket'], SOCKET % 8443)

    def test_a_failing_restart_puts_the_old_port_back(self):
        original = self.state_of_files()
        self.sys.refuse_binds = 1
        with self.assertRaises(RuntimeError):
            self.run_main('--set-port', '5000')
        self.assertEqual(self.state_of_files(), original)
        self.assertEqual(self.panel_port, 8443)

    def test_it_is_not_reachable_through_the_json_entry_point(self):
        with self.assertRaises(ValueError):
            self.call_api({'action': 'set-port', 'port': 5000})

    def call_api(self, payload):
        with patch.object(p.sys, 'stdin', io.TextIOWrapper(io.BytesIO(json.dumps(payload).encode()))):
            return p.api()

    def test_sudoers_allows_the_helper_without_arguments_only(self):
        line = next(x for x in (DIR / 'install_tailscale_panel.sh').read_text().splitlines() if x.startswith('tspanel ALL='))
        self.assertIn('tailscale-panel-port-helper ""', line)
        self.assertNotIn('--set-port', line)


class InstallerTests(unittest.TestCase):
    """Un aggiornamento non deve riportare la porta a 8443: la porta scelta dal pannello va conservata."""
    INSTALLER = (DIR / 'install_tailscale_panel.sh').read_text()

    def effective_port(self, unit_text, env_port=None):
        start = self.INSTALLER.index('if [ -z "${PORT:-}" ] && [ -r "$SOCKET_UNIT" ]; then')
        end = self.INSTALLER.index('PORT=${PORT:-8443}\n') + len('PORT=${PORT:-8443}\n')
        fragment = self.INSTALLER[start:end]
        with tempfile.TemporaryDirectory() as folder:
            unit = pathlib.Path(folder) / 'tailscale-panel.socket'
            if unit_text is not None:
                unit.write_text(unit_text)
            env = {'PATH': '/usr/bin:/bin'}
            if env_port:
                env['PORT'] = env_port
            done = subprocess.run(['sh', '-c', 'set -eu\nSOCKET_UNIT=%s\n%s\necho "$PORT"' % (unit, fragment)],
                                  capture_output=True, text=True, env=env)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout.strip()

    def test_a_chosen_port_survives_the_update(self):
        self.assertEqual(self.effective_port(SOCKET % 5000), '5000')

    def test_fresh_board_uses_8443(self):
        self.assertEqual(self.effective_port(None), '8443')

    def test_an_unreadable_unit_does_not_break_it(self):
        for text in ('', '[Socket]\nListenStream=8443\n', '[Socket]\nListenStream=0.0.0.0:abc\n', '[Socket]\nListenStream=0.0.0.0:123456\n'):
            with self.subTest(text=text):
                self.assertEqual(self.effective_port(text), '8443')

    def test_an_explicit_port_on_the_command_line_wins(self):
        self.assertEqual(self.effective_port(SOCKET % 5000, env_port='9000'), '9000')

    def test_the_port_is_read_before_the_old_value_is_validated(self):
        self.assertLess(self.INSTALLER.index('SOCKET_UNIT" | head -n 1)'), self.INSTALLER.index('Scegliere una porta TCP fra 1024 e 65535'))

    def test_the_helper_the_sudoers_rule_and_the_boot_recovery_are_installed(self):
        self.assertIn('"$DIR/tailscale_panel_port.py" "$PORT_HELPER"', self.INSTALLER)
        self.assertIn('tailscale-panel-port-helper ""', self.INSTALLER)
        self.assertIn('ExecStart=$PORT_HELPER --recover', self.INSTALLER)
        self.assertIn('systemctl enable tailscale-panel-port-recovery.service', self.INSTALLER)

    def test_an_update_is_refused_while_a_port_change_is_pending(self):
        start = self.INSTALLER.index('if [ -e /var/lib/tailscale-panel-port/pending.json ]; then')
        end = self.INSTALLER.index('\nfi\n', start) + len('\nfi\n')
        self.assertLess(start, self.INSTALLER.index('install -m 755 -o root -g root "$DIR/tailscale_panel_port.py"'))
        block = self.INSTALLER[start:end]
        with tempfile.TemporaryDirectory() as folder:
            pending = pathlib.Path(folder) / 'pending.json'
            script = block.replace('/var/lib/tailscale-panel-port/pending.json', str(pending)) + 'echo proceeds\n'
            free = subprocess.run(['sh', '-c', script], capture_output=True, text=True)
            pending.write_text('{}')
            busy = subprocess.run(['sh', '-c', script], capture_output=True, text=True)
        self.assertEqual((free.returncode, free.stdout.strip()), (0, 'proceeds'))
        self.assertEqual(busy.returncode, 1)
        self.assertNotIn('proceeds', busy.stdout)
        self.assertIn('in sospeso', busy.stderr)

    def test_backup_and_factory_lists_know_the_new_files(self):
        self.assertIn('usr/local/libexec/tailscale-panel-port-helper', (DIR / 'backup_panel.sh').read_text())
        self.assertIn('etc/systemd/system/tailscale-panel-port-recovery.service', (DIR / 'backup_panel.sh').read_text())
        self.assertEqual((DIR / 'install_factory.sh').read_text().count('tailscale_panel_port.py'), 2)

    def test_the_check_reads_the_real_port(self):
        check = (DIR / 'check_installation.sh').read_text()
        self.assertNotIn(':8443/login', check)
        self.assertIn('$PANEL_PORT/login', check)
        self.assertIn('tailscale-panel-port-helper', check)


@unittest.skipUnless(__import__('shutil').which('bash'), 'bash non disponibile')
class FirewallFollowsThePortTests(unittest.TestCase):
    """Se il firewall in ingresso viene installato DOPO il cambio, deve aprire la porta vera, non 8443."""

    def plan(self, unit_text, conf_text=None):
        script = (DIR / 'hardening' / 'input_firewall.sh').read_text()
        with tempfile.TemporaryDirectory() as folder:
            base = pathlib.Path(folder)
            unit = base / 'tailscale-panel.socket'
            if unit_text is not None:
                unit.write_text(unit_text)
            conf = base / 'guard.conf'
            if conf_text is not None:
                conf.write_text(conf_text)
            script = (script.replace('/etc/systemd/system/tailscale-panel.socket', str(unit))
                            .replace('CONF=/etc/raptor-input-guard.conf', 'CONF=%s' % conf)
                            .replace('/etc/tailscale-panel-lan.conf', str(base / 'none')))
            (base / 'fw.sh').write_text(script)
            done = subprocess.run(['bash', str(base / 'fw.sh'), 'plan'], capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout

    def test_default_is_8443(self):
        out = self.plan(None)
        self.assertIn('porta pannello: 8443', out)
        self.assertIn('--dport 8443 -j ACCEPT', out)

    def test_a_changed_port_is_the_one_opened(self):
        out = self.plan(SOCKET % 5000)
        self.assertIn('porta pannello: 5000', out)
        self.assertIn('-i end0 -p tcp --dport 5000 -j ACCEPT', out)
        self.assertNotIn('--dport 8443', out)

    def test_the_saved_file_still_wins_when_it_exists(self):
        out = self.plan(SOCKET % 5000, conf_text='PANEL_PORT=6000\nSSH_LAN=1\n')
        self.assertIn('porta pannello: 6000', out)


class BootRecoveryTests(Sandbox):
    def run_main(self, *argv):
        out = io.StringIO()
        with patch.object(p.sys, 'argv', ['helper', *argv]), patch.object(p.os, 'geteuid', return_value=0), \
             patch('sys.stdout', out), patch.object(p.os, 'chmod'):
            p.main()
        return json.loads(out.getvalue())

    def test_power_lost_before_confirmation_means_the_old_port_at_boot(self):
        self.applied(5000)
        self.assertEqual(self.panel_port, 5000)
        result = self.run_main('--recover')
        self.assertTrue(result['rolled_back'])
        self.assertEqual(p.get_current()['current'], 8443)

    def test_nothing_to_recover(self):
        self.assertEqual(self.run_main('--recover')['note'], 'No restore needed.')

    def test_internal_entry_points_check_their_arguments(self):
        for argv in (('--apply',), ('--apply', 'zzz'), ('--rollback', '../x'), ('--bogus',), ('--recover', 'x')):
            with self.subTest(argv=argv):
                with self.assertRaises(ValueError):
                    self.run_main(*argv)


class ApiTests(Sandbox):
    def call(self, payload, raw=None):
        data = raw if raw is not None else json.dumps(payload).encode()
        with patch.object(p.sys, 'stdin', io.TextIOWrapper(io.BytesIO(data))):
            return p.api()

    def test_status_start_and_confirm_through_the_json_entry_point(self):
        self.assertTrue(self.call({'action': 'status'})['ok'])
        started = self.call({'action': 'start', 'port': 5000})
        p.apply(started['id'])
        self.assertEqual(self.call({'action': 'confirm', 'id': started['id'], 'port': 5000})['port'], 5000)

    def test_unknown_actions_and_extra_fields_are_refused(self):
        for payload in ({'action': 'nonsense'}, {'action': 'status', 'x': 1}, {'action': 'start'},
                        {'action': 'start', 'port': 5000, 'x': 1}, {'action': 'confirm', 'id': 'a' * 14},
                        {'action': 'confirm', 'id': 'A' * 14, 'port': 5000}, {'action': 'confirm', 'id': 'a' * 13, 'port': 5000},
                        {'action': 'confirm', 'id': 5, 'port': 5000}, [], 'x', 5):
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    self.call(payload)

    def test_oversized_request_is_refused(self):
        with self.assertRaises(ValueError):
            self.call(None, raw=b'{"action":"status","pad":"' + b'x' * 5000 + b'"}')

    def test_only_root_can_use_it(self):
        with patch.object(p.sys, 'argv', ['helper']), patch.object(p.os, 'geteuid', return_value=1000):
            with self.assertRaises(ValueError):
                p.main()

    def test_port_cannot_inject_anything_into_the_files(self):
        for evil in ('5000\nExecStart=/bin/sh', '5000; reboot', '5000/../x', 5000.0 + 1e-9):
            with self.subTest(evil=evil):
                with self.assertRaises(ValueError):
                    self.call({'action': 'start', 'port': evil})
        self.assertEqual(self.state_of_files()['socket'], SOCKET % 8443)


if __name__ == '__main__':
    unittest.main()
