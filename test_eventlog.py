#!/usr/bin/env python3
"""Test del registro eventi (raptor_eventlog.py). Nessun test tocca /var o systemd."""
import importlib.util
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

DIR = pathlib.Path(__file__).resolve().parent
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('eventlog', DIR / 'raptor_eventlog.py')
ev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ev)


class Box(unittest.TestCase):
    """Cartella temporanea + orologio, uptime, boot_id e systemd finti."""
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = pathlib.Path(tmp.name)
        self.clock = {'now': 1_800_000_000, 'uptime': 25.0, 'boot': 'boot-A', 'synced': True,
                      'stopping': True, 'jobs': 'reboot.target'}
        for name, value in (('DIR', root / 'ev'), ('EVENTS', root / 'ev' / 'events.jsonl'),
                            ('STATE', root / 'ev' / 'state.json')):
            patcher = patch.object(ev, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        for name, fake in (('uptime_seconds', lambda: self.clock['uptime']),
                           ('boot_id', lambda: self.clock['boot']),
                           ('clock_synced', lambda: self.clock['synced']),
                           ('system_is_stopping', lambda: self.clock['stopping']),
                           ('shutdown_kind', lambda: ev.SHUTDOWN_KINDS_FAKE.get(self.clock['jobs'], 'unknown')
                            if hasattr(ev, 'SHUTDOWN_KINDS_FAKE') else self.clock['jobs'])):
            patcher = patch.object(ev, name, fake)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(ev.time, 'time', lambda: self.clock['now'])
        patcher.start()
        self.addCleanup(patcher.stop)

    def events(self):
        if not ev.EVENTS.exists():
            return []
        return [json.loads(line) for line in ev.EVENTS.read_text().splitlines() if line.strip()]

    def types(self):
        return [e['type'] for e in self.events()]

    def next_boot(self, name, uptime=25.0):
        self.clock.update(boot=name, uptime=uptime, now=self.clock['now'] + 100)

    def power_cut(self, gap=600):
        self.clock['now'] += gap


class BootTests(Box):
    def test_first_boot(self):
        result = ev.cmd_boot()
        self.assertEqual(result['previous'], 'first_boot')
        (boot,) = self.events()
        self.assertEqual((boot['type'], boot['previous'], boot['boot_id']), ('boot', 'first_boot', 'boot-A'))
        self.assertEqual(boot['epoch'], self.clock['now'] - 25)
        self.assertTrue(boot['clock_synced'])
        self.assertNotIn('logged_late', boot)
        self.assertFalse(ev.read_state()['clean'])

    def test_clean_reboot_is_recognised(self):
        ev.cmd_boot()
        self.clock['jobs'] = 'reboot'
        ev.cmd_shutdown()
        self.next_boot('boot-B')
        self.assertEqual(ev.cmd_boot()['previous'], 'clean_reboot')
        self.assertEqual(self.types(), ['boot', 'shutdown', 'boot'])
        self.assertNotIn('unclean_shutdown', self.types())

    def test_clean_poweroff_is_recognised(self):
        ev.cmd_boot()
        self.clock['jobs'] = 'poweroff'
        ev.cmd_shutdown()
        self.next_boot('boot-B')
        self.assertEqual(ev.cmd_boot()['previous'], 'clean_poweroff')

    def test_power_loss_is_detected_with_last_seen(self):
        ev.cmd_boot()
        self.clock['now'] += 300
        ev.cmd_heartbeat()
        seen = self.clock['now']
        self.power_cut(gap=900)
        self.next_boot('boot-B')
        self.assertEqual(ev.cmd_boot()['previous'], 'unclean')
        kinds = self.types()
        self.assertEqual(kinds, ['boot', 'unclean_shutdown', 'boot'])
        lost = self.events()[1]
        self.assertEqual(lost['last_seen_epoch'], seen)
        self.assertGreater(lost['detected_epoch'], seen)
        self.assertEqual(self.events()[2]['previous_last_seen_epoch'], seen)

    def test_rerun_in_the_same_boot_changes_nothing(self):
        ev.cmd_boot()
        before = ev.EVENTS.read_text()
        result = ev.cmd_boot()
        self.assertEqual(result['note'], 'avvio gia registrato')
        self.assertEqual(ev.EVENTS.read_text(), before)

    def test_installed_late_is_flagged_and_dated_at_real_boot(self):
        self.clock['uptime'] = 5000.0
        ev.cmd_boot()
        (boot,) = self.events()
        self.assertTrue(boot['logged_late'])
        self.assertEqual(boot['epoch'], self.clock['now'] - 5000)
        self.assertEqual(boot['logged_epoch'], self.clock['now'])

    def test_corrupt_state_is_not_called_first_boot(self):
        ev.cmd_boot()
        ev.STATE.write_text('{non json')
        self.next_boot('boot-B')
        self.assertEqual(ev.cmd_boot()['previous'], 'unknown')

    def test_unsynced_clock_is_flagged(self):
        self.clock['synced'] = False
        ev.cmd_boot()
        self.assertFalse(self.events()[0]['clock_synced'])


class ShutdownTests(Box):
    def test_manual_service_stop_is_not_a_shutdown(self):
        ev.cmd_boot()
        self.clock['stopping'] = False
        self.assertIn('ignorato', ev.cmd_shutdown()['note'])
        self.assertEqual(self.types(), ['boot'])
        self.assertFalse(ev.read_state()['clean'])           # un vero blocco dopo resterebbe "anomalo"
        self.power_cut()
        self.next_boot('boot-B')
        self.assertEqual(ev.cmd_boot()['previous'], 'unclean')

    def test_shutdown_without_state_still_logs(self):
        self.clock['jobs'] = 'poweroff'
        ev.cmd_shutdown()
        self.assertEqual(self.events()[0]['kind'], 'poweroff')

    def test_job_kinds(self):
        for text, kind in (('123 reboot.target start waiting', 'reboot'), ('9 poweroff.target start', 'poweroff'),
                           ('9 halt.target start', 'halt'), ('9 kexec.target start', 'reboot'), ('', 'unknown')):
            with self.subTest(kind=kind), patch.object(ev, 'run', return_value=text):
                # shutdown_kind e' stato sostituito nel Box: richiamo quello vero
                real = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(real)
                with patch.object(real, 'run', return_value=text):
                    self.assertEqual(real.shutdown_kind(), kind)


class HeartbeatTests(Box):
    def test_updates_last_seen(self):
        ev.cmd_boot()
        self.clock['now'] += 300
        ev.cmd_heartbeat()
        self.assertEqual(ev.read_state()['last_seen_epoch'], self.clock['now'])

    def test_does_not_touch_a_clean_shutdown_marker(self):
        ev.cmd_boot()
        self.clock['jobs'] = 'reboot'
        ev.cmd_shutdown()
        marked = ev.read_state()
        self.clock['now'] += 5
        ev.cmd_heartbeat()
        self.assertEqual(ev.read_state(), marked)

    def test_clock_sync_event_once_with_jump(self):
        self.clock['synced'] = False
        ev.cmd_boot()
        self.clock['now'] += 120; self.clock['uptime'] += 120
        ev.cmd_heartbeat()                                    # ancora non sincronizzato
        self.assertEqual(self.types(), ['boot'])
        # l'orologio salta in avanti di 40 s quando si sincronizza
        self.clock['now'] += 300 + 40; self.clock['uptime'] += 300
        self.clock['synced'] = True
        ev.cmd_heartbeat()
        ev.cmd_heartbeat()
        synced = [e for e in self.events() if e['type'] == 'clock_synced']
        self.assertEqual(len(synced), 1)
        self.assertEqual(synced[0]['jump_seconds'], 40)

    def test_no_state_is_harmless(self):
        self.assertIn('nessuno stato', ev.cmd_heartbeat()['note'])


class FileTests(Box):
    def test_permissions_and_json_lines(self):
        ev.cmd_boot()
        self.assertEqual(oct(ev.EVENTS.stat().st_mode & 0o777), '0o644')
        self.assertEqual(oct(ev.STATE.stat().st_mode & 0o777), '0o644')
        for line in ev.EVENTS.read_text().splitlines():
            json.loads(line)

    def test_trim_keeps_the_newest(self):
        with patch.object(ev, 'MAX_BYTES', 200), patch.object(ev, 'KEEP_LINES', 5):
            for i in range(40):
                ev.append_event({'type': 'boot', 'epoch': i})
            self.assertTrue(ev.trim_events())
        epochs = [e['epoch'] for e in self.events()]
        self.assertEqual(epochs, [35, 36, 37, 38, 39])

    def test_small_file_is_not_trimmed(self):
        ev.append_event({'type': 'boot', 'epoch': 1})
        self.assertFalse(ev.trim_events())

    def test_main_requires_root_and_known_command(self):
        with patch.object(ev.os, 'geteuid', return_value=1000):
            self.assertEqual(ev.main(['x', '--boot']), 1)
        with patch('builtins.print'):
            self.assertEqual(ev.main(['x', '--boh']), 2)
            self.assertEqual(ev.main(['x']), 2)


if __name__ == '__main__':
    unittest.main()
