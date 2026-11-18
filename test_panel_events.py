#!/usr/bin/env python3
"""Test della lettura del registro eventi da parte del pannello (sola lettura, campi controllati)."""
import importlib.util
import json
import pathlib
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

DIR = pathlib.Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(DIR))
spec = importlib.util.spec_from_file_location('panel_ev', DIR / 'tailscale_panel.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

NOW = 1_800_000_000


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = pathlib.Path(tmp.name) / 'events.jsonl'

    def write(self, *items, raw=''):
        lines = [i if isinstance(i, str) else json.dumps(i) for i in items]
        self.path.write_text('\n'.join(lines) + ('\n' if lines else '') + raw)

    def read(self):
        return p.events_data(str(self.path), now=NOW)


class ReadTests(Base):
    def test_missing_file(self):
        data = self.read()
        self.assertFalse(data['available'])
        self.assertIn('raptor-eventlog', data['reason'])

    def test_unreadable_file(self):
        self.path.mkdir()                       # una cartella al posto del file
        self.assertFalse(self.read()['available'])

    def test_newest_first_in_file_order(self):
        self.write({'type': 'boot', 'epoch': NOW - 300, 'previous': 'first_boot'},
                   {'type': 'unclean_shutdown', 'epoch': NOW - 200, 'last_seen_epoch': NOW - 250},
                   {'type': 'boot', 'epoch': NOW - 200, 'previous': 'unclean', 'clock_synced': True})
        events = self.read()['events']
        self.assertEqual([e['type'] for e in events], ['boot', 'unclean_shutdown', 'boot'])
        self.assertEqual(events[0]['previous'], 'unclean')
        self.assertEqual(events[1]['last_seen_epoch'], NOW - 250)

    def test_bad_lines_are_skipped(self):
        self.write('{non json', {'type': 'boot', 'epoch': NOW - 1}, '[1,2]', '"testo"', 'null',
                   {'type': 'sconosciuto', 'epoch': NOW}, {'type': 'boot'},
                   {'type': 'boot', 'epoch': 'ieri'}, {'type': 'boot', 'epoch': True},
                   {'type': 'boot', 'epoch': -5}, {'type': 'boot', 'epoch': 10 ** 12},
                   raw='{"type":"boot","epoch":17')                # riga tagliata da uno spegnimento di colpo
        events = self.read()['events']
        self.assertEqual([e['epoch'] for e in events], [NOW - 1])

    def test_fields_are_whitelisted_and_checked(self):
        self.write({'type': 'boot', 'epoch': NOW, 'previous': '<script>alert(1)</script>', 'kind': 'X' * 60,
                    'clock_synced': 'si', 'logged_late': True, 'kernel': '6.18', 'boot_id': 'abc',
                    'jump_seconds': 'molti', 'last_seen_epoch': 'x', 'extra': {'a': 1}})
        (event,) = self.read()['events']
        self.assertEqual(event, {'type': 'boot', 'epoch': NOW, 'logged_late': True})

    def test_valid_optional_fields_pass(self):
        self.write({'type': 'clock_synced', 'epoch': NOW, 'jump_seconds': -42},
                   {'type': 'shutdown', 'epoch': NOW - 5, 'kind': 'poweroff'},
                   {'type': 'boot', 'epoch': NOW - 90, 'previous': 'clean_reboot', 'clock_synced': False,
                    'previous_last_seen_epoch': NOW - 100})
        boot, shutdown, synced = self.read()['events']          # piu' recente per primo
        self.assertEqual(synced['jump_seconds'], -42)
        self.assertEqual(shutdown['kind'], 'poweroff')
        self.assertIs(boot['clock_synced'], False)
        self.assertEqual(boot['previous_last_seen_epoch'], NOW - 100)

    def test_limit_keeps_the_newest(self):
        self.write(*[{'type': 'boot', 'epoch': NOW - 1000 + i} for i in range(300)])
        events = self.read()['events']
        self.assertEqual(len(events), p.EVENTS_LIMIT)
        self.assertEqual(events[0]['epoch'], NOW - 1000 + 299)
        self.assertEqual(self.read()['summary']['total'], 300)

    def test_only_the_tail_is_read_and_a_cut_first_line_is_dropped(self):
        self.write(*[{'type': 'boot', 'epoch': NOW - 5000 + i, 'previous': 'clean_reboot'} for i in range(400)])
        size = self.path.stat().st_size
        with patch.object(p, 'EVENTS_TAIL_BYTES', size // 3):
            data = self.read()
        self.assertTrue(0 < len(data['events']) < 400)
        self.assertEqual(data['events'][0]['epoch'], NOW - 5000 + 399)
        for e in data['events']:                                  # nessuna riga monca scambiata per evento
            self.assertEqual(e['previous'], 'clean_reboot')

    def test_summary(self):
        day = 86400
        self.write({'type': 'boot', 'epoch': NOW - 40 * day},
                   {'type': 'unclean_shutdown', 'epoch': NOW - 40 * day},
                   {'type': 'boot', 'epoch': NOW - 10 * day},
                   {'type': 'unclean_shutdown', 'epoch': NOW - 5 * day},
                   {'type': 'boot', 'epoch': NOW - 5 * day},
                   {'type': 'boot', 'epoch': NOW - day})
        summary = self.read()['summary']
        self.assertEqual((summary['boots_30d'], summary['unclean_30d']), (3, 1))
        self.assertEqual(summary['last_unclean_epoch'], NOW - 5 * day)
        self.assertEqual(summary['total'], 6)
        self.assertIsInstance(summary['uptime_seconds'], int)
        self.assertEqual(summary['now'], NOW)

    def test_empty_file(self):
        self.write()
        data = self.read()
        self.assertTrue(data['available'])
        self.assertEqual(data['events'], [])
        self.assertIsNone(data['summary']['last_unclean_epoch'])


class PageTests(unittest.TestCase):
    def test_events_section_exists(self):
        self.assertIn('id="events"', p.DASH)
        self.assertIn('id="eventsList"', p.DASH)

    def test_event_rendering_never_uses_innerhtml(self):
        body = re.search(r'async function loadEvents\(\)\{(.*?)\n\}\n', p.DASH, re.S).group(1)
        self.assertNotIn('innerHTML', body)
        self.assertNotIn('insertAdjacentHTML', body)
        self.assertIn('textContent', body)


if __name__ == '__main__':
    unittest.main()
