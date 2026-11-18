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

    def test_restart_and_power_loss_lists_for_the_counters(self):
        day = 86400
        self.write({'type': 'boot', 'epoch': NOW - 90 * day, 'previous': 'first_boot'},
                   {'type': 'boot', 'epoch': NOW - 20 * day, 'previous': 'clean_reboot'},
                   {'type': 'unclean_shutdown', 'epoch': NOW - 3 * day},
                   {'type': 'boot', 'epoch': NOW - 3 * day, 'previous': 'unclean'},
                   {'type': 'shutdown', 'epoch': NOW - day, 'kind': 'reboot'},
                   {'type': 'boot', 'epoch': NOW - day + 40, 'previous': 'clean_reboot'})
        summary = self.read()['summary']
        # il primo avvio assoluto non e' un riavvio; gli spegnimenti regolari non contano come avvii
        self.assertEqual(summary['restart_epochs'], [NOW - 20 * day, NOW - 3 * day, NOW - day + 40])
        self.assertEqual(summary['unclean_epochs'], [NOW - 3 * day])

    def test_lists_cover_the_whole_history_not_only_the_returned_events(self):
        self.write(*[{'type': 'boot', 'epoch': NOW - 10000 + i, 'previous': 'clean_reboot'} for i in range(250)])
        data = self.read()
        self.assertEqual(len(data['events']), p.EVENTS_LIMIT)
        self.assertEqual(len(data['summary']['restart_epochs']), 250)

    def test_clock_correction_moves_the_boot_and_the_power_loss_of_the_same_boot(self):
        bid, other = 'aaaaaaaa-1111', 'bbbbbbbb-2222'
        self.write({'type': 'boot', 'epoch': 1_700_000_100, 'boot_id': other, 'previous': 'clean_reboot'},
                   {'type': 'boot', 'epoch': 1_000_000_100, 'boot_id': bid, 'previous': 'unclean', 'clock_synced': False},
                   {'type': 'unclean_shutdown', 'epoch': 1_000_000_100, 'boot_id': bid, 'detected_epoch': 1_000_000_100},
                   {'type': 'clock_synced', 'epoch': 1_790_000_000, 'boot_id': bid, 'jump_seconds': 789_999_000})
        data = self.read()
        by_type = {e['type']: e for e in data['events']}
        corrected = [e for e in data['events'] if e['type'] == 'boot' and e.get('previous') == 'unclean'][0]
        self.assertEqual(corrected['epoch'], 1_000_000_100 + 789_999_000)
        self.assertEqual(by_type['unclean_shutdown']['epoch'], 1_000_000_100 + 789_999_000)
        self.assertEqual(by_type['clock_synced']['epoch'], 1_790_000_000)           # l'evento di sincronizzazione non si sposta
        self.assertIn(1_000_000_100 + 789_999_000, data['summary']['restart_epochs'])
        self.assertIn(1_700_000_100, data['summary']['restart_epochs'])             # un altro avvio resta com'e'
        self.assertEqual(data['summary']['unclean_epochs'], [1_000_000_100 + 789_999_000])

    def test_clock_correction_ignores_an_unusable_boot_id(self):
        self.write({'type': 'boot', 'epoch': NOW - 500, 'boot_id': '../../x', 'previous': 'clean_reboot'},
                   {'type': 'clock_synced', 'epoch': NOW, 'boot_id': '../../x', 'jump_seconds': 100})
        data = self.read()
        self.assertEqual([e['epoch'] for e in data['events'] if e['type'] == 'boot'], [NOW - 500])

    def test_internal_fields_never_reach_the_page(self):
        self.write({'type': 'boot', 'epoch': NOW - 5, 'boot_id': 'cccccccc-3333', 'previous': 'clean_reboot'})
        for e in self.read()['events']:
            self.assertFalse([k for k in e if k.startswith('_') or k == 'boot_id'])

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
