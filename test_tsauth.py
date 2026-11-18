#!/usr/bin/env python3
"""Test del programma root che gestisce l'accesso a Tailscale (con un finto "tailscale")."""
import io
import json
import os
import pathlib
import stat
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

DIR = pathlib.Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(DIR))
import tailscale_panel_auth as a  # noqa: E402

KEY = 'tskey-auth-kAbCdE12CNTRL-0123456789abcdefghijklmnopqrstuv'
URL = 'https://login.tailscale.com/a/1a2b3c4d5e6f'

FAKE = '''#!{python}
import json, os, stat, sys
base = {base!r}
args = sys.argv[1:]
with open(os.path.join(base, 'calls.log'), 'a') as log:
    log.write(json.dumps(args) + '\\n')
cfg = json.load(open(os.path.join(base, 'cfg.json')))
if args[:1] == ['status']:
    print(json.dumps(cfg['status']))
    sys.exit(0)
if args[:1] in (['login'], ['up']):
    for arg in args:
        if arg.startswith('--auth-key=file:'):
            path = arg.split('file:', 1)[1]
            with open(os.path.join(base, 'keyfile.json'), 'w') as dump:
                json.dump({{'path': path, 'mode': stat.S_IMODE(os.stat(path).st_mode), 'content': open(path).read()}}, dump)
    sys.stdout.write(cfg.get('login_out', ''))
    if cfg.get('after_login_status'):
        cfg['status'] = cfg['after_login_status']
        json.dump(cfg, open(os.path.join(base, 'cfg.json'), 'w'))
    sys.exit(cfg.get('login_code', 0))
if args[:1] == ['down']:
    sys.stdout.write(cfg.get('down_out', ''))
    if cfg.get('after_down_status'):
        cfg['status'] = cfg['after_down_status']
        json.dump(cfg, open(os.path.join(base, 'cfg.json'), 'w'))
    sys.exit(cfg.get('down_code', 0))
if args[:1] == ['logout']:
    sys.stdout.write(cfg.get('logout_out', ''))
    sys.exit(cfg.get('logout_code', 0))
sys.exit(9)
'''


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = pathlib.Path(tmp.name)
        (self.base / 'run').mkdir()
        self.fake = self.base / 'tailscale'
        self.fake.write_text(FAKE.format(python=sys.executable, base=str(self.base)))
        self.fake.chmod(0o755)
        self.configure(status={'BackendState': 'NeedsLogin'})
        for name, value in (('TAILSCALE', str(self.fake)), ('RUN_DIR', str(self.base / 'run')),
                            ('LOCK_PATH', str(self.base / 'lock'))):
            patcher = patch.object(a, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def configure(self, **cfg):
        (self.base / 'cfg.json').write_text(json.dumps(cfg))

    def calls(self):
        path = self.base / 'calls.log'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def login_calls(self):
        return [c for c in self.calls() if c[:1] == ['login']]

    def main(self, body, euid=0, argv=None):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()

        class Stdin:
            buffer = io.BytesIO(raw)
        out = io.StringIO()
        with patch.object(sys, 'stdin', Stdin), patch.object(sys, 'stdout', out), \
                patch.object(sys, 'argv', argv or ['x']), patch.object(os, 'geteuid', lambda: euid):
            code = a.main()
        return code, json.loads(out.getvalue())


class ValidationTests(Base):
    def test_valid_requests(self):
        self.assertEqual(a.validate({'action': 'login_url'}), ('login_url', {'hostname': ''}))
        self.assertEqual(a.validate({'action': 'login_url', 'hostname': 'raptor-cliente1'})[1]['hostname'], 'raptor-cliente1')
        self.assertEqual(a.validate({'action': 'login_key', 'key': ' ' + KEY + ' ', 'tags': ['tag:cliente', 'tag:cliente', 'tag:vpn-1']}),
                         ('login_key', {'hostname': '', 'key': KEY, 'tags': ['tag:cliente', 'tag:vpn-1']}))
        self.assertEqual(a.validate({'action': 'logout'}), ('logout', {}))
        self.assertEqual(a.validate({'action': 'down'}), ('down', {}))

    def test_rejected_requests(self):
        bad = [None, [], 'x', {}, {'action': 5}, {'action': 'rm'}, {'action': 'logout', 'x': 1}, {'action': 'down', 'x': 1},
               {'action': 'login_url', 'key': KEY}, {'action': 'login_key'},
               {'action': 'login_key', 'key': 'password123'},
               {'action': 'login_key', 'key': KEY + ' --ssh'},
               {'action': 'login_key', 'key': KEY, 'tags': 'tag:a'},
               {'action': 'login_key', 'key': KEY, 'tags': ['tag:a --ssh']},
               {'action': 'login_key', 'key': KEY, 'tags': ['cliente']},
               {'action': 'login_key', 'key': KEY, 'tags': ['tag:A']},
               {'action': 'login_key', 'key': KEY, 'tags': [1]},
               {'action': 'login_key', 'key': KEY, 'tags': ['tag:a%d' % i for i in range(6)]},
               {'action': 'login_url', 'hostname': 'a b'}, {'action': 'login_url', 'hostname': 'A'},
               {'action': 'login_url', 'hostname': '-x'}, {'action': 'login_url', 'hostname': 'x-'},
               {'action': 'login_url', 'hostname': 'x' * 64}, {'action': 'login_url', 'hostname': 'x;reboot'},
               {'action': 'login_url', 'hostname': 7}]
        for body in bad:
            with self.assertRaises(a.Refused, msg=repr(body)):
                a.validate(body)


class LoginUrlTests(Base):
    def test_returns_the_link_printed_by_tailscale(self):
        self.configure(status={'BackendState': 'NeedsLogin'}, login_code=1,
                       login_out='\nTo authenticate, visit:\n\n\t%s\n' % URL)
        code, result = self.main({'action': 'login_url', 'hostname': 'raptor-1'})
        self.assertEqual((code, result), (0, {'ok': True, 'auth_url': URL}))
        self.assertEqual(self.login_calls(), [['login', '--timeout=15s', '--hostname=raptor-1']])

    def test_falls_back_to_the_pending_link_in_status(self):
        self.configure(status={'BackendState': 'NeedsLogin', 'AuthURL': URL}, login_code=1, login_out='timeout')
        self.assertEqual(self.main({'action': 'login_url'})[1], {'ok': True, 'auth_url': URL})

    def test_foreign_links_are_ignored(self):
        self.configure(status={'BackendState': 'NeedsLogin', 'AuthURL': 'https://evil.example/a/abcd1234'}, login_code=1,
                       login_out='visit https://evil.example/a/abcd1234 and https://login.tailscale.com.evil.example/a/abcd1234')
        code, result = self.main({'action': 'login_url'})
        self.assertEqual(code, 1)
        self.assertFalse(result['ok'])
        self.assertNotIn('auth_url', result)

    def test_refused_when_already_connected(self):
        self.configure(status={'BackendState': 'Running'})
        code, result = self.main({'action': 'login_url'})
        self.assertEqual(code, 1)
        self.assertIn('already connected', result['error'])
        self.assertEqual(self.login_calls(), [])

    def test_becoming_connected_during_login(self):
        self.configure(status={'BackendState': 'NeedsLogin'}, login_code=0, login_out='Success.\n',
                       after_login_status={'BackendState': 'Running'})
        self.assertEqual(self.main({'action': 'login_url'})[1], {'ok': True, 'connected': True})

    def test_missing_binary(self):
        with patch.object(a, 'TAILSCALE', str(self.base / 'nessuno')):
            code, result = self.main({'action': 'login_url'})
        self.assertEqual(code, 1)
        self.assertFalse(result['ok'])


class LoginKeyTests(Base):
    def test_key_goes_through_a_private_temporary_file_only(self):
        self.configure(status={'BackendState': 'NeedsLogin'}, after_login_status={'BackendState': 'Running'}, login_out='ok\n')
        code, result = self.main({'action': 'login_key', 'key': KEY, 'tags': ['tag:cliente', 'tag:vpn'], 'hostname': 'raptor-2'})
        self.assertEqual((code, result), (0, {'ok': True, 'connected': True}))
        (call,) = self.login_calls()
        self.assertFalse(any(KEY in arg for arg in call), 'la chiave non deve stare negli argomenti')
        self.assertEqual(call[0:2], ['login', call[1]])
        self.assertTrue(call[1].startswith('--auth-key=file:' + str(self.base / 'run') + '/'))
        self.assertIn('--advertise-tags=tag:cliente,tag:vpn', call)
        self.assertIn('--hostname=raptor-2', call)
        dump = json.loads((self.base / 'keyfile.json').read_text())
        self.assertEqual(dump['content'].strip(), KEY)
        self.assertEqual(dump['mode'], 0o600)
        self.assertEqual(list((self.base / 'run').iterdir()), [], 'file della chiave non cancellato')

    def test_no_tags_no_flag(self):
        self.configure(status={'BackendState': 'NeedsLogin'}, after_login_status={'BackendState': 'Running'})
        self.main({'action': 'login_key', 'key': KEY})
        (call,) = self.login_calls()
        self.assertFalse(any(arg.startswith('--advertise-tags') for arg in call))
        self.assertFalse(any(arg.startswith('--hostname') for arg in call))

    def test_failure_never_leaks_the_key(self):
        self.configure(status={'BackendState': 'NeedsLogin'}, login_code=1,
                         login_out='backend error: invalid key %s (also tskey-auth-zzzzzz-other)\n\nrequested tags invalid' % KEY)
        code, result = self.main({'action': 'login_key', 'key': KEY, 'tags': ['tag:x']})
        self.assertEqual(code, 1)
        self.assertFalse(result['ok'])
        self.assertNotIn(KEY, json.dumps(result))
        self.assertNotIn('zzzzzz', json.dumps(result))
        self.assertIn('requested tags invalid', result['error'])
        self.assertLessEqual(len(result['error']), 300)
        self.assertEqual(list((self.base / 'run').iterdir()), [])

    def test_nonzero_exit_but_running_is_success(self):
        self.configure(status={'BackendState': 'NeedsLogin'}, login_code=1, after_login_status={'BackendState': 'Running'})
        self.assertEqual(self.main({'action': 'login_key', 'key': KEY})[1], {'ok': True, 'connected': True})

    def test_refused_when_already_connected(self):
        self.configure(status={'BackendState': 'Running'})
        code, result = self.main({'action': 'login_key', 'key': KEY})
        self.assertEqual(code, 1)
        self.assertEqual(self.login_calls(), [])
        self.assertEqual(list((self.base / 'run').iterdir()), [])

    def test_injection_attempts_never_reach_the_command(self):
        self.configure(status={'BackendState': 'NeedsLogin'})
        for body in ({'action': 'login_key', 'key': KEY, 'tags': ['tag:a,tag:b --ssh']},
                     {'action': 'login_key', 'key': KEY + '\n--ssh'},
                     {'action': 'login_key', 'key': KEY, 'hostname': 'x --ssh'}):
            code, result = self.main(body)
            self.assertEqual(code, 1)
            self.assertFalse(result['ok'])
        self.assertEqual(self.login_calls(), [])


class LogoutTests(Base):
    def test_logout(self):
        self.assertEqual(self.main({'action': 'logout'}), (0, {'ok': True}))
        self.assertIn(['logout'], self.calls())

    def test_logout_failure(self):
        self.configure(status={'BackendState': 'Running'}, logout_code=1, logout_out='permission denied\n')
        code, result = self.main({'action': 'logout'})
        self.assertEqual(code, 1)
        self.assertIn('permission denied', result['error'])


class DownTests(Base):
    def test_turn_off_runs_tailscale_down_and_nothing_else(self):
        self.configure(status={'BackendState': 'Running'}, after_down_status={'BackendState': 'Stopped'}, down_out='')
        self.assertEqual(self.main({'action': 'down'}), (0, {'ok': True}))
        self.assertEqual([c for c in self.calls() if c[:1] != ['status']], [['down']], 'nessuna opzione, nessun logout')

    def test_it_can_be_turned_on_again_without_a_new_login(self):
        self.configure(status={'BackendState': 'Running'}, after_down_status={'BackendState': 'Stopped'})
        self.main({'action': 'down'})
        self.configure(status={'BackendState': 'Stopped'}, after_login_status={'BackendState': 'Running'}, login_out='Success.\n')
        self.assertEqual(self.main({'action': 'connect'}), (0, {'ok': True, 'connected': True}))
        self.assertEqual([c for c in self.calls() if c[:1] == ['logout']], [])

    def test_already_stopped_is_success_even_if_the_command_complains(self):
        self.configure(status={'BackendState': 'Stopped'}, down_code=1, down_out='already stopped\n')
        self.assertEqual(self.main({'action': 'down'}), (0, {'ok': True}))

    def test_failure_is_reported_with_the_reason(self):
        self.configure(status={'BackendState': 'Running'}, down_code=1, down_out='permission denied\n')
        code, result = self.main({'action': 'down'})
        self.assertEqual(code, 1)
        self.assertEqual(result['error'], 'Unable to turn Tailscale off: permission denied')

    def test_a_board_that_is_still_running_is_an_error_even_with_exit_code_zero(self):
        self.configure(status={'BackendState': 'Running'})
        code, result = self.main({'action': 'down'})
        self.assertEqual(code, 1)
        self.assertTrue(result['error'].startswith('Unable to turn Tailscale off: '))

    def test_takes_no_extra_fields(self):
        code, _ = self.main({'action': 'down', 'tags': ['tag:x']})
        self.assertEqual(code, 1)
        self.assertEqual([c for c in self.calls() if c[:1] == ['down']], [])


class ConnectTests(Base):
    def test_reconnect_a_stopped_board_changes_no_settings(self):
        self.configure(status={'BackendState': 'Stopped'}, after_login_status={'BackendState': 'Running'}, login_out='Success.\n')
        self.assertEqual(self.main({'action': 'connect'}), (0, {'ok': True, 'connected': True}))
        (call,) = [c for c in self.calls() if c[:1] == ['up']]
        self.assertEqual(call, ['up', '--timeout=20s'], 'nessuna opzione: non deve toccare rotte o DNS')

    def test_connect_may_ask_for_a_new_login(self):
        self.configure(status={'BackendState': 'Stopped'}, login_code=1, login_out='visit %s' % URL)
        self.assertEqual(self.main({'action': 'connect'})[1], {'ok': True, 'auth_url': URL})

    def test_connect_failure(self):
        self.configure(status={'BackendState': 'Stopped'}, login_code=1, login_out='daemon not running\n')
        code, result = self.main({'action': 'connect'})
        self.assertEqual(code, 1)
        self.assertIn('daemon not running', result['error'])

    def test_already_running_is_a_no_op(self):
        self.configure(status={'BackendState': 'Running'})
        self.assertEqual(self.main({'action': 'connect'}), (0, {'ok': True, 'connected': True}))
        self.assertEqual([c for c in self.calls() if c[:1] == ['up']], [])

    def test_connect_takes_no_extra_fields(self):
        code, result = self.main({'action': 'connect', 'tags': ['tag:x']})
        self.assertEqual(code, 1)
        self.assertEqual([c for c in self.calls() if c[:1] == ['up']], [])


class MainTests(Base):
    def test_requires_root(self):
        code, result = self.main({'action': 'logout'}, euid=1000)
        self.assertEqual(code, 1)
        self.assertIn('root', result['error'])
        self.assertNotIn(['logout'], self.calls())

    def test_no_arguments_allowed(self):
        self.assertEqual(self.main({'action': 'logout'}, argv=['x', '--boh'])[0], 1)
        self.assertEqual(self.calls(), [])

    def test_bad_bodies(self):
        for raw in (b'', b'{non json', b'[]', b'null', b'x' * (a.MAX_BODY + 1), b'\xff\xfe'):
            code, result = self.main(raw)
            self.assertEqual(code, 1, raw[:20])
            self.assertFalse(result['ok'])
        self.assertEqual(self.calls(), [])

    def test_second_concurrent_login_is_refused(self):
        import fcntl
        with open(self.base / 'lock', 'a+') as held:
            fcntl.flock(held, fcntl.LOCK_SH)          # basta un lock condiviso: quello esclusivo deve comunque essere rifiutato
            code, result = self.main({'action': 'logout'})
        self.assertEqual(code, 1)
        self.assertIn('already in progress', result['error'])
        self.assertEqual(self.calls(), [])
        self.assertEqual(stat.S_IMODE(os.stat(self.base / 'lock').st_mode), 0o600)

    def test_internal_errors_do_not_leak(self):
        with patch.dict(a.ACTIONS, {'logout': lambda p: 1 / 0}):
            code, result = self.main({'action': 'logout'})
        self.assertEqual(code, 1)
        self.assertNotIn('division', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
