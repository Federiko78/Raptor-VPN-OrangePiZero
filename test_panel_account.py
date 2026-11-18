#!/usr/bin/env python3
"""Test dell'accesso Tailscale lato pannello: lettura dello stato e risposta ripulita del programma root."""
import importlib.util
import json
import pathlib
import re
import subprocess
import sys
import unittest
from unittest.mock import patch

DIR = pathlib.Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(DIR))
spec = importlib.util.spec_from_file_location('panel_acc', DIR / 'tailscale_panel.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

URL = 'https://login.tailscale.com/a/1a2b3c4d5e6f'


def done(stdout='', code=0, stderr=''):
    return subprocess.CompletedProcess([], code, stdout=stdout, stderr=stderr)


class StatusTests(unittest.TestCase):
    def status(self, payload):
        def fake_run(args, timeout=6, input_text=None):
            if args[:2] == ['/usr/bin/tailscale', 'status']:
                return done(json.dumps(payload))
            return done('', 1)
        with patch.object(p, 'run', fake_run), patch.object(p, 'lan_details', return_value={}):
            return p.status_data()

    def test_pending_link_and_tags_are_read(self):
        data = self.status({'BackendState': 'NeedsLogin', 'AuthURL': URL,
                            'Self': {'HostName': 'raptor', 'TailscaleIPs': [], 'Tags': ['tag:cliente', 'tag:vpn-1']}})
        self.assertEqual((data['backend'], data['auth_url']), ('NeedsLogin', URL))
        self.assertEqual(data['tags'], ['tag:cliente', 'tag:vpn-1'])

    def test_foreign_links_and_bad_tags_are_dropped(self):
        for bad in ('http://login.tailscale.com/a/abcd1234', 'https://evil.example/a/abcd1234',
                    'https://login.tailscale.com.evil.example/a/abcd1234', 'javascript:alert(1)',
                    URL + '"><script>', URL + ' x', 5, None, ['x']):
            data = self.status({'BackendState': 'NeedsLogin', 'AuthURL': bad})
            self.assertEqual(data['auth_url'], '', bad)
        data = self.status({'BackendState': 'Running', 'Self': {'Tags': ['tag:ok', '<b>x</b>', 'TAG:A', 3, 'tag:' + 'a' * 70]}})
        self.assertEqual(data['tags'], ['tag:ok'])
        self.assertEqual(self.status({'BackendState': 'Running', 'Self': {'Tags': 'tag:ok'}})['tags'], [])

    def test_unreachable_tailscale(self):
        with patch.object(p, 'run', side_effect=OSError('no tailscale')), patch.object(p, 'lan_details', return_value={}):
            data = p.status_data()
        self.assertEqual((data['auth_url'], data['tags']), ('', []))


class AuthCallTests(unittest.TestCase):
    def call(self, result=None, **kwargs):
        with patch.object(p, 'run', return_value=result, **kwargs) as run:
            out = p.tailscale_auth({'action': 'login_url'})
        return out, run

    def test_request_goes_through_sudo_stdin_only(self):
        out, run = self.call(done(json.dumps({'ok': True, 'auth_url': URL})))
        self.assertEqual(out, {'ok': True, 'auth_url': URL})
        args, kwargs = run.call_args
        self.assertEqual(args[0], ['/usr/bin/sudo', '-n', p.AUTH_HELPER])
        self.assertEqual(json.loads(kwargs['input_text']), {'action': 'login_url'})

    def test_key_is_sent_on_stdin_never_in_arguments(self):
        key = 'tskey-auth-kAbCdE12CNTRL-0123456789abcdef'
        with patch.object(p, 'run', return_value=done(json.dumps({'ok': True, 'connected': True}))) as run:
            p.tailscale_auth({'action': 'login_key', 'key': key, 'tags': [], 'hostname': ''})
        args, kwargs = run.call_args
        self.assertNotIn(key, json.dumps(args))
        self.assertIn(key, kwargs['input_text'])

    def test_reply_is_whitelisted(self):
        out, _ = self.call(done(json.dumps({'ok': True, 'connected': True, 'auth_url': 'https://evil.example/a/abcd1234',
                                            'segreto': 'x', 'error': '<script>'})))
        self.assertEqual(out, {'ok': True, 'connected': True})
        out, _ = self.call(done(json.dumps({'ok': True, 'auth_url': URL, 'connected': 'si'})))
        self.assertEqual(out, {'ok': True, 'auth_url': URL})

    def test_failures_are_normalised(self):
        out, _ = self.call(done(json.dumps({'ok': False, 'error': 'x' * 900}), 1))
        self.assertFalse(out['ok'])
        self.assertEqual(len(out['error']), 300)
        out, _ = self.call(done(json.dumps({'ok': True}), 1))           # codice di uscita diverso da 0: non e' un successo
        self.assertFalse(out['ok'])
        for stdout in ('', 'non json', '[]', json.dumps({'ok': 'true'}), json.dumps({'error': 5})):
            out, _ = self.call(done(stdout, 1, 'sudo: a password is required'))
            self.assertFalse(out['ok'], stdout)
            self.assertIn('install_tailscale_panel.sh', out['error'])
            self.assertNotIn('sudo', out['error'])

    def test_timeout_and_missing_sudo(self):
        out, _ = self.call(side_effect=subprocess.TimeoutExpired('sudo', 85))
        self.assertFalse(out['ok'])
        self.assertIn('did not answer in time', out['error'])
        out, _ = self.call(side_effect=OSError('sudo non trovato'))
        self.assertFalse(out['ok'])


class PageTests(unittest.TestCase):
    def test_account_card_never_renders_server_text_as_html(self):
        js = p.DASH[p.DASH.index('function renderAccount'):p.DASH.index("for(const id of ['accModeUrl'")]
        # l'unico innerHTML ammesso e' quello della pillola di stato, con valori scappati da escapeHtml
        for line in js.splitlines():
            if 'innerHTML' in line:
                self.assertIn('escapeHtml(', line)
                self.assertNotIn('d.auth_url', line)
        self.assertNotIn('insertAdjacentHTML', p.DASH)
        self.assertNotIn('alert(', p.DASH)

    def test_client_checks_the_link_before_showing_it(self):
        self.assertIn('function safeAuthUrl', p.DASH)
        self.assertRegex(p.DASH, r"startsWith\('/a/'\)")
        self.assertIn("rel=\"noopener noreferrer\"", p.DASH[p.DASH.index('id="accLinkA"') - 80:p.DASH.index('id="accLinkA"') + 80])

    def test_key_field_is_a_password_box_without_autofill(self):
        tag = re.search(r'<input id="accKey"[^>]*>', p.DASH).group(0)
        self.assertIn('type="password"', tag)
        self.assertIn('autocomplete="off"', tag)

    def test_login_page_message_is_escaped_text_only(self):
        self.assertIn('<div class="authmsg" role="alert">Invalid password.</div>', p.login_page('login.bad_password'))
        self.assertIn('<div class="authmsg" role="alert">Password non valida.</div>', p.login_page('login.bad_password', 'it'))
        self.assertNotIn('<div class="authmsg"', p.login_page())
        self.assertNotIn('__MSG__', p.login_page())
        self.assertNotIn('__MSG__', p.login_page('x'))
        # anche un messaggio sconosciuto non puo' portare markup nella pagina
        self.assertIn('&lt;b&gt;x&lt;/b&gt;', p.login_page('<b>x</b>'))
        self.assertNotIn('<b>x</b>', p.login_page('<b>x</b>'))


if __name__ == '__main__':
    unittest.main()
