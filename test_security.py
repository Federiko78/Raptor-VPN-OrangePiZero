#!/usr/bin/env python3
"""Test di robustezza e sicurezza del server web del pannello (ramo "sicurezza").

Avviano il vero server HTTPS (Server + Handler) su 127.0.0.1 con un certificato
temporaneo. Non toccano la rete, i servizi o i file di sistema.
Richiedono il comando openssl (presente sulla Orange Pi: lo installa l'installer).
"""
import http.client
import json
import pathlib
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

DIR = pathlib.Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(DIR))
import password_policy  # noqa: E402
import tailscale_panel as p  # noqa: E402

PASSWORD = 'Correct-Horse-Battery-42'


def unverified_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


@unittest.skipUnless(shutil.which('openssl'), 'openssl non disponibile')
class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.cert, cls.key = cls.tmp + '/cert.pem', cls.tmp + '/key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', cls.key,
                        '-out', cls.cert, '-days', '1', '-subj', '/CN=test'],
                       check=True, capture_output=True)
        cls._log = patch.object(p.Handler, 'log_message', lambda *a, **k: None)
        cls._log.start()

    @classmethod
    def tearDownClass(cls):
        cls._log.stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self.auth = patch.object(p, 'AUTH_PATH', self.tmp + '/auth.json')
        self.auth.start()
        p.write_password(PASSWORD)
        with p.LOCK:
            p.SESSIONS.clear()
            p.FAILURES.clear()
        self.srv = p.Server(('127.0.0.1', 0), p.Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(self.cert, self.key)
        # Identico a main(): l'handshake non avviene in accept().
        self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True, do_handshake_on_connect=False)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.auth.stop()

    # ---------------------------------------------------------------- helpers
    def request(self, method, path, body=None, headers=None, timeout=8):
        conn = http.client.HTTPSConnection('127.0.0.1', self.port, timeout=timeout, context=unverified_context())
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, resp.getheader('Set-Cookie'), resp.read().decode('utf-8', 'replace')
        finally:
            conn.close()

    def login(self, password=PASSWORD):
        return self.request('POST', '/login', body='password=' + password,
                            headers={'Content-Type': 'application/x-www-form-urlencoded'})

    def session(self):
        status, cookie, _ = self.login()
        self.assertEqual(status, 303)
        token = cookie.split(';')[0]
        status, _, html = self.request('GET', '/', headers={'Cookie': token})
        self.assertEqual(status, 200)
        return token, re.search(r"const csrf = '([^']+)'", html).group(1)

    # ---------------------------------------------------------------- registro eventi
    def test_events_api_requires_login(self):
        status, _, body = self.request('GET', '/api/events')
        self.assertEqual(status, 401)
        self.assertNotIn('events', json.loads(body))

    def test_events_api_returns_the_log_after_login(self):
        log = pathlib.Path(self.tmp) / 'events.jsonl'
        now = int(time.time())
        log.write_text(json.dumps({'type': 'boot', 'epoch': now - 60, 'previous': 'unclean'}) + '\n')
        token, _ = self.session()
        with patch.object(p, 'EVENTS_PATH', str(log)):
            status, _, body = self.request('GET', '/api/events', headers={'Cookie': token})
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertTrue(data['available'])
        self.assertEqual(data['events'][0]['previous'], 'unclean')
        self.assertEqual(data['summary']['unclean_30d'], 0)

    def test_dashboard_contains_the_events_section(self):
        token, _ = self.session()
        status, _, html = self.request('GET', '/', headers={'Cookie': token})
        self.assertEqual(status, 200)
        self.assertIn('id="events"', html)

    # ---------------------------------------------------------------- accesso Tailscale dal pannello
    TS_PATHS = ('/api/tailscale/login', '/api/tailscale/logout', '/api/tailscale/connect')

    def post_json(self, path, payload, token, csrf, content_type='application/json'):
        headers = {'Cookie': token, 'Content-Type': content_type}
        if csrf is not None:
            headers['X-CSRF-Token'] = csrf
        return self.request('POST', path, body=json.dumps(payload), headers=headers)

    def test_tailscale_routes_require_login(self):
        for path in self.TS_PATHS:
            with patch.object(p, 'tailscale_auth') as auth:
                status, _, _ = self.request('POST', path, body='{}', headers={'Content-Type': 'application/json'})
            self.assertEqual(status, 401, path)
            auth.assert_not_called()

    def test_tailscale_routes_require_csrf_and_json(self):
        token, csrf = self.session()
        for path in self.TS_PATHS:
            with patch.object(p, 'tailscale_auth') as auth:
                self.assertEqual(self.post_json(path, {}, token, None)[0], 403, path)
                self.assertEqual(self.post_json(path, {}, token, 'sbagliato')[0], 403, path)
                self.assertEqual(self.post_json(path, {}, token, csrf, 'text/plain')[0], 415, path)
            auth.assert_not_called()

    def test_tailscale_login_forwards_only_checked_fields(self):
        token, csrf = self.session()
        key = 'tskey-auth-kAbCdE12CNTRL-0123456789abcdef'
        cases = [
            ({'mode': 'url', 'hostname': 'raptor-1'}, {'action': 'login_url', 'hostname': 'raptor-1'}),
            ({'mode': 'url'}, {'action': 'login_url', 'hostname': ''}),
            ({'mode': 'key', 'key': key, 'tags': ['tag:a'], 'hostname': 'x'},
             {'action': 'login_key', 'hostname': 'x', 'key': key, 'tags': ['tag:a']}),
            ({'mode': 'key', 'key': key}, {'action': 'login_key', 'hostname': '', 'key': key, 'tags': []}),
        ]
        for payload, expected in cases:
            with patch.object(p, 'tailscale_auth', return_value={'ok': True, 'connected': True}) as auth:
                status, _, body = self.post_json('/api/tailscale/login', payload, token, csrf)
            self.assertEqual(status, 200, payload)
            auth.assert_called_once_with(expected)
            self.assertNotIn(key, body)

    def test_tailscale_login_rejects_bad_requests_before_the_helper(self):
        token, csrf = self.session()
        bad = [[], {}, {'mode': 'rm'}, {'mode': 'url', 'key': 'tskey-auth-xxxxxxxx'}, {'mode': 'url', 'tags': ['tag:a']},
               {'mode': 'key', 'extra': 1}, {'mode': 'key', 'comando': '--ssh'}]
        for payload in bad:
            with patch.object(p, 'tailscale_auth') as auth:
                status, _, _ = self.post_json('/api/tailscale/login', payload, token, csrf)
            self.assertEqual(status, 400, payload)
            auth.assert_not_called()
        for path in ('/api/tailscale/logout', '/api/tailscale/connect'):
            with patch.object(p, 'tailscale_auth') as auth:
                self.assertEqual(self.post_json(path, {'tags': ['tag:a']}, token, csrf)[0], 400, path)
            auth.assert_not_called()

    def test_tailscale_logout_connect_and_failure(self):
        token, csrf = self.session()
        for path, action in (('/api/tailscale/logout', 'logout'), ('/api/tailscale/connect', 'connect')):
            with patch.object(p, 'tailscale_auth', return_value={'ok': True}) as auth:
                self.assertEqual(self.post_json(path, {}, token, csrf)[0], 200)
            auth.assert_called_once_with({'action': action})
        with patch.object(p, 'tailscale_auth', return_value={'ok': False, 'error': 'chiave scaduta'}):
            status, _, body = self.post_json('/api/tailscale/login', {'mode': 'url'}, token, csrf)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)['error'], 'chiave scaduta')

    def test_login_errors_are_shown_inside_the_card_and_csp_allows_only_data_images(self):
        status, _, body = self.login('sbagliata-sbagliata')
        self.assertEqual(status, 401)
        self.assertRegex(body, re.compile(r'<section class="auth">.*<div class="authmsg" role="alert">Password non valida\.</div>.*</section>', re.S))
        conn = http.client.HTTPSConnection('127.0.0.1', self.port, timeout=8, context=unverified_context())
        try:
            conn.request('GET', '/login')
            csp = conn.getresponse().getheader('Content-Security-Policy')
        finally:
            conn.close()
        self.assertIn("img-src data:", csp)
        self.assertIn("default-src 'none'", csp)
        self.assertNotIn('img-src *', csp)
        self.assertNotIn('http:', csp)

    def test_dashboard_contains_the_account_section(self):
        token, _ = self.session()
        status, _, html = self.request('GET', '/', headers={'Cookie': token})
        self.assertEqual(status, 200)
        for marker in ('id="account"', 'id="accForm"', 'id="accModeKey"', 'Raptor <b>VPN</b>'):
            self.assertIn(marker, html)

    def wait_for_free_slots(self, expected, seconds=5):
        deadline = time.time() + seconds
        while time.time() < deadline:
            free = 0
            while p.Server._slots.acquire(blocking=False):
                free += 1
            for _ in range(free):
                p.Server._slots.release()
            if free >= expected:
                return True
            time.sleep(0.05)
        return False

    # ------------------------------------------------- blocco da connessione muta
    def test_idle_tcp_connection_does_not_block_server(self):
        idle = socket.create_connection(('127.0.0.1', self.port))
        try:
            time.sleep(0.3)
            status, _, _ = self.request('GET', '/login', timeout=4)   # prima del fix: timeout
            self.assertEqual(status, 200)
        finally:
            idle.close()

    def test_idle_connection_is_dropped_after_handshake_timeout(self):
        with patch.object(p, 'HANDSHAKE_TIMEOUT', 1):
            idle = socket.create_connection(('127.0.0.1', self.port))
            idle.settimeout(5)
            started = time.time()
            try:
                data = idle.recv(1)          # il server chiude: b'' oppure reset
            except (ConnectionResetError, ssl.SSLError):
                data = b''
            idle.close()
        self.assertEqual(data, b'')
        self.assertLess(time.time() - started, 4)

    def test_connection_cap_closes_extra_connections(self):
        with patch.object(p.Server, '_slots', threading.BoundedSemaphore(2)), \
             patch.object(p, 'HANDSHAKE_TIMEOUT', 5):
            held = [socket.create_connection(('127.0.0.1', self.port)) for _ in range(2)]
            try:
                time.sleep(0.4)                          # i due slot sono occupati
                extra = socket.create_connection(('127.0.0.1', self.port))
                extra.settimeout(3)
                try:
                    data = extra.recv(1)
                except ConnectionResetError:
                    data = b''
                extra.close()
                self.assertEqual(data, b'')              # chiusa subito, senza thread
            finally:
                for sock in held:
                    sock.close()
            self.assertTrue(self.wait_for_free_slots(2), 'gli slot devono liberarsi')
            status, _, _ = self.request('GET', '/login')
            self.assertEqual(status, 200)

    # ----------------------------------------------------------------- login
    def test_login_ok_and_wrong_password(self):
        self.assertEqual(self.login()[0], 303)
        self.assertEqual(self.login('Sbagliata-Password-1')[0], 401)

    def test_password_hash_is_not_computed_while_holding_global_lock(self):
        seen = []
        original = p.verify_password

        def spy(password):
            seen.append(p.LOCK.locked())
            return original(password)
        with patch.object(p, 'verify_password', spy):
            self.assertEqual(self.login()[0], 303)
        self.assertEqual(seen, [False])

    def test_other_requests_are_served_while_a_login_hashes(self):
        token, _ = self.session()          # sessione valida, creata prima di rallentare l'hash
        started, release = threading.Event(), threading.Event()
        original = p.verify_password

        def slow(password):
            started.set()
            release.wait(5)
            return original(password)
        with patch.object(p, 'verify_password', slow):
            worker = threading.Thread(target=self.login, daemon=True)
            worker.start()
            self.assertTrue(started.wait(3))
            t0 = time.time()
            # GET / controlla la sessione e quindi prende il LOCK globale:
            # prima del fix restava bloccata finche' il login non finiva di calcolare l'hash.
            status, _, _ = self.request('GET', '/', headers={'Cookie': token}, timeout=3)
            elapsed = time.time() - t0
            release.set()
            worker.join(5)
        self.assertEqual(status, 200)
        self.assertLess(elapsed, 1.5)

    def test_login_rate_limit_per_ip(self):
        with patch.object(p, 'LOGIN_FAILURES_PER_IP', 2), patch.object(p, 'LOGIN_FAILURES_GLOBAL', 100):
            codes = [self.login('Sbagliata-Password-1')[0] for _ in range(3)]
        self.assertEqual(codes, [401, 401, 429])

    def test_login_rate_limit_global(self):
        with patch.object(p, 'LOGIN_FAILURES_PER_IP', 100), patch.object(p, 'LOGIN_FAILURES_GLOBAL', 3):
            codes = [self.login('Sbagliata-Password-1')[0] for _ in range(4)]
        self.assertEqual(codes, [401, 401, 401, 429])

    def test_purge_expired_sessions_and_failures(self):
        now = time.time()
        with p.LOCK:
            p.SESSIONS['vecchia'] = {'expires': now - 1}
            p.SESSIONS['valida'] = {'expires': now + 100}
            p.FAILURES['10.0.0.1'] = [now - p.FAILURE_WINDOW - 5]
            p.FAILURES['10.0.0.2'] = [now - 5]
            p._purge_expired(now)
            self.assertEqual(set(p.SESSIONS), {'valida'})
            self.assertEqual(set(p.FAILURES), {'10.0.0.2'})

    # --------------------------------------------------------- cambio password
    def change_password(self, token, csrf, new, old=PASSWORD):
        body = json.dumps({'current_password': old, 'new_password': new, 'confirm_password': new})
        return self.request('POST', '/api/password', body=body,
                            headers={'Cookie': token, 'X-CSRF-Token': csrf, 'Content-Type': 'application/json'})

    def test_change_password_enforces_minimum_length(self):
        token, csrf = self.session()
        status, _, text = self.change_password(token, csrf, 'Abcdefg1')
        self.assertEqual(status, 400)
        self.assertIn('12', text)

    def test_change_password_rejects_wrong_current_password(self):
        token, csrf = self.session()
        status, _, _ = self.change_password(token, csrf, 'Nuova-Password-Lunga-77', old='Sbagliata-Password-1')
        self.assertEqual(status, 403)

    def test_change_password_revokes_all_sessions(self):
        token, csrf = self.session()
        status, _, _ = self.change_password(token, csrf, 'Nuova-Password-Lunga-77')
        self.assertEqual(status, 200)
        self.assertEqual(self.request('GET', '/api/status', headers={'Cookie': token})[0], 401)
        self.assertEqual(self.login('Nuova-Password-Lunga-77')[0], 303)
        self.assertEqual(self.login(PASSWORD)[0], 401)


class PolicyTests(unittest.TestCase):
    def test_minimum_length_is_12(self):
        self.assertIsNone(password_policy.password_error('Abcdefghij12'))
        self.assertIsNotNone(password_policy.password_error('Abcdefghi12'))     # 11 caratteri
        self.assertIsNotNone(password_policy.password_error('abcdefghij12'))    # senza maiuscola
        self.assertIsNotNone(password_policy.password_error('ABCDEFGHIJ12'))    # senza minuscola
        self.assertIsNotNone(password_policy.password_error('Abcdefghijkl'))    # senza numero
        self.assertIsNotNone(password_policy.password_error('A' * 129))

    def test_description_mentions_limits(self):
        self.assertIn('12', password_policy.POLICY_DESCRIPTION)
        self.assertIn('128', password_policy.POLICY_DESCRIPTION)

    def test_generated_reset_password_satisfies_policy(self):
        with patch.object(p, 'write_password', lambda _: None):
            for _ in range(20):
                self.assertIsNone(password_policy.password_error(p.make_password()))


if __name__ == '__main__':
    unittest.main(verbosity=2)
