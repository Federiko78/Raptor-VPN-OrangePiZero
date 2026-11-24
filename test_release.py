#!/usr/bin/env python3
"""Mock tests that never invoke iptables, Tailscale, arp-scan or change LAN."""
import importlib.util
import ipaddress
import json
import pathlib
import unittest
from unittest.mock import patch

DIR=pathlib.Path(__file__).parent

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,DIR/path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

r=load('routes','tailscale_panel_helper.py')
d=load('discover','tailscale_panel_discovery.py')
p=load('panel','tailscale_panel.py')

class RoutesTests(unittest.TestCase):
    def setUp(self):
        self.lan=patch.object(r,'current_lan',return_value=('end0',ipaddress.IPv4Address('192.168.1.200'),ipaddress.IPv4Network('192.168.1.0/24')))
        self.lan.start()
        self.addCleanup(self.lan.stop)
        self.payload={'mode':'selected','subnets':'192.168.1.0/24','selected_hosts':['192.168.1.10','192.168.1.20'],
                      'snat':True,'accept_routes':False,'accept_dns':True,'auto_update':True}

    def test_selected_routes(self):
        payload,_=r.validate(self.payload)
        self.assertEqual(r.active_routes(payload),'192.168.1.10/32,192.168.1.20/32')
    def test_migration_modes(self):
        for mode,route in [('off',''),('all','192.168.1.0/24'),('selected','192.168.1.10/32,192.168.1.20/32')]:
            payload,_=r.validate(dict(self.payload, mode=mode))
            self.assertEqual(r.active_routes(payload),route)
    def test_outside_lan_rejected(self):
        for ip in ('192.168.2.15','192.168.1.200','192.168.1.0','192.168.1.255','8.8.8.8','0.0.0.0'):
            with self.subTest(ip=ip):
                with self.assertRaises(ValueError): r.validate(dict(self.payload,selected_hosts=[ip]))
    def test_bad_payload_rejected(self):
        for bad in (dict(self.payload, mode='everything'), dict(self.payload,subnets='0.0.0.0/0',mode='all'),
                    dict(self.payload,snat='true'), dict(self.payload,selected_hosts=['192.168.1.10']*65),
                    dict(self.payload,selected_hosts=[]), dict(self.payload,selected_hosts=['192.168.1.999'])):
            with self.assertRaises((ValueError,TypeError)): r.validate(bad)
    def test_guard_deny_vs_allow(self):
        rules=[]
        def fake_ipt(*args, check=True):
            rules.append(args)
            class O: returncode=0
            return O()
        our_new=['-i','tailscale0','-o','end0','-j',r.CHAIN_A]
        old=['-i','tailscale0','-o','end0','-j',r.CHAIN_B]
        with patch.object(r,'fwd_rules',side_effect=[[],[our_new,old],[our_new]]), \
             patch.object(r,'ipt',side_effect=fake_ipt), \
             patch.object(r,'guard_ip6') as ipv6:
            r.apply_guard('selected',['192.168.1.10'],'end0','192.168.1.0/24')
        self.assertIn(('-A',r.CHAIN_A,'-d','192.168.1.10/32','-j','RETURN'),rules)
        self.assertIn(('-A',r.CHAIN_A,'-j','DROP'),rules)
        self.assertIn(('-I','FORWARD','1','-i','tailscale0','-o','end0','-j',r.CHAIN_A),rules)
        ipv6.assert_called_once_with('end0')
    def test_off_guard_has_no_allowlist(self):
        rules=[]
        def fake_ipt(*args,check=True):
            rules.append(args)
            class O: returncode=0
            return O()
        our_new=['-i','tailscale0','-o','end0','-j',r.CHAIN_A]
        old=['-i','tailscale0','-o','end0','-j',r.CHAIN_B]
        with patch.object(r,'fwd_rules',side_effect=[[],[our_new,old],[our_new]]), \
             patch.object(r,'ipt',side_effect=fake_ipt), patch.object(r,'guard_ip6'):
            r.apply_guard('off',[],'end0')
        self.assertNotIn('RETURN',str(rules))
        self.assertIn(('-A',r.CHAIN_A,'-j','DROP'),rules)
    def test_all_mode_limits_destination(self):
        rules=[]
        def fake_ipt(*args,check=True):
            rules.append(args)
            class O: returncode=0
            return O()
        our_new=['-i','tailscale0','-o','end0','-j',r.CHAIN_A]
        old=['-i','tailscale0','-o','end0','-j',r.CHAIN_B]
        with patch.object(r,'fwd_rules',side_effect=[[],[our_new,old],[our_new]]), \
             patch.object(r,'ipt',side_effect=fake_ipt), patch.object(r,'guard_ip6'):
            r.apply_guard('all',[],'end0','192.168.1.0/24')
        self.assertIn(('-A',r.CHAIN_A,'-d','192.168.1.0/24','-j','RETURN'),rules)
        self.assertIn(('-A',r.CHAIN_A,'-j','DROP'),rules)
    def test_missing_policy_is_off_not_imported(self):
        with patch('builtins.open',side_effect=FileNotFoundError):
            self.assertEqual(r.read_policy(), {'mode':'off','subnets':'','selected_hosts':[]})
    def test_saving_existing_non_root_policy(self):
        with patch.object(r,'read_policy',return_value={'mode':'off','subnets':'','selected_hosts':[]}):
            self.assertEqual(r.read_policy()['mode'],'off')

class DiscoveryTests(unittest.TestCase):
    def test_scanner_interface_configuration_consistent(self):
        self.assertEqual(d.INTERFACE_FILE, '/etc/tailscale-panel-lan.conf')
        self.assertEqual(r.INTERFACE_FILE, d.INTERFACE_FILE)
        self.assertIn('/etc/tailscale-panel-lan.conf', DIR.joinpath('install_tailscale_panel.sh').read_text())

    def test_output_parse_and_reverse(self):
        with patch.object(d,'discover_network',return_value=('end0',ipaddress.IPv4Address('192.168.1.200'),ipaddress.IPv4Network('192.168.1.0/24'))),\
             patch.object(d.os,'geteuid',return_value=0),\
             patch.object(d,'call') as call,\
             patch.object(d,'hostname',return_value='RAPTOR-AI'),\
             patch('builtins.print') as out:
            import io
            with patch.object(d.sys,'stdin',type('stdin',(object,),{'buffer':io.BytesIO(b'{"action":"scan"}')})()):
                call.return_value.returncode=0
                call.return_value.stdout='192.168.1.10\tAA:BB:CC:DD:EE:FF\tHikvision\n192.168.1.200\tAA:AA:AA:AA:AA:AA\tSelf\n'
                d.main()
            obj=json.loads(out.call_args.args[0])
            self.assertEqual(obj['devices'][0]['hostname'],'RAPTOR-AI')
            self.assertEqual(obj['devices'][0]['mac'],'AA:BB:CC:DD:EE:FF')
            self.assertEqual(len(obj['devices']),1)
    def test_scan_scope_large(self):
        # Private /16 still must be rejected by scanner to prevent 65k probes.
        with patch.object(d,'call') as call, patch('builtins.open', create=True) as f:
            import io
            f.return_value.__enter__.return_value=io.StringIO('end0')
            call.return_value.returncode=0
            call.return_value.stdout=json.dumps([{'addr_info':[{'family':'inet','scope':'global','local':'192.168.1.200','prefixlen':16}]}])
            with self.assertRaises(ValueError): d.discover_network()

class AppTests(unittest.TestCase):
    def test_version_and_routes_visible(self):
        page=p.dashboard_page('0'*64,'en')
        self.assertIn('Web UI v1.6.0',page)
        self.assertIn('LAN Device Discovery',page)
        self.assertIn("'/api/scan'",DIR.joinpath('tailscale_panel.py').read_text())
        self.assertIn("routeSelected",page)
    def test_password_behavior_retained(self):
        from sys import path
        self.assertIsNone(p.password_error('Abcdefghij12'))
        self.assertIsNotNone(p.password_error('abcdefghij12'))   # manca la maiuscola
        self.assertIsNotNone(p.password_error('Abcdefg1'))       # troppo corta (minimo 12)

class SystemdWaitTests(unittest.TestCase):
    """L'attesa di systemd negli installer: riprova, poi mostra il motivo vero."""
    def setUp(self):
        import tempfile
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__('shutil').rmtree(self.tmp, ignore_errors=True))
        bin_ = self.tmp / 'bin'; bin_.mkdir()
        (bin_ / 'sleep').write_text('#!/bin/sh\necho x >> "$LOG_DIR/sleeps"\n')
        (bin_ / 'timeout').write_text('#!/bin/sh\nshift\nexec "$@"\n')
        (bin_ / 'systemctl').write_text(
            '#!/bin/sh\n'
            'echo x >> "$LOG_DIR/calls"\n'
            'n=$(wc -l < "$LOG_DIR/calls")\n'
            '[ "$n" -gt "$FAKE_FAILS" ] && exit 0\n'
            'echo "$FAKE_ERROR" >&2\nexit "$FAKE_RC"\n')
        for f in bin_.iterdir(): f.chmod(0o755)
        self.bin = bin_

    def snippet(self, script):
        text = (DIR / script).read_text()
        a = text.index('# --- attesa systemd ---'); b = text.index('# --- fine attesa systemd ---')
        return text[a:b]

    def run_loop(self, script, fails, rc=1, error='Failed to connect to bus'):
        import os, subprocess
        for f in ('calls', 'sleeps'): (self.tmp / f).write_text('')
        code = 'set -eu\n' + self.snippet(script) + 'echo "ready=$systemd_ready rc=$systemd_rc err=$systemd_err"\n'
        env = dict(os.environ, PATH=str(self.bin) + ':' + os.environ['PATH'], LOG_DIR=str(self.tmp),
                   FAKE_FAILS=str(fails), FAKE_RC=str(rc), FAKE_ERROR=error)
        out = subprocess.run(['sh', '-c', code], env=env, capture_output=True, text=True)
        calls = len((self.tmp / 'calls').read_text().split())
        return out, calls

    def test_both_installers_wait_for_systemd_and_report_the_reason(self):
        for script in ('install_factory.sh', 'install_tailscale_panel.sh'):
            with self.subTest(script=script):
                text = (DIR / script).read_text()
                self.assertIn('[ "$systemd_ready" != yes ]', text)
                self.assertIn('Stato di systemd', text)
                self.assertNotIn('timeout 12 systemctl', text)
                out, calls = self.run_loop(script, fails=0)
                self.assertEqual((out.returncode, calls), (0, 1))
                self.assertIn('ready=yes', out.stdout)

    def test_a_busy_systemd_is_waited_for(self):
        for script in ('install_factory.sh', 'install_tailscale_panel.sh'):
            with self.subTest(script=script):
                out, calls = self.run_loop(script, fails=3)
                self.assertEqual(out.returncode, 0, out.stderr)
                self.assertIn('ready=yes', out.stdout)
                self.assertEqual(calls, 4)
                self.assertEqual(out.stdout.count('attendo'), 3)

    def test_a_dead_systemd_gives_up_after_six_tries_and_keeps_the_error(self):
        for script in ('install_factory.sh', 'install_tailscale_panel.sh'):
            with self.subTest(script=script):
                out, calls = self.run_loop(script, fails=99, rc=1, error='Failed to connect to bus')
                self.assertEqual(calls, 6)
                self.assertEqual(len((self.tmp / 'sleeps').read_text().split()), 5)
                self.assertIn('ready=no rc=1 err=Failed to connect to bus', out.stdout)

    def test_a_timeout_is_reported_as_no_answer(self):
        text = (DIR / 'install_factory.sh').read_text()
        self.assertIn('[ "$systemd_rc" -ne 124 ] || systemd_err=', text)
        self.assertIn('nessuna risposta entro 15 secondi', text)
        out, calls = self.run_loop('install_factory.sh', fails=99, rc=124, error='')
        self.assertIn('ready=no rc=124', out.stdout)

class PackageTests(unittest.TestCase):
    """update.sh e install_factory.sh rifiutano un pacchetto con SHA256SUMS non aggiornato: lo controlliamo qui."""
    def listed(self):
        out={}
        for line in DIR.joinpath('SHA256SUMS').read_text().splitlines():
            digest,name=line.split('  ',1)
            out[name]=digest
        return out

    def test_sha256sums_match_every_listed_file(self):
        import hashlib
        for name,digest in self.listed().items():
            self.assertEqual(hashlib.sha256(DIR.joinpath(name).read_bytes()).hexdigest(),digest,name+': rigenerare SHA256SUMS')

    def test_sha256sums_cover_the_program_files(self):
        listed=self.listed()
        for path in sorted(DIR.glob('*.py'))+sorted(DIR.glob('*.sh'))+sorted(DIR.glob('i18n/*.json')):
            self.assertIn(path.relative_to(DIR).as_posix(),listed,'manca in SHA256SUMS')

    def test_language_files_are_installed_backed_up_and_checked(self):
        panel=DIR.joinpath('install_tailscale_panel.sh').read_text()
        self.assertIn('panel_i18n.py',panel)
        self.assertIn('"$DIR"/i18n/*.json',panel)
        self.assertIn('i18n/en.json',panel)                    # senza la lingua predefinita non si installa
        factory=DIR.joinpath('install_factory.sh').read_text()
        for name in ('panel_i18n.py','i18n/en.json','i18n/it.json'):
            self.assertIn(name,factory)
        backup=DIR.joinpath('backup_panel.sh').read_text()
        for name in ('opt/tailscale-panel/panel_i18n.py','opt/tailscale-panel/i18n/en.json','opt/tailscale-panel/i18n/it.json'):
            self.assertIn(name,backup)
        self.assertIn('Lingue del pannello',DIR.joinpath('check_installation.sh').read_text())

if __name__=='__main__': unittest.main(verbosity=2)
