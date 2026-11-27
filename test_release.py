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

class FakeNat:
    """Tabella nat di iptables, quanto basta: stessi comandi e stesso comportamento di errore del programma vero."""
    def __init__(self):
        self.chains = {'PREROUTING': [], 'POSTROUTING': []}
        self.builtin = {'PREROUTING', 'POSTROUTING'}
        self.log = []
        self.ignore_insert = False

    def __call__(self, *args, check=True):
        import types
        args = list(args); self.log.append(args)
        op, chain, rest = args[0], args[1], args[2:]
        rc, out = 0, ''
        if op == '-S':
            if chain not in self.chains: rc = 1
            else:
                out = '\n'.join((['-P %s ACCEPT' % chain] if chain in self.builtin else ['-N ' + chain]) +
                                ['-A %s %s' % (chain, ' '.join(rule)) for rule in self.chains[chain]]) + '\n'
        elif op == '-N':
            if chain in self.chains: rc = 1
            else: self.chains[chain] = []
        elif op in ('-F', '-X'):
            if chain not in self.chains: rc = 1
            elif op == '-F': self.chains[chain] = []
            else: del self.chains[chain]
        elif op == '-A':
            self.chains[chain].append(rest)
        elif op == '-I':
            if not self.ignore_insert: self.chains[chain].insert(int(rest[0]) - 1, rest[1:])
        elif op == '-D':
            if rest in self.chains[chain]: self.chains[chain].remove(rest)
            else: rc = 1
        else:
            raise AssertionError('comando iptables non previsto: %s' % args)
        if rc and check: raise RuntimeError('iptables ha risposto %d' % rc)
        return types.SimpleNamespace(returncode=rc, stdout=out, stderr='')

    def rules(self, chain):
        return [' '.join(rule) for rule in self.chains.get(chain, [])]


class AliasTests(unittest.TestCase):
    HOST = '192.168.1.64'
    PAYLOAD = {'mode': 'alias', 'subnets': '', 'selected_hosts': [HOST], 'snat': True, 'accept_routes': False,
               'accept_dns': True, 'auto_update': True}

    def setUp(self):
        import tempfile, shutil
        self.lan = patch.object(r, 'current_lan', return_value=('end0', ipaddress.IPv4Address('192.168.1.200'), ipaddress.IPv4Network('192.168.1.0/24')))
        self.lan.start(); self.addCleanup(self.lan.stop)
        self.tmp = pathlib.Path(tempfile.mkdtemp()); self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.paths = [patch.object(r, 'BASE', str(self.tmp)), patch.object(r, 'LOCK', str(self.tmp / 'lock')),
                      patch.object(r, 'POLICY', str(self.tmp / 'policy.json'))]
        for x in self.paths: x.start(); self.addCleanup(x.stop)
        self.nat = FakeNat()
        patcher = patch.object(r, 'ipt_nat', self.nat); patcher.start(); self.addCleanup(patcher.stop)

    # --- validazione e rotte --------------------------------------------------------------------
    def test_alias_takes_exactly_one_lan_device_and_publishes_no_route(self):
        payload, dev = r.validate(self.PAYLOAD)
        self.assertEqual((payload['mode'], payload['selected_hosts'], dev), ('alias', [self.HOST], 'end0'))
        self.assertEqual(r.active_routes(payload), '')

    def test_alias_with_zero_two_or_foreign_devices_is_rejected(self):
        for hosts in ([], [self.HOST, '192.168.1.65'], ['192.168.2.10'], ['192.168.1.200'], ['192.168.1.255'], ['8.8.8.8'], ['x']):
            with self.subTest(hosts=hosts):
                with self.assertRaises(ValueError): r.validate(dict(self.PAYLOAD, selected_hosts=hosts))

    def test_alias_is_a_known_mode_everywhere(self):
        self.assertIn('alias', r.MODES)
        (self.tmp / 'policy.json').write_text(json.dumps({'mode': 'alias', 'subnets': '', 'selected_hosts': [self.HOST]}))
        self.assertEqual(r.read_policy()['mode'], 'alias')
        self.assertIn('"alias"', DIR.joinpath('check_installation.sh').read_text())

    def test_alias_publishes_an_empty_route_list_to_tailscale(self):
        with patch.object(r, 'run') as run:
            r.apply_tailscale(r.validate(self.PAYLOAD)[0])
        self.assertIn('--advertise-routes=', run.call_args[0][0])

    def test_guard_lets_only_the_alias_device_reach_the_lan(self):
        rules = []
        def fake_ipt(*args, check=True):
            rules.append(args)
            class O: returncode = 0
            return O()
        new, old = ['-i', 'tailscale0', '-o', 'end0', '-j', r.CHAIN_A], ['-i', 'tailscale0', '-o', 'end0', '-j', r.CHAIN_B]
        with patch.object(r, 'fwd_rules', side_effect=[[], [new, old], [new]]), patch.object(r, 'ipt', side_effect=fake_ipt), patch.object(r, 'guard_ip6'):
            r.apply_guard('alias', [self.HOST], 'end0')
        self.assertEqual([x for x in rules if 'RETURN' in x], [('-A', r.CHAIN_A, '-d', self.HOST + '/32', '-j', 'RETURN')])
        self.assertIn(('-A', r.CHAIN_A, '-j', 'DROP'), rules)

    # --- regole nat -----------------------------------------------------------------------------
    def test_alias_forwards_everything_for_the_pi_address_to_the_device_and_masquerades(self):
        r.apply_alias(self.HOST, 'end0')
        self.assertEqual(self.nat.rules(r.CHAIN_ALIAS_PRE), ['-m addrtype --dst-type LOCAL -j DNAT --to-destination ' + self.HOST])
        self.assertEqual(self.nat.rules(r.CHAIN_ALIAS_POST), ['-s 100.64.0.0/10 -d %s/32 -j MASQUERADE' % self.HOST])
        self.assertEqual(self.nat.rules('PREROUTING'), ['-i tailscale0 -j ' + r.CHAIN_ALIAS_PRE])
        self.assertEqual(self.nat.rules('POSTROUTING'), ['-o end0 -j ' + r.CHAIN_ALIAS_POST])

    def test_the_jumps_are_added_only_after_the_chains_are_filled(self):
        r.apply_alias(self.HOST, 'end0')
        ops = [(a[0], a[1]) for a in self.nat.log if a[0] in ('-A', '-I')]
        first_jump = min(n for n, (op, chain) in enumerate(ops) if op == '-I')
        self.assertEqual({chain for op, chain in ops[:first_jump]}, {r.CHAIN_ALIAS_PRE, r.CHAIN_ALIAS_POST})

    def test_applying_twice_changes_nothing(self):
        r.apply_alias(self.HOST, 'end0'); first = {k: list(v) for k, v in self.nat.chains.items()}
        r.apply_alias(self.HOST, 'end0')
        self.assertEqual(self.nat.chains, first)

    def test_changing_device_or_interface_replaces_the_old_rules(self):
        r.apply_alias(self.HOST, 'end0')
        r.apply_alias('192.168.1.70', 'eth1')
        text = str(self.nat.chains)
        self.assertNotIn(self.HOST, text); self.assertNotIn('end0', text)
        self.assertEqual(self.nat.rules('PREROUTING'), ['-i tailscale0 -j ' + r.CHAIN_ALIAS_PRE])
        self.assertEqual(self.nat.rules('POSTROUTING'), ['-o eth1 -j ' + r.CHAIN_ALIAS_POST])

    def test_other_rules_of_the_hooks_are_left_alone(self):
        self.nat.chains['PREROUTING'].append(['-j', 'ts-prerouting-ish']); self.nat.chains['POSTROUTING'].append(['-j', 'ts-postrouting'])
        r.apply_alias(self.HOST, 'end0'); r.clear_alias()
        self.assertEqual(self.nat.rules('PREROUTING'), ['-j ts-prerouting-ish'])
        self.assertEqual(self.nat.rules('POSTROUTING'), ['-j ts-postrouting'])

    def test_clear_removes_jumps_and_chains_and_is_safe_when_there_is_nothing(self):
        r.clear_alias()
        r.apply_alias(self.HOST, 'end0'); r.clear_alias()
        self.assertEqual(self.nat.chains, {'PREROUTING': [], 'POSTROUTING': []})
        r.clear_alias()

    def test_apply_nat_follows_the_mode(self):
        r.apply_nat('alias', [self.HOST], 'end0'); self.assertTrue(self.nat.rules(r.CHAIN_ALIAS_PRE))
        r.apply_nat('selected', [self.HOST], 'end0'); self.assertNotIn(r.CHAIN_ALIAS_PRE, self.nat.chains)
        r.apply_nat('alias', [self.HOST], 'end0'); r.apply_nat('off', [], 'end0'); self.assertNotIn(r.CHAIN_ALIAS_PRE, self.nat.chains)
        r.apply_nat('alias', [self.HOST], 'end0'); r.apply_nat('alias', [], 'end0'); self.assertNotIn(r.CHAIN_ALIAS_PRE, self.nat.chains)
        r.apply_nat('alias', [self.HOST, '192.168.1.65'], 'end0'); self.assertNotIn(r.CHAIN_ALIAS_PRE, self.nat.chains)

    def test_a_jump_that_cannot_be_verified_is_an_error(self):
        self.nat.ignore_insert = True
        with self.assertRaises(RuntimeError): r.apply_alias(self.HOST, 'end0')

    def test_an_invalid_address_never_reaches_iptables(self):
        for bad in ('192.168.1.64; reboot', '999.1.1.1', '', 'x'):
            with self.assertRaises(ValueError): r.apply_alias(bad, 'end0')
        self.assertEqual(self.nat.log, [])

    # --- applicazione e riavvio -----------------------------------------------------------------
    def main(self, *argv, body=None):
        import contextlib, io, sys as _sys
        class In: buffer = io.BytesIO(json.dumps(body).encode() if body is not None else b'')
        out = io.StringIO()
        with patch.object(_sys, 'argv', ['helper', *argv]), patch.object(_sys, 'stdin', In), patch.object(r.os, 'geteuid', return_value=0), \
             contextlib.redirect_stdout(out):
            r.main()
        return json.loads(out.getvalue())

    def recorder(self, fail=None):
        calls = []
        def make(name):
            def inner(*args, **kwargs):
                calls.append((name,) + tuple(a if not isinstance(a, dict) else a['mode'] for a in args[:2]))
                if fail == name and not getattr(inner, 'failed', False):
                    inner.failed = True; raise RuntimeError('guasto ' + name)
            return inner
        for name in ('apply_guard', 'apply_nat', 'apply_tailscale'):
            patcher = patch.object(r, name, side_effect=make(name)); patcher.start(); self.addCleanup(patcher.stop)
        return calls

    def test_guard_comes_first_then_nat_then_tailscale(self):
        calls = self.recorder()
        out = self.main(body=self.PAYLOAD)
        self.assertEqual([c[0] for c in calls], ['apply_guard', 'apply_nat', 'apply_tailscale'])
        self.assertEqual(calls[0][1:], ('alias', [self.HOST])); self.assertEqual(calls[1][1:], ('alias', [self.HOST]))
        self.assertEqual((out['ok'], out['mode'], out['advertised']), (True, 'alias', []))
        self.assertEqual(json.loads((self.tmp / 'policy.json').read_text())['mode'], 'alias')

    def test_a_failed_nat_step_restores_the_previous_policy_including_its_nat_state(self):
        (self.tmp / 'policy.json').write_text(json.dumps({'mode': 'selected', 'subnets': '', 'selected_hosts': ['192.168.1.65']}))
        calls = self.recorder(fail='apply_nat')
        with self.assertRaises(RuntimeError): self.main(body=self.PAYLOAD)
        self.assertEqual([c[0] for c in calls], ['apply_guard', 'apply_nat', 'apply_guard', 'apply_nat', 'apply_tailscale'])
        self.assertEqual(calls[3][1:], ('selected', ['192.168.1.65']))
        self.assertEqual(json.loads((self.tmp / 'policy.json').read_text())['mode'], 'selected')

    def restore(self, policy, nat_fails=False):
        (self.tmp / 'policy.json').write_text(json.dumps(policy))
        calls = []
        def nat(mode, hosts, dev):
            calls.append(('nat', mode, list(hosts)))
            if nat_fails: raise RuntimeError('guasto')
        def guard(mode, hosts, dev, subnets=''): calls.append(('guard', mode, list(hosts)))
        with patch.object(r, 'apply_guard', guard), patch.object(r, 'apply_nat', nat), patch.object(r, 'lan_interface', return_value='end0'), \
             patch.object(r.time, 'sleep'):
            out = self.main('--restore')
        return calls, out

    def test_boot_restores_the_alias_after_a_closed_guard(self):
        calls, out = self.restore({'mode': 'alias', 'subnets': '', 'selected_hosts': [self.HOST]})
        self.assertEqual(calls, [('guard', 'off', []), ('guard', 'alias', [self.HOST]), ('nat', 'alias', [self.HOST])])
        self.assertEqual(out['guard_mode'], 'alias')

    def test_boot_never_restores_an_alias_for_a_device_of_another_lan_or_for_several(self):
        for hosts in (['192.168.9.64'], [self.HOST, '192.168.1.65'], []):
            with self.subTest(hosts=hosts):
                calls, out = self.restore({'mode': 'alias', 'subnets': '', 'selected_hosts': hosts})
                self.assertEqual(out['guard_mode'], 'off')
                self.assertNotIn(('nat', 'alias', hosts), calls)
                self.assertEqual(calls[-1], ('nat', 'off', []))

    def test_if_the_alias_cannot_be_set_up_at_boot_everything_stays_closed(self):
        calls, out = self.restore({'mode': 'alias', 'subnets': '', 'selected_hosts': [self.HOST]}, nat_fails=True)
        self.assertEqual(calls[-1], ('guard', 'off', []))
        self.assertEqual(out['guard_mode'], 'off')

    def test_boot_in_selected_mode_is_unchanged(self):
        calls, out = self.restore({'mode': 'selected', 'subnets': '', 'selected_hosts': [self.HOST, '192.168.1.65']})
        self.assertEqual(calls, [('guard', 'off', []), ('guard', 'selected', [self.HOST, '192.168.1.65']), ('nat', 'selected', [])])

    # --- stato mostrato dal pannello ------------------------------------------------------------
    def test_the_panel_keeps_the_alias_mode_while_no_route_is_published(self):
        import subprocess
        def status(saved, advertised):
            def fake_run(args, timeout=6, input_text=None):
                if args[:2] == ['/usr/bin/tailscale', 'status']: return subprocess.CompletedProcess([], 0, stdout='{"BackendState":"Running"}', stderr='')
                return subprocess.CompletedProcess([], 1, stdout='', stderr='')
            with patch.object(p, 'run', fake_run), patch.object(p, 'lan_details', return_value={}), patch.object(p, 'saved_state', return_value=dict(p.DEFAULTS, **saved)), \
                 patch.object(p, 'pref', side_effect=lambda flag: advertised if flag == 'advertise-routes' else None):
                return p.status_data()['settings']
        alias = {'mode': 'alias', 'selected_hosts': [self.HOST]}
        self.assertEqual(status(alias, [])['mode'], 'alias')
        self.assertEqual(status(alias, [])['selected_hosts'], [self.HOST])
        self.assertEqual(status({'mode': 'alias', 'selected_hosts': []}, [])['mode'], 'off')
        self.assertEqual(status({'mode': 'alias', 'selected_hosts': [self.HOST, '192.168.1.65']}, [])['mode'], 'off')
        self.assertEqual(status({'mode': 'off', 'selected_hosts': []}, [])['mode'], 'off')
        self.assertEqual(status(alias, ['192.168.1.65/32'])['mode'], 'selected')      # rotte vere pubblicate: vincono
        self.assertEqual(status(alias, ['192.168.1.0/24'])['mode'], 'all')

    # --- iptables vero --------------------------------------------------------------------------
    def test_with_the_real_iptables_in_a_private_network_namespace(self):
        import shutil, subprocess as sp
        probe = sp.run(['unshare', '-Urn', 'iptables', '-w', '5', '-t', 'nat', '-S'], capture_output=True, text=True) if shutil.which('unshare') and shutil.which('iptables') else None
        if probe is None or probe.returncode: self.skipTest('iptables o user namespace non disponibili')
        script = r"""
import importlib.util, subprocess, sys
spec = importlib.util.spec_from_file_location('h', sys.argv[1]); h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
nat = lambda: subprocess.run(['/usr/sbin/iptables', '-t', 'nat', '-S'], capture_output=True, text=True).stdout
h.clear_alias(); assert 'TSPANEL' not in nat()
h.apply_alias('192.168.1.64', 'end0'); a = nat()
assert '-A TSPANEL_ALIAS_PRE -m addrtype --dst-type LOCAL -j DNAT --to-destination 192.168.1.64' in a, a
assert '-A TSPANEL_ALIAS_POST -s 100.64.0.0/10 -d 192.168.1.64/32 -j MASQUERADE' in a, a
assert a.count('-j TSPANEL_ALIAS_PRE') == 1 and a.count('-A PREROUTING -i tailscale0 -j TSPANEL_ALIAS_PRE') == 1, a
h.apply_alias('192.168.1.64', 'end0'); assert nat() == a
h.apply_alias('192.168.1.70', 'eth1'); b = nat()
assert '192.168.1.64' not in b and b.count('-j TSPANEL_ALIAS_POST') == 1 and '-o eth1 -j TSPANEL_ALIAS_POST' in b, b
h.apply_nat('off', [], 'end0'); assert 'TSPANEL' not in nat()
print('IPTABLES-OK')
"""
        done = sp.run(['unshare', '-Urn', 'python3', '-c', script, str(DIR / 'tailscale_panel_helper.py')], capture_output=True, text=True, timeout=120)
        self.assertIn('IPTABLES-OK', done.stdout, done.stderr + done.stdout)


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
    """systemd_wait.sh: attesa di systemd, motivo dell'errore e sblocco del deadlock noto di /dev/console."""
    LIB = DIR / 'systemd_wait.sh'

    def setUp(self):
        import tempfile, shutil
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.bin = self.tmp / 'bin'; self.bin.mkdir()
        self.proc = self.tmp / 'proc'; self.proc.mkdir()
        self.procs = []
        self.addCleanup(self.stop_procs)
        self.write_bin('sleep', 'echo x >> "$LOG_DIR/sleeps"\n')
        self.write_bin('timeout', 'shift\nexec "$@"\n')
        self.write_bin('systemctl',
            'echo x >> "$LOG_DIR/calls"\n'
            'n=$(wc -l < "$LOG_DIR/calls")\n'
            # con STUCK_PID: systemctl risponde solo quando quel processo non esiste piu'
            'if [ -n "${STUCK_PID:-}" ]; then st=$(awk \'{print $3}\' "/proc/$STUCK_PID/stat" 2>/dev/null); '
            '[ -n "$st" ] && [ "$st" != Z ] && { echo "bloccato" >&2; exit 124; }; exit 0; fi\n'
            '[ "$n" -gt "$FAKE_FAILS" ] && exit 0\n'
            'echo "$FAKE_ERROR" >&2\nexit "$FAKE_RC"\n')
        # come il vero lslocks: un processo morto (anche se zombie) non tiene piu' nessun lock
        self.write_bin('lslocks',
            'printf "%s\\n" "${FAKE_LOCKS:-}" | while read pid path; do\n'
            '  [ -n "$pid" ] || continue\n'
            '  if [ "$pid" = 1 ]; then echo "$pid $path"; continue; fi\n'
            '  st=$(awk \'{print $3}\' "/proc/$pid/stat" 2>/dev/null)\n'
            '  [ -n "$st" ] && [ "$st" != Z ] && echo "$pid $path"\n'
            'done\n')

    def write_bin(self, name, body):
        path = self.bin / name
        path.write_text('#!/bin/sh\n' + body); path.chmod(0o755)

    def stop_procs(self):
        for p in self.procs:
            if p.poll() is None: p.kill()
            p.wait()

    def spawn(self, comm, ppid='1'):
        """Un processo vero, con quel nome (comm), e il suo finto /proc."""
        import shutil, subprocess
        exe = self.tmp / comm
        if not exe.exists(): shutil.copy(shutil.which('sleep'), exe)
        p = subprocess.Popen([str(exe), '60']); self.procs.append(p)
        d = self.proc / str(p.pid); d.mkdir()
        (d / 'comm').write_text(comm + '\n'); (d / 'status').write_text('Name:\t%s\nPPid:\t%s\n' % (comm, ppid))
        return p

    def pid1(self, wchan):
        d = self.proc / '1'; d.mkdir(exist_ok=True)
        (d / 'wchan').write_text(wchan); (d / 'comm').write_text('systemd\n')

    def run_wait(self, fails=0, rc=1, error='Failed to connect to bus', locks='', stuck=None):
        import os, subprocess
        for name in ('calls', 'sleeps'): (self.tmp / name).write_text('')
        code = 'set -eu\n. "$LIB"\nwait_for_systemd || true\necho "ready=$systemd_ready rc=$systemd_rc err=$systemd_err"\n'
        env = dict(os.environ, PATH=str(self.bin) + ':' + os.environ['PATH'], LOG_DIR=str(self.tmp), LIB=str(self.LIB),
                   FAKE_FAILS=str(fails), FAKE_RC=str(rc), FAKE_ERROR=error, FAKE_LOCKS=locks, RAPTOR_PROC=str(self.proc))
        if stuck is not None: env['STUCK_PID'] = str(stuck)
        out = subprocess.run(['sh', '-c', code], env=env, capture_output=True, text=True)
        return out, len((self.tmp / 'calls').read_text().split())

    def alive(self, p):
        return p.poll() is None

    # --- attesa e motivo dell'errore -------------------------------------------------------------
    def test_both_installers_use_the_shared_wait_and_report_the_reason(self):
        for script, var in (('install_factory.sh', 'BASE'), ('install_tailscale_panel.sh', 'DIR')):
            with self.subTest(script=script):
                text = (DIR / script).read_text()
                self.assertIn('. "$%s/systemd_wait.sh"' % var, text)
                self.assertIn('wait_for_systemd || true', text)
                self.assertIn('[ "$systemd_ready" != yes ]', text)
                self.assertIn('Stato di systemd', text)
                self.assertNotIn('timeout 12 systemctl', text)
        factory = (DIR / 'install_factory.sh').read_text()
        for loop in ('for f in ', 'for script in '):      # elenco dei file richiesti e controllo di sintassi
            self.assertRegex(factory, loop + r'[^\n]*\bsystemd_wait\.sh\b')

    def test_a_ready_systemd_needs_one_call(self):
        out, calls = self.run_wait(fails=0)
        self.assertEqual((out.returncode, calls), (0, 1))
        self.assertIn('ready=yes', out.stdout)

    def test_a_busy_systemd_is_waited_for(self):
        out, calls = self.run_wait(fails=3)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn('ready=yes', out.stdout)
        self.assertEqual(calls, 4)
        self.assertEqual(out.stdout.count('attendo'), 3)

    def test_a_dead_systemd_gives_up_after_six_tries_and_keeps_the_error(self):
        out, calls = self.run_wait(fails=99, rc=1, error='Failed to connect to bus')
        self.assertEqual(calls, 6)
        self.assertEqual(len((self.tmp / 'sleeps').read_text().split()), 5)
        self.assertIn('ready=no rc=1 err=Failed to connect to bus', out.stdout)

    def test_a_timeout_is_reported_as_no_answer(self):
        text = (DIR / 'install_factory.sh').read_text()
        self.assertIn('[ "$systemd_rc" -ne 124 ] || systemd_err=', text)
        self.assertIn('nessuna risposta entro 15 secondi', text)
        out, calls = self.run_wait(fails=99, rc=124, error='')
        self.assertIn('ready=no rc=124', out.stdout)

    # --- deadlock di /dev/console ----------------------------------------------------------------
    def locks(self, *pairs):
        return '\n'.join('%s %s' % pair for pair in pairs)

    def test_the_console_deadlock_is_cleared_and_systemd_answers(self):
        usb, uart = self.spawn('(agetty)'), self.spawn('(agetty)')
        self.pid1('locks_lock_inode_wait')
        locks = self.locks((usb.pid, '/dev/console'), (uart.pid, '/dev/console'), (1, '/dev/console'))
        out, calls = self.run_wait(locks=locks, stuck=usb.pid)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn('ready=yes', out.stdout)
        self.assertEqual(calls, 2)                      # una chiamata ferma, lo sblocco, una chiamata riuscita
        self.assertNotIn('attendo', out.stdout)         # dopo lo sblocco non c'e' l'attesa lunga...
        self.assertEqual(len((self.tmp / 'sleeps').read_text().split()), 1)   # ...solo la pausa breve
        self.assertIn('terminato il processo %d' % usb.pid, out.stdout)
        self.assertIn('terminato il processo %d' % uart.pid, out.stdout)
        usb.wait(timeout=5); uart.wait(timeout=5)
        self.assertFalse(self.alive(usb) or self.alive(uart))

    def test_only_the_stuck_agetty_on_the_console_are_terminated(self):
        stuck = self.spawn('(agetty)')
        other_file = self.spawn('(agetty)')             # (agetty) che tiene un altro file
        started = self.spawn('agetty')                  # agetty gia' avviato: non e' un blocco a meta' avvio
        not_child = self.spawn('(agetty)', ppid='4242')  # non figlio di PID 1
        shell = self.spawn('bash')
        self.pid1('locks_lock_inode_wait')
        locks = self.locks((stuck.pid, '/dev/console'), (started.pid, '/dev/console'), (not_child.pid, '/dev/console'),
                           (shell.pid, '/dev/console'), (other_file.pid, '/run/crond.pid'), (1, '/dev/console'))
        out, calls = self.run_wait(locks=locks, stuck=stuck.pid)
        stuck.wait(timeout=5)
        self.assertFalse(self.alive(stuck))
        for survivor in (other_file, started, not_child, shell):
            self.assertTrue(self.alive(survivor))
        self.assertEqual(out.stdout.count('terminato il processo'), 1)

    def test_nothing_is_terminated_unless_pid1_is_waiting_for_a_lock(self):
        agetty = self.spawn('(agetty)')
        self.pid1('do_epoll_wait')                      # systemd lento, ma non fermo su un lock
        out, calls = self.run_wait(fails=99, locks=self.locks((agetty.pid, '/dev/console')))
        self.assertTrue(self.alive(agetty))
        self.assertNotIn('terminato', out.stdout)
        self.assertEqual(calls, 6)

    def test_a_missing_proc_entry_or_lslocks_does_not_break_the_wait(self):
        import os
        out, calls = self.run_wait(fails=1)             # nessun finto /proc/1
        self.assertIn('ready=yes', out.stdout)
        self.assertNotIn('terminato', out.stdout)
        agetty = self.spawn('(agetty)'); self.pid1('locks_lock_inode_wait')
        (self.bin / 'lslocks').unlink()
        out, calls = self.run_wait(fails=99, locks=self.locks((agetty.pid, '/dev/console')))
        self.assertTrue(self.alive(agetty))
        self.assertEqual(calls, 6)

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
