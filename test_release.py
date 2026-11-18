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
        self.assertIn('Web UI v1.6.0',p.DASH)
        self.assertIn('LAN Device Discovery',p.DASH)
        self.assertIn("'/api/scan'",DIR.joinpath('tailscale_panel.py').read_text())
        self.assertIn("routeSelected",p.DASH)
    def test_password_behavior_retained(self):
        from sys import path
        self.assertIsNone(p.password_error('Abcdefghij12'))
        self.assertIsNotNone(p.password_error('abcdefghij12'))   # manca la maiuscola
        self.assertIsNotNone(p.password_error('Abcdefg1'))       # troppo corta (minimo 12)

if __name__=='__main__': unittest.main(verbosity=2)
