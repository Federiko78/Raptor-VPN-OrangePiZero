#!/usr/bin/env python3
"""Test delle lingue del pannello (i18n/*.json), dei contatori dei riavvii e del JavaScript della pagina.

Controlli statici: stesse chiavi in tutte le lingue, nessuna chiave usata e mancante, nessuna chiave inutilizzata,
stesso markup e stessi segnaposto in ogni lingua, nessun contenuto attivo nei testi.
Controllo dinamico (se c'e' node): l'intero script della pagina gira con un DOM finto, con la data fissata.
"""
import importlib.util
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

DIR = pathlib.Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(DIR))
import panel_i18n as i18n  # noqa: E402

spec = importlib.util.spec_from_file_location('panel_i18n_test', DIR / 'tailscale_panel.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

CAT = i18n.Catalog()
EN = CAT.langs['en']
NAMESPACES = ('top', 'nav', 'lang', 'stat', 'sum', 'state', 'acc', 'routes', 'info', 'lan', 'eth', 'sec', 'ev', 'count', 'unit', 'js', 'login')
# Valori che il server/registro puo' produrre e che il JavaScript traduce con una famiglia di chiavi.
PREVIOUS = ('first_boot', 'clean_reboot', 'clean_poweroff', 'clean_halt', 'clean_unknown', 'unclean', 'unknown')
KINDS = ('reboot', 'poweroff', 'halt', 'unknown')
EVENT_TYPES = ('boot', 'shutdown', 'unclean_shutdown', 'clock_synced')
BACKEND_STATES = ('Running', 'NeedsLogin', 'NeedsMachineAuth', 'Stopped', 'Starting', 'NoState', 'Unavailable', 'Unknown')
PYTHON_FILES = sorted(DIR.glob('*.py'))


def dash_js():
    return re.search(r'<script>(.*)</script>', p.DASH, re.S).group(1)


def tokens(template):
    return set(re.findall(r'(?:\[\[|\{\{)([a-z][a-z0-9_.]*)(?:\]\]|\}\})', template))


def js_key_literals():
    js = dash_js()
    found = set(re.findall(r"""['"]([a-z]+\.[A-Za-z_.]+)['"]""", js))
    bases = set(re.findall(r"plural\([^,]+,'([a-z.]+)'\)", js))
    return {k for k in found if k.split('.')[0] in NAMESPACES and not k.endswith('.') and k not in bases}


def dynamic_prefixes():
    js = dash_js()
    prefixes = set(re.findall(r"(?:T|has)\('([a-z.]+\.)'\+", js))
    prefixes |= {m + '_' for m in re.findall(r"plural\([^,]+,'([a-z.]+)'\)", js)}
    return prefixes


class CatalogTests(unittest.TestCase):
    def test_languages_load_without_problems(self):
        self.assertEqual(CAT.problems, [])
        self.assertEqual(CAT.codes()[0], 'en')
        self.assertIn('it', CAT.codes())

    def test_same_keys_in_every_language_and_no_empty_text(self):
        for code in CAT.codes():
            ui = CAT.langs[code]['ui']
            self.assertEqual(sorted(set(EN['ui']) - set(ui)), [], code + ': missing')
            self.assertEqual(sorted(set(ui) - set(EN['ui'])), [], code + ': extra')
            for key, value in ui.items():
                self.assertTrue(value.strip(), '%s/%s empty' % (code, key))

    def test_every_template_key_exists(self):
        for name, template in (('DASH', p.DASH), ('LOGIN', p.LOGIN)):
            for key in tokens(template):
                self.assertIn(key, EN['ui'], '%s uses an unknown key %s' % (name, key))
        for code in CAT.codes():                                   # rendering "strict": any missing key raises
            CAT.render(p.DASH, code, strict=True)
            CAT.render(p.LOGIN, code, strict=True)

    def test_every_key_used_by_the_javascript_exists(self):
        for key in js_key_literals():
            self.assertIn(key, EN['ui'], 'the JavaScript uses an unknown key ' + key)
        prefixes = dynamic_prefixes()
        self.assertEqual(prefixes, {'ev.prev.', 'ev.kind.', 'ev.type.', 'state.', 'count.time_'})
        wanted = ([('ev.prev.', v) for v in PREVIOUS] + [('ev.kind.', v) for v in KINDS] + [('ev.type.', v) for v in EVENT_TYPES] +
                  [('state.', v) for v in BACKEND_STATES] + [('count.time_', 'one'), ('count.time_', 'other')])
        for prefix, value in wanted:
            self.assertIn(prefix + value, EN['ui'])

    def test_no_unused_keys(self):
        used = tokens(p.DASH) | tokens(p.LOGIN) | js_key_literals()
        panel_source = (DIR / 'tailscale_panel.py').read_text(encoding='utf-8')
        used |= set(re.findall(r"""['"](login\.[a-z_]+)['"]""", panel_source))
        prefixes = dynamic_prefixes()
        unused = sorted(k for k in EN['ui'] if k not in used and not any(k.startswith(x) for x in prefixes))
        self.assertEqual(unused, [])

    def test_event_values_known_by_the_logger_have_texts(self):
        source = (DIR / 'raptor_eventlog.py').read_text(encoding='utf-8')
        for value in ('first_boot', 'unknown', "'clean_' + ") + EVENT_TYPES:
            self.assertIn(value, source, value + ' is not produced by the logger any more')
        for kind in KINDS[:-1]:
            self.assertIn(kind, source)
        self.assertEqual({'clean_' + k for k in KINDS}, {v for v in PREVIOUS if v.startswith('clean_')})

    def test_texts_keep_the_same_markup_and_placeholders_in_every_language(self):
        tag = re.compile(r'<[^>]+>')
        holder = re.compile(r'\{[A-Za-z_]+\}')
        for code in CAT.codes():
            for key, value in CAT.langs[code]['ui'].items():
                self.assertEqual(sorted(tag.findall(value)), sorted(tag.findall(EN['ui'][key])), '%s/%s markup' % (code, key))
                self.assertEqual(sorted(holder.findall(value)), sorted(holder.findall(EN['ui'][key])), '%s/%s placeholders' % (code, key))

    def test_texts_hold_no_active_content(self):
        for code in CAT.codes():
            for key, value in CAT.langs[code]['ui'].items():
                low = value.lower()
                self.assertNotRegex(low, r'<\s*(script|style|iframe|img|svg|object|embed|form|input)', key)
                self.assertNotRegex(low, r'\son[a-z]+\s*=', key)
                self.assertNotIn('javascript:', low, key)
                for tag in re.findall(r'<([a-z]+)', low):
                    self.assertIn(tag, ('strong', 'b', 'a'), '%s/%s uses <%s>' % (code, key, tag))
                for href in re.findall(r'href="([^"]*)"', value):
                    self.assertTrue(href.startswith('https://login.tailscale.com/'), '%s/%s links to %s' % (code, key, href))

    def test_attribute_tokens_are_escaped_and_raw_ones_are_not(self):
        tiny = {'_meta': {'name': 'T'}, 'ui': {'a.b': 'Tom & "Jerry" <b>x</b>'}, 'server': {}}
        with tempfile.TemporaryDirectory() as folder:
            pathlib.Path(folder, 'en.json').write_text(json.dumps(tiny), encoding='utf-8')
            cat = i18n.Catalog(folder)
        self.assertEqual(cat.render('<i title="{{a.b}}">[[a.b]]</i>', 'en'),
                         '<i title="Tom &amp; &quot;Jerry&quot; &lt;b&gt;x&lt;/b&gt;">Tom & "Jerry" <b>x</b></i>')

    def test_missing_key_falls_back_to_english_then_to_the_key(self):
        with tempfile.TemporaryDirectory() as folder:
            pathlib.Path(folder, 'en.json').write_text(json.dumps({'ui': {'a.one': 'One', 'a.two': 'Two'}}), encoding='utf-8')
            pathlib.Path(folder, 'xx.json').write_text(json.dumps({'ui': {'a.one': 'Uno'}}), encoding='utf-8')
            cat = i18n.Catalog(folder)
        self.assertEqual((cat.text('xx', 'a.one'), cat.text('xx', 'a.two'), cat.text('xx', 'a.zzz')), ('Uno', 'Two', 'a.zzz'))
        self.assertEqual(cat.text('zz', 'a.one'), 'One')
        with self.assertRaises(i18n.MissingKey):
            cat.text('xx', 'a.zzz', strict=True)

    def test_damaged_language_files_are_skipped(self):
        with tempfile.TemporaryDirectory() as folder:
            base = pathlib.Path(folder)
            (base / 'en.json').write_text(json.dumps({'ui': {'a': 'A'}}), encoding='utf-8')
            (base / 'bad.json').write_text('{not json', encoding='utf-8')
            (base / 'xx.json').write_text(json.dumps({'ui': {'a': 'X', 'n': 5, 'l': ['x']}, 'server': 'x'}), encoding='utf-8')
            (base / 'Bad-Name.json').write_text('{}', encoding='utf-8')
            cat = i18n.Catalog(folder)
        self.assertEqual(cat.codes(), ['en', 'xx'])
        self.assertEqual(cat.langs['xx']['ui'], {'a': 'X'})          # solo coppie testo -> testo
        self.assertEqual(len(cat.problems), 1)
        self.assertEqual(i18n.Catalog('/nonexistent/folder').codes(), [])

    def test_client_data_is_safe_inside_a_script_and_complete(self):
        text = CAT.client('it')
        for ch in '<>&':
            self.assertNotIn(ch, text)
        data = json.loads(text)
        self.assertEqual(data['lang'], 'it')
        self.assertEqual(set(data['ui']), set(EN['ui']))
        self.assertEqual(data['ui']['nav.events'], 'Eventi')
        self.assertEqual(data['locale'], 'it-IT')
        self.assertEqual(json.loads(CAT.client('en'))['server'], {})
        self.assertEqual(json.loads(CAT.client('<script>'))['lang'], 'en')

    def test_switcher_marks_the_current_language(self):
        html = CAT.switcher('it')
        self.assertIn('href="/lang?set=en"', html)
        self.assertRegex(html, r'class="lang on"[^>]*aria-current="true">IT<')
        self.assertNotIn('aria-current', CAT.switcher('en').split('IT')[0].split('>EN<')[1] if '>EN<' in CAT.switcher('en') else '')


class ServerMessageTests(unittest.TestCase):
    TABLE = CAT.langs['it']['server']

    def test_every_translated_message_exists_in_the_source(self):
        sources = '\n'.join(f.read_text(encoding='utf-8') for f in PYTHON_FILES if not f.name.startswith('test_'))
        for key in self.TABLE:
            pieces = [x for x in re.split(r'%[sd]', key) if x.strip()]
            self.assertTrue(pieces, key)
            fragment = max(pieces, key=len).strip()
            if fragment not in sources:                      # message built from two literals: 'Prefix: ' + 'detail.'
                halves = [x for x in re.split(r'(?<=: )', key) if x.strip()]
                self.assertTrue(len(halves) > 1 and all(h.strip() in sources for h in halves),
                                'translation for a message that no longer exists: ' + key)

    def test_placeholders_match(self):
        for key, value in self.TABLE.items():
            self.assertEqual(sorted(re.findall(r'%[sd]', key)), sorted(re.findall(r'%[sd]', value)), key)

    def test_translation_rules(self):
        t = CAT.translate_server
        self.assertEqual(t('it', 'Invalid JSON'), 'JSON non valido')
        self.assertEqual(t('it', 'Invalid subnet: 10.0.0.0/33 (example 192.168.1.0/24)'), 'Subnet non valida: 10.0.0.0/33 (esempio 192.168.1.0/24)')
        self.assertEqual(t('it', 'The password must contain from 12 to 128 characters.'), 'La password deve contenere da 12 a 128 caratteri.')
        self.assertEqual(t('it', 'Netplan generate failed: boom'), 'Netplan generate fallito: boom')
        self.assertEqual(t('it', 'Key login failed: no answer from Tailscale.'), 'Accesso con chiave non riuscito: nessuna risposta da Tailscale.')
        self.assertEqual(t('it', 'Key login failed: invalid key'), 'Accesso con chiave non riuscito: invalid key')
        self.assertEqual(t('it', 'Something we never wrote'), 'Something we never wrote')
        self.assertEqual(t('en', 'Invalid JSON'), 'Invalid JSON')
        self.assertIsNone(t('it', None))


# ------------------------------------------------------------------------------------------------ JavaScript
HARNESS = r"""
const fs=require('fs'),vm=require('vm');
const page=fs.readFileSync(process.argv[2],'utf8'),cfg=JSON.parse(fs.readFileSync(process.argv[3],'utf8'));
const code=/<script>([\s\S]*)<\/script>/.exec(page)[1];
const ids=new Set([...page.matchAll(/\bid="([A-Za-z0-9_]+)"/g)].map(m=>m[1]));
const make=id=>{let t='',h='';const o={id,hidden:false,className:'',value:'',checked:false,disabled:false,style:{},children:[],handlers:{},href:'',selectionStart:0,
 classList:{toggle(){},add(){},remove(){}},append(...a){this.children.push(...a)},replaceChildren(...a){this.children=a},
 addEventListener(t,f){this.handlers[t]=f},setSelectionRange(){}};
 Object.defineProperty(o,'textContent',{get:()=>t,set:v=>{t=String(v)},enumerable:true});
 Object.defineProperty(o,'innerHTML',{get:()=>h,set:v=>{h=String(v)},enumerable:true});return o;};
const els={};const E=id=>els[id]||(els[id]=make(id));
const document={hidden:false,getElementById(id){if(!ids.has(id))throw new Error('the page has no element with id '+id);return els[id]||(els[id]=make(id));},createElement:t=>make('<'+t+'>')};
const RealDate=Date;
class FakeDate extends RealDate{constructor(...a){if(a.length===0)super(cfg.now*1000);else super(...a);}static now(){return cfg.now*1000;}}
const calls=[],bodies={};
const fetch=async(url,opts)=>{calls.push(url);if(opts&&opts.body)bodies[url]=JSON.parse(opts.body);const r=cfg.responses[url];if(r===undefined)throw new Error('unexpected fetch '+url);
 return {ok:r.ok!==false,json:async()=>r.body};};
const ctx={document,fetch,Date:FakeDate,window:{confirm:()=>true,location:{replace(){}}},navigator:{},setInterval(){},setTimeout:setTimeout,console,Error,Promise,URL,JSON,Math,Set,Array,Object,String,Number,RegExp,Boolean,Intl,isNaN};
vm.createContext(ctx);
const errors=[];process.on('unhandledRejection',e=>errors.push(String(e)));
(async()=>{
 vm.runInContext(code,ctx);
 await new Promise(r=>setTimeout(r,80));
 const txt=i=>E(i).textContent;
 const out={errors,calls};
 out.stats=['stToday','stWeek','stMonth','stYear'].map(txt);
 out.statsPl=['stTodayPl','stWeekPl','stMonthPl','stYearPl'].map(txt);
 out.bar=E('evBar').children.map(c=>({cls:c.className,parts:c.children.map(x=>x.textContent)}));
 out.updated=txt('statsUpdated');out.summary=txt('eventsSummary');out.eventsMsg=txt('eventsMsg');
 out.rows=E('eventsList').children.map(r=>r.className+'|'+r.children[0].children.map(x=>x.textContent).join(' / '));
 out.backend=E('backend').innerHTML;out.account=E('accConnectedText').innerHTML;out.connectedHidden=E('accConnected').hidden;out.message=txt('message');
 out.dhcp=txt('dhcp');out.forwarding=txt('forwarding');out.detected=txt('detected');
 for(const [id,value] of Object.entries(cfg.typing||{})){const e=E(id);e.value=value;e.handlers.input();(out.typed=out.typed||{})[id]=e.value;}
 if(cfg.submit){for(const [id,v] of Object.entries(cfg.submit.fields)){E(id).value=v;}
  if(cfg.submit.key)E('accModeKey').checked=true;
  await E('accForm').handlers.submit({preventDefault(){}});await new Promise(r=>setTimeout(r,40));out.sent=bodies['/api/tailscale/login'];out.accMsg=txt('accMsg');}
 if(cfg.messages)out.translated=cfg.messages.map(m=>vm.runInContext('S('+JSON.stringify(m)+')',ctx));
 out.pending=await Promise.resolve(0);
 console.log(JSON.stringify(out));
})().catch(e=>{console.log(JSON.stringify({fatal:String(e&&e.stack||e)}));});
"""

NODE = shutil.which('node')
EPOCH = {}


def stamp(text):
    """'2026-11-18 09:30' (fuso orario dell'Italia, +01:00 in questo periodo) -> epoch."""
    import datetime
    return int(datetime.datetime.strptime(text, '%Y-%m-%d %H:%M:%S').replace(tzinfo=datetime.timezone(datetime.timedelta(hours=1))).timestamp())


RESTARTS = ['2026-11-18 00:00:00', '2026-11-18 09:30:00', '2026-11-17 23:59:59', '2026-11-16 00:00:00', '2026-11-15 23:59:59',
            '2026-11-01 00:00:00', '2026-10-31 23:59:59', '2026-01-01 00:00:00', '2025-12-31 23:59:59']
UNCLEAN = ['2026-11-18 09:30:00', '2026-11-15 23:59:59', '2025-12-31 23:59:59']


def events_body():
    boots = sorted(stamp(x) for x in RESTARTS)
    return {'available': True,
            'events': [{'type': 'unclean_shutdown', 'epoch': stamp('2026-11-18 09:30:00'), 'last_seen_epoch': stamp('2026-11-18 09:28:00')},
                       {'type': 'boot', 'epoch': stamp('2026-11-18 09:30:00'), 'previous': 'unclean', 'clock_synced': False},
                       {'type': 'shutdown', 'epoch': stamp('2026-11-18 00:00:00'), 'kind': 'reboot'},
                       {'type': 'clock_synced', 'epoch': stamp('2026-11-18 09:31:00'), 'jump_seconds': 42}],
            'summary': {'now': stamp('2026-11-18 12:00:00'), 'uptime_seconds': 93784, 'boot_epoch': stamp('2026-11-17 09:57:36'),
                        'boots_30d': 6, 'unclean_30d': 2, 'last_unclean_epoch': stamp('2026-11-18 09:30:00'),
                        'restart_epochs': boots, 'unclean_epochs': sorted(stamp(x) for x in UNCLEAN), 'total': 40}}


def status_body(**extra):
    body = {'backend': 'Running', 'tailscale_ip': '100.64.0.7', 'hostname': 'raptor-cliente', 'tailnet': 'example.ts.net', 'tags': ['tag:cliente'],
            'lan': {'ip': '192.168.1.50', 'device': 'end0', 'subnet': '192.168.1.0/24', 'gateway': '192.168.1.1', 'dhcp': 'Active', 'web_name': 'orangepizero.local'},
            'settings': {'mode': 'off', 'subnets': '', 'selected_hosts': [], 'snat': True, 'accept_routes': False, 'accept_dns': False, 'auto_update': False},
            'forwarding': True, 'version': '1.99.0', 'network': {'supported': True, 'mode': 'dhcp'}}
    body.update(extra)
    return body


@unittest.skipUnless(NODE, 'node not installed')
class JavaScriptRuntimeTests(unittest.TestCase):
    def run_page(self, lang='en', status=None, events=None, typing=None, messages=None, submit=None, extra=None):
        cfg = {'now': stamp('2026-11-18 12:00:00'), 'typing': typing, 'messages': messages, 'submit': submit,
               'responses': {'/api/status': {'body': status or status_body()}, '/api/events': {'body': events or events_body()}}}
        cfg['responses'].update(extra or {})
        with tempfile.TemporaryDirectory() as folder:
            base = pathlib.Path(folder)
            (base / 'page.html').write_text(p.dashboard_page('0' * 64, lang), encoding='utf-8')
            (base / 'cfg.json').write_text(json.dumps(cfg), encoding='utf-8')
            (base / 'run.js').write_text(HARNESS, encoding='utf-8')
            env = {'TZ': 'Europe/Rome', 'PATH': '/usr/bin:/bin:/usr/local/bin'}
            done = subprocess.run([NODE, str(base / 'run.js'), str(base / 'page.html'), str(base / 'cfg.json')],
                                  capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual(done.returncode, 0, done.stderr)
        out = json.loads(done.stdout.strip().splitlines()[-1])
        self.assertNotIn('fatal', out, out.get('fatal'))
        self.assertEqual(out['errors'], [])
        return out

    def test_counters_use_calendar_periods_and_include_the_boundaries(self):
        out = self.run_page()
        self.assertEqual(out['stats'], ['2', '4', '6', '8'])      # oggi / settimana (da lunedi') / mese / anno
        self.assertEqual(out['statsPl'], ['of which power loss: 1', 'of which power loss: 1', 'of which power loss: 2', 'of which power loss: 2'])
        self.assertEqual([c['parts'] for c in out['bar']],
                         [['Today', 'restarted 2 times', 'power loss: 1'], ['This week', 'restarted 4 times', 'power loss: 1'],
                          ['This month', 'restarted 6 times', 'power loss: 2'], ['This year', 'restarted 8 times', 'power loss: 2']])
        self.assertEqual(out['updated'], 'Updated at 12:00')

    def test_counters_in_italian(self):
        out = self.run_page('it')
        self.assertEqual([c['parts'][:2] for c in out['bar']],
                         [['Oggi', 'riavviato 2 volte'], ['Questa settimana', 'riavviato 4 volte'], ['Questo mese', 'riavviato 6 volte'], ['Quest’anno', 'riavviato 8 volte']])
        self.assertEqual(out['statsPl'][0], 'di cui mancanza di corrente: 1')
        self.assertEqual(out['updated'], 'Aggiornato alle 12:00')

    def test_singular_zero_and_no_power_loss(self):
        body = events_body()
        body['summary']['restart_epochs'] = [stamp('2026-11-18 08:00:00'), stamp('2026-01-02 08:00:00')]
        body['summary']['unclean_epochs'] = []
        out = self.run_page(events=body)
        self.assertEqual(out['stats'], ['1', '1', '1', '2'])
        self.assertEqual([c['parts'][1] for c in out['bar']], ['restarted 1 time', 'restarted 1 time', 'restarted 1 time', 'restarted 2 times'])
        self.assertEqual(out['statsPl'], ['No power loss'] * 4)
        self.assertTrue(all(len(c['parts']) == 2 and 'hot' not in c['cls'] for c in out['bar']))
        body['summary']['restart_epochs'] = []
        out = self.run_page(events=body)
        self.assertEqual(out['stats'], ['0', '0', '0', '0'])
        self.assertEqual([c['parts'][1] for c in out['bar']], ['no restarts'] * 4)

    def test_power_loss_chip_is_highlighted(self):
        out = self.run_page()
        self.assertIn('hot', out['bar'][0]['cls'])

    def test_unavailable_log(self):
        out = self.run_page(events={'available': False, 'reason': 'Event log not active on this board yet (install raptor-eventlog).'})
        self.assertEqual(out['stats'], ['-'] * 4)
        self.assertEqual(out['bar'], [])
        self.assertEqual(out['updated'], 'Event log not available')
        out = self.run_page('it', events={'available': False, 'reason': 'Event log not readable.'})
        self.assertEqual(out['summary'], 'Registro eventi non leggibile.')
        self.assertEqual(out['updated'], 'Registro eventi non disponibile')

    def test_event_rows_and_summary(self):
        out = self.run_page()
        self.assertTrue(out['rows'][0].startswith('device alertrow|Unclean shutdown (power loss or freeze) / '))
        self.assertIn('last sign of life: ', out['rows'][0])
        self.assertIn('after an unclean shutdown · time not yet synchronised', out['rows'][1])
        self.assertTrue(out['rows'][2].endswith('restart'))
        self.assertTrue(out['rows'][3].endswith('clock correction: 42 s'))
        self.assertTrue(out['summary'].startswith('Running for 1 d 2 h 3 min (since '))
        it = self.run_page('it')
        self.assertTrue(it['summary'].startswith('In funzione da 1 g 2 h 3 min (avvio: '))
        self.assertIn('dopo uno spegnimento anomalo · orario non ancora sincronizzato', it['rows'][1])
        self.assertTrue(it['rows'][2].endswith('riavvio'))

    def test_account_and_status_texts(self):
        out = self.run_page()
        self.assertEqual(out['backend'], '<span class="dot good"></span>Connected')
        self.assertEqual(out['account'], 'The board is connected to the Tailscale network <strong>example.ts.net</strong> as <strong>raptor-cliente</strong>.')
        self.assertEqual((out['dhcp'], out['forwarding'], out['detected']), ('Active', 'Active', '192.168.1.0/24'))
        it = self.run_page('it')
        self.assertEqual(it['backend'], '<span class="dot good"></span>Collegato')
        self.assertIn('con il nome <strong>raptor-cliente</strong>', it['account'])
        self.assertEqual((it['dhcp'], it['forwarding']), ('Attivo', 'Attivo'))

    def test_account_names_from_the_network_are_escaped(self):
        out = self.run_page(status=status_body(tailnet='<img src=x onerror=alert(1)>', hostname='a"b'))
        self.assertNotIn('<img', out['account'])
        self.assertIn('&lt;img', out['account'])
        self.assertIn('a&quot;b', out['account'])

    def test_down_and_server_error_texts(self):
        down = status_body(backend='Unavailable', error='Tailscale did not answer in time: check the status and try again.')
        out = self.run_page('it', status=down)
        self.assertEqual(out['backend'], '<span class="dot bad"></span>Non disponibile')
        self.assertEqual(out['message'], 'Tailscale non ha risposto in tempo: controlla lo stato e riprova.')
        out = self.run_page('en', status=down)
        self.assertEqual(out['message'], 'Tailscale did not answer in time: check the status and try again.')

    def test_board_name_and_tags_cannot_hold_capital_letters(self):
        out = self.run_page(typing={'accName': 'Raptor_Cliente 2', 'accTagsIn': 'TAG:Cliente, Tag:B'})
        self.assertEqual(out['typed']['accName'], 'raptor-cliente-2')
        self.assertEqual(out['typed']['accTagsIn'], 'tag:cliente, tag:b')

    def test_the_form_lowercases_again_when_no_typing_event_fired(self):
        # Riempimento automatico del browser: nessun evento "input", ma cio' che parte verso il server e' comunque minuscolo.
        fields = {'accName': ' -RAPTOR-Cliente- ', 'accTagsIn': 'TAG:Cliente, Tag:B', 'accKey': 'tskey-auth-AbCdEf-xyz'}
        reply = {'/api/tailscale/login': {'body': {'ok': True, 'connected': True}}}
        out = self.run_page(submit={'fields': fields, 'key': True}, extra=reply)
        self.assertEqual(out['sent']['hostname'], 'raptor-cliente')
        self.assertEqual(out['sent']['tags'], ['tag:cliente', 'tag:b'])
        self.assertEqual(out['sent']['key'], 'tskey-auth-AbCdEf-xyz')        # la chiave NON si tocca
        self.assertEqual(out['sent']['mode'], 'key')
        self.assertEqual(out['accMsg'], 'Board connected to Tailscale.')

    def test_login_error_from_the_server_is_translated(self):
        reply = {'/api/tailscale/login': {'ok': False, 'body': {'ok': False, 'error': 'Invalid key: it must start with tskey-auth- (or tskey-client-).'}}}
        out = self.run_page('it', submit={'fields': {'accName': 'x', 'accKey': 'tskey-auth-abcdef'}, 'key': True}, extra=reply)
        self.assertEqual(out['accMsg'], 'Chiave non valida: deve iniziare con tskey-auth- (o tskey-client-).')

    def test_the_key_field_is_left_untouched(self):
        self.assertNotIn("'accKey'", re.search(r"for\(const id of \['accName','accTagsIn'\]\)", dash_js()).group(0))

    def test_javascript_translation_matches_the_python_one(self):
        messages = []
        for key in CAT.langs['it']['server']:
            messages.append(key.replace('%s', 'abc').replace('%d', '12'))
            if key.endswith((': ', '. ')):
                messages.append(key + 'some detail from the system')
        messages += ['Something we never wrote', 'Invalid JSON', '', 'Request too large']
        out = self.run_page('it', messages=messages)
        self.assertEqual(out['translated'], [CAT.translate_server('it', m) for m in messages])
        out = self.run_page('en', messages=messages)
        self.assertEqual(out['translated'], messages)


class StaticPageTests(unittest.TestCase):
    def test_every_element_the_script_looks_up_exists(self):
        ids = set(re.findall(r'\bid="([A-Za-z0-9_]+)"', p.DASH))
        wanted = set(re.findall(r"\$\('([A-Za-z0-9_]+)'\)", dash_js())) | set(re.findall(r"'((?:acc|st|ev)[A-Za-z]*)'", dash_js()))
        looked = {i for i in wanted if re.fullmatch(r'[A-Za-z0-9_]+', i)}
        missing = sorted(i for i in set(re.findall(r"\$\('([A-Za-z0-9_]+)'\)", dash_js())) if i not in ids)
        self.assertEqual(missing, [])
        self.assertTrue(looked)

    def test_events_is_the_last_tab(self):
        tabs = re.findall(r'<a class="tab" href="#([A-Za-z]+)">', p.DASH)
        self.assertEqual(tabs[-1], 'events')
        self.assertEqual(tabs, ['account', 'routes', 'lanDiscovery', 'ethernet', 'security', 'events'])

    def test_sections_follow_the_tab_order(self):
        order = [p.DASH.index('id="%s"' % i) for i in ('account', 'routes', 'lanDiscovery', 'ethernet', 'security', 'events')]
        self.assertEqual(order, sorted(order))

    def test_statistics_strip_sits_at_the_top(self):
        self.assertLess(p.DASH.index('id="stats"'), p.DASH.index('id="account"'))
        for i in ('stToday', 'stWeek', 'stMonth', 'stYear', 'statsUpdated', 'statsRefresh', 'evBar'):
            self.assertIn('id="%s"' % i, p.DASH)

    def test_name_and_tag_fields_ask_for_lowercase(self):
        for field in ('accName', 'accTagsIn'):
            tag = re.search(r'<input id="%s"[^>]*>' % field, p.DASH).group(0)
            self.assertIn('autocapitalize="none"', tag)

    def test_no_italian_left_in_the_templates_and_the_script(self):
        # La pagina e' tutta in inglese: l'italiano vive solo in i18n/it.json.
        words = r'\b(Salva|Scansiona|Aggiorna|Sezioni|Rotte|Dispositivi|Sicurezza|Eventi|Collega|Scollega|Annulla|Caricamento|Esci|Accedi)\b'
        self.assertEqual(re.findall(words, p.DASH + p.LOGIN), [])
        self.assertEqual([m for m in re.findall(r'[àèéìòù]', p.DASH + p.LOGIN)], [])

    def test_python_messages_are_english(self):
        for name in ('tailscale_panel.py', 'tailscale_panel_helper.py', 'tailscale_panel_network.py', 'tailscale_panel_discovery.py',
                     'tailscale_panel_auth.py', 'password_policy.py'):
            import ast
            tree = ast.parse((DIR / name).read_text(encoding='utf-8'))
            docs = set()
            for node in ast.walk(tree):
                if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef)) and node.body and isinstance(node.body[0], ast.Expr) \
                        and isinstance(getattr(node.body[0], 'value', None), ast.Constant):
                    docs.add(id(node.body[0].value))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docs:
                    if name == 'tailscale_panel.py' and node.lineno > 380 and 'class="' in node.value:
                        continue
                    self.assertNotRegex(node.value, r'[àèéìòù]', '%s:%d %r' % (name, node.lineno, node.value[:60]))


if __name__ == '__main__':
    unittest.main()
