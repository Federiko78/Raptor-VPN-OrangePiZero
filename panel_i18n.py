#!/usr/bin/env python3
"""Translations for the Raptor VPN panel.

Every language is one JSON file in ./i18n (en.json = default and fallback, it.json, ...):

    {"_meta": {"code": "it", "name": "Italiano", "locale": "it-IT"},
     "ui":     {"nav.account": "Account", ...},   texts shown by the page and by its JavaScript
     "server": {"Login required": "Accesso richiesto", ...}}   translations of the English messages sent by the server

To add a language, copy en.json to xx.json, translate the values and reinstall: no code change is needed.

Template tokens (replaced on the server, before the page is sent):
    [[key]]  the value as it is. Values are trusted markup written by us (they may contain <strong> or <a>).
    {{key}}  the value escaped for use inside an HTML attribute.
"""
import html
import json
import os
import re

DEFAULT_LANG = 'en'
I18N_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'i18n')

TOKEN_RAW = re.compile(r'\[\[([a-z][a-z0-9_.]*)\]\]')
TOKEN_ESC = re.compile(r'\{\{([a-z][a-z0-9_.]*)\}\}')
CODE_RE = re.compile(r'^[a-z]{2,3}$')
MAX_FILE = 256 * 1024


class MissingKey(KeyError):
    pass


def _clean_table(raw):
    """Keeps only string -> string pairs, so a damaged file cannot inject anything else."""
    if not isinstance(raw, dict):
        return {}
    return {k: v for k, v in raw.items() if isinstance(k, str) and isinstance(v, str)}


class Catalog:
    def __init__(self, directory=I18N_DIR):
        self.langs = {}
        self.problems = []
        self._load(directory)

    def _load(self, directory):
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            self.problems.append('translations folder not readable: %s' % directory)
            return
        for name in names:
            code = name[:-5]
            if not name.endswith('.json') or not CODE_RE.match(code):
                continue
            path = os.path.join(directory, name)
            try:
                if os.path.getsize(path) > MAX_FILE:
                    raise ValueError('file too large')
                with open(path, encoding='utf-8') as stream:
                    data = json.load(stream)
                if not isinstance(data, dict):
                    raise ValueError('not an object')
            except (OSError, ValueError) as exc:
                self.problems.append('%s skipped: %s' % (name, exc))
                continue
            meta = _clean_table(data.get('_meta'))
            self.langs[code] = {
                'name': meta.get('name') or code.upper(),
                'locale': meta.get('locale') or code,
                'ui': _clean_table(data.get('ui')),
                'server': _clean_table(data.get('server')),
            }

    def codes(self):
        """Available languages, the default one first."""
        rest = sorted(c for c in self.langs if c != DEFAULT_LANG)
        return ([DEFAULT_LANG] if DEFAULT_LANG in self.langs else []) + rest

    def pick(self, code):
        return code if isinstance(code, str) and code in self.langs else DEFAULT_LANG

    def locale(self, lang):
        return self.langs.get(self.pick(lang), {}).get('locale', 'en')

    def text(self, lang, key, strict=False):
        table = self.langs.get(self.pick(lang), {}).get('ui', {})
        if key in table:
            return table[key]
        fallback = self.langs.get(DEFAULT_LANG, {}).get('ui', {})
        if key in fallback:
            return fallback[key]
        if strict:
            raise MissingKey(key)
        return key

    def render(self, template, lang, strict=False):
        template = TOKEN_RAW.sub(lambda m: self.text(lang, m.group(1), strict), template)
        return TOKEN_ESC.sub(lambda m: html.escape(self.text(lang, m.group(1), strict), quote=True), template)

    def client(self, lang):
        """Dictionary handed to the page's JavaScript, as text that is safe inside <script>."""
        lang = self.pick(lang)
        ui = dict(self.langs.get(DEFAULT_LANG, {}).get('ui', {}))
        ui.update(self.langs.get(lang, {}).get('ui', {}))
        data = {'lang': lang, 'locale': self.locale(lang), 'ui': ui,
                'server': self.langs.get(lang, {}).get('server', {}) if lang != DEFAULT_LANG else {}}
        text = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
        for ch, esc in (('<', '\\u003c'), ('>', '\\u003e'), ('&', '\\u0026'), (' ', '\\u2028'), (' ', '\\u2029')):
            text = text.replace(ch, esc)
        return text

    def switcher(self, lang):
        """Language links for the header and the login page (fixed markup, language codes only)."""
        lang = self.pick(lang)
        codes = self.codes()
        if len(codes) < 2:
            return ''
        parts = []
        for code in codes:
            name = html.escape(self.langs[code]['name'], quote=True)
            on = code == lang
            parts.append('<a class="lang%s" href="/lang?set=%s" title="%s" hreflang="%s"%s>%s</a>' %
                         (' on' if on else '', code, name, code, ' aria-current="true"' if on else '', code.upper()))
        return ''.join(parts)

    def translate_server(self, lang, message):
        """Translates an English message sent by the server (the same rule as the page's JavaScript)."""
        table = self.langs.get(self.pick(lang), {}).get('server', {})
        return translate_message(table, message)


def translate_message(table, message):
    """Exact text first, then texts with %s / %d, then texts that end with ': ' or '. ' followed by a detail."""
    if not isinstance(message, str):
        return message
    if message in table:
        return table[message]
    for key, value in table.items():
        if '%s' in key or '%d' in key:
            pattern = '^' + re.escape(key).replace('%s', '(.+?)').replace('%d', '(\\d+)') + '$'
            found = re.match(pattern, message, re.S)
            if found:
                parts = iter(found.groups())
                return re.sub(r'%[sd]', lambda _: next(parts), value)
        elif key.endswith((': ', '. ')) and message.startswith(key):
            return value + message[len(key):]
    return message
