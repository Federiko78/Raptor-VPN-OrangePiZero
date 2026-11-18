# Lingue del pannello

Il pannello è disponibile in **inglese** (lingua predefinita) e in **italiano**. Si cambia con il selettore **EN | IT** in alto
(e nella pagina di accesso); la scelta resta salvata nel browser (cookie `lang`, un anno).

## Dove sono i testi

Un file JSON per lingua in `i18n/` (installato in `/opt/tailscale-panel/i18n/`):

```json
{
 "_meta": { "code": "it", "name": "Italiano", "locale": "it-IT" },
 "ui":     { "nav.account": "Account", "stat.today": "Riavvii oggi", ... },
 "server": { "Login required": "Accesso richiesto", ... }
}
```

- `ui`: i testi della pagina e del suo JavaScript. Le chiavi sono le stesse in tutte le lingue; `{nome}` è un segnaposto da lasciare com'è.
- `server`: traduzione dei messaggi (in inglese) che il pannello e i suoi programmi di sistema restituiscono, per esempio un errore di rete.
  `%s` e `%d` sono segnaposto; una voce che finisce con `: ` o `. ` vale anche quando dopo c'è un dettaglio.
- `_meta.locale` decide il formato di date e orari nel browser.
- L'inglese è anche la lingua di riserva: un testo mancante in un'altra lingua compare in inglese.

## Aggiungere una lingua

1. Copia `i18n/en.json` in `i18n/xx.json` (due o tre lettere minuscole: `de`, `fr`, ...).
2. Traduci i valori di `ui` e `server`, e cambia `_meta`.
3. Rigenera `SHA256SUMS`, poi `python3 test_panel_i18n.py`: controlla che non manchi nessuna chiave e che i segnaposto e i collegamenti siano gli stessi.
4. Installa con `sh update.sh` (o `install_tailscale_panel.sh`): il selettore mostra la nuova lingua da solo.

Nei testi si possono usare solo `<strong>`, `<b>` e i collegamenti a `https://login.tailscale.com/`: il test rifiuta qualsiasi altro markup.

## Cosa non è tradotto

I commenti nel codice e il testo che gli installatori (`*.sh`) scrivono nel terminale restano in italiano.
