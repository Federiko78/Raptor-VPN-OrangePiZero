# Registro eventi: riavvii, spegnimenti e mancanze di corrente

Il pannello ha una sezione **Eventi · Riavvii e stato del sistema** che mostra quando la scheda si è
avviata, quando è stata spenta in modo regolare e quando invece è stata **spenta di colpo**
(mancanza di corrente, blocco, watchdog). Il registro resta sulla scheda anche dopo uno spegnimento.
Si installa con `sh install_eventlog.sh` (lo fa anche `install_factory.sh` e `update.sh`).

## Come funziona

- Il file è `/var/lib/raptor-events/events.jsonl`: **un evento JSON per riga** (JSON Lines). Se la
  corrente manca mentre si scrive, si perde al più l'ultima riga e il resto resta leggibile.
- Lo scrive solo `raptor-eventlog` (root). Il pannello lo **legge soltanto** e controlla ogni campo
  prima di mostrarlo.
- All'avvio registra l'avvio e **come era finito il precedente**: se lo spegnimento non è stato
  segnato come regolare, la scheda è stata spenta di colpo.
- Ogni 5 minuti un "battito" aggiorna l'ultimo istante in cui la scheda era viva. Dopo una mancanza
  di corrente, quell'istante dice **entro quando** è successo (al massimo 5 minuti prima).
- Allo spegnimento regolare registra se era un riavvio, uno spegnimento o un arresto. Un semplice
  `systemctl stop raptor-eventlog` non conta come spegnimento.

## Tipi di evento

| Tipo | Significato | Campi principali |
|---|---|---|
| `boot` | avvio della scheda | `previous` (come era finito il precedente), `clock_synced`, `kernel`, `boot_id` |
| `shutdown` | spegnimento regolare | `kind`: `reboot`, `poweroff`, `halt` |
| `unclean_shutdown` | rilevato un spegnimento anomalo | `last_seen_epoch`, `detected_epoch` |
| `clock_synced` | l'orologio si è sincronizzato | `jump_seconds` (di quanto è stato corretto) |

`previous` in `boot` vale `first_boot`, `clean_reboot`, `clean_poweroff`, `clean_halt`, `unclean` o
`unknown` (stato non leggibile). Gli orari (`epoch`) sono secondi Unix in UTC; il pannello li mostra
nel fuso del tuo computer.

## Da sapere

- **L'orologio.** Senza batteria la scheda parte con l'orologio indietro finché non si sincronizza
  con Internet. Finché non compare "Orologio sincronizzato", gli orari dell'ultimo avvio possono essere
  sbagliati (l'evento `boot` porta `clock_synced: false`).
- **Il primo evento** di una scheda su cui il registro viene installato a caldo ha `logged_late: true`:
  l'orario è quello dell'accensione reale, ma è stato registrato dopo.
- **Consumo della microSD:** un battito ogni 5 minuti scrive poche centinaia di byte; il file viene
  accorciato da solo oltre 400 KB (restano gli ultimi 1000 eventi).
- Un cliente che stacca la presa non lascia traccia dello *stacco* in sé: lo si riconosce dall'avvio
  successivo (`unclean`).

## Aggiungere altri eventi in futuro

Basta una riga con `type`, `epoch` e i campi che servono, scritta con `append_event()` in
`raptor_eventlog.py`; poi si aggiunge il tipo a `EVENT_TYPES` nel pannello (che altrimenti lo ignora
per sicurezza) e un'etichetta nella tabella JavaScript.
