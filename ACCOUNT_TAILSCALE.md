# Collegare la scheda a Tailscale dal pannello

Nel pannello, la scheda **Account Tailscale** sostituisce ogni comando da SSH (`tailscale up`, `tailscale logout`).
Ci sono due modi per collegare una scheda nuova. Si sceglie nella scheda; il nome della scheda nella tailnet è facoltativo.

Il nome della scheda e i tag accettano **solo minuscole**: la maiuscola non si può scrivere (viene trasformata subito), spazi e trattini bassi nel nome diventano `-`. La chiave di autenticazione non viene mai modificata.

## 1. Accedi con link

1. Premi **Ottieni il link di accesso**.
2. Apri il link con un browser (anche dal telefono), accedi al tuo account Tailscale e approva la scheda.
3. La pagina si aggiorna da sola e passa a **Collegato**. Se hai ricaricato la pagina nel frattempo, il link in attesa riappare.

Va bene per una scheda che configuri tu, di persona o in videochiamata, con il tuo account.

## 2. Accedi con chiave e tag

Per schede da consegnare ai clienti, senza usare un account personale:

1. In [Tailscale Admin → Settings → Keys](https://login.tailscale.com/admin/settings/keys) crea una **chiave di autenticazione**
   (meglio monouso, con scadenza breve; *preapproved* se la tailnet richiede l'approvazione dei dispositivi).
2. Per usare i **tag**, crea la chiave con quegli stessi tag, e nella policy della tailnet definisci chi può assegnarli:

   ```json
   "tagOwners": { "tag:cliente": ["autogroup:admin"] }
   ```

3. Nel pannello scegli **Accedi con chiave e tag**, incolla la chiave, scrivi i tag separati da virgola (`tag:cliente`) e premi **Collega con la chiave**.

## Spegnere, riaccendere e scollegare

Con la scheda collegata ci sono due pulsanti, che fanno cose diverse:

- **Spegni Tailscale** (`tailscale down`): ferma la VPN ma la scheda resta nell'account. Le rotte pubblicate smettono di funzionare e la scheda non è più raggiungibile da remoto. Si riaccende con **Riattiva Tailscale**, senza un nuovo link o una nuova chiave.
- **Scollega dall'account Tailscale** (`tailscale logout`): toglie la scheda dall'account. Per ricollegarla serve di nuovo un link o una chiave.

Entrambi chiedono una conferma. La scheda resta sempre raggiungibile dalla LAN, perché il pannello non passa da Tailscale.

Con un nodo "taggato" i permessi li decide la policy (ACL/Grants) sul tag, non l'utente che lo ha creato: è la strada giusta per i clienti.
Ricorda che le rotte `/32` pubblicate richiedono comunque l'approvazione nella console (o `autoApprovers` nella policy).

## Altre azioni

- **Scollega da Tailscale**: toglie la scheda dall'account (con conferma). Poi serve un nuovo accesso.
- **Riattiva Tailscale**: se la scheda è autenticata ma ferma (`tailscale down`), la riattiva senza cambiare rotte o DNS.
- Stati mostrati: *Collegato*, *Accesso richiesto*, *In attesa di approvazione*, *Fermo*, *Avvio in corso*, *Tailscale non risponde*.

## Sicurezza

- Le richieste passano da un programma root dedicato (`/usr/local/libexec/tailscale-panel-auth`), autorizzato con una regola sudoers
  senza argomenti. Ogni campo (chiave, tag, nome) è controllato con espressioni rigide prima di arrivare al comando.
- **La chiave non resta sulla scheda**: viene scritta in un file privato (permessi 600) sulla memoria (`/run`), passata a Tailscale con
  `--auth-key=file:...`, e cancellata subito. Non compare mai tra gli argomenti dei programmi, nei log o nelle risposte; se Tailscale la
  restituisce in un errore, viene oscurata.
- Il link di accesso viene mostrato solo se è `https://*.tailscale.com/a/...`; qualsiasi altro indirizzo viene scartato.
- Tutte le azioni richiedono la sessione del pannello e il token CSRF.

## Requisiti

- Tailscale recente (serve `--auth-key=file:`, presente nelle versioni attuali dei pacchetti ufficiali).
- La scheda deve raggiungere Internet (o almeno i server Tailscale) per collegarsi.

## Stato di collaudo

Il programma è testato con un finto `tailscale` (argomenti, file della chiave, errori, concorrenza) e il pannello è stato visto in un browser
con dati di prova. **Il collaudo con `tailscaled` reale sulla scheda va ancora fatto**: dopo l'aggiornamento prova prima il link, poi la chiave.
