# Porta del pannello

Il pannello risponde di norma sulla porta TCP **8443** (HTTPS, solo dalla rete Ethernet). Se quella porta
dà fastidio sulla rete del cliente (per esempio il suo router la usa già per altro) la cambi dal pannello,
scheda **Ethernet**, sezione **Cambia la porta del pannello**, senza toccare la scheda da SSH.

La scheda Ethernet raccoglie tutto quello che riguarda la rete cablata:

1. in alto, **IP attuale** (con l'indicazione *DHCP automatico* o *IP statico*), **indirizzo dell'interfaccia web**
   (`https://IP:PORTA/`, cliccabile) e **porta del pannello**;
2. **Indirizzo IP: automatico (DHCP) o statico**;
3. **Cambia la porta del pannello**.

Il cambio di rete e il cambio di porta restano due operazioni separate, ognuna con la propria conferma
e il proprio ripristino automatico.

## Come si cambia

1. Nella scheda **Ethernet** scrivi la nuova porta (da **1024 a 65535**) e premi **Cambia porta**, poi conferma la domanda.
2. Dopo pochi secondi la pagina si sposta da sola al nuovo indirizzo (`https://…:NUOVA-PORTA/`).
   Il browser può chiedere di accettare di nuovo il certificato e bisogna **accedere di nuovo** con la password.
3. Sul nuovo indirizzo compare il riquadro **Cambio di porta da confermare**: premi **Conferma la nuova porta**.

**Se non confermi entro 150 secondi, la scheda torna da sola alla porta precedente.** È la rete di sicurezza:
se il router o il firewall del cliente non lasciano passare la nuova porta, non puoi confermare e dopo due
minuti e mezzo tutto è com'era prima. Lo stesso vale se manca la corrente durante quei minuti: al riavvio la
porta precedente viene ripristinata (`tailscale-panel-port-recovery.service`).

La conferma funziona **solo dalla nuova porta**: confermare dalla vecchia non è possibile, proprio perché
serve a dimostrare che la nuova si raggiunge.

## Porte non ammesse

- sotto 1024 (riservate);
- 41641 (Tailscale) e 5353 (mDNS);
- una porta già usata da un altro servizio della scheda (il pannello lo controlla e rifiuta).

## Cosa cambia dietro le quinte

Il programma root `tailscale-panel-port-helper` riscrive **solo la riga della porta** in questi file e poi
applica la modifica:

| File | Riga |
|---|---|
| `/etc/systemd/system/tailscale-panel.socket` | `ListenStream=0.0.0.0:PORTA` |
| `/etc/systemd/system/tailscale-panel.service` | `Environment=PANEL_PORT=PORTA` |
| `/etc/avahi/services/tailscale-panel.service` | `<port>PORTA</port>` (se presente) |
| `/etc/raptor-input-guard.conf` | `PANEL_PORT=PORTA` (se il firewall in ingresso è installato; le regole vengono riapplicate) |

Se uno di questi file non è nel formato atteso il cambio si ferma prima di cominciare. Il pannello (utente
`tspanel`) può lanciare l'helper solo senza argomenti, con una richiesta JSON controllata.

La porta **sopravvive agli aggiornamenti**: `update.sh` / `install_tailscale_panel.sh` la leggono dall'unità
socket già installata invece di rimettere 8443. Se un cambio è in sospeso l'installer si rifiuta di partire:
conferma o attendi il ripristino (circa 2 minuti) e rilancia.

Anche `hardening/input_firewall.sh` la legge dall'unità socket quando non ha ancora un file di configurazione,
quindi installare il firewall **dopo** il cambio apre la porta giusta.

## Se il pannello non si raggiunge più

Succede solo se, dopo una conferma, qualcosa sulla rete del cliente cambia e blocca la porta. Da SSH o dalla
console (come root):

```
/usr/local/libexec/tailscale-panel-port-helper --set-port 8443
```

Cambia la porta subito, senza conferma, con gli stessi controlli (e rimette tutto a posto se non riesce).
Per annullare un cambio rimasto in sospeso:

```
/usr/local/libexec/tailscale-panel-port-helper --recover
```

Stato attuale della porta: `grep ListenStream /etc/systemd/system/tailscale-panel.socket`.
