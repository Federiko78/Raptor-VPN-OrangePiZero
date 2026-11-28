# Rete tradotta: la rete del cliente vista con un'altra numerazione

Serve quando la rete del cliente (per esempio l'autolavaggio, `192.168.1.x`) deve essere raggiunta da un'altra sede che **usa la stessa numerazione** (per esempio l'autosalone, anche lui `192.168.1.x`). Se si pubblicasse la rete così com'è, gli indirizzi si pesterebbero.

Con la rete tradotta la Orange Pi la pubblica su Tailscale con **un'altra numerazione**, per esempio `192.168.2.x`: dall'autosalone si apre `192.168.2.64` e si arriva al dispositivo che all'autolavaggio è `192.168.1.64`. È come una piccola rete VPN a parte. Nella rete dell'autolavaggio non cambia niente.

## Come funziona

- Tu scegli la **rete tradotta** (per esempio `192.168.2.0/24`). Il pannello mostra accanto la **rete attuale** e l'indirizzo IP della Orange Pi.
- Ogni dispositivo mantiene il suo numero finale: `192.168.1.64` diventa `192.168.2.64`, `192.168.1.10` diventa `192.168.2.10`, e così via.
- Quando un pacchetto arriva da Tailscale per `192.168.2.64`, la Orange Pi lo riscrive in `192.168.1.64`, lo manda nella LAN e rimanda indietro la risposta. Il dispositivo vede arrivare le richieste dalla Orange Pi e non sa nulla di Tailscale.
- Si pubblica **tutta la rete** (nessun dispositivo scelto) oppure **solo i dispositivi che spunti** nella scheda *Dispositivi*. Con i dispositivi scelti, gli altri restano invisibili.

## Come si imposta

1. Collega la Orange Pi alla LAN del cliente e collega Tailscale (scheda **Account**).
2. Nella scheda **Rotte** scegli **Rete tradotta**. Vedi la **rete attuale** (per esempio `192.168.1.0/24`) e l'indirizzo della Orange Pi.
3. Scrivi la **rete tradotta**: della **stessa dimensione** della rete attuale e **libera in entrambe le sedi**. Il pannello ne propone una (di solito `192.168.2.0/24`). Non va bene una rete che esiste già nella sede remota, né quella che la Orange Pi usa per altro (per esempio il Wi-Fi).
4. Se vuoi pubblicare solo alcuni dispositivi, fai **Scansiona la rete** nella scheda **Dispositivi** e spunta quelli che servono: sotto ognuno compare l'indirizzo con cui si raggiunge da Tailscale (`Da Tailscale: 192.168.2.64`). Se non spunti nulla viene tradotta tutta la rete.
5. **Salva la configurazione.**
6. **Approva la rotta** nella console di amministrazione di Tailscale (*Machines*, la Orange Pi, sezione *Subnets*). Con una sola rotta (`192.168.2.0/24`, oppure `192.168.2.64/32` per dispositivo) è un'operazione di un attimo.
7. Dal PC remoto apri l'indirizzo tradotto: per esempio `http://192.168.2.64`, oppure scrivilo come IP del dispositivo nel programma che usi. Windows e macOS usano le rotte approvate da soli; su Linux serve `tailscale set --accept-routes`.

Dà più sicurezza dare ai dispositivi un **indirizzo fisso** (o una prenotazione DHCP sul router): la traduzione segue il loro indirizzo.

## Rispetto all'alias

| | Alias Tailscale | Rete tradotta |
|---|---|---|
| Dispositivi | uno solo | tutta la rete, oppure quelli scelti |
| Indirizzo da usare | quello `100.x.y.z` della Orange Pi | `192.168.2.x`, con lo stesso finale dell'originale |
| Rotta da approvare | no | sì (una) |
| Rischio di conflitto di numeri | nessuno | la rete tradotta deve essere libera nelle due sedi |

## Cosa cambia e cosa no

- **La Orange Pi non è raggiungibile dalla rete tradotta**: né il suo indirizzo tradotto né quello vero. Il suo pannello resta raggiungibile solo dalla rete locale.
- Un pacchetto da Tailscale per un indirizzo vero della LAN (per esempio `192.168.1.64`) non passa mai: passano soltanto quelli arrivati dalla rete tradotta e solo verso la rete (o i dispositivi) scelta.
- Le impostazioni «SNAT» e «Accetta rotte» non servono a questa modalità: la mascheratura verso i dispositivi è fatta comunque dalla Orange Pi.
- Dopo un riavvio la traduzione torna da sola, **solo se la scheda è ancora nella stessa rete**. Se viene spostata in un'altra rete non viene riattivata e va riconfigurata.
- Le connessioni già aperte continuano anche dopo un cambio di impostazioni, finché non si chiudono.

## Limiti da conoscere

- **Se si pubblica tutta la rete, chi ha il permesso di raggiungere la Orange Pi raggiunge tutti i dispositivi della LAN.** Per limitarlo scegli i dispositivi, oppure usa le regole di accesso (ACL/grants) di Tailscale, che non sono configurate da questo progetto. Per esempio, per far vedere al solo PC dell'autosalone l'NVR sulle sole porte 80, 443, 554 e 8000, nelle regole di accesso va indicato come destinazione `192.168.2.64` con `"ip": ["tcp:80", "tcp:443", "tcp:554", "tcp:8000"]`. Controlla la sintassi esatta nella guida di Tailscale (grants).
- Se un dispositivo scrive il proprio indirizzo della LAN dentro le sue risposte (certi NVR lo fanno in alcune funzioni), la funzione interessata può non andare dal lato remoto. Si scopre solo provando con il dispositivo vero: la funzione base (web e video) di solito funziona.
- La traduzione di **tutta** la rete richiede il modulo `NETMAP` del sistema. Se la scheda non lo ha, il pannello lo dice e basta scegliere i dispositivi da tradurre (quella modalità non lo richiede).
- Il dispositivo con lo stesso numero finale dell'Orange Pi stessa non è raggiungibile (l'Orange Pi non si traduce mai).

## Come controllare

Dal PC remoto: l'indirizzo tradotto (per esempio `192.168.2.64`) deve rispondere come il dispositivo (pagina web, programma, ping). Un indirizzo tradotto di un dispositivo non scelto non deve rispondere, e nemmeno l'indirizzo vero `192.168.1.x`.

Sulla Orange Pi, come root, per vedere le regole attive:

```sh
iptables -t nat -S | grep TSPANEL
iptables -t mangle -S | grep TSPANEL
tailscale get --json advertise-routes
```

Nella tabella `nat` devono comparire le regole di traduzione (`NETMAP` per tutta la rete, oppure un `DNAT` per ogni dispositivo) e una `MASQUERADE`; nella tabella `mangle` le regole `RETURN` con `--ctstate DNAT` verso la LAN (o verso i dispositivi scelti). L'ultimo comando mostra la rotta tradotta.

Per sapere in anticipo se la scheda può tradurre tutta la rete: `iptables -t nat -j NETMAP --help`.

## Tornare indietro

Nella scheda **Rotte** scegli un'altra modalità (per esempio **Nessuna LAN**) e salva: le regole di traduzione vengono tolte e la rotta non è più pubblicata.
