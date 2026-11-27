# Alias Tailscale: vedere un solo dispositivo con l'indirizzo della Orange Pi

Serve quando un dispositivo della rete del cliente (per esempio un NVR) deve essere visto da un'altra sede, e **l'indirizzo della sua LAN potrebbe coincidere con quello di un dispositivo della sede remota** (per esempio tutte e due le reti usano `192.168.1.x`).

Con le rotte normali (`/32`) il PC remoto riceve un percorso verso l'indirizzo vero del dispositivo: se nella sede remota esiste già quell'indirizzo, il PC manderebbe il traffico nel posto sbagliato. Con l'alias questo non può succedere, perché **il PC remoto non vede mai l'indirizzo della LAN**.

## Come funziona

- La Orange Pi non pubblica nessuna rotta.
- Tutto quello che arriva all'**indirizzo Tailscale della Orange Pi** (`100.x.y.z`), su qualunque porta e protocollo (TCP, UDP, ping), viene inoltrato al dispositivo scelto.
- Il dispositivo risponde alla Orange Pi, che inoltra la risposta: per il PC remoto è come se il dispositivo avesse l'indirizzo `100.x.y.z`.
- Il dispositivo non cambia indirizzo e non sa nulla di Tailscale.

## Come si imposta

1. Collega la Orange Pi alla stessa LAN del dispositivo e collega Tailscale (scheda **Account**).
2. Nella scheda **Rotte** scegli **Alias Tailscale (un solo dispositivo, nessuna rotta)**.
3. Nella scheda **Dispositivi** fai **Scansiona la rete** e spunta **un solo** dispositivo. In questa modalità la scelta precedente viene sostituita da quella nuova.
4. **Salva la configurazione.** Il pannello mostra l'indirizzo da usare, per esempio `100.101.102.103`.
5. Dal PC remoto, con Tailscale attivo con lo stesso account, apri quell'indirizzo: nel browser (`http://100.101.102.103`) o nel programma che usi per il dispositivo (per un NVR Hikvision, per esempio iVMS-4200, scrivendo quell'indirizzo come IP del dispositivo).

Non c'è nessuna rotta da approvare nella console di Tailscale.

Dà più sicurezza dare al dispositivo un **indirizzo fisso** (o una prenotazione DHCP sul router): l'alias è legato al suo indirizzo.

## Cosa cambia

- **La Orange Pi non è più raggiungibile da Tailscale per sé stessa**, perché tutto quello che arriva al suo indirizzo Tailscale va al dispositivo. Il pannello è comunque raggiungibile solo dalla rete locale (indirizzo della scheda Ethernet), come sempre.
- **Un solo dispositivo per Orange Pi.**
- La Orange Pi lascia passare dalla LAN **solo** il dispositivo scelto: il resto della rete resta invisibile da Tailscale.
- Le impostazioni «SNAT» e «Accetta rotte» non servono a questa modalità: la mascheratura verso il dispositivo è fatta comunque dalla Orange Pi.
- Dopo un riavvio l'alias torna da solo. Se la scheda viene spostata in un'altra rete, dove il dispositivo non c'è, l'alias non viene riattivato e va riconfigurato.

## Limiti da conoscere

- Se il dispositivo scrive il proprio indirizzo della LAN dentro le sue risposte (certi NVR lo fanno in alcune funzioni), la funzione interessata può non andare dal lato remoto. Si scopre solo provando con il dispositivo vero: la funzione base (web e video) di solito funziona.
- Chi, nella tua rete Tailscale, ha il permesso di raggiungere la Orange Pi raggiunge anche il dispositivo. Per limitarlo (per esempio al solo PC del cliente e alle sole porte dell'NVR: 80, 443, 554, 8000) servono le regole di accesso (ACL) di Tailscale, che non sono configurate da questo progetto.

## Come controllare

Dal PC remoto: l'indirizzo mostrato dal pannello deve rispondere come il dispositivo (pagina web, programma, ping). Un altro dispositivo della stessa LAN **non** deve rispondere, né con il suo indirizzo della LAN né con quello Tailscale.

Sulla Orange Pi, come root, per vedere le regole attive:

```sh
iptables -t nat -S | grep TSPANEL
iptables -t mangle -S | grep TSPANEL
```

Nella tabella `nat` devono comparire una regola `DNAT` verso l'indirizzo del dispositivo e una `MASQUERADE`; nella tabella `mangle` il solo indirizzo del dispositivo ha `RETURN`.

## Tornare indietro

Nella scheda **Rotte** scegli un'altra modalità (per esempio **Nessuna LAN**) e salva: le regole dell'alias vengono tolte e l'indirizzo Tailscale della Orange Pi torna a essere suo.
