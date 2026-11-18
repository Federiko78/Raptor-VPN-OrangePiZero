# Accesso di servizio: Wi-Fi "Raptor VPN - <IP>" e IP di recupero

Due funzioni pensate per le schede consegnate ai clienti, quando non conosci l'IP che il DHCP
della loro rete ha assegnato alla scheda. **Da collaudare sulla scheda reale** prima di consegnare.

Si installano con `sh install_access.sh` (lo lancia anche `install_factory.sh`).

## 1. Wi-Fi che annuncia l'IP

Dopo ogni avvio, appena la porta Ethernet ha un IP, la scheda apre per circa **3 minuti** una rete
Wi-Fi chiamata `Raptor VPN - 192.168.1.57` (l'IP reale). L'installatore lo legge dall'elenco delle
reti Wi-Fi del telefono, senza collegarsi. Se dopo 90 secondi non c'è nessun IP, la rete si chiama
`Raptor VPN - nessun IP`: è già una diagnosi (cavo o DHCP del cliente).

**Non è un punto di accesso utilizzabile**, di proposito:

- password WPA2 casuale a ogni avvio, mai mostrata né salvata;
- hostapd rifiuta comunque ogni dispositivo (lista MAC ammessi vuota);
- nessun server DHCP, nessun IP su `wlan0`, nessun inoltro verso la LAN, nessuna socket di controllo;
- dopo i 3 minuti l'AP si spegne e `wlan0` viene messa giù.

Configurazione in `/etc/raptor-ap.conf` (`ENABLED`, `DURATION` 20-300 s, `CHANNEL` 1-11, `IFACE`,
`WAIT_IP`); dopo una modifica: `systemctl restart raptor-ap`. Per rilanciare l'AP a mano senza
riavviare: `systemctl restart raptor-ap`.

Limiti da conoscere:

- **Chi è nel raggio Wi-Fi può leggere l'IP** durante quei minuti. È un'informazione di poco valore
  (non dà accesso), ma se un cliente lo ritiene un problema imposta `ENABLED=0`.
- Il chip Wi-Fi dell'Orange Pi Zero (XR819, firmware del 2018) in modalità AP è noto per essere
  instabile e un test in rete ha riportato anche blocchi del kernel. Per questo l'AP dura poco, il
  watchdog hardware (`hardening/harden_system.sh`) riavvia la scheda se si pianta, e il driver
  non viene mai scaricato. **Prima della consegna fai un collaudo di una ventina di riavvii**
  (`journalctl -u raptor-ap -b`). Se il chip fa i capricci: `ENABLED=0`, immagine Armbian stabile,
  oppure una chiavetta Wi-Fi USB.

## 2. IP di recupero

Un indirizzo **tuo** della forma `169.254.X.Y` (X e Y da 1 a 254) che la scheda risponde sempre su
`end0`, in DHCP e in statico, anche con Tailscale spento, con IP sconosciuto o configurazione
statica sbagliata. Dal pannello (Rete) rimetti il DHCP e sei a posto.

**Non salta la password**: il pannello chiede sempre l'accesso. Un indirizzo "segreto" non è una
misura di sicurezza; lo è la password (minimo 12 caratteri).

Come funziona: è un indirizzo aggiuntivo (alias) sull'interfaccia, scritto nel Netplan del pannello
(per sopravvivere ai riavvii) e attivato subito senza riavviare la rete. Il valore sta solo in
`/etc/raptor-recovery.conf` sulla scheda (root, 0600): non è nel repository, non compare nel
pannello e `status` riporta solo "attivo / non attivo".

Limiti da conoscere:

- Funziona **solo dalla stessa rete locale** (stesso switch/router) della scheda, non da Internet
  e non attraverso un router. Se il cliente ha reti separate (VLAN) devi stare nella stessa.
- Il tuo PC deve sapere che quell'indirizzo è "qui accanto". Su Windows, come amministratore:
  `powershell -ExecutionPolicy Bypass -File recupero_windows.ps1 169.254.77.12` (aggiunge una rotta
  temporanea, apre il pannello e la toglie quando premi INVIO). Su Linux/macOS:
  `sudo ip route add 169.254.77.12/32 dev eth0` (Linux) oppure
  `sudo route add -host 169.254.77.12 -interface en0` (macOS).
- **mDNS (da verificare sulla scheda):** l'alias viene attivato con `scope link` perché Avahi ignori
  gli indirizzi "link" quando ne esiste uno globale: così il valore non finisce negli annunci
  `orangepizero.local`. Dopo un riavvio controlla con `ip -4 addr show dev end0` che l'alias abbia
  ancora `scope link` (se systemd-networkd lo ricrea come `global`, `check_installation.sh` lo segnala)
  e con `avahi-resolve -4 -n orangepizero.local` che risponda solo l'IP della LAN.
- Sono vietati 169.254.0.x e 169.254.255.x (riservati) e qualunque indirizzo fuori da 169.254.0.0/16:
  non può quindi entrare in conflitto con la LAN del cliente.
- Se hai attivato il firewall in ingresso (`hardening/input_firewall.sh`), la regola per la porta
  8443 su `end0` vale anche per l'IP di recupero: non serve altro.

Cambiare o togliere il valore (da SSH, come root):

```
/usr/local/libexec/tailscale-panel-net-helper --set-recovery 169.254.88.5   # cambia
/usr/local/libexec/tailscale-panel-net-helper --set-recovery random         # ne genera uno
/usr/local/libexec/tailscale-panel-net-helper --set-recovery none           # lo toglie
```

Il pannello (utente `tspanel`) può lanciare l'helper solo senza argomenti: questa funzione non è
raggiungibile dal web.

## Collaudo sulla scheda (checklist)

1. `sh install_access.sh --recovery-ip 169.254.77.12 --ap on`
2. `ip -4 addr show dev end0` mostra anche `169.254.77.12/16 ... scope link`; `sh check_installation.sh` è OK.
3. `ping` e `https://169.254.77.12:8443` dal PC con lo script Windows.
4. Riavvio: l'alias torna da solo; il telefono vede `Raptor VPN - <IP>` per circa tre minuti (alcuni telefoni, iPhone compresi, aggiornano l'elenco Wi-Fi con ritardo: ricarica la lista).
5. Dal pannello passa a IP statico sbagliato di proposito: dopo i 150 s il ripristino scatta, e
   comunque l'IP di recupero risponde durante tutta la prova.
6. Ripeti 20 riavvii controllando `journalctl -u raptor-ap -b` e che la scheda torni sempre in rete.
