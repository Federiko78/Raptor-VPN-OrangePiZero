# Accesso di servizio: Wi-Fi "Raptor VPN - <IP>"

Pensato per le schede consegnate ai clienti, quando non conosci l'IP che il DHCP della loro rete
ha assegnato alla scheda. **Da collaudare sulla scheda reale** prima di consegnare.

Si installano con `sh install_access.sh` (lo lancia anche `install_factory.sh`).

## Wi-Fi che annuncia l'IP

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

## IP di recupero: funzione rimossa

L'indirizzo di recupero `169.254.X.Y` (e lo script `recupero_windows.ps1`) non fa più parte del progetto.
`sh update.sh` lo toglie dalle schede che lo avevano: elimina l'indirizzo, la riga nel Netplan del pannello
e `/etc/raptor-recovery.conf`, senza toccare il DHCP né le sessioni SSH aperte. Per rientrare in una scheda
di cui non conosci l'IP usa il Wi-Fi qui sopra, la lista dei dispositivi del router o Tailscale.
