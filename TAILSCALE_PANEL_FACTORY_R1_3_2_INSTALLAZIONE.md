# Tailscale Control Panel — Factory R1.3.2

**Web User Interface v1.5.0 · Orange Pi Zero — Subnet Router**  
**Destinazione:** installazione **pulita** su Armbian Debian 13 Trixie Minimal, ARM32 (`armhf`).  
**Stato:** candidato Factory, verificato con test statici e simulati; **prima messa in servizio da collaudare su una nuova Orange Pi Zero**.

## Obiettivo

Installer unico, senza trascinare le scelte fatte per i test. La rete Ethernet riceve normalmente un indirizzo tramite DHCP. La Web UI è disponibile via HTTPS sulla porta 8443; contiene la configurazione DHCP/IP statico, lo scanner LAN (IP, MAC, hostname e produttore quando riconoscibili) e tre modalità di pubblicazione Tailscale.

### Stato iniziale obbligatorio

| Componente | Dopo l'installazione pulita |
|---|---|
| Pubblicazione Tailscale | **OFF — nessuna rotta** |
| Modalità accesso LAN | `off` |
| Lista dispositivi selezionati | Vuota |
| Subnet salvate nella policy di routing | Nessuna |
| Scansione LAN | Manuale, non automatica |
| DHCP Ethernet | Si mantiene la configurazione nativa Armbian, senza alterarla |
| IPv4 VPN → LAN | **DROP** preventivo in `mangle/FORWARD` |
| IPv6 VPN → LAN | **DROP** (la Web UI gestisce soltanto IPv4) |
| Tailscale | Identità nuova, da autenticare con `tailscale up` |
| Credenziali | Nuova password Web UI; quella SSH è indipendente |

La Factory **non include** alcun indirizzo IP di prova, password esistente, profilo cliente, autenticazione Tailscale, configurazione Netplan del laboratorio o immagini della microSD precedente. Il nome della rete del cliente è rilevato dinamicamente e **non provoca la pubblicazione automatica**.

## Componenti installati

- Repository ufficiale **Tailscale Stable** per Debian 13 e servizio `tailscaled` abilitato all'avvio.
- Server Python HTTPS leggero con socket systemd legato all'interfaccia Ethernet, non all'indirizzo DHCP.
- Accesso amministrativo con password (12–128 caratteri, almeno una maiuscola, una minuscola e una cifra) e cambio password dalla GUI.
- Scansione della sola LAN Ethernet (`arp-scan`); ricerca hostnames DNS inverso/mDNS ove possibile.
- Router IPv4: rete completa, singoli host `/32` o OFF; SNAT, DNS Tailscale, rotte remote e auto-update configurabili.
- Guard IPv4 tramite `iptables -t mangle` **prima** delle regole Tailscale in `filter/FORWARD`; guard IPv6 di blocco.
- Ripristino guard all'avvio (servizio `tailscale-panel-route-guard.service` ordinato prima di `tailscaled`).
- DHCP o indirizzo statico via Netplan con conferma entro 150 secondi e tentativo di rollback automatico in caso di mancata conferma.
- Avahi/mDNS ove supportato dalla LAN: `orangepizero.local` non è garantito su ogni router o PC.
- Test di preflight, backup dei file software, controlli finali e tentativo di ripristino in caso di errore. Un'installazione interrotta può lasciare pacchetti apt già installati e il guard in stato di blocco: verificare i log prima di usare il sistema.

> **Nota di sicurezza:** l'applicazione controlla il traffico inoltrato sul percorso `tailscale0 → end0`, non tutte le possibili vie di accesso alla rete. Utilizzare anche le **Grants/ACL Tailscale** e verificare che non esistano altri subnet router che pubblicano la stessa rete. Non aprire TCP 8443 sul router Internet.

## Requisiti e primo accesso Armbian

- Orange Pi Zero originale con Armbian Debian 13 Trixie Minimal (`armhf`) e Ethernet `end0`.
- Consigliata microSD da **16 GB o più**, almeno 450 MiB disponibili al preflight.
- Internet temporaneo per apt/Tailscale; servizio systemd e interfaccia TUN funzionanti.
- Al primo login Armbian, salvo configurazione preventiva tramite Imager: **utente `root`, password iniziale `1234`**. Il sistema chiede di cambiare questa password e creare un utente amministrativo. Completare la procedura prima dell'installer.

## Installazione Factory — da una scheda nuova

Con FileZilla/SFTP, copiare **`TAILSCALE_PANEL_FACTORY_R1_3_2.zip`** nella cartella `/root`.

Accedere via SSH come `root` e incollare:

```bash
mkdir -p /root/tspanel-factory-r1.3.2
cd /root/tspanel-factory-r1.3.2
python3 -m zipfile -e /root/TAILSCALE_PANEL_FACTORY_R1_3_2.zip .
sh ./install_factory.sh
```

L'installer esegue i controlli preliminari **prima di alterare il progetto**; arresta l'installazione se trova già credenziali, policy, stato Tailscale o servizi Panel. È destinato **soltanto a una Armbian pulita**: non utilizzarlo per aggiornare una Orange Pi già configurata.

Durante l'installazione:

1. Puoi scegliere se cambiare nuovamente la password Linux `root` (facoltativo, indipendente dalla Web UI).
2. Imposti e confermi una nuova password Web UI (minimo 12 caratteri, maiuscola, minuscola e numero).
3. L'installer configura il guard in modalità **OFF** e i servizi. Non effettua `tailscale up` e non pubblica alcuna rotta.
4. La verifica finale include il guard IPv4 in `mangle`, il blocco IPv6 e la policy vuota.

### Associazione del nuovo Orange Pi

Terminata l'installazione:

```bash
tailscale up
```

Aprire il collegamento di autenticazione nel terminale e autorizzare il **nuovo** dispositivo. L'autenticazione non abilita automaticamente l'accesso alla LAN. Verificare l'assenza di rotte:

```bash
tailscale get advertise-routes
tailscale status
```

Quindi aprire dal PC nella stessa LAN:

`https://IP-ASSEGNATO-DAL-ROUTER:8443`

Il certificato iniziale è autofirmato; verificarne l'impronta se necessario. Per impieghi permanenti è preferibile un certificato attendibile.

## Pubblicare dispositivi dopo il collaudo

- Nella GUI aprire **LAN Device Discovery** e fare la scansione.
- Selezionare modalità **Solo dispositivi selezionati** e scegliere gli IP voluti, oppure **Intera subnet** e inserire il CIDR corretto.
- Salvare le modifiche: il pannello aggiorna il filtro preventivo e le rotte IPv4 Tailscale.
- Autorizzare le rotte nella **console amministrativa Tailscale**, salvo regole di approvazione automatica già configurate.
- Effettuare prova remota sia verso un host consentito sia verso un host non consentito. La sola presenza di una rotta `/32` non dimostra l'efficacia del filtro firewall.

Gli hostname e MAC address servono a **identificare** i dispositivi, non a garantire che mantengano lo stesso IP: usare prenotazioni DHCP o indirizzi statici sugli host critici.

## Verifiche e diagnostica

```bash
cd /root/tspanel-factory-r1.3.2
sh ./check_installation.sh
systemctl is-active tailscaled tailscale-panel.socket tailscale-panel.service
systemctl status tailscale-panel-route-guard.service --no-pager
iptables -t mangle -S FORWARD
ip6tables -t mangle -S FORWARD
cat /var/lib/tailscale-panel-guard/policy.json
```

Per la **prima installazione non ancora configurata**, la policy deve essere:

```json
{"mode":"off","subnets":"","selected_hosts":[]}
```

Dopo un primo test dal PC remoto, controllare i contatori `iptables -t mangle -L FORWARD -n -v` e il filtro selettivo; eseguire anche un riavvio controllato in presenza di accesso fisico alla scheda. Il nome `.local` potrebbe non funzionare in reti con DNS/multicast filtrati: l'accesso tramite IP rimane disponibile.

### Backup, rollback e limiti

I backup del software sono conservati sotto `/var/backups/tailscale-panel/`. Il ripristino automatico è **best effort** e non rimuove pacchetti apt installati. Il guard deve rimanere restrittivo se un'installazione fallisce. Conservare sempre la microSD precedente o un'immagine recuperabile prima di testare cambiamenti al firewall e alla rete.

L'installer non è una funzione di clonazione hardware: Tailscale, password e certificato della nuova macchina sono generati o autenticati separatamente. Per installazioni esistenti servirà un **pacchetto di aggiornamento distinto** che preservi policy, utenti e rotte.

## Contenuto ZIP

| File | Scopo |
|---|---|
| `install_factory.sh` | Unico punto di avvio, preflight + installazione + verifica |
| `install_tailscale_panel.sh` | Configura Web UI, helper e unità systemd |
| `tailscale_panel.py` | Web UI HTTPS v1.5.0 |
| `tailscale_panel_helper.py` | Tailscale, rotte, `mangle` IPv4 e blocco IPv6 |
| `tailscale_panel_discovery.py` | Scanner LAN IP/MAC/hostname |
| `tailscale_panel_network.py` | Netplan DHCP/statico con rollback |
| `password_policy.py` | Regole delle password |
| `check_installation.sh` | Controlli del sistema e guard |
| `backup_panel.sh`, `restore_panel.sh` | Backup/rollback file del software |
| `test_release.py` | Test simulati, non modifica la rete |
| `SHA256SUMS` | Integrità dei file del pacchetto |
| questo `.md` | Guida per Visual Studio Code |

**Stato collaudo:** test statici e simulati superati nel laboratorio di generazione; l'installer **non è stato eseguito su una nuova Orange Pi reale**. Non dichiarare STABLE finché non vengono superati i test hardware di installazione, riavvio e traffico remoto consentito/bloccato.
