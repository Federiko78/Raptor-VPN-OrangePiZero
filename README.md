# Raptor VPN · Orange Pi Zero

Pannello di controllo **Tailscale** per **Orange Pi Zero** usato come *subnet router* da lasciare nella rete di un cliente.

L'installatore collega la scheda alla LAN del cliente, apre il pannello dal browser, scansiona i dispositivi della rete e sceglie quali rendere raggiungibili da remoto tramite Tailscale. Nessuna configurazione sul router del cliente.

> Stato: baseline **Factory R1.3.2 · Web UI v1.6.0**. Come indicato nella guida di installazione, la Factory non è ancora stata dichiarata STABLE: mancano i test hardware su una scheda nuova (installazione, riavvio, traffico consentito/bloccato).

## Cosa fa

- Web UI HTTPS sulla porta **8443** (si cambia dal pannello, vedi [`PORTA_PANNELLO.md`](PORTA_PANNELLO.md)), raggiungibile **solo dalla LAN Ethernet** (socket systemd legato a `end0`, mai su `tailscale0` né Wi-Fi).
- Accesso con password (PBKDF2-SHA256), sessioni con CSRF, limite ai tentativi di login.
- **LAN Device Discovery**: scanner ARP (IP, MAC, produttore, hostname) della sola rete locale.
- Pubblicazione rotte Tailscale in quattro modalità: nessuna LAN, intera subnet, **solo dispositivi selezionati (/32)** e **alias Tailscale** (un solo dispositivo visto con l'indirizzo Tailscale della scheda, senza pubblicare nessuna rotta: utile quando gli indirizzi delle due sedi potrebbero coincidere, vedi [`ALIAS_DISPOSITIVO.md`](ALIAS_DISPOSITIVO.md)).
- **Guard di forwarding** `iptables -t mangle` che parte prima di `tailscaled` e blocca per default `tailscale0 → LAN`.
- DHCP o IP statico via Netplan, con **conferma entro 150 s** e rollback automatico.
- Helper root con schema JSON fisso, nessuna shell; `sudo` limitato a cinque programmi, senza argomenti.
- **Wi-Fi "Raptor VPN - <IP>"** per ~3 minuti dopo l'avvio: l'installatore legge l'IP assegnato dal DHCP dal telefono.
- **Account Tailscale dal pannello**: accesso con link oppure con chiave di autenticazione + tag, **spegnimento e riaccensione di Tailscale**, scollegamento dall'account, senza SSH. Vedi [`ACCOUNT_TAILSCALE.md`](ACCOUNT_TAILSCALE.md).
- **Grafica Raptor**: stesso stile nero e oro del pannello Raptor AI, con menu, tema scuro e versione per telefono.
- **Registro eventi** persistente (JSON Lines) con avvii, spegnimenti e **mancanze di corrente**, visibile nel pannello (ultima scheda). Vedi [`REGISTRO_EVENTI.md`](REGISTRO_EVENTI.md).
- **Statistiche dei riavvii** in cima al pannello (oggi, settimana, mese, anno, con le mancanze di corrente) e contatori nella sezione Eventi.
- **Due lingue**, inglese (predefinita) e italiano, scelte con il selettore EN | IT in alto: i testi stanno in `i18n/*.json`. Vedi [`LINGUE.md`](LINGUE.md).
- **Porta del pannello cambiabile dall'interfaccia**, nella scheda Ethernet insieme a DHCP/IP statico, con IP attuale e indirizzo web in evidenza (per esempio 5000 se il router del cliente usa già la 8443): il cambio va confermato dalla nuova porta entro 150 secondi, altrimenti la scheda torna da sola alla precedente; la porta scelta resta dopo gli aggiornamenti. Vedi [`PORTA_PANNELLO.md`](PORTA_PANNELLO.md).
- **Wi-Fi che annuncia l'IP** (`Raptor VPN - <IP>`, non collegabile, circa 3 minuti dopo ogni avvio): per trovare la scheda in una rete che non conosci. Vedi [`ACCESSO_DI_SERVIZIO.md`](ACCESSO_DI_SERVIZIO.md).

## Installazione

Serve: una **Orange Pi Zero**, una microSD da 16 GB o più (servono almeno 450 MiB liberi), un cavo Ethernet collegato a una rete con **DHCP e accesso a Internet** (di solito il router).

### 1. Sistema operativo

Immagine collaudata:

```
Armbian_community_26.11.0-trunk.130_Orangepizero_trixie_current_6.18.63_minimal
```

È **Armbian Debian 13 "Trixie" Minimal (CLI), armhf, per Orange Pi Zero** (Allwinner H2+, 32 bit), kernel `6.18.63-current-sunxi`. Scaricala da [armbian.com/orange-pi-zero](https://www.armbian.com/orange-pi-zero/) (scegli *Debian 13 trixie · Minimal*) e scrivila sulla microSD con [Armbian Imager](https://www.armbian.com/imager/) o balenaEtcher. Una build più recente della stessa immagine dovrebbe andare bene, ma l'unica collaudata è quella indicata sopra.

L'installer rifiuta Ubuntu, Debian 12, le versioni Desktop e qualunque immagine senza `systemd-networkd` e Netplan.

### 2. Primo avvio

1. Inserisci la microSD, collega il cavo Ethernet e accendi la scheda. Aspetta un paio di minuti.
2. Trova l'IP della scheda nell'elenco dei dispositivi (client DHCP) del router.
3. Collegati da un computer della stessa rete: `ssh root@IP-DELLA-SCHEDA`, password `1234`. Armbian chiede di cambiarla e di creare un utente: fallo, ma **resta collegato come `root`** (oppure rientra con `sudo -i`).

### 3. Installazione (un solo comando)

Da root, nella sessione SSH, lancia:

```sh
curl -fsSL https://raw.githubusercontent.com/Federiko78/Raptor-VPN-OrangePiZero/main/bootstrap.sh | sh
```

Il comando installa git e python3, scarica il progetto in `/root/Raptor-VPN-OrangePiZero` e avvia l'installer, che ti chiede:

- la **password del pannello** (minimo 12 caratteri);
- se attivare il **Wi-Fi che annuncia l'IP**.

Alla fine l'installer verifica da solo l'installazione e stampa l'indirizzo del pannello. Serve una sessione SSH con terminale (le domande si rispondono da tastiera).

Per provare un ramo di lavoro al posto di `main`: `... | RAPTOR_BRANCH=nome-ramo sh`.

Se preferisci passo per passo:

```sh
apt-get update && apt-get install -y git python3
git clone https://github.com/Federiko78/Raptor-VPN-OrangePiZero.git
cd Raptor-VPN-OrangePiZero
sh ./install_factory.sh
```

L'installer è pensato **solo per un Armbian pulito**: si ferma se trova credenziali, policy o servizi già presenti. Dettagli, verifiche e rollback in [`TAILSCALE_PANEL_FACTORY_R1_3_2_INSTALLAZIONE.md`](TAILSCALE_PANEL_FACTORY_R1_3_2_INSTALLAZIONE.md).

### 4. Primo accesso al pannello

1. Da un computer della stessa rete apri `https://IP-DELLA-SCHEDA:8443/`. Il browser avvisa che il certificato non è attendibile (è generato dalla scheda): accetta e prosegui.
2. Entra con la password del pannello scelta durante l'installazione.
3. Nella scheda **Account** collega Tailscale (con un link oppure con una chiave di autenticazione): non serve nessun comando da SSH. Vedi [`ACCOUNT_TAILSCALE.md`](ACCOUNT_TAILSCALE.md).
4. Poi scegli le rotte da pubblicare (scheda **Rotte** e **Dispositivi**). All'inizio non è pubblicata nessuna rotta.

La porta 8443 si può cambiare dal pannello, scheda **Ethernet** (vedi [`PORTA_PANNELLO.md`](PORTA_PANNELLO.md)). Se non conosci l'IP della scheda, dopo ogni avvio compare per circa 3 minuti il Wi-Fi **`Raptor VPN - <IP>`** (non collegabile: il nome indica l'IP), se lo hai attivato durante l'installazione. È descritto in [`ACCESSO_DI_SERVIZIO.md`](ACCESSO_DI_SERVIZIO.md).

## Aggiornamento (scheda già installata)

**Non rilanciare il comando di installazione**: si ferma se trova una scheda già configurata. Per portare una scheda già in servizio all'ultima versione, da root:

```sh
cd /root/Raptor-VPN-OrangePiZero && sh update.sh
```

Se il progetto sta in un'altra cartella, entra in quella. Con un utente normale al posto di root: `cd ~/Raptor-VPN-OrangePiZero && sudo sh update.sh`.

Lo script scarica l'ultima versione del ramo in uso (di norma `main`), controlla l'integrità dei file e aggiorna pannello, registro eventi e, se c'è, il Wi-Fi che annuncia l'IP. Al termine fa le verifiche. **Non tocca**: password del pannello, account Tailscale, impostazioni di rete (DHCP/IP statico), rotte scelte e porta del pannello. Il pannello si riavvia: dopo l'aggiornamento devi rifare l'accesso.

Se sulla scheda non c'è la cartella del progetto (installata con una versione molto vecchia, oppure cancellata), scaricala prima e poi aggiorna:

```sh
git clone --depth 1 https://github.com/Federiko78/Raptor-VPN-OrangePiZero.git /root/Raptor-VPN-OrangePiZero
cd /root/Raptor-VPN-OrangePiZero && sh update.sh
```

Per sapere a che versione è la scheda: in alto a destra nel pannello c'è *Web UI v…*; nella cartella del progetto `git log --oneline -1` mostra l'ultima modifica scaricata.

## Sicurezza

- Password del pannello: minimo **12** caratteri. Script di hardening di SSH, sistema e firewall in ingresso in [`hardening/`](hardening/README.md).
- **Non aprire su Internet la porta TCP del pannello (8443 o quella scelta).**
- Il guard filtra solo il forwarding `tailscale0 → end0`: usa anche le **Grants/ACL Tailscale** e verifica che nessun altro subnet router pubblichi la stessa rete.
- Non committare mai `auth.json`, `*.pem`, `tailscaled.state`, `policy.json`: sono già nel `.gitignore`.

## Sviluppo

```sh
python3 test_release.py      # test simulati, non toccano la rete
python3 test_security.py     # server HTTPS reale su 127.0.0.1 (serve openssl)
python3 test_access.py       # indirizzi link-local, pulizia del vecchio IP di recupero
python3 test_ap.py           # Wi-Fi annuncio-IP
python3 test_port.py         # cambio porta del pannello
python3 test_eventlog.py     # registro eventi (scrittore)
python3 test_tsauth.py       # accesso Tailscale (programma root)
python3 test_panel_account.py # accesso Tailscale (lato pannello)
python3 test_update.py       # update.sh (come root)
python3 test_panel_events.py # registro eventi (lettura nel pannello)
python3 test_panel_i18n.py   # lingue, contatori e JavaScript della pagina (serve node)
sha256sum -c SHA256SUMS      # integrità del pacchetto (usata da install_factory.sh)
```

Se modifichi i file del pacchetto, rigenera `SHA256SUMS`, altrimenti l'installer si ferma alla verifica di integrità.

## Licenza

Nessuna licenza, per scelta. Il codice è pubblico e visibile, ma senza licenza non è concesso a terzi di copiarlo, modificarlo o riusarlo.
