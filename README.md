# Raptor VPN · Orange Pi Zero

Pannello di controllo **Tailscale** per **Orange Pi Zero** usato come *subnet router* da lasciare nella rete di un cliente.

L'installatore collega la scheda alla LAN del cliente, apre il pannello dal browser, scansiona i dispositivi della rete e sceglie quali rendere raggiungibili da remoto tramite Tailscale. Nessuna configurazione sul router del cliente.

> Stato: baseline **Factory R1.3.2 · Web UI v1.5.0**. Come indicato nella guida di installazione, la Factory non è ancora stata dichiarata STABLE: mancano i test hardware su una scheda nuova (installazione, riavvio, traffico consentito/bloccato).

## Cosa fa

- Web UI HTTPS sulla porta **8443**, raggiungibile **solo dalla LAN Ethernet** (socket systemd legato a `end0`, mai su `tailscale0` né Wi-Fi).
- Accesso con password (PBKDF2-SHA256), sessioni con CSRF, limite ai tentativi di login.
- **LAN Device Discovery**: scanner ARP (IP, MAC, produttore, hostname) della sola rete locale.
- Pubblicazione rotte Tailscale in tre modalità: nessuna LAN, intera subnet, **solo dispositivi selezionati (/32)**.
- **Guard di forwarding** `iptables -t mangle` che parte prima di `tailscaled` e blocca per default `tailscale0 → LAN`.
- DHCP o IP statico via Netplan, con **conferma entro 150 s** e rollback automatico.
- Helper root con schema JSON fisso, nessuna shell; `sudo` limitato a tre comandi senza argomenti.
- **Wi-Fi "Raptor VPN - <IP>"** per ~1 minuto dopo l'avvio: l'installatore legge l'IP assegnato dal DHCP dal telefono.
- **IP di recupero** `169.254.X.Y` scelto da te: raggiunge sempre il pannello dalla stessa LAN, anche con Tailscale spento o IP sconosciuto (la password resta obbligatoria). Vedi [`ACCESSO_DI_SERVIZIO.md`](ACCESSO_DI_SERVIZIO.md).

## Requisiti

- Orange Pi Zero con **Armbian Debian 13 (Trixie) Minimal, armhf**, Ethernet `end0`, `systemd-networkd` e Netplan.
- microSD da 16 GB o più (almeno 450 MiB liberi), Internet temporaneo per apt/Tailscale.

## Installazione (scheda nuova)

Da root, in una sessione SSH interattiva:

```sh
git clone https://github.com/Federiko78/Raptor-VPN-OrangePiZero.git
cd Raptor-VPN-OrangePiZero
sh ./install_factory.sh
tailscale up
```

L'installer è pensato **solo per un Armbian pulito**: si ferma se trova credenziali, policy o servizi già presenti. Dettagli, verifiche e rollback sono in [`TAILSCALE_PANEL_FACTORY_R1_3_2_INSTALLAZIONE.md`](TAILSCALE_PANEL_FACTORY_R1_3_2_INSTALLAZIONE.md).

## Sicurezza

- Password del pannello: minimo **12** caratteri. Script di hardening di SSH, sistema e firewall in ingresso in [`hardening/`](hardening/README.md).
- **Non aprire la porta TCP 8443 su Internet.**
- Il guard filtra solo il forwarding `tailscale0 → end0`: usa anche le **Grants/ACL Tailscale** e verifica che nessun altro subnet router pubblichi la stessa rete.
- Non committare mai `auth.json`, `*.pem`, `tailscaled.state`, `policy.json`: sono già nel `.gitignore`.

## Sviluppo

```sh
python3 test_release.py      # test simulati, non toccano la rete
python3 test_security.py     # server HTTPS reale su 127.0.0.1 (serve openssl)
python3 test_access.py       # IP di recupero
python3 test_ap.py           # Wi-Fi annuncio-IP
sha256sum -c SHA256SUMS      # integrità del pacchetto (usata da install_factory.sh)
```

Se modifichi i file del pacchetto, rigenera `SHA256SUMS`, altrimenti l'installer si ferma alla verifica di integrità.

## Licenza

Da definire.
