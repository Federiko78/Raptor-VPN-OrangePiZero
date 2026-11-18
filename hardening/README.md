# Hardening della Orange Pi (da collaudare sulla scheda)

Tre script indipendenti, da lanciare **come root sulla Orange Pi**. Tutti partono in modalità
"mostra cosa farei" e modificano il sistema solo con `--apply` (il firewall con `install`).
Ognuno scrive un solo file di configurazione e si può annullare.

| Script | Cosa fa | Come si annulla |
|---|---|---|
| `harden_ssh.sh` | SSH solo con chiave, niente login root, meno tentativi | `harden_ssh.sh --revert` |
| `harden_system.sh` | LLMNR/mDNS di resolved spenti, solo aggiornamenti di sicurezza Debian, watchdog hardware | cancellare i file indicati a video |
| `input_firewall.sh` | scarta il traffico in ingresso dalla LAN tranne pannello (8443), DHCP, mDNS, ping (+ SSH se voluto) | `input_firewall.sh remove` |

## Ordine consigliato

1. **Chiave SSH**: genera la chiave con PuTTYgen, mettila in `~/.ssh/authorized_keys` dell'utente
   amministratore e verifica di entrare *senza* password. `harden_ssh.sh` si rifiuta di procedere
   se non trova nessuna chiave.
2. `sudo ./harden_ssh.sh` (anteprima), poi `sudo ./harden_ssh.sh --apply`. **Non chiudere la
   sessione aperta**: prova una nuova sessione PuTTY prima di uscire.
3. `sudo ./harden_system.sh`, poi `--apply`.
4. `sudo ./input_firewall.sh plan`, poi `sudo ./input_firewall.sh install`. Dopo aver applicato le
   regole ha 60 secondi per essere confermato: se non premi INVIO le toglie.
5. **Prima di consegnare la scheda**: `sudo ./input_firewall.sh install --ssh-lan off`, dopo aver
   verificato che SSH funzioni via Tailscale (`ssh utente@100.x.y.z`).

## Cosa NON fanno

- Non toccano le ACL di Tailscale. Per le schede dei clienti si consiglia di usare un tag
  (`tag:cliente`) con una chiave di autenticazione e ACL/grants che impediscano al dispositivo del
  cliente di raggiungere qualunque altro nodo della tua tailnet.
- Non sostituiscono la password del pannello (minimo 12 caratteri) né l'aggiornamento del kernel.
