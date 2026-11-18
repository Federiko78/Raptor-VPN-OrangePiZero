#!/bin/bash
# Raptor VPN - firewall in INGRESSO (catena INPUT) per Orange Pi.
#
#   input_firewall.sh plan    [--ssh-lan on|off]   mostra le regole, nessuna modifica
#   input_firewall.sh install [--ssh-lan on|off]   installa il servizio d'avvio e applica CON CONFERMA
#   input_firewall.sh apply                        applica la configurazione salvata (lo usa systemd)
#   input_firewall.sh remove                       toglie regole e servizio
#
# Politica: dalla LAN del cliente entra solo il pannello (TCP 8443), il DHCP, mDNS
# (orangepizero.local), ping e, se --ssh-lan on, SSH. Da tailscale0 entra tutto
# (a filtrare provvedono le ACL/Grants Tailscale). Il resto viene scartato.
#
# --ssh-lan on  (predefinito) e' la scelta sicura mentre configuri la scheda.
# --ssh-lan off va impostato PRIMA di consegnarla: SSH resta raggiungibile solo via
# Tailscale. Verifica prima di poter entrare da Tailscale: ssh utente@100.x.y.z
#
# Le regole stanno in una catena dedicata (RAPTOR_IN) agganciata IN FONDO a INPUT, dopo
# la catena ts-input di Tailscale, che non viene toccata. Non usa nftables.
# Se qualcosa va storto resta la console seriale/HDMI: "input_firewall.sh remove".
set -eu

CHAIN=RAPTOR_IN
CONF=/etc/raptor-input-guard.conf
BIN=/usr/local/libexec/raptor-input-guard
UNIT=/etc/systemd/system/raptor-input-guard.service

die() { echo "ERRORE: $*" >&2; exit 1; }

load_conf() {
  LAN_DEV=end0; PANEL_PORT=8443; SSH_LAN=1
  if [ -r /etc/tailscale-panel-lan.conf ]; then
    LAN_DEV=$(head -c 40 /etc/tailscale-panel-lan.conf | tr -d '[:space:]')
  fi
  # shellcheck disable=SC1090
  if [ -r "$CONF" ]; then . "$CONF"; fi
  [[ "$LAN_DEV" =~ ^[A-Za-z0-9._-]{1,15}$ ]] || die "interfaccia LAN non valida: $LAN_DEV"
  [[ "$PANEL_PORT" =~ ^[0-9]{4,5}$ ]] && [ "$PANEL_PORT" -ge 1024 ] && [ "$PANEL_PORT" -le 65535 ] || die "porta pannello non valida: $PANEL_PORT"
  [ "$SSH_LAN" = 0 ] || [ "$SSH_LAN" = 1 ] || die "SSH_LAN deve essere 0 o 1"
}

rules4() {
  cat <<RULES
-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-i lo -j ACCEPT
-i tailscale0 -j ACCEPT
-p udp --dport 41641 -j ACCEPT
-p icmp -j ACCEPT
-i $LAN_DEV -p tcp --dport $PANEL_PORT -j ACCEPT
-i $LAN_DEV -p udp --sport 67 --dport 68 -j ACCEPT
-i $LAN_DEV -p udp --dport 5353 -j ACCEPT
RULES
  if [ "$SSH_LAN" = 1 ]; then echo "-i $LAN_DEV -p tcp --dport 22 -j ACCEPT"; fi
  echo "-j DROP"
}

rules6() {
  cat <<RULES
-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-i lo -j ACCEPT
-i tailscale0 -j ACCEPT
-p udp --dport 41641 -j ACCEPT
-p ipv6-icmp -j ACCEPT
-p udp --sport 547 --dport 546 -j ACCEPT
-i $LAN_DEV -p udp --dport 5353 -j ACCEPT
RULES
  if [ "$SSH_LAN" = 1 ]; then echo "-i $LAN_DEV -p tcp --dport 22 -j ACCEPT"; fi
  echo "-j DROP"
}

plan() {
  echo "Interfaccia LAN: $LAN_DEV | porta pannello: $PANEL_PORT | SSH dalla LAN: $([ "$SSH_LAN" = 1 ] && echo SI || echo NO)"
  echo; echo "# IPv4 (iptables)";  rules4 | sed "s/^/iptables  -A $CHAIN /"
  echo; echo "# IPv6 (ip6tables)"; rules6 | sed "s/^/ip6tables -A $CHAIN /"
  echo; echo "Aggancio: -A INPUT -j $CHAIN (in fondo, dopo ts-input di Tailscale)"
}

apply_family() {   # $1 = iptables|ip6tables, $2 = funzione che stampa le regole
  local ipt="$1" fn="$2" rule
  command -v "$ipt" >/dev/null 2>&1 || { echo "($ipt non disponibile: salto)"; return 0; }
  "$ipt" -w 5 -N "$CHAIN" 2>/dev/null || true
  "$ipt" -w 5 -F "$CHAIN"
  # Durante la ricostruzione la catena non ha ancora il DROP finale: i pacchetti legittimi
  # passano comunque. Il DROP e' l'ultima regola aggiunta.
  while IFS= read -r rule; do
    # shellcheck disable=SC2086
    "$ipt" -w 5 -A "$CHAIN" $rule
  done < <("$fn")
  "$ipt" -w 5 -C INPUT -j "$CHAIN" 2>/dev/null || "$ipt" -w 5 -A INPUT -j "$CHAIN"
}

remove_rules() {
  local ipt
  for ipt in iptables ip6tables; do
    command -v "$ipt" >/dev/null 2>&1 || continue
    while "$ipt" -w 5 -D INPUT -j "$CHAIN" 2>/dev/null; do :; done
    "$ipt" -w 5 -F "$CHAIN" 2>/dev/null || true
    "$ipt" -w 5 -X "$CHAIN" 2>/dev/null || true
  done
}

apply_all() { apply_family iptables rules4; apply_family ip6tables rules6; }

parse_ssh_flag() {   # imposta SSH_LAN dal flag --ssh-lan
  SSH_FLAG=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --ssh-lan) [ $# -ge 2 ] || die "--ssh-lan richiede on oppure off"
                 case "$2" in on) SSH_FLAG=1 ;; off) SSH_FLAG=0 ;; *) die "--ssh-lan: usare on oppure off" ;; esac
                 shift 2 ;;
      *) die "argomento sconosciuto: $1" ;;
    esac
  done
}

CMD=${1:-}; [ $# -eq 0 ] || shift
case "$CMD" in
  plan)
    parse_ssh_flag "$@"; load_conf; [ -z "$SSH_FLAG" ] || SSH_LAN=$SSH_FLAG
    plan ;;
  apply)
    [ "$(id -u)" -eq 0 ] || die "eseguire come root"
    load_conf; apply_all ;;
  install)
    [ "$(id -u)" -eq 0 ] || die "eseguire come root"
    parse_ssh_flag "$@"; load_conf; [ -z "$SSH_FLAG" ] || SSH_LAN=$SSH_FLAG
    plan; echo
    install -d -m 755 /usr/local/libexec
    install -m 755 "$0" "$BIN"
    printf '# Gestito da input_firewall.sh\nPANEL_PORT=%s\nSSH_LAN=%s\n' "$PANEL_PORT" "$SSH_LAN" > "$CONF"
    chmod 644 "$CONF"
    cat > "$UNIT" <<UNITFILE
[Unit]
Description=Raptor VPN - firewall in ingresso (INPUT)
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$BIN apply
ExecStop=$BIN remove-rules

[Install]
WantedBy=multi-user.target
UNITFILE
    systemctl daemon-reload
    apply_all
    if [ -t 0 ]; then
      echo
      echo "Regole applicate. Verifica ORA da un'altra finestra: pannello https://<IP>:$PANEL_PORT"
      [ "$SSH_LAN" = 1 ] || echo "(SSH dalla LAN e' BLOCCATO: verifica l'accesso via Tailscale)"
      echo "Premi INVIO entro 60 secondi per CONFERMARE; altrimenti le regole vengono tolte."
      if read -r -t 60 _; then
        systemctl enable raptor-input-guard.service >/dev/null 2>&1
        echo "Confermato e abilitato all'avvio."
      else
        echo "Nessuna conferma: ripristino."; remove_rules; exit 1
      fi
    else
      systemctl enable raptor-input-guard.service >/dev/null 2>&1
    fi ;;
  remove-rules)
    [ "$(id -u)" -eq 0 ] || die "eseguire come root"
    load_conf; remove_rules ;;
  remove)
    [ "$(id -u)" -eq 0 ] || die "eseguire come root"
    systemctl disable --now raptor-input-guard.service 2>/dev/null || true
    load_conf; remove_rules
    rm -f "$UNIT" "$CONF" "$BIN"; systemctl daemon-reload 2>/dev/null || true
    echo "Firewall in ingresso rimosso." ;;
  *)
    sed -n '2,19p' "$0"; exit 1 ;;
esac
