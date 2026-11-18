TAILSCALE CONTROL PANEL FACTORY R1.3.2 — WEB UI v1.5.0
Leggere TAILSCALE_PANEL_FACTORY_R1_3_2_INSTALLAZIONE.md (Visual Studio Code).
Installazione da Armbian pulito:
  mkdir -p /root/tspanel-factory-r1.3.2
  cd /root/tspanel-factory-r1.3.2
  python3 -m zipfile -e /root/TAILSCALE_PANEL_FACTORY_R1_3_2.zip .
  sh ./install_factory.sh
Poi: tailscale up
Prima configurazione: policy OFF, lista host vuota, nessuna rotta pubblicata.
NON usare questo install_factory.sh per aggiornare una Orange Pi gia' configurata.
