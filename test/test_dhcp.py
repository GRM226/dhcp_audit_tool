from core.sniffer import DHCPSniffer
from core.models import DHCPPacket

# Remplace "en0" par ton interface si besoin
sniffer = DHCPSniffer(interface="en0")
print("Envoi du DHCP Discover...")

raw_packet = sniffer.get_dhcp_offer()

if raw_packet:
    # On passe le paquet brut dans notre modèle
    dhcp_data = DHCPPacket(raw_packet)
    print(f"Réponse reçue du serveur : {dhcp_data.server_ip}")
    print(f"DNS configurés : {dhcp_data.dns_servers}")
    print(f"Nom de domaine : {dhcp_data.options.get('domain_name')}")
else:
    print("Aucune réponse du serveur DHCP. Vérifie ta VM.")

