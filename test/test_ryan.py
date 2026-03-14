from scapy.all import *

dhcp_discover = (
    Ether(dst="ff:ff:ff:ff:ff:ff") /
    IP(src="0.0.0.0", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /
    BOOTP(chaddr=get_if_hwaddr(conf.iface)) /
    DHCP(options=[("message-type", "discover"), "end"])
)

    # Capturer les réponses DHCP Offer
responses = srp(dhcp_discover, timeout=5)

# Liste des plages d'adresses et serveurs DHCP
dhcp_servers = []

for pkt in responses[0]:
    if DHCP in pkt and pkt[DHCP].options[0][1] == 2:  # Vérifie que c'est une réponse DHCP OFFER
        server_ip = pkt[IP].src  # L'adresse IP du serveur DHCP
        offered_ip = pkt[BOOTP].yiaddr  # L'adresse IP proposée par le serveur

        # Affichage des résultats
        print(f"Serveur DHCP : {server_ip} propose l'adresse IP : {offered_ip}")
        dhcp_servers.append((server_ip, offered_ip))

if not dhcp_servers:
    print("Aucun serveur DHCP trouvé.")
else:
    print(f"\nServeurs DHCP détectés : {dhcp_servers}")
