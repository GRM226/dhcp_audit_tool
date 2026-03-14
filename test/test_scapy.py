from scapy.all import *

iface = "ens4" # Interface réseau par défaut (ens4 dans ce cas)
mac = get_if_hwaddr(iface) # Adresse MAC de l'interface
xid = random.randint(1, 0xFFFFFFFF) # Transaction ID aléatoire (obliogatoire pour la communication DHCP)

fake_mac = "02:13:26:%02x:%02x:%02x" % (
    random.randint(0,255),
    random.randint(0,255),
    random.randint(0,255)
)

dhcp_discover = (
    Ether(dst="ff:ff:ff:ff:ff:ff") /
    IP(src="0.0.0.0", dst="10.1.1.1") /
    UDP(sport=68, dport=67) /
    BOOTP(chaddr=mac, xid=xid) /
    DHCP(options=[("message-type", 1), "end"])
)


def send_request(server_id, offered_ip):
        dhcp_request = (
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="10.1.1.1") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac, xid=xid) /
            DHCP(options= [
                ("message-type", "request"),
                ("server_id", server_id),
                ("requested_addr", offered_ip),
                "end"       
            ])
        )

        print("Envoi du REQUEST DHCP...")
        sendp(dhcp_request, iface=iface, verbose=False)


def handle_dhcp(packet):
    if DHCP in packet and BOOTP in packet:
        if packet[BOOTP].xid != xid: # Vérifie que le transaction ID correspond
            return
        
        for option in packet[DHCP].options:
            if isinstance(option, tuple) and option[0] == "message-type":

                if option[1] == 2: # Offre DHCP
                    print("Offre DHCP reçue")
                    
                    server_id = None
                    for opt in packet[DHCP].options:
                        if isinstance(opt, tuple) and opt[0] == "server_id":
                            server_id = opt[1]

                    offered_ip = packet[BOOTP].yiaddr

                    print(f"IP proposée : {offered_ip}")
                    print(f"Serveur DHCP : {server_id}")

                    send_request(server_id, offered_ip)

                elif option[1] == 5: # ACK DHCP
                    print("ACK DHCP reçu")
                    print(f"IP assignée : {packet[BOOTP].yiaddr}")


sniffer = threading.Thread(
    target=sniff,
    kwargs={
        "filter": "udp and (port 67 or 68)",
        "prn": handle_dhcp,
        "timeout": 3
    }
)

sniffer.start()
time.sleep(0.5)  # laisse le sniff se lancer

sendp(dhcp_discover, iface=iface, verbose=False)

sniffer.join()