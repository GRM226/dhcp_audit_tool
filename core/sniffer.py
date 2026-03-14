from scapy.all import *
import threading
import time
from core.models import DHCPPacket

class DHCPScanner:
    def __init__(self, iface, xid):
        self.iface = iface
        self.responses = []
        self.xid = xid
        
    def make_fake_mac(self):
        """Création d'une fausse adresse MAC.
        
        @return: fausse adresse MAC(str).
        """
        return "02:13:26:%02x:%02x:%02x" % (
            random.randint(0,255),
            random.randint(0,255),
            random.randint(0,255)
        )

    def build_discover(self):
        """Création d'un paquet de discover (en vu de scanner les réponses de potentiel server dhcp).
        
        return: un paquet DISCOVER DHCP (_PacketIterable)
        """
        return (
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="10.1.1.1") /
            UDP(sport= 68, dport=67) /
            BOOTP(chaddr=self.make_fake_mac(), xid=self.xid) /
            DHCP(options=[("message-type", "discover"), "end"]  )
        )

    def send_discover(self):
        sendp(self.build_discover(), iface=self.iface, verbose=False)

    def handle_dhcp(self, packet):
        """Fonction qui gère les paquets capturés pendant le scan. Seulement les paquets DHCP sont gardés et stockés dans une liste.
        
        @param packet: instance d'un paquet capturé par scapy lors du scan.   
        """
        
        if DHCP in packet and BOOTP in packet and packet[BOOTP].xid == self.xid:

            if packet[BOOTP].op == 1 and packet[IP].src == "0.0.0.0":
                return # Ignorer les paquets DHCP Discover envoyés par d'autres machines et par nous même.

            # Récupère les options du paquet DHCP et les mets dans un dictionnaire pour les manipulées plus facilement par la suite.
            dhcp_options = {}
            for opt in packet[DHCP].options:
                if isinstance(opt, tuple):
                    dhcp_options[opt[0]] = opt[1]

            # Crée l'instance de DHCPPacket en recopiant seulement les infos utiles du paquet capturé
            response = DHCPPacket(
                message_type=dhcp_options.get("message-type"),
                server_id=dhcp_options.get("server_id"),
                xid=packet[BOOTP].xid,
                offered_ip=packet[BOOTP].yiaddr,
                lease_time=dhcp_options.get("lease_time"),
                router=dhcp_options.get("router"),
                dns=dhcp_options.get("name_server"),
                domain=dhcp_options.get("domain")
            )

            self.responses.append(response)
            
    
    def scan(self, timeout=5):
        """Fonction qui lance le scan (thread), envoie les paquets de test DISCOVER DHCP et appel handle_dhcp pour récupérer les paquets DHCP.
        
        @param timeout: temps total du scan (égale à 5s par défaut).
        
        @return: liste de DHCPPacket représenant l'ensemble des paquets DHCP capturés lors du scan.
        """
        
        
        sniffer = threading.Thread(
            target=sniff,
            kwargs={
                "filter": "udp and (port 67 or 68)",
                "prn": self.handle_dhcp,
                "timeout": timeout,
            }
        )
        sniffer.start()
        time.sleep(1)
        self.send_discover()
        self.send_discover()
        sniffer.join()
        return self.responses