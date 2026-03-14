from core.sniffer import DHCPScanner
from core.models import DHCPPacket
from rules.dns_rules import check_dns
from rules.rogue_rule import check_rogue
from rules.logs_rules import check_logs
from rules.baux_rules import check_baux


class AuditEngine:
    def __init__(self, iface,ipAdd,xid):
        self.scanner = DHCPScanner(iface, xid)
        self.ipAdd = ipAdd
        self.xid = xid
        self.__datas = []

    def run(self):
        # TODO faire en sorte que l'on puisse selectionner les regles à appliquer dans l'audit
        responses = self.scanner.scan()
        results = []
        
        #responses = []

        if responses != []:
        
            # Appel de la fonction qui test la configuration d'un server DNS
            statusDNS, msgDNS = check_dns(responses, self.ipAdd)
            results.append({
                    "rule": "DNS",
                    "status": statusDNS,
                    "message": msgDNS
                })
            
            # Ajoute un faut paquet simulant un rogue DHCP server
            """
            fake_rogue_server = DHCPPacket(server_id="192.168.10.10", xid=self.xid, message_type=2)
            responses.append(fake_rogue_server)
            """
            
            # Appel de la fonction qui test la présence de plusieurs server DHCP
            status,msg = check_rogue(responses, self.ipAdd, self.xid)
            results.append({
                    "rule": "Rogue",
                    "status": status,
                    "message": msg
                })
            
            # Supprétion du faux paquet pour le test du rogue DHCP server
            """responses.remove(fake_rogue_server)"""
            
            grospath = "/var/log/dhcpd.log"
            status,msg = check_logs(grospath)
            results.append({
                    "rule": "Logs",
                    "status": status,
                    "message": msg
                })
            
            status,msg = check_baux()
            results.append({
                    "rule": "Baux",
                    "status": status,
                    "message": msg
                })

        else:
            results.append(f"Aucun test n'a été effectués, aucun paquet DHCP capturé")
        
        self.datas = results
      
        
    def getResults(self):
        return self.datas