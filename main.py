from utils.report_gen import DHCPReport
from scapy.all import *
import ipaddress

def pause():
    print("Appuyez sur entrée pour continuer : ")
    input()
    return


if __name__ == "__main__":
    iface = conf.iface
    #print(iface)
    listeFormatExportable = ["md" , "pdf", "txt"]
    fileExportType = "md"
    
    # Récupération du type de fichier a exporter
    while True: 
        fileExportType = input(f"Veuillez entrer un format du fichier à exporter : {listeFormatExportable} \n> ")
        if (fileExportType in listeFormatExportable):
            #print(f"Très bien, exporation du fichier sous format .{fileExportType}")
            break
        print("Format non disponible ou erroné")
    
    #Récupération de l'IP
    ipDHCP = "10.1.1.174"
    # TODO spéficier le cas par défaut 
    while True: 
        ipDHCPgiven = input(f"Veuillez fournir l'ip du DHCP à auditer :\n> ")
        try:
            ipDHCP = ipaddress.ip_address(ipDHCPgiven)
        except ValueError:
            if(ipDHCPgiven == ""):
                break
            print("Adresse IP non valide")
    #print(ipDHCP)  
    
    # Création de l'id de la transmission DHCP
    xid = random.randint(1, 0xFFFFFFFF)   
    
    rapport = DHCPReport(iface,ipDHCP,xid,fileExportType)
    rapport.loadDatas()
    rapport.generateReport()
        
        
