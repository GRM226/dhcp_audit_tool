import ipaddress
from datetime import datetime,timedelta

confPathFile = "/etc/dhcp/dhcpd.conf"
bauxPathFile = "/var/lib/dhcp/dhcpd.leases"

def check_baux():
    """
        Parcours tous les baux défini dans bauxPathFile et 
        vérifie la validité via checkValiditeBaux de chacun des baux.
        Renvoie vrai si tous les baux respecte la conf donnée dans le fichier de conf
    """
    bauxFile =None
    with open(bauxPathFile,"r") as f:
        bauxFile = f.read()
    
    allStarts = []
    allEnds = []
    allIps = []
    #print(bauxFile)
    bloks = bauxFile.split("lease")[1:]
    
    for boutDeLigne in bloks:
        try:
            start = boutDeLigne.split("starts 3 ")[1]
            start = start.split(";\n")[0]
            allStarts.append(start)
        except IndexError:
            #print("--- Debug ---")
            #print("Pas de correspondance pour 'starts '")
            #print("-------------\n")
            pass
            
    for boutDeLigne in bloks:
        try:
            end = boutDeLigne.split("ends 3 ")[1]
            end = start.split(";\n")[0]
            allEnds.append(end)
        except IndexError:
            #print("--- Debug ---")
            #print("Pas de correspondance pour 'ends '")
            #print("-------------\n")
            pass
        
    with open(bauxPathFile,"r") as f:
        lines = f.readlines()
    
    for line in lines:
        if line.startswith("lease "):
            ip = line.split(" {")[0]
            ip = ip.split("lease ")[1]
            allIps.append(ip)

    valide = True
    for i in range(len(allStarts)):
        bailInfos = (allStarts[i], allEnds[i],allIps[i])
        #print(bailInfos)
        valide = valide and checkValiditeBaux(bailInfos)
    
    if valide :
        return ("OK", "Les baux sont bien conformes à la conf du dhcp")
    return ("FAIL", "Baux pas bien")
    
def checkValiditeBaux(bail): 
    """
        Renvoie vrai si le bail est conforme:
            - adresse IP comprise dans la range de la conf du dhcp
            - Temps de validité du bail égale aux temps défini dans la conf du dhcp
        Paramètres : bail - tuples comprenant trois listes (début bail , fin bail, ip reservée)
    """
    with open(confPathFile,"r") as f:
        confFile = f.readlines()
    ipConf = None
    defaultConf = None
    maxConf = None
    # On catch la ligne qui nous intéresse (on enleve les espaces du début via strip)
    for line in confFile:
        if line.strip().startswith("range "):
            ipConf = line.split("range ")[1]
            ipConf = ipConf.split(";")[0]
            ipConf = tuple(ipConf.split(" "))
        if line.strip().startswith("default-lease-time"):
            defaultConf = line.split("default-lease-time ")[1]
            defaultConf = int(defaultConf.split(";")[0])
        if line.strip().startswith("max-lease-time"):
            maxConf = line.split("max-lease-time ")[1]
            maxConf = int(maxConf.split(";")[0])
            
    #print(defaultConf)
    #print(maxConf) 
    if(ipConf == None) or (maxConf == None) or (defaultConf == None):
        raise ValueError("Fichier de configuration corrompu")
    
    firstIP = ipaddress.ip_address(ipConf[0])
    lastIP = ipaddress.ip_address(ipConf[1])
    if firstIP > ipaddress.ip_address(bail[2]) or lastIP < ipaddress.ip_address(bail[2]) :
        return False
    
    time1 = datetime.strptime(bail[0],"%Y/%m/%d %H:%M:%S")
    time2 = datetime.strptime(bail[1],"%Y/%m/%d %H:%M:%S")
    duration = time2 - time1
    duration = int(duration.total_seconds())
    if duration > maxConf or duration < defaultConf:
        #print("oui")
        return False
    return True