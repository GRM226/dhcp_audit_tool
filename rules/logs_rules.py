def check_logs(grosPath):
    with open(grosPath,'r')as f:
        lines = f.readlines()
        
    dchpInfos = ["DHCPOFFER", "DHCPACK", "DHCPDISCOVER", "DHCPREQUEST","DHCPNAK"]
    dhcpLogs =[]
    for line in lines:
        
        cleanedLines = line.strip().upper()
        #print(f"voici la ligne {cleanedLines}")
        if any(info in cleanedLines for info in dchpInfos):
            dhcpLogs.append(line.strip())
    #for log in dhcpLogs:
        #print(log)
    
    if(dhcpLogs):
        return ("OK", "Log detecté et bien !")
    return ("FAIL", f"Aucun Log detecté dans {grosPath}")
        
    