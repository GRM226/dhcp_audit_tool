from core.engine import AuditEngine
#from main import pause
class DHCPReport:
    """ 
        Classe qui permet la génération d'un rapport détaillé de l'audit.
        
        Attributs : 
            fileType = Nom de l'extension du fichier en sortie - par défaut = md ; valeurs possible = md ; pdf
            engine = moteur qui va effectuer l'audit
            path = Emplacement (absolu) de l'export du fichier
    """
    def __init__(self, iface,ipAdd ,xid,fileType = "md",path = "/tmp"):
        self.ipAdd = ipAdd
        self.fileType = fileType
        self.engine = AuditEngine(iface,ipAdd,xid)
        self.xid = xid
        self.path = path
        
    def generateReport(self):
        resultsToExport = self.engine.getResults()
        
        if not(isinstance(resultsToExport[0], str)):
            #print("Génération du Rapport de l'audit")
            #print(resultsToPrint)
            #pause()
            print("Génération de rapport en cours...")
            CONTENUDUFICHEIR = f"# Rapport Audit DHCP {self.ipAdd}\n\n"
            CONTENUDUFICHEIR += "## Résultat par règle\n\n"
                
            
            for r in resultsToExport:
                CONTENUDUFICHEIR += "- Rules --- " + r["rule"] + " = " + r["status"] +" | "+ r["message"]
                CONTENUDUFICHEIR += "\n"
            with open(self.path+"/exportedResults."+self.fileType,"w",encoding="utf-8") as f:
                f.write(CONTENUDUFICHEIR)
            #return resultsToPrint
            print(f"Exportation du fichier {self.path+"/exportedResults."+self.fileType} complétée avec succès")
        
        else:
            print(f"{resultsToExport[0]}")
        
    def loadDatas(self):
        self.engine.run()
        
