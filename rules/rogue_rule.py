def check_rogue(responses,ipadd,xid):
    """Vérifie la présence de serveurs DHCP rogue sur le réseau en analysant les réponses reçues.
    
    @param responses: liste de tous les paquets capturés lors du scan.
    @param ipadd: server_id du server DHCP visé par l'audit.
    @param xid: transaction ID utilisé pour identifier les réponses légitimes du server DHCP visé. 
    
    @return: un tuple contenant le statut de la vérification ("OK" ou "FAIL") et un message explicatif. 
    """
    
    compteur_server_diff = 0
    
    for resp in responses:
        
        # Vérifie si le paquet à le bon transaction ID, si c'est un paquet envoyé par un server DHCP et si le server_id est différent de celui de notre server DHCP cible.
        if (resp.xid and resp.xid == xid) and (resp.message_type and resp.message_type in [2, 5, 6]) and (resp.server_id and resp.server_id != ipadd):
            print("Y A UN AUTRE SERVER YOUHOU ALERTE GENERAL")
            compteur_server_diff += 1
            
    return ("FAIL", f"Détection de {compteur_server_diff} autre(s) server(s) sur le réseau") if compteur_server_diff > 0 else ("OK", "Aucun server DHCP rogue détecté sur le réseau") 