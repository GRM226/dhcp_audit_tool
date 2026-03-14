def check_dns(responses, ipadd):
    """Vérifie que tous les paquets envoyés par le server DHCP cible ont un DNS de configuré dans leurs options.
    
    @param responses: liste de tous les paquets capturés lors du scan.
    @param ipadd: server_id du server DHCP visé par l'audit.
    
    @return: un tuple contenant le statut de la vérification ("OK" ou "FAIL") et un message explicatif.
    """
       
    for resp in responses:
        
        # Vérifie si le paquet provient du server DHCP cible, si c'est un paquet envoyé par un server DHCP et si il comporte bien un dns dans les dhcp options.
        if (resp.server_id and resp.server_id == ipadd) and (resp.message_type and resp.message_type in [2, 5, 6]) and not(resp.dns):
            # [2, 5, 6] sont les codes de message_type envoyé par le server (OFFER, ACK, NAK)
            return ("FAIL", "Aucun DNS Fourni")
        
    return ("OK", "DNS configuré")