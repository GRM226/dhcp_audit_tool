# dhcp_audit_tool

## Description du projet

Dans le cadre d'un projet en cours de python nous avons dû réaliser un outil qui soit en rapport avec des problématique réseau, ici l'audit d'un reseau et en particulier de son DHCP.
Notre outil permet d'auditer le dhcp d'un reseau en se basant sur des regles strictes qui sont améliorables, modifiables et flexibles en fonction des besoins de l'utilisateur.
Dû à la deadline assez courte, notre projet propose ici les règles primordiales (selon nous) qu'un dhcp doit respecter dans n'importe quelle situation.

### Structure du projet :

```
dhcp_audit_tool/
│
├── main.py # Point d'entrée (lancement du script)
├── requirements.txt # Liste des bibliothèques (scapy, etc.)
│
├── core/ # Le "moteur" du programme
│ ├── init.py
│ ├── sniffer.py # Classe pour capturer les paquets
│ ├── engine.py # Classe qui orchestre l'audit
│ └── models.py # Classes représentant un Paquet DHCP
│
├── rules/ # Dossier contenant vos règles d'audit
│ ├── init.py # Contient la "Classe de Base" pour vos règles
│ ├── dns_rule.py # Règle 1 : Vérifier les DNS
│ ├── lease_rule.py # Règle 2 : Vérifier la durée du bail
│ └── rogue_rule.py # Règle 3 : Détecter un serveur inconnu
│
└── utils/ # Petits outils d'aide
├── logger.py # Pour afficher les alertes en couleur
└── report_gen.py # Pour sauvegarder l'audit en JSON ou texte
```

### Les règles actuellement implémentées : 

- Vérification des règles de bail IP
- Vérification des règles DNS
- Vérification d'une possible présence de serveur rogue DHCP sur le réseau
- Analyse des logs DHCP.
