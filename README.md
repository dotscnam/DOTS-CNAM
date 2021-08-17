# DOTS (DDOS Open Threat Signaling)

### Quelques mots sur DOTS
« Contrairement à d’autres systèmes anti-DDOS, DDOS Open Threat Signaling (DOTS) n’est pas une solution qui empêche les attaques DDOS, mais plutôt un système qui facilite la coordination entre plusieurs acteurs, lorsque ceux-ci doivent atténuer une attaque DDOS. Grâce à cette technologie, la victime pourra rapidement demander le soutien d’un défenseur » [RFC 8612]. L’objectif de cet article est de détailler le fonctionnement de DOTS et l’architecture associée. Puis, de présenter un Proof Of Concept (POC), afin de prouver que lors d’une attaque, la victime peut continuer à délivrer les services attendus. 

En une phrase: DOTS va permettre de demander une redirection des flux à un défenseur, celui ci prendra en charge l’analyse et le traitement des flux illégitimes puis renverra le trafic qu’il considère légitime au client.

## Trois éléments dans l'architecture proposée:

### Client DOTS
Le client DOTS permet de demander une mitigation anti-DDOS au fournisseur, il utilise les ressources COAP en utilisant un système proche de REST. Il ping le data server tous les x secondes.

Le client DOTS n’a pas pour vocation de détecter un évènement ou une attaque. Il peut s’appuyer sur divers systèmes permettant de détecter une attaque comme un IDS par exemple.
SNORT est configuré pour créer un fichier uniquement quand une attaque a lieu  ; dans le projet le client DOTS détecte le création d’un fichier SNORT et va donc envoyer une demande de mitigation.


### Serveur de signalement
Le serveur DOTS est séparé pour des raisons de sécurité. Le signal server permet de recevoir la demande de mitigation en provenance de clients DOTS. 

Il génère les nonces nécessaires à la demande de mitigation du client DOTS. Si le client demande une certaine ressource via COAP, et envoie dans le champs payload une nonce valide pour la requête correspondante, alors la ressource est livrée. La ressource demandée par le client DOTS peut être une demande de mitigation DDOS.

### Serveur de données 
Le data channel est l’autre partie du serveur DOTS. Il permet de réaliser de la télémétrie et il peut être vu comme le système d’authentification du client puisque c’est lui qui fournit les nonces cryptographiques. 

La télémétrie permet de savoir si le client est présent ou si il rencontre des problèmes ; suivant la configuration le data server peut alors demander une analyse des flux si le client ne répond plus durant un laps de temps défini. Les échanges sont chiffrés via ce canal en utilisant TLS.

En une image : ![alt text](.\github\uml.jpg "diagramme de fonctionnement UML")

## Fonctionnement
Le client DOTS vérifie si il possède des nonces -  éléments indispensables pour l'envoi de requêtes  de mitigation. Si il n’y en a pas, le data server lui en fournira via une connexion TLS. Ces nonces sont générés par le signal server.

Une fois que le client DOTS possède assez de nonces alors il passe en mode opérationnel. Il va pouvoir vérifier si l’IDS reporte des alertes. Si il en reporte alors il va demander une mitigation ; typiquement, une demande de reroutage, et/ou éventuellement des mesures de contre-attaque.

Le signal server vérifie si la nonce est valide et connaît donc les attributs du client-DOTS. Il réalise alors une demande de mitigation. Une fois la mitigation prise en compte le client DOTS rechargera son stock de nonces pour de futures évènements ou attaques.

Le data server reçoit de la télémétrie via un canal TLS entre le clients DOTS et le data server DOTS (lui-même donc). Si le client est absent pendant trop longtemps, une analyse des flux est effectuée et donc le trafic est temporairement rerouté. 

## INSTALL / USAGE
Le POC est fonctionnel sur une seule machine.

Mettre à jour vos paquets:
```
apt update
```
Vérifier les requirements : (Tout n'est pas nécessaire, ici tous les packages installés sur la machine de test)
```
client-and-signal-dots/requirement.txt
```

Copier tous les fichiers dans le repertoire de votre choix.

Vérifier si les fichiers sont exécutables puis activer la défense DOTS:

```
python3 signalchannelDOTS.py
python3 datachannelDOTS.py
python3 clientDOTS.py
```

Ici tout est lancé sur un seul et même poste mais en réalité signalchannelDOTS.py et datachannelDOTS.py seront du côté du fournisseur du service.

Puis vous pouvez lancer l'attaque :
```
python3 ddos.py
ip to attack = ip locale
Number of IPs = entre 1 et 255 (ce sont les ips dans ddos_simulation/ips.)
Number of Message by ip : autant que souhaité
Interface : Interface utilisé pour lancer l'attaque (eth0 par exemple)
Select type : 1 pour flood attack
Select ip origin : 1 pour utilisé les ips dans ddos_simulation/ips.txt

L'attaque est lancée !

```

Ce que va détecter le client est la création d'un fichier snort dans un répertoire précis.

```
def trigger(): #check every 5 second if snortfile is createdm in our case snort create file only if it detects attack
    threading.Timer(5.0, trigger).start()
    mypath = '/home/debian/Documents/snortfiles'
```
Vous pouvez changer ce repertoire à souhait.

Pour mener à bien ce POC dans le script de DDOS, une ligne à été rajoutée:
```
os.system('''cp /home/debian/Documents/fichier_alertes_snort /home/debian/Documents/snortfiles''')
```
 Cela va déclencher la fonction trigger() du clientDOTS est ainsi stopper l'attaque via une règle de pare feu qui sera en réalité une rédirection BGP dans la réalité.

 C'est le script signalchannelDOTS.py qui enclenche le changement des règles de parefeu:
```
 os.system('''sudo /home/debian/Documents/dropddos.sh''')
```

L'attaque est maintenant stoppée. Le client va alors demandé de nouvelles nonces pour de futures attaques.

## Démonstration

![Alt Text](https://media.giphy.com/media/Xl8H3n8sT6Uf8xeTzK/source.gif)


