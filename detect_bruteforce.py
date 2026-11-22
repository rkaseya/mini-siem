"""
detect_bruteforce.py - Détecteur d'attaques par force brute SSH
================================================================

Ce script fait partie de mon mini-SIEM. Il lit un fichier de logs SSH
(produit par OpenSSH et centralisé avec rsyslog) et repère les adresses IP
qui échouent trop souvent à se connecter dans un court laps de temps.

Principe :
    1. Lecture du fichier ligne par ligne.
    2. Pour chaque échec de connexion, extraction de l'IP source,
       de l'utilisateur visé et de l'heure.
    3. Pour chaque IP, recherche du plus grand nombre d'échecs
       survenus dans une fenêtre de FENETRE secondes.
    4. Si ce nombre atteint SEUIL : alerte (brute force probable).

Pourquoi une fenêtre de temps ?
    3 échecs en 10 secondes = un robot qui teste des mots de passe.
    3 échecs étalés sur une journée = un humain qui se trompe.
    Sans fenêtre, le second cas serait un "faux positif".

Utilisation :
    python3 detect_bruteforce.py
"""

import re                      # expressions régulières, pour extraire l'IP et l'utilisateur
from datetime import datetime  # pour convertir les dates des logs et calculer des écarts


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

FICHIER_LOG = "sshd-session.log"  # fichier de logs SSH à analyser
SEUIL = 3                         # nombre d'échecs à partir duquel on lève une alerte
FENETRE = 60                      # durée de la fenêtre de détection, en secondes

# Capture le "mot" qui suit "from" : c'est l'adresse IP source.
# Exemple : "... from 192.168.1.20 port 51234" -> "192.168.1.20"
REGEX_IP = r"from (\S+)"

# Capture le nom d'utilisateur visé. Gère les trois formats d'OpenSSH :
#   "Failed password for remikaseya from ..."         -> remikaseya
#   "Invalid user admin from ..."                     -> admin
#   "Failed password for invalid user test from ..."  -> test
# Le " from" final sert d'ancre : il évite de capturer le mot "invalid"
# dans le troisième cas.
REGEX_UTILISATEUR = r"(?:[Ii]nvalid user|for) (\S+) from"


# ---------------------------------------------------------------------------
# Règle de détection
# ---------------------------------------------------------------------------

def max_echecs_dans_fenetre(heures):
    """Renvoie le plus grand nombre d'échecs trouvés dans une fenêtre de FENETRE secondes.

    Chaque échec sert tour à tour de point de départ : on compte combien
    d'échecs ont lieu entre ce départ et FENETRE secondes plus tard,
    puis on garde le plus grand de ces comptes.

    Exemple avec FENETRE = 60 :
        heures = 11:05:22, 11:05:24, 11:05:27, 11:05:29
        départ 11:05:22 -> 4 échecs avant 11:06:22 -> maximum = 4
    """
    # Les logs ne sont pas toujours dans l'ordre : on trie les heures
    # pour que la notion de "avant / après" ait un sens.
    heures.sort()
    maximum = 0

    for depart in heures:
        compte = 0
        for heure in heures:
            # L'échec est dans la fenêtre s'il a lieu après le départ (ou en même temps)
            # et au plus FENETRE secondes plus tard.
            if heure >= depart and (heure - depart).total_seconds() <= FENETRE:
                compte += 1
        # Une fois tous les échecs comptés pour ce départ, on garde le plus grand compte.
        maximum = max(maximum, compte)

    return maximum


# ---------------------------------------------------------------------------
# Programme principal
# ---------------------------------------------------------------------------

def main():
    # Trois dictionnaires, tous indexés par adresse IP :
    compteur = {}       # IP -> nombre total d'échecs          ex : {"192.168.1.20": 4}
    utilisateurs = {}   # IP -> liste des utilisateurs tentés  ex : {"192.168.1.20": ["admin", "root"]}
    horaires = {}       # IP -> liste des heures d'échec       ex : {"192.168.1.20": [datetime, ...]}

    # --- 1. Lecture et extraction ------------------------------------------
    # Toute l'extraction se fait pendant la lecture, ligne par ligne.
    with open(FICHIER_LOG, "r", encoding="utf-8") as fichier:
        for ligne in fichier:

            # On ne garde que les lignes d'échec de connexion.
            # Les autres (ex : "Accepted publickey") sont ignorées.
            if "Failed password" in ligne or "Invalid user" in ligne:

                # Extraction de l'IP source et de l'utilisateur visé.
                # .group(1) renvoie ce qui a été capturé entre parenthèses dans la regex.
                ip = re.search(REGEX_IP, ligne).group(1)
                utilisateur = re.search(REGEX_UTILISATEUR, ligne).group(1)

                # Extraction de la date : ce sont les 3 premiers mots de la ligne,
                # ex : "Nov 20 11:05:22". Le format syslog ne contient pas l'année,
                # on ajoute donc l'année en cours (obligatoire depuis Python 3.15).
                # Limite connue : des logs du 31 décembre lus le 1er janvier
                # seraient datés de la mauvaise année (sans impact sur les écarts).
                texte_date = f"{datetime.now().year} " + " ".join(ligne.split()[:3])
                moment = datetime.strptime(texte_date, "%Y %b %d %H:%M:%S")

                # Comptage : get() renvoie 0 si l'IP n'a encore jamais été vue.
                compteur[ip] = compteur.get(ip, 0) + 1

                # Liste des utilisateurs : on crée la liste à la 1re apparition
                # de l'IP, puis on y ajoute l'utilisateur à chaque échec.
                if ip not in utilisateurs:
                    utilisateurs[ip] = []
                utilisateurs[ip].append(utilisateur)

                # Même principe pour les heures d'échec.
                if ip not in horaires:
                    horaires[ip] = []
                horaires[ip].append(moment)

    # --- 2. Analyse et affichage -------------------------------------------
    # La lecture est terminée : on applique la règle de détection à chaque IP.
    for ip, nb_echecs in compteur.items():
        pic = max_echecs_dans_fenetre(horaires[ip])
        liste_utilisateurs = ", ".join(utilisateurs[ip])

        if pic >= SEUIL:
            # Trop d'échecs en peu de temps : comportement typique d'un outil automatisé.
            print(f"⚠️  ALERTE : {ip} a échoué {pic} fois en moins de {FENETRE} secondes "
                  f"(brute force probable) - utilisateurs : {liste_utilisateurs}")
        else:
            # Échecs isolés ou espacés : simple information.
            print(f"ℹ️  {ip} - {nb_echecs} échec(s) - utilisateurs : {liste_utilisateurs}")


# Ce bloc ne s'exécute que si on lance le fichier directement
# (python3 detect_bruteforce.py), et pas s'il est importé depuis un autre script.
if __name__ == "__main__":
    main()
