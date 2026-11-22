"""
detect_bruteforce.py - Détecteur d'attaques par force brute SSH
================================================================

Ce script fait partie de mon mini-SIEM. Il lit un fichier de logs SSH
(produit par OpenSSH et centralisé avec rsyslog) et repère les adresses IP
qui échouent trop souvent à se connecter dans un court laps de temps.

Principe :
    1. Lecture du fichier ligne par ligne.
    2. Pour chaque échec de connexion (mot de passe refusé, utilisateur
       inexistant, ou utilisateur existant non authentifié), extraction
       de l'IP source, de l'utilisateur visé et de l'heure.
    3. Pour chaque IP, recherche du plus grand nombre d'échecs
       survenus dans une fenêtre de FENETRE secondes.
    4. Si ce nombre atteint SEUIL : alerte (brute force probable).

Pourquoi une fenêtre de temps ?
    3 échecs en 10 secondes = un robot qui teste des mots de passe.
    3 échecs étalés sur une journée = un humain qui se trompe.
    Sans fenêtre, le second cas serait un "faux positif".

Format attendu des logs (rsyslog, dates ISO 8601) :
    2026-11-20T11:38:07+00:00 ubuntu-01 sshd-session[3478]: Invalid user admin from 192.168.1.29 port 36864

Utilisation :
    sudo python3 detect_bruteforce.py                 # sur siem, vrais logs
    python3 detect_bruteforce.py sshd-session.log     # test avec un autre fichier
"""

import re                      # expressions régulières, pour extraire l'IP et l'utilisateur
import sys                     # pour lire le fichier à analyser passé en argument
from datetime import datetime  # pour convertir les dates des logs et calculer des écarts


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Fichier de logs SSH à analyser : passé en argument, sinon les vrais logs de siem par défaut.
#   sudo python3 detect_bruteforce.py                  -> vrais logs (sur siem)
#   python3 detect_bruteforce.py sshd-session.log      -> fichier de test (sur le Mac)
# sys.argv est la liste des mots tapés après "python3" : sys.argv[1] est le 1er argument.
FICHIER_PAR_DEFAUT = "/var/log/remote/ubuntu-01/sshd-session.log"
FICHIER_LOG = sys.argv[1] if len(sys.argv) > 1 else FICHIER_PAR_DEFAUT
SEUIL = 3                         # nombre d'échecs à partir duquel on lève une alerte
FENETRE = 60                      # durée de la fenêtre de détection, en secondes

# Motifs des lignes d'échec écrites par OpenSSH.
# Chaque motif capture deux informations grâce à des "groupes nommés" :
#   (?P<utilisateur>...) -> le nom d'utilisateur visé
#   (?P<ip>...)          -> l'adresse IP source
# \S+ signifie "une suite de caractères sans espace" (un mot).
MOTIFS_ECHEC = [
    # Mot de passe refusé, pour un utilisateur existant ou non :
    #   "Failed password for remikaseya from 192.168.1.14 port 49376 ssh2"
    #   "Failed password for invalid user test from 192.168.1.20 port 51245 ssh2"
    r"Failed password for (?:invalid user )?(?P<utilisateur>\S+) from (?P<ip>\S+) port",

    # Utilisateur qui n'existe pas sur la machine :
    #   "Invalid user admin from 192.168.1.29 port 36864"
    r"[Ii]nvalid user (?P<utilisateur>\S+) from (?P<ip>\S+) port",

    # Utilisateur qui EXISTE (ex : root), mais qui n'a pas pu s'authentifier.
    # Comme les mots de passe sont désactivés, OpenSSH n'écrit ni "Invalid user"
    # ni "Failed password" : sans ce motif, l'attaque passerait inaperçue.
    # Attention : ici il n'y a pas de "from" avant l'IP.
    #   "Connection closed by authenticating user root 192.168.1.29 port 51234 [preauth]"
    #   "Disconnected from authenticating user root 192.168.1.29 port 51234 [preauth]"
    r"(?:Connection closed by|Disconnected from) authenticating user (?P<utilisateur>\S+) (?P<ip>\S+) port",
]


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
# Analyse d'une ligne de log (le "parseur")
# ---------------------------------------------------------------------------

def analyser_ligne(ligne):
    """Si la ligne est un échec de connexion, renvoie (ip, utilisateur). Sinon, renvoie None.

    On essaie chaque motif de MOTIFS_ECHEC l'un après l'autre :
    dès qu'un motif correspond, on renvoie ce qu'il a capturé.
    """
    for motif in MOTIFS_ECHEC:
        resultat = re.search(motif, ligne)
        if resultat:
            return resultat.group("ip"), resultat.group("utilisateur")
    # Aucun motif ne correspond : ce n'est pas un échec (ex : "Accepted publickey").
    return None


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

            # On cherche si la ligne correspond à un échec de connexion.
            # Les autres lignes (ex : "Accepted publickey") sont ignorées.
            echec = analyser_ligne(ligne)
            if echec:

                # analyser_ligne() renvoie deux valeurs : on les range dans deux variables.
                ip, utilisateur = echec

                # Extraction de la date : c'est le 1er mot de la ligne.
                # rsyslog l'écrit au format ISO 8601, ex : "2026-11-20T11:17:28+00:00"
                # (année, jour, heure et fuseau horaire en un seul bloc).
                texte_date = ligne.split()[0]

                # fromisoformat() convertit directement ce format en objet datetime,
                # fuseau horaire compris : pas besoin de décrire le format à la main.
                moment = datetime.fromisoformat(texte_date)

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
