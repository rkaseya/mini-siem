import re
from datetime import datetime

FICHIER_LOG = "sshd-session.log"
SEUIL = 3       # nombre d'échecs à partir duquel on lève une alerte
FENETRE = 60    # durée de la fenêtre de détection, en secondes

REGEX_IP = r"from (\S+)"
REGEX_UTILISATEUR = r"(?:[Ii]nvalid user|for) (\S+) from"


def max_echecs_dans_fenetre(heures):
    """Renvoie le plus grand nombre d'échecs trouvés dans une fenêtre de FENETRE secondes."""
    heures.sort()
    maximum = 0

    for depart in heures:
        compte = 0
        for heure in heures:
            if heure >= depart and (heure - depart).total_seconds() <= FENETRE:
                compte += 1
        maximum = max(maximum, compte)

    return maximum


def main():
    compteur = {}       # clé : IP, valeur : nombre d'échecs
    utilisateurs = {}   # clé : IP, valeur : liste des utilisateurs tentés
    horaires = {}       # clé : IP, valeur : liste des heures d'échec

    with open(FICHIER_LOG, "r", encoding="utf-8") as fichier:
        for ligne in fichier:
            if "Failed password" in ligne or "Invalid user" in ligne:
                ip = re.search(REGEX_IP, ligne).group(1)
                utilisateur = re.search(REGEX_UTILISATEUR, ligne).group(1)
                texte_date = f"{datetime.now().year} " + " ".join(ligne.split()[:3])
                moment = datetime.strptime(texte_date, "%Y %b %d %H:%M:%S")

                compteur[ip] = compteur.get(ip, 0) + 1

                if ip not in utilisateurs:
                    utilisateurs[ip] = []
                utilisateurs[ip].append(utilisateur)

                if ip not in horaires:
                    horaires[ip] = []
                horaires[ip].append(moment)

    for ip, nb_echecs in compteur.items():
        pic = max_echecs_dans_fenetre(horaires[ip])
        liste_utilisateurs = ", ".join(utilisateurs[ip])

        if pic >= SEUIL:
            print(f"⚠️  ALERTE : {ip} a échoué {pic} fois en moins de {FENETRE} secondes "
                  f"(brute force probable) - utilisateurs : {liste_utilisateurs}")
        else:
            print(f"ℹ️  {ip} - {nb_echecs} échec(s) - utilisateurs : {liste_utilisateurs}")


if __name__ == "__main__":
    main()
