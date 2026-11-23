"""
generer_alertes_test.py - Remplit une base d'alertes FICTIVES pour développer le tableau de bord
================================================================================================

La vraie base (sur siem) ne contient que quelques alertes de test. Pour travailler
le tableau de bord sur le Mac, ce script crée "alertes.db" avec une semaine
d'alertes simulées : plusieurs IP, des brute force et quelques compromissions.

Il réutilise les fonctions de surveillance.py : les alertes sont donc enregistrées
exactement comme le ferait le vrai service.

Utilisation (depuis le dossier mini-siem) :
    python3 outils/generer_alertes_test.py
"""

import os
import random
import sys
from datetime import datetime, timedelta, timezone

# Permet d'importer surveillance.py, qui se trouve dans le dossier parent
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from surveillance import BASE_ALERTES, initialiser_base, enregistrer_alerte  # noqa: E402

random.seed(42)  # mêmes données à chaque exécution

IPS = ["192.168.1.29", "192.168.1.29", "192.168.1.29", "192.168.1.66",
       "192.168.1.66", "10.0.0.13", "172.16.4.20", "192.168.1.14"]
UTILISATEURS = ["admin", "root", "test", "oracle", "guest", "ubuntu", "pi", "remikaseya"]


def main():
    if os.path.exists(BASE_ALERTES):
        os.remove(BASE_ALERTES)  # on repart d'une base vide
    initialiser_base()

    maintenant = datetime.now(timezone.utc).replace(microsecond=0)
    nb = 0
    for jour in range(7, -1, -1):
        for _ in range(random.randint(2, 9)):
            moment = maintenant - timedelta(days=jour, hours=random.randint(0, 23), minutes=random.randint(0, 59))
            ip = random.choice(IPS)
            utilisateur = random.choice(UTILISATEURS)
            echecs = random.randint(3, 12)

            message = (f"🚨 [{moment:%Y-%m-%d %H:%M:%S}] ALERTE BRUTE FORCE : {ip} a échoué "
                       f"{echecs} fois en moins de 60 s (dernier utilisateur visé : {utilisateur})")
            enregistrer_alerte(moment, "brute_force", ip, utilisateur, echecs, None, message)
            nb += 1

            # De temps en temps, le brute force réussit : compromission
            if random.random() < 0.08:
                moment_succes = moment + timedelta(seconds=random.randint(5, 40))
                methode = random.choice(["password", "publickey"])
                message = (f"🔴 ALERTE CRITIQUE: {ip} a réussi par bruteforce ({methode}) à se connecter "
                           f"à {utilisateur} à {moment_succes:%Y-%m-%d %H:%M:%S} après {echecs} échecs!")
                enregistrer_alerte(moment_succes, "compromission", ip, utilisateur, echecs, methode, message)
                nb += 1

    # Une alerte "piégée", comme pourrait l'envoyer un attaquant :
    # elle sert à vérifier que le tableau de bord n'exécute pas de HTML venu des logs (XSS).
    piege = "<script>alert('XSS')</script>"
    enregistrer_alerte(maintenant, "brute_force", "192.168.1.66", piege, 4, None,
                       f"🚨 ALERTE BRUTE FORCE : utilisateur piégé {piege}")
    nb += 1

    print(f"✅ {nb} alertes fictives écrites dans {BASE_ALERTES}")


if __name__ == "__main__":
    main()
