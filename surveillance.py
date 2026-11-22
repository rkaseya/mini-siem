import time
from datetime import datetime
from detect_bruteforce import analyser_ligne, analyser_succes, SEUIL, FENETRE, FICHIER_PAR_DEFAUT


def suivre(chemin):
    """Renvoie les nouvelles lignes du fichier au fur et à mesure qu'elles arrivent (comme tail -f)."""
    with open(chemin, "r", encoding="utf-8") as fichier:
        fichier.seek(0, 2)              # on se place à la FIN du fichier : on ignore l'historique
        while True:
            ligne = fichier.readline()
            if not ligne:               # pas de nouvelle ligne pour l'instant...
                time.sleep(1)           # ...on attend 1 seconde et on réessaie
                continue
            yield ligne                 # on "donne" la ligne à la boucle qui nous appelle


def main():
    horaires = {}         # IP -> heures des échecs RÉCENTS (dans la fenêtre)
    derniere_alerte = {}  # IP -> moment de la dernière alerte (anti-répétition)

    print(f"🔎 Surveillance de {FICHIER_PAR_DEFAUT} (Ctrl+C pour arrêter)")
    try: 
        for ligne in suivre(FICHIER_PAR_DEFAUT):
            succes = analyser_succes(ligne)
            if succes:
                ip, utilisateur, methode = succes
                moment = datetime.fromisoformat(ligne.split()[0])

         
                recents = horaires.get(ip, [])

                recents = [h for h in recents if (moment - h).total_seconds() <= FENETRE]

               
                if len(recents) >= SEUIL:
                    print(f"🔴 ALERTE CRITIQUE: {ip} a réussi par bruteforce ({methode}) à se connecter à {utilisateur} à {moment:%Y-%m-%d %H:%M:%S} après {len(recents)} échecs!")

                continue   # une ligne de succès n'est pas un échec : on passe à la suivante
            
            
            
            
            echec = analyser_ligne(ligne)
            if not echec:
                continue
            ip, utilisateur = echec
            moment = datetime.fromisoformat(ligne.split()[0])
            
            if ip not in horaires:
                horaires[ip] = []
            
            horaires[ip].append(moment)

            horaires[ip] = [h for h in horaires[ip] if (moment - h).total_seconds() <= FENETRE]


            if len(horaires[ip]) >= SEUIL:
                derniere = derniere_alerte.get(ip)

                # Pas d'alerte si on en a déjà levé une pour cette IP il y a moins de FENETRE secondes
                if derniere is None or (moment - derniere).total_seconds() > FENETRE:
                    print(f"🚨 [{moment:%Y-%m-%d %H:%M:%S}] ALERTE BRUTE FORCE : "
                        f"{ip} a échoué {len(horaires[ip])} fois en moins de {FENETRE} s "
                        f"(dernier utilisateur visé : {utilisateur})")
                    derniere_alerte[ip] = moment

    except KeyboardInterrupt:
        # Ctrl+C : on quitte proprement au lieu d'afficher une erreur
        print("\n🛑 Surveillance arrêtée.")

        
if __name__ == "__main__":
    main()