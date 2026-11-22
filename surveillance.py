import time
import os
import urllib.request
import sqlite3
from datetime import datetime
from detect_bruteforce import analyser_ligne, analyser_succes, SEUIL, FENETRE, FICHIER_PAR_DEFAUT


# Sujet ntfy lu dans l'environnement (défini dans mini-siem.service), jamais dans le code
NTFY_TOPIC = os.environ.get("NTFY_TOPIC")
# Base des alertes : chemin défini dans le service, fichier local sinon (tests sur le Mac)
BASE_ALERTES = os.environ.get("MINI_SIEM_DB", "alertes.db")


def initialiser_base():
    """Crée la table des alertes si elle n'existe pas encore."""
    with sqlite3.connect(BASE_ALERTES) as connexion:
        connexion.execute("""
            CREATE TABLE IF NOT EXISTS alertes (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                moment      TEXT NOT NULL,     -- date de l'événement (ISO 8601)
                type        TEXT NOT NULL,     -- 'brute_force' ou 'compromission'
                ip          TEXT NOT NULL,
                utilisateur TEXT,
                nb_echecs   INTEGER,
                methode     TEXT,              -- uniquement pour une compromission
                message     TEXT
            )
        """)


def enregistrer_alerte(moment, type_alerte, ip, utilisateur, nb_echecs, methode, message):
    """Ajoute une alerte dans la base SQLite."""
    with sqlite3.connect(BASE_ALERTES) as connexion:
        connexion.execute(
            "INSERT INTO alertes (moment, type, ip, utilisateur, nb_echecs, methode, message) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (moment.isoformat(), type_alerte, ip, utilisateur, nb_echecs, methode, message),
        )


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


def notifier(titre, message, priorite="default", tags=""):
    """Envoie une notification sur le téléphone via ntfy. N'interrompt jamais la surveillance."""
    headers={"Title": titre, "Priority": priorite, "Tags": tags, "User-Agent": "mini-siem"}
    if not NTFY_TOPIC:
        return  # pas de sujet configuré (ex : test sur le Mac) : on n'envoie rien
    requete = urllib.request.Request(
        f"https://ntfy.sh/{NTFY_TOPIC}",
        data=message.encode("utf-8"),
        headers=headers)
        
    try:
        urllib.request.urlopen(requete, timeout=5)
    except Exception as erreur:
        # Panne réseau, ntfy indisponible... : on le signale mais le SIEM continue de tourner
        print(f"⚠️  Échec de l'envoi de la notification : {erreur}")
        

def main():
    horaires = {}         # IP -> heures des échecs RÉCENTS (dans la fenêtre)
    derniere_alerte = {}  # IP -> moment de la dernière alerte (anti-répétition)
    initialiser_base()
    print(f"🔎 Surveillance de {FICHIER_PAR_DEFAUT} (Ctrl+C pour arrêter)")
    if NTFY_TOPIC:
        print("📱 Notifications ntfy activées")
    else:
        print("⚠️  NTFY_TOPIC non défini : notifications désactivées")
    try: 
        for ligne in suivre(FICHIER_PAR_DEFAUT):
            succes = analyser_succes(ligne)
            if succes:
                ip, utilisateur, methode = succes
                moment = datetime.fromisoformat(ligne.split()[0])

         
                recents = horaires.get(ip, [])

                recents = [h for h in recents if (moment - h).total_seconds() <= FENETRE]

               
                if len(recents) >= SEUIL:
                    message_alerte_compromission = f"🔴 ALERTE CRITIQUE: {ip} a réussi par bruteforce ({methode}) à se connecter à {utilisateur} à {moment:%Y-%m-%d %H:%M:%S} après {len(recents)} échecs!"
                    print(message_alerte_compromission)
                    notifier("COMPROMISSION", message_alerte_compromission, "urgent", "red_circle")
                    enregistrer_alerte(moment, "compromission", ip, utilisateur, len(recents), methode, message_alerte_compromission)
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
                    
                    message_alerte_bruteforce = (f"🚨 [{moment:%Y-%m-%d %H:%M:%S}] ALERTE BRUTE FORCE : "
                             f"{ip} a échoué {len(horaires[ip])} fois en moins de {FENETRE} s "
                             f"(dernier utilisateur visé : {utilisateur})")
                    print(message_alerte_bruteforce)
                    notifier("Brute force", message_alerte_bruteforce, "high", "rotating_light")
                    enregistrer_alerte(moment, "brute_force", ip, utilisateur,len(horaires[ip]), None, message_alerte_bruteforce)
                    derniere_alerte[ip] = moment

    except KeyboardInterrupt:
        # Ctrl+C : on quitte proprement au lieu d'afficher une erreur
        print("\n🛑 Surveillance arrêtée.")




if __name__ == "__main__":
    main()