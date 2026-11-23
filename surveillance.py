"""
surveillance.py - Surveillance en temps réel du mini-SIEM
=========================================================

Suit en continu les logs centralisés sur siem et lève des alertes au fil de l'eau :

    🚨 Brute force    : au moins SEUIL échecs SSH d'une même IP en FENETRE secondes   (MITRE T1110)
    🔴 Compromission  : connexion réussie d'une IP juste après un brute force          (MITRE T1078)
    🔍 Scan de ports  : au moins SEUIL_PORTS ports différents bloqués par le pare-feu  (MITRE T1046)

Chaque alerte est :
    - affichée (journal système, via journalctl quand le script tourne en service) ;
    - envoyée sur le téléphone (ntfy) ;
    - enregistrée dans la base SQLite lue par le tableau de bord.

Configuration par variables d'environnement (définies dans mini-siem.service) :
    NTFY_TOPIC     sujet ntfy des notifications (un secret : jamais dans le code)
    MINI_SIEM_DB   chemin de la base des alertes (par défaut : alertes.db)

Utilisation :
    sudo python3 surveillance.py      # lancement manuel, arrêt avec Ctrl+C
"""

import os
import sqlite3
import time
import urllib.request

from detect_bruteforce import (
    FENETRE,
    FICHIER_PAR_DEFAUT,
    SEUIL,
    analyser_ligne,
    analyser_scan,
    analyser_succes,
    lire_moment,
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Fichiers surveillés : authentification SSH et blocages du pare-feu (log du noyau)
FICHIER_SSH = FICHIER_PAR_DEFAUT
FICHIER_PARE_FEU = "/var/log/remote/ubuntu-01/kernel.log"

# Nombre de ports DIFFÉRENTS bloqués en FENETRE secondes pour parler de scan.
# Volontairement bas : ufw limite ses messages (environ 3 par minute après une
# première rafale), un scan de 1 000 ports ne laisse souvent que 2 à 3 lignes.
SEUIL_PORTS = 3

# Sujet ntfy lu dans l'environnement (défini dans mini-siem.service), jamais dans le code
NTFY_TOPIC = os.environ.get("NTFY_TOPIC")

# Base des alertes : chemin défini dans le service, fichier local sinon (tests sur le Mac)
BASE_ALERTES = os.environ.get("MINI_SIEM_DB", "alertes.db")


# ---------------------------------------------------------------------------
# Stockage des alertes (SQLite)
# ---------------------------------------------------------------------------

def initialiser_base():
    """Crée la table des alertes si elle n'existe pas encore."""
    with sqlite3.connect(BASE_ALERTES) as connexion:
        connexion.execute("""
            CREATE TABLE IF NOT EXISTS alertes (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                moment      TEXT NOT NULL,     -- date de l'événement (ISO 8601)
                type        TEXT NOT NULL,     -- 'brute_force', 'compromission' ou 'scan_ports'
                ip          TEXT NOT NULL,
                utilisateur TEXT,              -- vide pour un scan de ports
                nb_echecs   INTEGER,           -- nombre d'échecs, ou de ports pour un scan
                methode     TEXT,              -- uniquement pour une compromission
                message     TEXT
            )
        """)


def enregistrer_alerte(moment, type_alerte, ip, utilisateur, nb_echecs, methode, message):
    """Ajoute une alerte dans la base SQLite.

    Les valeurs sont passées en paramètres (?) et jamais insérées dans le texte SQL :
    l'IP et l'utilisateur viennent des logs, donc potentiellement d'un attaquant
    (protection contre l'injection SQL).
    """
    with sqlite3.connect(BASE_ALERTES) as connexion:
        connexion.execute(
            "INSERT INTO alertes (moment, type, ip, utilisateur, nb_echecs, methode, message) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (moment.isoformat(), type_alerte, ip, utilisateur, nb_echecs, methode, message),
        )


# ---------------------------------------------------------------------------
# Notifications (ntfy)
# ---------------------------------------------------------------------------

def notifier(titre, message, priorite="default", tags=""):
    """Envoie une notification sur le téléphone via ntfy. N'interrompt jamais la surveillance.

    Le titre doit rester sans accents ni emojis (en-tête HTTP) ; le message peut tout contenir.
    """
    if not NTFY_TOPIC:
        return  # pas de sujet configuré (ex : test sur le Mac) : on n'envoie rien

    requete = urllib.request.Request(
        f"https://ntfy.sh/{NTFY_TOPIC}",
        data=message.encode("utf-8"),
        headers={"Title": titre, "Priority": priorite, "Tags": tags, "User-Agent": "mini-siem"},
    )
    try:
        urllib.request.urlopen(requete, timeout=5)
    except Exception as erreur:
        # Panne réseau, ntfy indisponible... : on le signale mais le SIEM continue de tourner
        print(f"⚠️  Échec de l'envoi de la notification : {erreur}")


def lever_alerte(moment, type_alerte, ip, utilisateur, nombre, methode, message, titre, priorite, tags):
    """Affiche l'alerte, l'envoie sur le téléphone et l'enregistre dans la base."""
    print(message)
    notifier(titre, message, priorite, tags)
    enregistrer_alerte(moment, type_alerte, ip, utilisateur, nombre, methode, message)


# ---------------------------------------------------------------------------
# Lecture des logs en continu
# ---------------------------------------------------------------------------

def suivre_plusieurs(chemins):
    """Renvoie les nouvelles lignes de plusieurs fichiers au fur et à mesure (comme tail -f).

    Les fichiers sont lus à tour de rôle. "yield" fait de cette fonction un générateur :
    la boucle qui l'utilise ne se termine jamais et attend les nouvelles lignes.
    """
    fichiers = [open(chemin, "r", encoding="utf-8") for chemin in chemins]
    for fichier in fichiers:
        fichier.seek(0, 2)                  # fin de chaque fichier : on ignore l'historique
    try:
        while True:
            nouvelle_ligne = False
            for fichier in fichiers:
                ligne = fichier.readline()
                if ligne:
                    nouvelle_ligne = True
                    yield ligne
            if not nouvelle_ligne:          # aucun fichier n'a de nouvelle ligne...
                time.sleep(1)               # ...on attend avant de réessayer
    finally:
        for fichier in fichiers:            # à l'arrêt (Ctrl+C), on referme proprement
            fichier.close()


def dans_fenetre(moment, autre_moment):
    """Vrai si autre_moment date de moins de FENETRE secondes avant moment."""
    return (moment - autre_moment).total_seconds() <= FENETRE


# ---------------------------------------------------------------------------
# Programme principal
# ---------------------------------------------------------------------------

def main():
    # État en mémoire, indexé par adresse IP
    horaires = {}              # IP -> heures des échecs SSH récents (dans la fenêtre)
    scans = {}                 # IP -> liste de (moment, port) des blocages récents
    derniere_alerte = {}       # IP -> moment de la dernière alerte brute force (anti-répétition)
    derniere_alerte_scan = {}  # IP -> moment de la dernière alerte de scan (séparé : on veut les deux)

    initialiser_base()
    print(f"🔎 Surveillance de {FICHIER_SSH} et {FICHIER_PARE_FEU} (Ctrl+C pour arrêter)")
    if NTFY_TOPIC:
        print("📱 Notifications ntfy activées")
    else:
        print("⚠️  NTFY_TOPIC non défini : notifications désactivées")

    try:
        for ligne in suivre_plusieurs([FICHIER_SSH, FICHIER_PARE_FEU]):

            # --- 🔍 Paquet bloqué par le pare-feu : scan de ports ? -----------
            blocage = analyser_scan(ligne)
            if blocage:
                ip, port = blocage
                moment = lire_moment(ligne)

                if ip not in scans:
                    scans[ip] = []
                scans[ip].append((moment, port))
                scans[ip] = [(m, p) for (m, p) in scans[ip] if dans_fenetre(moment, m)]

                # Ensemble des ports DIFFÉRENTS (un set n'a pas de doublons)
                ports = {p for (m, p) in scans[ip]}

                if len(ports) >= SEUIL_PORTS:
                    derniere = derniere_alerte_scan.get(ip)
                    if derniere is None or not dans_fenetre(moment, derniere):
                        liste_ports = ", ".join(str(p) for p in sorted(ports))
                        message = (f"🔍 [{moment:%Y-%m-%d %H:%M:%S}] SCAN DE PORTS : "
                                   f"{ip} a tenté {len(ports)} ports différents "
                                   f"en moins de {FENETRE} s ({liste_ports})")
                        lever_alerte(moment, "scan_ports", ip, None, len(ports), None, message,
                                     "Scan de ports", "high", "mag")
                        derniere_alerte_scan[ip] = moment
                continue

            # --- 🔴 Connexion réussie : juste après un brute force ? ------------
            succes = analyser_succes(ligne)
            if succes:
                ip, utilisateur, methode = succes
                moment = lire_moment(ligne)

                # .get() : une IP qui n'a jamais échoué n'est pas dans horaires
                recents = [h for h in horaires.get(ip, []) if dans_fenetre(moment, h)]

                if len(recents) >= SEUIL:
                    message = (f"🔴 [{moment:%Y-%m-%d %H:%M:%S}] ALERTE CRITIQUE : "
                               f"{ip} s'est connecté en tant que {utilisateur} ({methode}) "
                               f"après {len(recents)} échecs en moins de {FENETRE} s")
                    lever_alerte(moment, "compromission", ip, utilisateur, len(recents), methode, message,
                                 "COMPROMISSION", "urgent", "red_circle")
                continue   # une ligne de succès n'est pas un échec : on passe à la suivante

            # --- 🚨 Échec de connexion SSH : brute force ? --------------------
            echec = analyser_ligne(ligne)
            if not echec:
                continue
            ip, utilisateur = echec
            moment = lire_moment(ligne)

            if ip not in horaires:
                horaires[ip] = []
            horaires[ip].append(moment)
            horaires[ip] = [h for h in horaires[ip] if dans_fenetre(moment, h)]

            if len(horaires[ip]) >= SEUIL:
                # Pas d'alerte si on en a déjà levé une pour cette IP il y a moins de FENETRE secondes
                derniere = derniere_alerte.get(ip)
                if derniere is None or not dans_fenetre(moment, derniere):
                    message = (f"🚨 [{moment:%Y-%m-%d %H:%M:%S}] ALERTE BRUTE FORCE : "
                               f"{ip} a échoué {len(horaires[ip])} fois en moins de {FENETRE} s "
                               f"(dernier utilisateur visé : {utilisateur})")
                    lever_alerte(moment, "brute_force", ip, utilisateur, len(horaires[ip]), None, message,
                                 "Brute force", "high", "rotating_light")
                    derniere_alerte[ip] = moment

    except KeyboardInterrupt:
        # Ctrl+C : on quitte proprement au lieu d'afficher une erreur
        print("\n🛑 Surveillance arrêtée.")


if __name__ == "__main__":
    main()
