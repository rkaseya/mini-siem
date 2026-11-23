"""
dashboard.py - Tableau de bord web du mini-SIEM
===============================================

Petite application Flask qui lit la base des alertes (SQLite) remplie par
surveillance.py et affiche une vue d'ensemble dans le navigateur :
compteurs, IP les plus actives, dernières alertes et évolution dans le temps.

La base est ouverte en LECTURE SEULE : le tableau de bord ne peut ni modifier
ni supprimer une alerte, même en cas de bug ou de faille.

Utilisation :
    python3 dashboard.py          puis ouvrir http://127.0.0.1:5000   (développement)
    gunicorn ... dashboard:app    en production, voir mini-siem-dashboard.service
"""

import os
import sqlite3

from flask import Flask, render_template

# Même variable d'environnement que surveillance.py : les deux lisent la même base
BASE_ALERTES = os.environ.get("MINI_SIEM_DB", "alertes.db")

app = Flask(__name__)


def requete(sql, parametres=()):
    """Exécute une requête SQL en lecture seule et renvoie la liste des lignes.

    Chaque ligne se manipule comme un dictionnaire : ligne["ip"], ligne["nb"]...
    """
    # mode=ro : SQLite refuse toute écriture sur cette connexion
    connexion = sqlite3.connect(f"file:{BASE_ALERTES}?mode=ro", uri=True)
    connexion.row_factory = sqlite3.Row
    try:
        return connexion.execute(sql, parametres).fetchall()
    finally:
        connexion.close()


@app.route("/")
def accueil():
    """Page principale du tableau de bord."""

    # Compteurs : SUM(type = '...') compte les lignes de ce type (une comparaison vaut 1 ou 0)
    compteurs = requete("""
        SELECT COUNT(*)                    AS total,
               SUM(type = 'brute_force')   AS brute_force,
               SUM(type = 'compromission') AS compromission,
               SUM(type = 'scan_ports')    AS scan_ports
        FROM alertes
    """)[0]

    # Top 5 des IP les plus actives (GROUP BY : une ligne par IP)
    top_ip = requete("""
        SELECT ip, COUNT(*) AS nb, MAX(moment) AS derniere
        FROM alertes
        GROUP BY ip
        ORDER BY nb DESC
        LIMIT 5
    """)

    # 20 dernières alertes, de la plus récente à la plus ancienne
    dernieres = requete("""
        SELECT moment, type, ip, utilisateur, nb_echecs, methode
        FROM alertes
        ORDER BY moment DESC
        LIMIT 20
    """)

    # Nombre d'alertes par jour, dans l'ordre chronologique (pour le graphique)
    # substr(moment, 1, 10) garde la date seule : "2026-11-23T17:12:01+00:00" -> "2026-11-23"
    par_jour = requete("""
        SELECT substr(moment, 1, 10) AS jour, COUNT(*) AS nb
        FROM alertes
        GROUP BY jour
        ORDER BY jour
    """)

    return render_template(
        "dashboard.html",
        compteurs=compteurs,
        top_ip=top_ip,
        dernieres=dernieres,
        par_jour=par_jour,
    )


if __name__ == "__main__":
    # 127.0.0.1 : le tableau de bord n'est accessible que depuis cette machine.
    # debug=False : le mode debug de Flask permet d'exécuter du code à distance,
    # il ne doit jamais être activé sur un serveur accessible par le réseau.
    app.run(host="127.0.0.1", port=5000, debug=False)
