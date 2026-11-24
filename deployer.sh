#!/usr/bin/env bash
#
# deployer.sh - Déploie le mini-SIEM depuis le Mac vers les serveurs du lab
# =========================================================================
#
# Utilisation (depuis le dossier mini-siem) :
#   ./deployer.sh             -> met à jour siem (surveillance + tableau de bord)
#   ./deployer.sh --reponse   -> idem, et met aussi à jour le script de blocage sur ubuntu-01
#
# Le script s'arrête à la première erreur : rien n'est installé si la vérification échoue.

set -euo pipefail   # -e : arrêt à la 1re erreur ; -u : variable inconnue = erreur ; pipefail : idem dans les "|"

SIEM="remikaseya@192.168.1.201"
CIBLE="remikaseya@192.168.1.28"
SCRIPTS="surveillance.py detect_bruteforce.py dashboard.py"

cd "$(dirname "$0")"   # on travaille toujours depuis le dossier du script

echo "1/4 🔍 Vérification de la syntaxe Python"
python3 -m py_compile $SCRIPTS reponse/mini-siem-bloquer

echo "2/4 📤 Envoi des fichiers vers siem"
ssh "$SIEM" "rm -rf ~/deploiement && mkdir -p ~/deploiement"
scp -q $SCRIPTS "$SIEM":~/deploiement/
scp -q -r templates "$SIEM":~/deploiement/

echo "3/4 ⚙️  Installation sur siem et redémarrage des services (mot de passe sudo demandé)"
ssh -t "$SIEM" '
  sudo cp ~/deploiement/*.py /opt/mini-siem/ &&
  sudo cp -r ~/deploiement/templates /opt/mini-siem/ &&
  sudo chown -R root:root /opt/mini-siem &&
  sudo chmod -R u=rwX,go=rX /opt/mini-siem &&
  { sudo systemctl reset-failed mini-siem mini-siem-dashboard 2>/dev/null || true; } &&
  sudo systemctl restart mini-siem mini-siem-dashboard &&
  sleep 3 &&
  systemctl is-active mini-siem mini-siem-dashboard &&
  sudo journalctl -u mini-siem -n 4 --no-pager -o cat
'

if [[ "${1:-}" == "--reponse" ]]; then
  echo "4/4 🛡️  Mise à jour du script de blocage sur ubuntu-01 (mot de passe sudo demandé)"
  scp -q reponse/mini-siem-bloquer "$CIBLE":~/
  ssh -t "$CIBLE" 'sudo install -o root -g root -m 755 ~/mini-siem-bloquer /usr/local/sbin/mini-siem-bloquer'
else
  echo "4/4 ⏭️  Script de blocage non modifié (ajouter --reponse pour le mettre à jour)"
fi

echo "✅ Déploiement terminé"
