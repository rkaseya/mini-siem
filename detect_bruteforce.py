import re

LOG_FILE = "sshd-session.log"
SEUIL = 3

def main():
    compteur = {}  # clé : IP, valeur : nombre d'échecs
    utilisateurs = {} #clé : IP, valeur : liste des utilisateurs
    with open(LOG_FILE, "r", encoding="utf-8") as file:
        
        for lines in file:
            if "Failed password" in lines or "Invalid user" in lines:
            
                ip = re.search(r"from (\S+)", lines).group(1)
                
                compteur[ip] = compteur.get(ip,0) + 1
                if ip not in utilisateurs:
                    utilisateurs[ip] = []
                utilisateurs[ip].append(re.search(r"(?:[Ii]nvalid user|for) (\S+) from", lines).group(1))
    for ip_address,number in compteur.items():
        if number >= SEUIL:
            print(f"{ip_address} a tenté de se connecter {number} fois.(brute force probable) sur {', '.join(utilisateurs[ip_address])}")
        else:
            print(f"{ip_address} - {number} échec(s) - utilisateurs : {', '.join(utilisateurs[ip_address])}")        
        

if __name__ == "__main__":
    main()