import re

LOG_FILE = "sshd-session.log"

def main():
    compteur = {}  # clé : IP, valeur : nombre d'échecs
   
    with open(LOG_FILE, "r", encoding="utf-8") as file:
        
        for lines in file:
            if "Failed password" in lines or "Invalid user" in lines:
            
                ip = re.search(r"from (\S+)", lines).group(1)
                compteur[ip] = compteur.get(ip,0) + 1
       
    for ip_address,number in compteur.items():
        print(f"{ip_address} a tenté de se connecter {number} fois.")

                 
        

if __name__ == "__main__":
    main()