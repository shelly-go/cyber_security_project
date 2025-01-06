import os

HOST = "127.0.0.1"
PORT = 443

SSL_CERT_PATH = "server/cert/certificate.crt"
SSL_PRIV_KEY_PATH = "server/cert/privatekey.key"
ISSUER_NAME = "ProtocolServer"

CONNECTION_TIMEOUT = 60

STARTUP_BANNER = """                                                                                                                                   
           8888888888  .d8888b.  8888888888 8888888888             
           888        d88P  Y88b 888        888                    
           888               888 888        888                    
           8888888         .d88P 8888888    8888888                
           888         .od888P"  888        888                    
           888        d88P"      888        888                    
           888        888"       888        888                    
           8888888888 888888888  8888888888 8888888888             
                                                                   
                                                                   
                                                                   
 .d8888b.  8888888888 8888888b.  888     888 8888888888 8888888b.  
d88P  Y88b 888        888   Y88b 888     888 888        888   Y88b 
Y88b.      888        888    888 888     888 888        888    888 
 "Y888b.   8888888    888   d88P Y88b   d88P 8888888    888   d88P 
    "Y88b. 888        8888888P"   Y88b d88P  888        8888888P"  
      "888 888        888 T88b     Y88o88P   888        888 T88b   
Y88b  d88P 888        888  T88b     Y888P    888        888  T88b  
 "Y8888P"  8888888888 888   T88b     Y8P     8888888888 888   T88b           
             
                By: Tal Druzhinin & Shelly Goltzman"""

SERVER_ID_KEY_DIR = os.path.join("server","client_info")
SERVER_ID_KEY_CLIENT_DIR = os.path.join(SERVER_ID_KEY_DIR, "{phone_num}")
SERVER_SIGNED_ID_KEY_PATH = os.path.join(SERVER_ID_KEY_CLIENT_DIR, "client_{phone_num}_id.pem")
