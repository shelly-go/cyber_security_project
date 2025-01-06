import os

STARTUP_BANNER = """
                8888888888  .d8888b.  8888888888 8888888888          
                888        d88P  Y88b 888        888                 
                888               888 888        888                 
                8888888         .d88P 8888888    8888888             
                888         .od888P"  888        888                 
                888        d88P"      888        888                 
                888        888"       888        888                 
                8888888888 888888888  8888888888 8888888888          
                                                                     
                                                                     
                                                                     
       .d8888b.  888      8888888 8888888888 888b    888 88888888888 
      d88P  Y88b 888        888   888        8888b   888     888     
      888    888 888        888   888        88888b  888     888     
      888        888        888   8888888    888Y88b 888     888     
      888        888        888   888        888 Y88b888     888     
      888    888 888        888   888        888  Y88888     888     
      Y88b  d88P 888        888   888        888   Y8888     888     
       "Y8888P"  88888888 8888888 8888888888 888    Y888     888       
       
                By: Tal Druzhinin & Shelly Goltzman"""

SERVER_URL = "https://localhost/client"

CLIENT_ID_KEY_DIR = "client/client_info/{phone_num}"
CLIENT_ID_PUB_KEY_PATH = os.path.join(CLIENT_ID_KEY_DIR, "client_{phone_num}_id.pem")
CLIENT_ID_PRIV_KEY_PATH = os.path.join(CLIENT_ID_KEY_DIR, "client_{phone_num}_id.key")
SERVER_CERT_PATH = "client/server_cert/certificate.crt"

MSG_RECEIVE_RATE = 3
MSG_RECEIVE_THREAD_TIMEOUT = 3
