import os

STARTUP_BANNER = """ ________  ________  ________  _________  ________  ________  ________  ___          
|\   __  \|\   __  \|\   __  \|\___   ___\\   __  \|\   ____\|\   __  \|\  \         
\ \  \|\  \ \  \|\  \ \  \|\  \|___ \  \_\ \  \|\  \ \  \___|\ \  \|\  \ \  \        
 \ \   ____\ \   _  _\ \  \\\  \   \ \  \ \ \  \\\  \ \  \    \ \  \\\  \ \  \       
  \ \  \___|\ \  \\  \\ \  \\\  \   \ \  \ \ \  \\\  \ \  \____\ \  \\\  \ \  \____  
   \ \__\    \ \__\\ _\\ \_______\   \ \__\ \ \_______\ \_______\ \_______\ \_______\
    \|__|     \|__|\|__|\|_______|    \|__|  \|_______|\|_______|\|_______|\|_______|
                                                                                     
                                                                                     
                                                                                     
 ________  ___       ___  _______   ________   _________                             
|\   ____\|\  \     |\  \|\  ___ \ |\   ___  \|\___   ___\                           
\ \  \___|\ \  \    \ \  \ \   __/|\ \  \\ \  \|___ \  \_|                           
 \ \  \    \ \  \    \ \  \ \  \_|/_\ \  \\ \  \   \ \  \                            
  \ \  \____\ \  \____\ \  \ \  \_|\ \ \  \\ \  \   \ \  \                           
   \ \_______\ \_______\ \__\ \_______\ \__\\ \__\   \ \__\                          
    \|_______|\|_______|\|__|\|_______|\|__| \|__|    \|__|                          
                                                                 
    By: Tal Druzhinin & Shelly Goltzman"""

SERVER_URL = "https://localhost/client"

CLIENT_ID_KEY_DIR = "client/client_info/{phone_num}"
CLIENT_ID_PUB_KEY_PATH = os.path.join(CLIENT_ID_KEY_DIR, "client_{phone_num}_id.pem")
CLIENT_ID_PRIV_KEY_PATH = os.path.join(CLIENT_ID_KEY_DIR, "client_{phone_num}_id.key")