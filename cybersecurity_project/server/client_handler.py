import logging
import os
import threading
from dataclasses import dataclass
from typing import List, Dict

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import Certificate

from common.crypto import CryptoHelper
from server.consts import SERVER_ID_KEY_DIR, SERVER_SIGNED_ID_KEY_PATH, SERVER_ID_KEY_CLIENT_DIR


@dataclass
class ClientData:
    phone_number: str
    messages: Dict[str, tuple] = None
    confirmations: Dict[str, tuple] = None
    signed_id_key: Certificate = None
    one_time_keys: Dict[str, RSAPublicKey] = None
    one_time_key_signatures: Dict[str, str] = None

    otp_hash: str = None
    registration_complete: bool = False


class ClientHandler:
    _instance = None
    _instance_lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        # Ensure only one instance is created (Singleton)
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = super(ClientHandler, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, 'clients'):
            self.clients = {}
            self._dict_lock = threading.Lock()
            self.logger = logging.getLogger()

    @property
    def clients_amount(self):
        with self._dict_lock:
            return len(self.clients)

    def update_client(self, client_id, client_data):
        with self._dict_lock:
            self.logger.debug(f"Client {client_id} updated")
            self.clients[client_id] = client_data

    def get_client(self, client_id) -> ClientData:
        with self._dict_lock:
            self.logger.debug(f"Client {client_id} requested")
            return self.clients.get(client_id, None)

    def save_client_id_key_to_file(self, client_id):
        with self._dict_lock:
            self.logger.debug(f"Client {client_id} is being saved to disk")
            client_info = self.clients.get(client_id, None)
            if client_info:
                client_info_dir = SERVER_ID_KEY_CLIENT_DIR.format(phone_num=client_id)
                if not os.path.exists(client_info_dir):
                    self.logger.info("Client directory does not exist, creating...")
                    os.makedirs(client_info_dir)
                client_key_path = SERVER_SIGNED_ID_KEY_PATH.format(phone_num=client_id)
                CryptoHelper.cert_to_file(client_info.signed_id_key, client_key_path)

    def load_client_id_keys(self):
        with self._dict_lock:
            if os.path.exists(SERVER_ID_KEY_DIR):
                for client_id in os.listdir(SERVER_ID_KEY_DIR):
                    client_dir_path = SERVER_ID_KEY_CLIENT_DIR.format(phone_num=client_id)

                    if os.path.isdir(client_dir_path) and client_id.isdigit():

                        pem_file_path = SERVER_SIGNED_ID_KEY_PATH.format(phone_num=client_id)

                        if os.path.exists(pem_file_path):
                            certificate = CryptoHelper.cert_from_file(pem_file_path)
                            self.logger.debug(f"Loaded client data for client {client_id}")
                            self.clients[client_id] = ClientData(phone_number=client_id, signed_id_key=certificate)
                        else:
                            self.logger.debug(f"Certificate not found for client {client_id}")
            else:
                self.logger.debug(f"No registered clients found.")

