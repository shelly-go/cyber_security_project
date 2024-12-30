import logging
import threading
from dataclasses import dataclass
from typing import List, Dict

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import Certificate


@dataclass
class ClientData:
    phone_number: str
    messages: List[bytes] = None
    signed_id_key: Certificate = None
    one_time_keys: Dict[str, RSAPublicKey] = None

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

    def update_client(self, client_id, client_data):
        with self._dict_lock:
            self.logger.debug(f"Client {client_id} updated")
            self.clients[client_id] = client_data

    def get_client(self, client_id) -> ClientData:
        with self._dict_lock:
            self.logger.debug(f"Client {client_id} requested")
            return self.clients.get(client_id, None)
