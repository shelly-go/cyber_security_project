import logging
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

logger = logging.getLogger()


class CryptoHelper:
    @staticmethod
    def generate_key_pair() -> Tuple[RSAPrivateKey, RSAPublicKey]:
        # Generate a new RSA key pair
        logger.debug("Generating new RSA private key")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        logger.debug("Getting RSA public key")
        public_key = private_key.public_key()

        return private_key, public_key

    @staticmethod
    def priv_key_to_str(private_key):
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()).decode()

    @staticmethod
    def priv_key_to_file(private_key, file_path):
        logger.debug("Saving RSA private key to file")
        with open(file_path, 'w') as f:
            f.write(CryptoHelper.priv_key_to_str(private_key))

    @staticmethod
    def pub_key_to_str(public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    @staticmethod
    def pub_key_to_file(public_key, file_path):
        logger.debug("Saving RSA public key to file")
        with open(file_path, 'w') as f:
            f.write(CryptoHelper.pub_key_to_str(public_key))

    @staticmethod
    def load_private_key(priv_key_file_path):
        logger.debug("Loading RSA private key from file")
        with open(priv_key_file_path, 'rb') as f:
            priv_key_data = f.read()
        private_key = load_pem_private_key(priv_key_data, password=None, backend=default_backend())
        return private_key

    @staticmethod
    def load_public_key(pub_key_file_path):
        logger.debug("Loading RSA public key from file")
        with open(pub_key_file_path, 'rb') as f:
            pub_key_data = f.read()
        public_key = load_pem_public_key(pub_key_data)
        return public_key

    @staticmethod
    def hash_with_sha256(data: bytes) -> str:
        logger.debug("Hashing data using SHA256")
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        hash_value = digest.finalize()

        return hash_value.hex()
