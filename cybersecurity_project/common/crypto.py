import datetime
import logging
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.dh import DHParameters, DHParameterNumbers
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.x509 import Certificate
from cryptography.x509.oid import NameOID

from common.crypto_consts import HASH_ALGO, DH_GENERATOR

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
    def generate_id_cert_from_key(private_key: RSAPrivateKey, public_key: RSAPublicKey, phone_num: str) -> Certificate:
        logger.debug(f"Generating new certificate for {phone_num}")
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.USER_ID, phone_num),
        ])
        certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now()
        ).not_valid_after(
            # Certificate valid for 1 year
            datetime.datetime.now() + datetime.timedelta(days=365)
        ).sign(private_key, HASH_ALGO, default_backend())
        return certificate

    @staticmethod
    def generate_signed_cert(cert_to_sign: Certificate, signer_private_key: RSAPrivateKey,
                             issuer_name: str) -> Certificate:
        subject = cert_to_sign.subject
        public_key = cert_to_sign.public_key()
        logger.debug(f"Generating new certificate by {issuer_name} to sign certificate {subject.rfc4514_string()}")

        # Define the issuer (your information)
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)
        ])

        # Build a new certificate
        signed_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now()
        ).not_valid_after(
            # Define validity period for 1 year
            datetime.datetime.now() + datetime.timedelta(days=365)
        ).sign(signer_private_key, HASH_ALGO, default_backend())

        return signed_cert

    @staticmethod
    def cert_to_str(certificate: Certificate):
        return certificate.public_bytes(encoding=serialization.Encoding.PEM).decode()

    @staticmethod
    def cert_from_str(certificate: str):
        return x509.load_pem_x509_certificate(certificate.encode(), default_backend())

    @staticmethod
    def user_id_from_cert(certificate: Certificate):
        return certificate.subject.get_attributes_for_oid(NameOID.USER_ID)[0].value

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
    def load_private_key_from_str(priv_key_str) -> RSAPrivateKey:
        logger.debug("Loading RSA private key from buffer")
        private_key = load_pem_private_key(priv_key_str.encode(), password=None, backend=default_backend())
        return private_key

    @staticmethod
    def load_public_key_from_str(pub_key_str) -> RSAPublicKey:
        logger.debug("Loading RSA public key from buffer")
        public_key = load_pem_public_key(pub_key_str.encode())
        return public_key

    @staticmethod
    def sign_data_hash_with_private_key(private_key: RSAPrivateKey, data: bytes):
        hash_hex = CryptoHelper.hash_data_to_hex(data).encode()
        return private_key.sign(hash_hex,
                                padding.PSS(
                                    mgf=padding.MGF1(HASH_ALGO),
                                    salt_length=padding.PSS.MAX_LENGTH),
                                HASH_ALGO)

    @staticmethod
    def verify_signature_on_data_hash(public_key: RSAPublicKey, signature: bytes, data: bytes):
        hash_hex = CryptoHelper.hash_data_to_hex(data).encode()
        try:
            public_key.verify(signature,
                              hash_hex,
                              padding.PSS(
                                  mgf=padding.MGF1(HASH_ALGO),
                                  salt_length=padding.PSS.MAX_LENGTH),
                              HASH_ALGO)
            return True
        except Exception:
            return False

    @staticmethod
    def hash_data_to_hex(data: bytes) -> str:
        logger.debug(f"Hashing data using {HASH_ALGO.name.upper()}")
        digest = hashes.Hash(HASH_ALGO)
        digest.update(data)
        hash_value = digest.finalize()

        return hash_value.hex()

    @staticmethod
    def dh_params_from_public_key(public_key: RSAPublicKey) -> DHParameters:
        return DHParameterNumbers(g=DH_GENERATOR, p=public_key.public_numbers().n).parameters()
