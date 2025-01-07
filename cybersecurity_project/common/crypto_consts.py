from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HASH_ALGO = hashes.SHA256()

RSA_KEY_SIZE_BITS = 2048
RSA_PUBLIC_EXPONENT = 65537
RSA_PADDING = padding.PSS(mgf=padding.MGF1(HASH_ALGO), salt_length=padding.PSS.MAX_LENGTH)

AES_KEY_SIZE_BITS = 256
AES_ALGO = algorithms.AES256
AES_MODE = modes.CBC
AES_PADDING = symmetric_padding.PKCS7(AES_ALGO.block_size)

KDF_ALGO = HKDF

DH_GENERATOR = 2
