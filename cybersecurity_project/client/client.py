import logging
import os.path
import sys
import uuid

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from client.consts import STARTUP_BANNER, CLIENT_ID_PUB_KEY_PATH, CLIENT_ID_PRIV_KEY_PATH
from client.server_api import ServerAPI
from common.api_consts import MAX_USERS, MAX_MSGS
from common.crypto import CryptoHelper


class Client:
    def __init__(self):
        self.logger = logging.getLogger()
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[logging.StreamHandler(sys.stdout)],
        )
        print(STARTUP_BANNER)
        self.server_api = ServerAPI(self)
        self.phone_num = input("Please enter your phone number:\t")
        self.logger.info(f"Initializing client for phone number - {self.phone_num}...")

        self.pub_id_key_path = CLIENT_ID_PUB_KEY_PATH.format(phone_num=self.phone_num)
        self.priv_id_key_path = CLIENT_ID_PRIV_KEY_PATH.format(phone_num=self.phone_num)
        self.priv_id_key: RSAPrivateKey = None
        self.pub_id_key: RSAPublicKey = None

        self.private_one_time_keys = dict()

    def set_up_communication(self):
        if not self.is_registered():
            self.logger.info("Client is not registered yet, starting registration...")
            self.priv_id_key, self.pub_id_key = self.register()
        else:
            self.logger.info("Client is registered already, loading client identity...")
            self.priv_id_key, self.pub_id_key = self.load_keys()

    def is_registered(self):
        return os.path.exists(self.pub_id_key_path) and os.path.exists(self.priv_id_key_path)

    def load_keys(self):
        try:
            return (CryptoHelper.load_private_key(self.priv_id_key_path),
                    CryptoHelper.load_public_key(self.pub_id_key_path))
        except:
            self.logger.critical("Client seems to be registered but the ID key is invalid, exiting...")
            exit(1)

    def register(self):
        key_dir = os.path.dirname(self.pub_id_key_path)
        if not os.path.exists(key_dir):
            self.logger.info("Registration directory does not exist, creating...")
            os.makedirs(key_dir)

        self.logger.info("Creating Identity key pair")
        priv_id_key, pub_id_key = CryptoHelper.generate_key_pair()
        id_key_cert = CryptoHelper.generate_id_cert_from_key(priv_id_key, pub_id_key, self.phone_num)

        otp = self.server_api.server_request_otp()
        if not self.server_api.server_submit_otp_with_id_key(otp, id_key_cert):
            self.logger.critical("Client cannot receive valid OTP from server, exiting...")
            exit(1)

        CryptoHelper.priv_key_to_file(private_key=priv_id_key, file_path=self.priv_id_key_path)
        CryptoHelper.pub_key_to_file(public_key=pub_id_key, file_path=self.pub_id_key_path)

        return priv_id_key, pub_id_key

    def generate_one_time_keys(self):
        self.logger.info("Creating One-time keys")
        pub_one_time_keys = dict()
        dh_parameters = CryptoHelper.dh_params_from_public_key(self.pub_id_key)
        for _ in range(MAX_USERS * MAX_MSGS):
            otk_uuid = str(uuid.uuid4())
            private_otk = dh_parameters.generate_private_key()
            self.private_one_time_keys.update({otk_uuid: private_otk})
            public_otk_str = CryptoHelper.pub_key_to_str(private_otk.public_key())
            public_otk_signature = CryptoHelper.sign_data_hash_with_private_key(self.priv_id_key,
                                                                                public_otk_str.encode()).hex()
            pub_one_time_keys.update({otk_uuid: (public_otk_str, public_otk_signature)})

        self.server_api.server_submit_otks(pub_one_time_keys)

    def send_message(self, target, message):
        target_signature = CryptoHelper.sign_data_hash_with_private_key(self.priv_id_key,
                                                                        target.encode()).hex()
        target_id_key = self.get_target_id_key(target, target_signature)

        target_otk = self.get_target_otk(target, target_signature, target_id_key)
        pass

    def get_target_id_key(self, target, target_signature):
        self.logger.info(f"Fetching target Id-Key for {target} from server")

        target_id_key = self.server_api.server_request_target_id_key(target, target_signature)
        CryptoHelper.verify_cert_signature(target_id_key, self.server_api.server_certificate.public_key())
        self.logger.info(f"Target Id-Key signature for {target} was verified")
        return target_id_key

    def get_target_otk(self, target, target_signature, target_id_key):
        self.logger.info(f"Fetching target OTK for {target} from server")
        target_otk_str, target_otk_signature = self.server_api.server_request_target_otk(target, target_signature)
        signature_match = CryptoHelper.verify_signature_on_data_hash(target_id_key.public_key(),
                                                                     bytes.fromhex(target_otk_signature),
                                                                     target_otk_str.encode())
        if not signature_match:
            raise Exception("Signature on OTK doesn't match client!")
        self.logger.info(f"Target OTK signature for {target} was verified")
        target_otk = CryptoHelper.load_public_key_from_str(target_otk_str)
        return target_otk
