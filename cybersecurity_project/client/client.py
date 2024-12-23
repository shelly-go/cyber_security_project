import logging
import os.path
import sys

from client.consts import STARTUP_BANNER, CLIENT_ID_PUB_KEY_PATH, CLIENT_ID_PRIV_KEY_PATH
from common.crypto import CryptoHelper
from client.server_api import ServerAPI


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
        self.priv_id_key = None
        self.pub_id_key = None

    def set_up_communication(self):
        if self.is_registered():
            self.logger.info("Client is registered already, loading client identity...")
            self.priv_id_key, self.pub_id_key = self.load_keys()
        else:
            self.logger.info("Client is not registered yet, starting registration...")
            self.priv_id_key, self.pub_id_key = self.register()

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
            os.mkdir(key_dir)

        self.logger.info("Creating Identity key pair")
        priv_id_key, pub_id_key = CryptoHelper.generate_key_pair()

        otp = self.server_api.server_request_otp()
        if not self.server_api.server_submit_otp_with_id_key(otp, pub_id_key):
            self.logger.critical("Client cannot receive valid OTP from server, exiting...")
            exit(1)

        CryptoHelper.priv_key_to_file(private_key=priv_id_key, file_path=self.priv_id_key_path)
        CryptoHelper.pub_key_to_file(public_key=pub_id_key, file_path=self.pub_id_key_path)

        return priv_id_key, pub_id_key

    def start_communication(self):
        pass
