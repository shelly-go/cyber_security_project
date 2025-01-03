import logging
import os.path
import sys
import uuid
from typing import Dict

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from client.consts import STARTUP_BANNER, CLIENT_ID_PUB_KEY_PATH, CLIENT_ID_PRIV_KEY_PATH
from client.server_api import ServerAPI
from common.api_consts import MAX_USERS, MAX_MSGS
from common.crypto import CryptoHelper


class Client:
    def __init__(self):
        print(STARTUP_BANNER)
        self.phone_num = input("Please enter your phone number:\t")

        self.logger = logging.getLogger()
        logging.basicConfig(
            level=logging.DEBUG,
            format=f"%(asctime)s [%(levelname)s] <{self.phone_num}> %(message)s",
            handlers=[logging.StreamHandler(sys.stdout)],
        )
        self.server_api = ServerAPI(self)
        self.logger.info(f"Initializing client for phone number - {self.phone_num}...")

        self.pub_id_key_path = CLIENT_ID_PUB_KEY_PATH.format(phone_num=self.phone_num)
        self.priv_id_key_path = CLIENT_ID_PRIV_KEY_PATH.format(phone_num=self.phone_num)
        self.priv_id_key: RSAPrivateKey | None = None
        self.pub_id_key: RSAPublicKey | None = None

        self.private_one_time_keys = dict()
        self.messages_sent = dict()
        self.client_id_keys = dict()

    def set_up_communication(self):
        if not self.is_registered():
            self.logger.info("Client is not registered yet, starting registration...")
            self.priv_id_key, self.pub_id_key, id_key_cert = self.register()
        else:
            self.logger.info("Client is registered already, loading client identity...")
            self.priv_id_key, self.pub_id_key = self.load_keys()
            id_key_cert = CryptoHelper.generate_id_cert_from_key(self.priv_id_key, self.pub_id_key, self.phone_num)

        self.client_id_keys.update({self.phone_num: id_key_cert})

    def is_registered(self):
        return os.path.exists(self.pub_id_key_path) and os.path.exists(self.priv_id_key_path)

    def load_keys(self):
        try:
            return (CryptoHelper.load_private_key(self.priv_id_key_path),
                    CryptoHelper.load_public_key(self.pub_id_key_path))
        except Exception:
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

        return priv_id_key, pub_id_key, id_key_cert

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
        self.logger.info(f"Sending message: \"{message}\" to {target}")
        target_id_key = self.get_target_id_key(target)
        target_otk_uuid, target_otk = self.get_target_otk(target, target_id_key)
        session_pub_key_str, shared_ephemeral_key = self.generate_pub_key_and_ek(target_id_key, target_otk)
        self.submit_encrypted_message(target, session_pub_key_str, shared_ephemeral_key, target_otk_uuid, message)

    def receive_messages(self):
        self.logger.info(f"Fetching all messages for {self.phone_num} from server")
        phone_num_signature = CryptoHelper.sign_data_hash_with_private_key(self.priv_id_key,
                                                                           self.phone_num.encode()).hex()
        incoming_messages, incoming_confirmations = self.server_api.server_request_inbox(phone_num_signature)
        self.parse_incoming_messages(incoming_messages)
        self.parse_incoming_confirmations(incoming_confirmations)

    def get_target_id_key(self, target):
        self.logger.info(f"Fetching target Id-Key for {target} from server")

        cached_id_key = self.client_id_keys.get(target)
        if cached_id_key:
            self.logger.info(f"Id-Key for {target} found in cache")
            return cached_id_key

        target_signature = CryptoHelper.sign_data_hash_with_private_key(self.priv_id_key,
                                                                        target.encode()).hex()

        target_id_key = self.server_api.server_request_target_id_key(target, target_signature)
        if not CryptoHelper.verify_cert_signature(target_id_key, self.server_api.server_certificate.public_key()):
            self.logger.critical(f"Target Id-Key signature for {target} was not verified by the server, exiting...")
            exit(1)
        if not CryptoHelper.user_id_from_cert(target_id_key) == target:
            raise Exception("Certificate subject doesn't match target!")
        self.logger.info(f"Target Id-Key signature for {target} was verified")
        self.logger.info(f"Saving Id-Key for {target} in cache")
        self.client_id_keys.update({target: target_id_key})
        return target_id_key

    def get_target_otk(self, target, target_id_key):
        self.logger.info(f"Fetching target OTK for {target} from server")

        target_sign = CryptoHelper.sign_data_hash_with_private_key(self.priv_id_key,
                                                                   target.encode()).hex()

        target_otk_uuid, target_otk_str, target_otk_signature = self.server_api.server_request_target_otk(target,
                                                                                                          target_sign)
        signature_match = CryptoHelper.verify_signature_on_data_hash(target_id_key.public_key(),
                                                                     bytes.fromhex(target_otk_signature),
                                                                     target_otk_str.encode())
        if not signature_match:
            raise Exception("Signature on OTK doesn't match client!")
        self.logger.info(f"Target OTK signature for {target} was verified")
        target_otk = CryptoHelper.load_public_key_from_str(target_otk_str)
        return target_otk_uuid, target_otk

    @staticmethod
    def generate_pub_key_and_ek(target_id_key, target_otk):
        client_session_dh_params = CryptoHelper.dh_params_from_public_key(target_id_key.public_key())
        session_priv_key = client_session_dh_params.generate_private_key()
        shared_secret = session_priv_key.exchange(target_otk)
        shared_ephemeral_key = CryptoHelper.dh_get_key_from_shared_secret(shared_secret)
        session_pub_key_str = CryptoHelper.pub_key_to_str(session_priv_key.public_key())
        return session_pub_key_str, shared_ephemeral_key

    def generate_ek_from_otk(self, otk_uuid, target_pub_key):
        otk_secret = self.private_one_time_keys.pop(otk_uuid)
        shared_secret = otk_secret.exchange(target_pub_key)
        shared_ephemeral_key = CryptoHelper.dh_get_key_from_shared_secret(shared_secret)
        return shared_ephemeral_key

    def submit_encrypted_message(self, target, session_pub_key_str, shared_ephemeral_key, target_otk_uuid, message):
        enc_message = CryptoHelper.aes_encrypt_message(shared_ephemeral_key, message.encode())

        bundle = self.phone_num.encode() + enc_message + session_pub_key_str.encode()
        bundle_signature = CryptoHelper.sign_data_hash_with_private_key(self.priv_id_key, bundle).hex()

        self.server_api.server_submit_message_and_ek(target, target_otk_uuid, session_pub_key_str,
                                                     enc_message.hex(), bundle_signature)

        self.messages_sent.update({target_otk_uuid: (target, CryptoHelper.hash_data_to_hex(message.encode()))})

        self.logger.info(f"Message: \"{message}\" sent to {target}, message ID - {target_otk_uuid}")

    def parse_incoming_messages(self, messages: Dict):
        for sender, sender_messages in messages.items():
            for message_bundle in sender_messages:
                self.logger.info(f"Received message from {sender}")
                otk_uuid, enc_message, session_pub_key_str, bundle_signature = message_bundle

                sender_id_key = self.get_target_id_key(sender)

                bundle = sender.encode() + bytes.fromhex(enc_message) + session_pub_key_str.encode()
                signature_match = CryptoHelper.verify_signature_on_data_hash(sender_id_key.public_key(),
                                                                             bytes.fromhex(bundle_signature),
                                                                             bundle)
                if not signature_match:
                    raise Exception("Signature on message doesn't match sender!")

                otk_secret = self.private_one_time_keys.get(otk_uuid)
                if not otk_secret:
                    self.logger.critical(f"Message was sent with an invalid UUID, skipping...")
                    continue
                session_pub_key = CryptoHelper.load_public_key_from_str(session_pub_key_str)
                shared_ephemeral_key = self.generate_ek_from_otk(otk_uuid, session_pub_key)
                dec_message = CryptoHelper.aes_decrypt_message(shared_ephemeral_key, bytes.fromhex(enc_message))
                self.logger.info(f"Message: \"{dec_message.decode()}\" received from {sender}, message ID - {otk_uuid}")
                self.confirm_received_message(sender, otk_uuid, dec_message)
        self.logger.info(f"All messages handled")

    def parse_incoming_confirmations(self, confirmations: Dict):
        for receiver, receiver_confirmations in confirmations.items():
            for confirmation_bundle in receiver_confirmations:
                self.logger.info(f"Received confirmation from {receiver}")
                otk_uuid, message_hash, hash_signature = confirmation_bundle

                receiver_id_key = self.get_target_id_key(receiver)
                signature_match = CryptoHelper.verify_signature_on_data_hash(receiver_id_key.public_key(),
                                                                             bytes.fromhex(hash_signature),
                                                                             message_hash.encode())
                if not signature_match:
                    raise Exception("Signature on message doesn't match receiver!")

                sent_message_data = self.messages_sent.get(otk_uuid)
                if not sent_message_data:
                    self.logger.critical(f"Confirmation from {receiver} was received with an invalid UUID, skipping...")
                    continue

                saved_receiver, saved_message_hash = sent_message_data

                if not saved_receiver == receiver:
                    self.logger.critical(f"Error: message {otk_uuid} confirmations was received from wrong number!")
                    continue

                if not saved_message_hash == message_hash:
                    self.logger.critical(f"Error: message {otk_uuid} was corrupted during delivery!")
                    continue

                self.logger.info(f"Message {otk_uuid} was delivered to {receiver} successfully")
                self.messages_sent.pop(otk_uuid)

    def confirm_received_message(self, sender, otk_uuid, message):
        self.logger.info(f"Sending read confirmation for message ID - {otk_uuid}")
        message_hash = CryptoHelper.hash_data_to_hex(message)
        hash_signature = CryptoHelper.sign_data_hash_with_private_key(self.priv_id_key, message_hash.encode()).hex()
        self.server_api.server_confirm_message_read(sender, otk_uuid, message_hash, hash_signature)
