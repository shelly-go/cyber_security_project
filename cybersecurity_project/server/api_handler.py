import http.server
import json
import logging
import re
from http import HTTPStatus
from typing import Dict, Callable
from urllib.parse import urlparse

from cryptography.x509 import Certificate

from common.api_consts import PHONE_NUMBER_FIELD, OTP_FIELD, OTP_HASH_FIELD, ID_KEY_FIELD, ONETIME_KEYS_FIELD, \
    API_ENDPOINT_REGISTER_VALIDATE, API_ENDPOINT_REGISTER_NUMBER, API_ENDPOINT_ROOT, STATUS_OK_RESPONSE, ERROR_FIELD, \
    UNSPECIFIED_ERROR, API_ENDPOINT_USER_KEYS, API_ENDPOINT_USER_ID, TARGET_NUMBER_FIELD, TARGET_NUMBER_SIGNATURE_FIELD, \
    API_ENDPOINT_MSG_REQUEST, ONETIME_KEY_FIELD, ONETIME_KEY_UUID_FIELD, MESSAGE_PUBLIC_KEY_FIELD, \
    MESSAGE_ENC_MESSAGE_FIELD, \
    MESSAGE_BUNDLE_SIGNATURE_FIELD, API_ENDPOINT_MSG_SEND, API_ENDPOINT_MSG_INBOX, MESSAGE_INCOMING_FIELD, \
    MESSAGE_CONF_INCOMING_FIELD, PHONE_NUMBER_SIGNATURE_FIELD
from common.crypto import CryptoHelper
from server.client_handler import ClientData, ClientHandler
from server.consts import SSL_PRIV_KEY_PATH, ISSUER_NAME
from server.utils import generate_otp, send_by_secure_channel


class APIHandler(http.server.SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        self.api_clients = ClientHandler()
        self.logger = logging.getLogger()
        super().__init__(*args, **kwargs)
        pass

    @staticmethod
    def __sign_certificate(cert_to_sign: Certificate) -> Certificate:
        server_priv_key = CryptoHelper.load_private_key(SSL_PRIV_KEY_PATH)
        return CryptoHelper.generate_signed_cert(cert_to_sign, server_priv_key, ISSUER_NAME)

    def extract_uri(self):
        return re.sub(r'/+', '/', urlparse(self.path).path).rstrip('/') or '/'

    def find_request_api_handler(self, uri) -> Callable[[dict], dict]:
        # URI mapping for different API endpoints
        self.logger.debug(f'Getting handler function for uri: "{uri}"')
        mapping = {
            API_ENDPOINT_ROOT: self.api_root,
            API_ENDPOINT_REGISTER_NUMBER: self.api_register_number,
            API_ENDPOINT_REGISTER_VALIDATE: self.api_register_otp,
            API_ENDPOINT_USER_KEYS: self.api_setup_client_keys,
            API_ENDPOINT_USER_ID: self.api_client_id,
            API_ENDPOINT_MSG_REQUEST: self.api_message_request,
            API_ENDPOINT_MSG_SEND: self.api_message_send,
            API_ENDPOINT_MSG_INBOX: self.api_message_inbox,
        }

        handler = mapping.get(uri) or self.api_not_implemented
        return handler

    def do_GET(self):
        raise NotImplementedError()

    def do_POST(self):
        uri = self.extract_uri()
        self.logger.info(f"Received API request for {uri}")
        handler = self.find_request_api_handler(uri=uri)

        data_json = None
        err = None
        try:
            content_length = int(self.headers['Content-Length'])
            incoming_data = self.rfile.read(content_length).decode() or "{}"
            self.logger.debug(f"Request length: {content_length}, request body: {incoming_data}")
            incoming_data_json = json.loads(incoming_data)
            data_json = handler(incoming_data_json)
        except Exception as e:
            self.logger.error(f"Failed to handle request with error: {e}")
            err = e
        finally:
            if err or data_json is None:
                error_response = {ERROR_FIELD: repr(err) if err else UNSPECIFIED_ERROR}
                data_json = self.api_error(error_response)

        data = json.dumps(data_json).encode()
        self.send_header("Content-type", 'application/json')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def api_not_implemented(self, input_data: Dict) -> Dict:
        self.send_response(HTTPStatus.NOT_IMPLEMENTED)
        return {"error": "Not implemented!"}

    def api_error(self, input_data: Dict = None) -> Dict:
        self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
        return input_data

    def api_root(self, input_data: Dict) -> Dict:
        self.send_response(HTTPStatus.OK)
        return STATUS_OK_RESPONSE

    def api_register_number(self, input_data: Dict) -> Dict:
        number = input_data.get(PHONE_NUMBER_FIELD)
        if not number:
            raise Exception("Phone number is required for registration")

        client_data = self.api_clients.get_client(number)
        if client_data and client_data.registration_complete:
            raise Exception("Phone number already exists.")

        otp = generate_otp()
        otp_hash = CryptoHelper.hash_data_to_hex(otp.encode())
        client_data = ClientData(phone_number=number, otp_hash=otp_hash)
        self.api_clients.update_client(number, client_data)

        send_by_secure_channel(number, otp)
        self.send_response(HTTPStatus.OK)
        return {PHONE_NUMBER_FIELD: number, OTP_FIELD: otp}

    def api_register_otp(self, input_data: Dict) -> Dict:
        number = input_data.get(PHONE_NUMBER_FIELD)
        otp_hash = input_data.get(OTP_HASH_FIELD)
        id_key = input_data.get(ID_KEY_FIELD)
        if not (number and otp_hash) or not id_key:
            raise Exception("Phone number, otp hash, and ID key are required.")

        client_data = self.api_clients.get_client(number)
        if not client_data:
            raise Exception("Phone number registration was never initiated.")

        if client_data.registration_complete:
            raise Exception("Phone number is already registered.")

        if client_data.otp_hash != otp_hash:
            raise Exception(f"Incorrect otp for number {number}.")

        if client_data.phone_number != number:
            raise Exception(f"Incorrect otp for number {number}.")

        id_key_cert = CryptoHelper.cert_from_str(id_key)

        if client_data.phone_number != CryptoHelper.user_id_from_cert(id_key_cert):
            raise Exception(f"Incorrect certificate for number {number}.")

        client_data.signed_id_key = self.__sign_certificate(id_key_cert)
        client_data.otp_hash = None
        self.api_clients.update_client(number, client_data)
        self.api_clients.save_client_id_key_to_file(number)

        self.send_response(HTTPStatus.OK)
        return STATUS_OK_RESPONSE

    def api_setup_client_keys(self, input_data: Dict) -> Dict:
        number = input_data.get(PHONE_NUMBER_FIELD)
        onetime_keys = input_data.get(ONETIME_KEYS_FIELD)

        if not (number and onetime_keys):
            raise Exception("Phone number and one-time keys are required.")

        client_data = self.api_clients.get_client(number)
        if not client_data:
            raise Exception("Phone number does not exist.")

        one_time_keys_dict = dict()
        one_time_key_signatures_dict = dict()
        for uuid, key_data in onetime_keys.items():
            otk_public_key_str, otk_signature_str = key_data
            signature_match = CryptoHelper.verify_signature_on_data_hash(client_data.signed_id_key.public_key(),
                                                                         bytes.fromhex(otk_signature_str),
                                                                         otk_public_key_str.encode())
            if not signature_match:
                raise Exception("Signature on OTK doesn't match client!")

            one_time_keys_dict.update({uuid: CryptoHelper.load_public_key_from_str(otk_public_key_str)})
            one_time_key_signatures_dict.update({uuid: otk_signature_str})

        client_data.one_time_keys = one_time_keys_dict
        client_data.one_time_key_signatures = one_time_key_signatures_dict
        client_data.registration_complete = True
        client_data.messages = dict()
        client_data.confirmations = dict()
        self.api_clients.update_client(number, client_data)

        self.send_response(HTTPStatus.OK)
        return STATUS_OK_RESPONSE

    def api_client_id(self, input_data: Dict) -> Dict:
        number = input_data.get(PHONE_NUMBER_FIELD)
        target = input_data.get(TARGET_NUMBER_FIELD)
        target_signature = input_data.get(TARGET_NUMBER_SIGNATURE_FIELD)

        if not (number and target and target_signature):
            raise Exception("Phone number, target and signature are required.")

        client_data = self.api_clients.get_client(number)
        if not client_data:
            raise Exception("Phone number does not exist.")

        signature_match = CryptoHelper.verify_signature_on_data_hash(client_data.signed_id_key.public_key(),
                                                                     bytes.fromhex(target_signature),
                                                                     target.encode())
        if not signature_match:
            raise Exception("Signature on target doesn't match client!")

        target_data = self.api_clients.get_client(target)
        if not target_data:
            raise Exception("Target number does not exist.")

        self.send_response(HTTPStatus.OK)
        return {TARGET_NUMBER_FIELD: number, ID_KEY_FIELD: CryptoHelper.cert_to_str(target_data.signed_id_key)}

    def api_message_request(self, input_data: Dict) -> Dict:
        number = input_data.get(PHONE_NUMBER_FIELD)
        target = input_data.get(TARGET_NUMBER_FIELD)
        target_signature = input_data.get(TARGET_NUMBER_SIGNATURE_FIELD)

        if not (number and target and target_signature):
            raise Exception("Phone number, target and signature are required.")

        client_data = self.api_clients.get_client(number)
        if not client_data:
            raise Exception("Phone number does not exist.")

        signature_match = CryptoHelper.verify_signature_on_data_hash(client_data.signed_id_key.public_key(),
                                                                     bytes.fromhex(target_signature),
                                                                     target.encode())
        if not signature_match:
            raise Exception("Signature on target doesn't match client!")

        target_data = self.api_clients.get_client(target)
        if not target_data:
            raise Exception("Target number does not exist.")

        otk_uuid, otk = target_data.one_time_keys.popitem()
        otk_signature = target_data.one_time_key_signatures.pop(otk_uuid)
        self.api_clients.update_client(target, target_data)

        self.send_response(HTTPStatus.OK)
        return {TARGET_NUMBER_FIELD: number,
                ONETIME_KEY_FIELD: [otk_uuid, CryptoHelper.pub_key_to_str(otk), otk_signature]}

    def api_message_send(self, input_data: Dict) -> Dict:
        sender_number = input_data.get(PHONE_NUMBER_FIELD)
        target = input_data.get(TARGET_NUMBER_FIELD)
        target_otk_uuid = input_data.get(ONETIME_KEY_UUID_FIELD)
        session_pub_key_str = input_data.get(MESSAGE_PUBLIC_KEY_FIELD)
        enc_message = input_data.get(MESSAGE_ENC_MESSAGE_FIELD)
        bundle_signature = input_data.get(MESSAGE_BUNDLE_SIGNATURE_FIELD)

        if not (
                sender_number and target and target_otk_uuid and session_pub_key_str and enc_message and bundle_signature):
            raise Exception("Phone number, target, OTK UUID, Session key, encrypted message and signature are required")

        sender_data = self.api_clients.get_client(sender_number)
        if not sender_data:
            raise Exception("Phone number does not exist.")

        bundle = target.encode() + bytes.fromhex(enc_message) + session_pub_key_str.encode()
        signature_match = CryptoHelper.verify_signature_on_data_hash(sender_data.signed_id_key.public_key(),
                                                                     bytes.fromhex(bundle_signature),
                                                                     bundle)
        if not signature_match:
            raise Exception("Signature on target doesn't match client!")

        receiver_data = self.api_clients.get_client(target)
        if not receiver_data:
            raise Exception("Target number does not exist.")

        outgoing_sender_messages = receiver_data.messages.get(sender_number) or list()
        outgoing_sender_messages.append((target_otk_uuid, enc_message, session_pub_key_str, bundle_signature))
        receiver_data.messages.update({sender_number: outgoing_sender_messages})
        self.api_clients.update_client(target, receiver_data)

        self.send_response(HTTPStatus.OK)
        return STATUS_OK_RESPONSE

    def api_message_inbox(self, input_data: Dict) -> Dict:
        number = input_data.get(PHONE_NUMBER_FIELD)
        number_signature = input_data.get(PHONE_NUMBER_SIGNATURE_FIELD)

        if not (number and number_signature):
            raise Exception("Phone number and signature are required.")

        client_data = self.api_clients.get_client(number)
        if not client_data:
            raise Exception("Phone number does not exist.")

        signature_match = CryptoHelper.verify_signature_on_data_hash(client_data.signed_id_key.public_key(),
                                                                     bytes.fromhex(number_signature),
                                                                     number.encode())
        if not signature_match:
            raise Exception("Signature on target doesn't match client!")

        self.send_response(HTTPStatus.OK)
        return {MESSAGE_INCOMING_FIELD: client_data.messages,
                MESSAGE_CONF_INCOMING_FIELD: client_data.confirmations}
