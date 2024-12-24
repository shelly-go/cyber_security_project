import http.server
import json
import logging
import re
from http import HTTPStatus
from typing import Dict, Callable
from urllib.parse import urlparse

from common.api_consts import PHONE_NUMBER_FIELD, OTP_FIELD, OTP_HASH_FIELD, PUB_ID_KEY_FIELD, SIGNED_KEY_FIELD, \
    ONETIME_KEYS_FIELD, API_ENDPOINT_REGISTER_VALIDATE, API_ENDPOINT_REGISTER_NUMBER, API_ENDPOINT_ROOT, STATUS_OK, \
    STATUS_OK_RESPONSE, ERROR_FIELD, UNSPECIFIED_ERROR
from common.crypto import CryptoHelper
from server.client_handler import ClientData, ClientHandler
from server.utils import generate_otp, send_by_secure_channel


class APIHandler(http.server.SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        self.api_clients = ClientHandler()
        self.logger = logging.getLogger()
        super().__init__(*args, **kwargs)

    def extract_uri(self):
        return re.sub(r'/+', '/', urlparse(self.path).path).rstrip('/') or '/'

    def find_request_api_handler(self, uri) -> Callable[[dict], dict]:
        # URI mapping for different API endpoints
        self.logger.debug(f'Getting handler function for uri: "{uri}"')
        mapping = {
            API_ENDPOINT_ROOT: self.api_root,
            API_ENDPOINT_REGISTER_NUMBER: self.api_register_number,
            API_ENDPOINT_REGISTER_VALIDATE: self.api_register_otp,
        }

        handler = mapping.get(uri) or self.api_not_implemented
        return handler

    def do_POST(self):
        uri = self.extract_uri()
        # self.log_message("Received API request for %s", uri)
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

    def api_register_number(self, input_data: Dict) -> Dict:
        number = input_data.get(PHONE_NUMBER_FIELD)
        if not number:
            raise Exception("Phone number is required for registration")

        client_data = self.api_clients.get_client(number)
        if client_data and client_data.registration_complete:
            raise Exception("Phone number already exists.")

        otp = generate_otp()
        otp_hash = CryptoHelper.hash_with_sha256(otp.encode())
        client_data = ClientData(phone_number=number, otp_hash=otp_hash)
        self.api_clients.update_client(number, client_data)

        send_by_secure_channel(number, otp)
        self.send_response(HTTPStatus.OK)
        return {PHONE_NUMBER_FIELD: number, OTP_FIELD: otp}

    def api_register_otp(self, input_data: Dict) -> Dict:
        number = input_data.get(PHONE_NUMBER_FIELD)
        otp_hash = input_data.get(OTP_HASH_FIELD)
        id_key = input_data.get(PUB_ID_KEY_FIELD)
        if not (number and otp_hash) or not id_key:
            raise Exception("Phone number, otp hash, and ID key are required.")

        client_data = self.api_clients.get_client(number)
        if not client_data:
            raise Exception("Phone number does not exist.")

        if otp_hash != client_data.otp_hash:
            raise Exception(f"Incorrect otp for number {number}.")

        client_data.identity_key = id_key
        client_data.registration_complete = True
        self.api_clients.update_client(number, client_data)

        self.send_response(HTTPStatus.OK)
        return STATUS_OK_RESPONSE

    def api_setup_client_keys(self, input_data: Dict) -> Dict:
        number = input_data.get(PHONE_NUMBER_FIELD)
        otp_hash = input_data.get(OTP_HASH_FIELD)
        signed_key = input_data.get(SIGNED_KEY_FIELD)
        onetime_keys = input_data.get(ONETIME_KEYS_FIELD)

        if not (number and otp_hash and signed_key and onetime_keys):
            raise Exception("Phone number, id key, signed key and one-time keys are required.")

        client_data = self.api_clients.get_client(number)
        if not client_data:
            raise Exception("Phone number does not exist.")

        if otp_hash != client_data.otp_hash:
            raise Exception(f"Incorrect otp for number {number}.")

        client_data.signed_key = signed_key
        client_data.one_time_keys = onetime_keys
        self.api_clients.update_client(number, client_data)

        self.send_response(HTTPStatus.OK)
        return STATUS_OK_RESPONSE

    def api_root(self, input_data: Dict) -> Dict:
        self.send_response(HTTPStatus.OK)
        return STATUS_OK_RESPONSE
