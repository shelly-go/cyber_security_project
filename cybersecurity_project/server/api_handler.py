import http.server
import json
import logging
import re
from http import HTTPStatus
from typing import Dict
from urllib.parse import urlparse

from common.crypto import CryptoHelper
from server.client_data import ClientData
from server.utils import generate_otp, send_by_secure_channel

PHONE_NUMBER_FIELD = 'phone_number'
OTP_FIELD = 'otp'
OTP_HASH_FIELD = 'otp_hash'
ID_KEY_FIELD = 'id_key'
SIGNED_KEY_FIELD = 'signed_key'
ONETIME_KEYS_FIELD = 'onetime_keys'


class Handler(http.server.SimpleHTTPRequestHandler):

    def __init__(self, clients, *args, **kwargs):
        self.clients = clients
        self.logger = logging.getLogger()
        super().__init__(*args, **kwargs)

    def extract_uri(self):
        return re.sub(r'/+', '/', urlparse(self.path).path).rstrip('/') or '/'

    def find_request_api_handler(self, uri):
        # URI mapping for different API endpoints
        self.logger.debug(f'Getting handler function for uri: "{uri}"')
        mapping = {
            "/": self.api_root,
            "/register/number": self.api_register_number,
            "/register/otp": self.api_register_otp,
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
            err = repr(e)
        finally:
            if err or data_json is None:
                data_json = self.api_error(err=err)

        data = json.dumps(data_json).encode()
        self.send_header("Content-type", 'application/json')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def api_not_implemented(self, input_data: Dict) -> Dict:
        self.send_response(HTTPStatus.NOT_IMPLEMENTED)
        return {"error": "Not implemented!"}

    def api_error(self, input_data: Dict = None, err=None) -> Dict:
        self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
        return {"error": str(err) if err else "Unspecified"}

    def api_register_number(self, input_data: Dict) -> Dict:
        number = input_data.get(PHONE_NUMBER_FIELD)
        if number is None:
            raise Exception("Phone number is required for registration")

        if self.clients.get(number) is not None:
            raise Exception("Phone number already exists.")

        otp = generate_otp()
        otp_hash = CryptoHelper.hash_with_sha256(otp.encode())
        client = ClientData(phone_number=number, otp_hash=otp_hash)
        self.clients[number] = client

        send_by_secure_channel(number, otp)
        self.send_response(HTTPStatus.OK)
        return {PHONE_NUMBER_FIELD: number, OTP_FIELD: otp}

    def api_register_otp(self, input_data: Dict) -> Dict:
        number = input_data.get(PHONE_NUMBER_FIELD)
        otp_hash = input_data.get(OTP_HASH_FIELD)
        id_key = input_data.get(ID_KEY_FIELD)
        signed_key = input_data.get(SIGNED_KEY_FIELD)
        onetime_keys = input_data.get(ONETIME_KEYS_FIELD)
        if number is None or otp_hash is None or id_key is None or signed_key is None or onetime_keys is None:
            raise Exception("Phone number, otp hash, id key, signed key and one-time keys are required.")

        client = self.clients.get(number)
        if client is None:
            raise Exception("Phone number does not exist.")

        if otp_hash != client.otp_hash:
            raise Exception(f"Incorrect otp for number {number}.")

        client.identity_key = id_key
        client.signed_key = signed_key
        client.one_time_keys = onetime_keys

        self.send_response(HTTPStatus.OK)
        return {"status": "ok"}

    def api_root(self, input_data: Dict = None) -> Dict:
        self.send_response(HTTPStatus.OK)
        return {"status": "ok"}
