import http.server
import json
import re
from http import HTTPStatus
from typing import Dict
from urllib.parse import urlparse

from common.crypto import CryproHelper
from server.client_data import ClientData
from server.utils import generate_otp, send_by_secure_channel

PHONE_NUMBER_FIELD = 'phone_number'
OTP_FIELD = 'otp'
OTP_HASH_FIELD = 'otp_hash'
CA_FIELD = 'ca'


class Handler(http.server.SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        self.clients = dict()
        super().__init__(*args, **kwargs)

    def extract_uri(self):
        return re.sub(r'/+', '/', urlparse(self.path).path).rstrip('/') or '/'

    def find_request_api_handler(self, uri):
        # URI mapping for different API endpoints
        mapping = {
            "/": self.api_root,
            "/register/number": self.api_register_number,
            "/register/otp": self.api_register_otp,
            "/register/ca": self.api_register_ca,
        }

        handler = mapping.get(uri) or self.api_not_implemented
        return handler

    def do_POST(self):
        uri = self.extract_uri()
        self.log_message("Received API request for %s", uri)
        handler = self.find_request_api_handler(uri=uri)

        data_json = None
        err = None
        try:
            content_length = int(self.headers['Content-Length'])
            incoming_data = self.rfile.read(content_length).decode() or "{}"
            incoming_data_json = json.loads(incoming_data)
            data_json = handler(incoming_data_json)
        except Exception as e:
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
        otp_hash = CryproHelper.hash_with_sha256(otp.encode())
        client = ClientData(phone_number=number, otp_hash=otp_hash)
        self.clients[number] = client

        send_by_secure_channel(number, otp)
        self.send_response(HTTPStatus.OK)
        return {PHONE_NUMBER_FIELD: number, OTP_FIELD: otp}

    def api_register_otp(self, input_data: Dict) -> Dict:
        number = input_data.get(PHONE_NUMBER_FIELD)
        otp_hash = input_data.get(OTP_HASH_FIELD)
        if number is None or otp_hash is None:
            raise Exception("Phone number and otp hash are required.")

        client = self.clients.get(number)
        if client is None:
            raise Exception("Phone number does not exist.")

        if otp_hash != client.otp_hash:
            raise Exception("Incorrect otp.")

        self.send_response(HTTPStatus.OK)
        return {"status": "ok"}

    def api_register_ca(self, input_data: Dict) -> Dict:
        self.send_response(HTTPStatus.OK)
        return input_data

    def api_root(self, input_data: Dict = None) -> Dict:
        self.send_response(HTTPStatus.OK)
        return {"status": "ok"}
