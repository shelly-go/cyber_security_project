import http.server
import json
import re
from http import HTTPStatus
from typing import Dict
from urllib.parse import urlparse


class Handler(http.server.SimpleHTTPRequestHandler):
    def extract_uri(self):
        return re.sub(r'/+', '/', urlparse(self.path).path).rstrip('/') or '/'

    def find_request_api_handler(self, uri):
        # URI mapping for different API endpoints
        mapping = {
            "/": self.api_root,
            "/signup": self.api_signup,
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
            if data_json is None or err:
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

    def api_signup(self, input_data: Dict) -> Dict:
        self.send_response(HTTPStatus.OK)
        return input_data

    def api_root(self, input_data: Dict = None) -> Dict:
        self.send_response(HTTPStatus.OK)
        return {"status": "ok"}
