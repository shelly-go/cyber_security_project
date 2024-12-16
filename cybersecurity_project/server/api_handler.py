import http.server
import json
import re
import traceback
from http import HTTPStatus
from typing import Dict
from urllib.parse import urlparse


class Handler(http.server.SimpleHTTPRequestHandler):
    def extract_uri(self):
        return re.sub(r'/+', '/', urlparse(self.path).path).rstrip('/')

    def find_request_api_handler(self, uri):
        # URI mapping for different API endpoints
        mapping = {
            "/": self.api_root,
            "/signup": self.api_signup,
        }

        handler = mapping.get(uri) or self.api_not_implemented
        return handler

    def do_GET(self):
        uri = self.extract_uri()
        self.log_message("Received API request for %s", uri)
        handler = self.find_request_api_handler(uri=uri)

        data_json = None
        err = None
        try:
            data_json = handler()
        except Exception as e:
            err = repr(e)
        finally:
            if not data_json or err:
                data_json = self.api_error(err)

        data = json.dumps(data_json)
        self.send_header("Content-type", 'application/json')
        self.send_header("Content-Length", str(len(data)))
        super().end_headers()
        self.wfile.write(data.encode())

    def api_not_implemented(self) -> Dict:
        self.send_response(HTTPStatus.NOT_IMPLEMENTED)
        return {"error": "Not implemented!"}

    def api_error(self, err=None) -> Dict:
        self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
        return {"error": str(err) if err else "Unspecified"}

    def api_signup(self) -> Dict:
        raise ZeroDivisionError("test")
        return self.api_not_implemented()

    def api_root(self) -> Dict:
        return {"status": "ok"}
