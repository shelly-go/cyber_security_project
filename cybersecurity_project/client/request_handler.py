import json
import logging
import ssl
from http.client import HTTPResponse
from urllib import request
from urllib.error import URLError, HTTPError
from urllib.parse import urljoin

from client.consts import SERVER_URL, SERVER_CERT_PATH
from common.api_consts import ERROR_FIELD
from common.crypto import CryptoHelper


class RequestHandler:
    def __init__(self, server_url=SERVER_URL):
        self.server_url = server_url
        self.ssl_context = self.get_ssl_context(SERVER_CERT_PATH)
        self.server_certificate = CryptoHelper.cert_from_file(SERVER_CERT_PATH)
        self.logger = logging.getLogger()

    @staticmethod
    def get_ssl_context(cert_file):
        # Create an SSL context
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

        # Load the server's public certificate into the SSL context
        context.load_verify_locations(cert_file)

        # Disable loading system-wide certificates
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_default_certs = False

        return context

    def request(self, endpoint='', data=None):
        try:
            if data:
                data = json.dumps(data).encode()

            url = urljoin(self.server_url, endpoint)
            response: HTTPResponse = request.urlopen(url, data=data, context=self.ssl_context)
            return json.loads(response.read()), response.status
        except HTTPError as e:
            error_data = json.loads(e.file.read().decode()) if e.file.length else {ERROR_FIELD: e.reason}
            return error_data, e.status
        except URLError as e:
            if isinstance(e.reason, ssl.SSLCertVerificationError):
                self.logger.critical("Server's certificate is not the one we have!")
                exit(1)
            elif isinstance(e.reason, ConnectionRefusedError):
                self.logger.critical("Server is unreachable or offline!")
                exit(1)
            else:
                self.logger.critical(f"A URL error occurred while requesting: {e}")
                raise e
        except Exception as e:
            self.logger.critical(f"An error occurred while requesting: {e}")
            raise e
