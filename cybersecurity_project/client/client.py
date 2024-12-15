import ssl
from http.client import HTTPResponse
from urllib import request
from urllib.error import URLError


class Client:

    def __init__(self):
        self.ssl_context = self.get_ssl_context("client/server_cert/certificate.crt")
        self.server = "https://localhost/client"

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

    def connect(self):
        try:
            response: HTTPResponse = request.urlopen(self.server, context=self.ssl_context)
            print(response.read().decode())
        except URLError as e:
            if isinstance(e.reason, ssl.SSLCertVerificationError):
                print("Server's certificate is not the one we have!")
            else:
                print(f"Error: {e}")
