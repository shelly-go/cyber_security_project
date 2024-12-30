import http.server
import logging
import ssl
import sys

from server.api_handler import APIHandler
from server.client_handler import ClientHandler
from server.consts import HOST, PORT, SSL_CERT_PATH, SSL_PRIV_KEY_PATH, STARTUP_BANNER


class Server:
    def __init__(self):
        self.logger = logging.getLogger()
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[logging.StreamHandler(sys.stdout)],
        )
        print(STARTUP_BANNER)

        self.host = HOST
        self.port = PORT

        ClientHandler().load_client_id_keys()

    @staticmethod
    def get_ssl_context(cert_file, key_file):
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.load_cert_chain(certfile=cert_file,
                                keyfile=key_file)
        return context

    def serve(self):
        print(f"Serving on {self.host}:{self.port}")

        server_address = (self.host, self.port)
        httpd = http.server.ThreadingHTTPServer(server_address, APIHandler)

        context = self.get_ssl_context(SSL_CERT_PATH, SSL_PRIV_KEY_PATH)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

        httpd.serve_forever()
