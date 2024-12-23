import http.server
import ssl

from server.api_handler import Handler
from server.consts import HOST, PORT, SSL_CERT_PATH, SSL_PRIV_KEY_PATH

from functools import partial


class Server:
    def __init__(self):
        self.host = HOST
        self.port = PORT
        self.clients = dict()

    @staticmethod
    def get_ssl_context(cert_file, key_file):
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.load_cert_chain(certfile=cert_file,
                                keyfile=key_file)
        return context

    def serve(self):
        print(f"Serving on {self.host}:{self.port}")

        server_address = (self.host, self.port)
        handler = partial(Handler, clients=self.clients)
        httpd = http.server.ThreadingHTTPServer(server_address, handler)

        context = self.get_ssl_context(SSL_CERT_PATH, SSL_PRIV_KEY_PATH)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

        httpd.serve_forever()
