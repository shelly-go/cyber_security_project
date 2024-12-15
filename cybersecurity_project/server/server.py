import http.server
import ssl
from http import HTTPStatus

from server.consts import HOST, PORT, SSL_CERT_PATH, SSL_PRIV_KEY_PATH


class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        print("Path:", self.path)
        data = "{'data': 'hi'}"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-type", 'application/json')
        self.send_header("Content-Length", str(data))
        super().end_headers()
        self.wfile.write(data.encode())


class Server:
    def __init__(self):
        self.host = HOST
        self.port = PORT
        self.clients = []

    @staticmethod
    def get_ssl_context(cert_file, key_file):
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.load_cert_chain(certfile=cert_file,
                                keyfile=key_file)
        return context

    def serve(self):
        print(f"Serving on {self.host}:{self.port}")

        server_address = (self.host, self.port)
        httpd = http.server.ThreadingHTTPServer(server_address, Handler)

        context = self.get_ssl_context(SSL_CERT_PATH, SSL_PRIV_KEY_PATH)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

        httpd.serve_forever()
