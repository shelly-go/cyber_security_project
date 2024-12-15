
import socket
import threading

from consts import HOST, PORT, MAX_CONNECTIONS
from connection_wrapper import ConnectionWrapper


class Server:
    def __init__(self):
        self.host = HOST
        self.port = PORT
        self.clients = []
        self.socket = self.__setup_socket()

    def __setup_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((str(self.host), int(self.port)))
        return sock

    def __handle_request(self, connection):
        try:
            self.coordinator.handle(connection)
            connection.disconnect()
        except Exception as e:
            print(f"CRITICAL: thread failed with error: {str(e)}")

    def serve(self):
        print(f"Serving on {self.host}:{self.port}")
        self.socket.listen(MAX_CONNECTIONS)
        while True:
            connection = ConnectionWrapper(*self.socket.accept())
            threading.Thread(target=self.__handle_request, args=(connection,)).start()
