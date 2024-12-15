import socket

from server.consts import CONNECTION_TIMEOUT
from exceptions import SocketCloseException, SocketRecvException, SocketSendException


class ConnectionWrapper:
    def __init__(self, client: socket.socket, addr: tuple):
        self.client = client
        self.addr = addr
        self.client.settimeout(CONNECTION_TIMEOUT)

        print(f"Connection from {self.addr}.")

    def disconnect(self):
        try:
            self.client.close()
        except socket.error as e:
            raise SocketCloseException(f"ERROR: socket disconnect got {str(e)}")
        else:
            print(f"INFO: Connection closed from {self.addr}.")

    def recv(self, num_of_bytes: int) -> bytes:
        try:
            data = self.client.recv(num_of_bytes)
            return data or b""
        except ConnectionError as ce:
            print(f"WARNING: socket closed with error {str(ce)}")
            return b""
        except socket.error as e:
            raise SocketRecvException(f"ERROR: socket receive got {str(e)}")

    def send(self, data: bytes):
        try:
            self.client.sendall(data)
        except socket.error as e:
            raise SocketSendException(f"ERROR: socket send got {str(e)}")
