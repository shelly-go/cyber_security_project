class BaseServerException(Exception):
    pass


class SocketBaseException(BaseServerException):
    pass


class SocketRecvException(SocketBaseException):
    pass


class SocketSendException(SocketBaseException):
    pass


class SocketCloseException(SocketBaseException):
    pass
