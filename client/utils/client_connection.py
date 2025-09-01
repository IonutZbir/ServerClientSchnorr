import socket
from schnorr_protocol import *

class ClientConnection:
    MESSAGE_LENGTH = 4096

    def __init__(self, sock: socket.socket):
        self.sock = sock

    def send(self, message: Message | Error): # TODO: rilanciare l'eccezione
        try:
            self.sock.sendall(encode_message(message))
        except (BrokenPipeError, OSError) as e:
            raise e

    def receive(self) -> Message | Error | None:
        try:
            data = self.sock.recv(self.MESSAGE_LENGTH)
            if not data:
                return None
            return decode_message(data.decode())
        except ConnectionResetError as e:
            raise e

    def close(self):
        try:
            self.sock.close()
        except Exception as e:
            raise e
