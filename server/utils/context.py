import socket
import datetime

from typing import Optional, Any, Dict

from schnorr_protocol import *

from dataclasses import dataclass

from models.user import User


@dataclass
class SessionData:
    user: User = None
    logged_device: Optional[str] = None
    login_time: datetime.datetime = None
    temp_pk: Optional[int] = None
    challenge: Optional[int] = None

    def is_authenticated(self) -> bool:
        return self.user is not None


class ConnContext:
    MESSAGE_LENGTH = 4096

    def __init__(self, conn: socket.socket, addr: str):
        self.conn = conn
        self.addr = addr
        self.session = SessionData()
        self._closed = False

    def close(self) -> None:
        """Chiude la connessione e pulisce i dati di sessione."""
        if self._closed:
            return
        try:
            self.conn.close()
            self.clear_session()
            self._closed = True
        except Exception as e:
            raise e
            
    def update_session(self, **kwargs):
        for key, value in kwargs.items():
            if hasattr(self.session, key):
                setattr(self.session, key, value)

    def get_session_data(self) -> Dict[str, Any]:
        """Restituisce una copia dei dati di sessione."""
        return self.session.copy()

    def clear_session(self):
        self.session = SessionData()  # reset

    @property
    def is_session_empty(self) -> bool:
        return not self.session.is_authenticated()

    def send(self, message: Message | Error) -> bool: # TODO: rilanciare l'eccezione
        """Invia un messaggio JSON al client."""
        if self._closed:
            print(f"[SERVER] Tentativo di invio a {self.addr}, ma connessione già chiusa.")
            return False
        try:
            self.conn.sendall(encode_message(message))
            return True
        except (BrokenPipeError, ConnectionResetError):
            print(f"[SERVER] Errore: connessione chiusa dal client {self.addr} durante l'invio")
            self.close()
            return False

    def receive(self) -> Message | Error | None:
        """Riceve un messaggio JSON dal client."""
        if self._closed:
            return None
        try:
            data = self.conn.recv(self.MESSAGE_LENGTH)
            if not data:
                self.close()
                return None
            return decode_message(data.decode())
        except ConnectionResetError:
            self.close()
            return None
