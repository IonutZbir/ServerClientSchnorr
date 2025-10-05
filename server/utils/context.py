import asyncio

from datetime import datetime

from typing import Optional, Any, Dict

from schnorr_protocol import *

from dataclasses import dataclass

from models import Pairing, PublicKey, User
from schnorr_protocol.exceptions import ConnectionAlreadyClosed

# TODO: rewrite

@dataclass(slots=True)
class SessionData:
    user: Optional[User] = None
    logged_pk: Optional[PublicKey] = None      # Public key of authenticated user
    login_time: Optional[datetime] = None
    temp_pk: Optional[int] = None        # Ephemeral PK during handshake
    challenge: Optional[int] = None      # Current Schnorr challenge

    def is_authenticated(self) -> bool:
        return self.user is not None

    def copy(self) -> Dict[str, Any]:
        return {
            "user": self.user,
            "logged_pk": self.logged_pk,
            "login_time": self.login_time,
            "temp_pk": self.temp_pk,
            "challenge": self.challenge,
        }

    def reset(self) -> None:
        self.user = None
        self.logged_pk = None
        self.login_time = None
        self.temp_pk = None
        self.challenge = None


class ConnContext:
    MESSAGE_LENGTH = 4096

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.addr = self.writer.get_extra_info("peername")
        self.session = SessionData()
        self._closed = False

    async def close(self) -> None:
        if self._closed:
            raise ConnectionAlreadyClosed()
        self.writer.close()
        await self.writer.wait_closed()
        self.clear_session()
        self._closed = True

    def update_session(self, **kwargs):
        for key, value in kwargs.items():
            if hasattr(self.session, key):
                setattr(self.session, key, value)

    def get_session_data(self) -> Dict[str, Any]:
        return self.session.copy()

    def clear_session(self):
        self.session.reset()

    @property
    def is_session_empty(self) -> bool:
        return not self.session.is_authenticated()

    async def send(self, message: str):
        if self._closed:
            raise ConnectionAlreadyClosed()
        self.writer.write(message)
        await self.writer.drain()

    async def receive(self) -> str:
        if self._closed:
            raise ConnectionAlreadyClosed()
        data = await self.reader.read(self.MESSAGE_LENGTH)
        return data.decode()

class GlobalSessionPairing:
    _active_connections: Dict[int, ConnContext] = {}
    _lock = asyncio.Lock()

    @classmethod
    async def register_connection(cls, pairing: Pairing, ctx: ConnContext) -> None:
        async with cls._lock:
            cls._active_connections[pairing.id] = ctx

    @classmethod
    async def get_connection(cls, pairing: Pairing) -> Optional[ConnContext]:
        async with cls._lock:
            return cls._active_connections.get(pairing.id)

    @classmethod
    async def remove_connection(cls, pairing: Pairing) -> None:
        async with cls._lock:
            cls._active_connections.pop(pairing.id, None)