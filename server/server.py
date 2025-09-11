import asyncio
import hashlib
import json
import os
import socket
import sys
import threading
import datetime
from pathlib import Path
from asyncio import transports

# Ensure project root is in sys.path for internal imports
project_root = Path(__file__).resolve().parent.parent
sys.path.append(str(project_root))

# Schnorr Protocol
from schnorr_protocol import *

from schnorr_protocol.exceptions import ValidationError
from common.logger import Logger

from utils.context import ConnContext

# from temp_token import *
from models import User, HashedUser, PublicKey

from services.user_services import UserService
from services.public_key_services import PublicKeyServices
from utils.db import Database

DEBUG = True

logger = Logger()

# --- Struttura globale per le connessioni attive ---
active_connections = {}
connections_lock = asyncio.Lock()


async def register_connection(identifier: str, ctx: ConnContext):
    with connections_lock:
        active_connections[identifier] = ctx


async def get_connection(identifier) -> ConnContext:
    with connections_lock:
        return active_connections.get(identifier)


async def remove_connection(identifier):
    with connections_lock:
        active_connections.pop(identifier, None)


def generate_token(token_length: int, pk: str, device_name: str) -> str:
    nonce = os.urandom(16).hex()
    token_raw = f"{pk}{device_name or ''}{nonce}"
    token = hashlib.sha256(token_raw.encode()).hexdigest()[:token_length]
    return token


async def safe_close(ctx: ConnContext):
    try:
        if not ctx.is_session_empty:
            await UserService.update_user_login(ctx.session.logged_pk, False)
            ctx.clear_session()
        await ctx.close()
        logger.info(f"[SERVER] Connessione chiusa con il client {ctx.addr}")
    except Exception as e:
        logger.error(f"[SERVER] Errore durante la chiusura di {ctx.addr}: {e}")


# ---------- handlers ----------


class Server:
    def __init__(self, conn, addr, db):
        self.ctx = ConnContext(conn, addr)
        self.schnorr_verifier = None
        self.db = db

    async def handle_handshake(self):
        handshake_res = Message(
            msg_type=MessageType.HANDSHAKE_RES,
            payload={"crypto_groups": GroupType.get_all_groups_str()},
        )

        if DEBUG:
            logger.debug(f"[SERVER] Inviata risposta di handshake {handshake_res.to_log()}")

        await self.ctx.send(handshake_res)

        msg = await self.ctx.receive()

        if msg is None:
            logger.info(f"[SERVER] Nessun messaggio ricevuto, chiudo la connessione...")
            await safe_close(self.ctx)
            return

        if msg.msg_type == MessageType.HANDSHAKE_OK:
            try:
                msg.validate_message({"group_id": str})
            except ValidationError as e:
                await self.ctx.send(Error(msg_type=ErrorType.MALFORMED_MESSAGE))
                if DEBUG:
                    logger.error(f"[SERVER] Errore di validazione: {e}")
                return

            data = msg.payload
            group_id = data["group_id"]
            self.schnorr_verifier = SchnorrVerifier(group_id=GroupType(group_id))

            logger.info(f"[SERVER] Handshake andato a buon fine con {self.ctx.addr}")
            logger.info(f"[SERVER] Gruppo crittografico scelto: {group_id}")

        if msg.msg_type == MessageType.HANDSHAKE_NOK:
            logger.info(
                f"[SERVER] Handshake non andato a buon fine con {self.ctx.addr}, chiudo la connessione..."
            )
            await safe_close(self.ctx)

        return

    async def handle_registration(self, msg: Message):
        try:
            msg.validate_message({"username": str, "device": str, "public_key": str})
        except ValidationError as e:
            await self.ctx.send(Error(msg_type=ErrorType.MALFORMED_MESSAGE))
            if DEBUG:
                logger.error(f"[SERVER] Errore di validazione: {e}")
            return

        data = msg.payload

        username = data["username"]
        device_name = data["device"]
        pk_raw = data["public_key"]

        self.schnorr_verifier.public_key = int(pk_raw, 16)
        pk_hash = hashlib.sha256(str(self.schnorr_verifier.public_key).encode()).hexdigest()

        user = await UserService.get_user(pk_hash)

        if user:
            await self.ctx.send(Error(msg_type=ErrorType.USERNAME_ALREADY_EXISTS))
            if DEBUG:
                logger.debug(f"[SERVER] Registrazione fallita: username '{username}' già esistente")
            return

        pk = await PublicKeyServices.create_public_key(
            pk=pk_raw, hash_pk=pk_hash, device_name=device_name, logged=True
        )

        user = await UserService.create_user(username=username, pk=pk)

        self.ctx.update_session(user=user, logged_pk=pk, login_time=datetime.datetime.now())

        await self.ctx.send(
            Message(msg_type=MessageType.REGISTERED, payload={"username": username})
        )

        if DEBUG:
            logger.debug(f"[SERVER] Utente registrato: {username}")

        return

    async def handle_auth_request(self, msg: Message):
        
        try:
            msg.validate_message({"username": str, "public_key_temp": str, "pk_hash": str})
        except ValidationError as e:
            await self.ctx.send(Error(msg_type=ErrorType.MALFORMED_MESSAGE))
            if DEBUG:
                logger.error(f"[SERVER] Errore di validazione {e}")
            return

        data = msg.payload

        username = data["username"]
        temp_pk_hex = data["public_key_temp"]
        pk_hash = data["pk_hash"]

        user = await UserService.get_user(pk_hash)


        if not user:
            await self.ctx.send(
                Message(msg_type=MessageType.AUTH_REJECTED, payload={"challenge": ""})
            )
            if DEBUG:
                logger.debug(f"[SERVER] Autenticazione fallita: username '{username}' non trovato")
            return
        
        if DEBUG:
            logger.debug(f"[SERVER] user: {user.model_dump()}")

        try:
            temp_pk = int(temp_pk_hex, 16)
            self.schnorr_verifier.public_key_temp = temp_pk
        except (ValueError, TypeError) as e:
            logger.error(f"[SERVER]: Errore di conversione: {e}")
            self.ctx.send(Error(msg_type=ErrorType.MALFORMED_MESSAGE))
            return

        challenge = self.schnorr_verifier.challenge  # Genera la challenge (int)

        self.ctx.update_session(temp_pk=temp_pk, user=user, challenge=challenge)

        await self.ctx.send(
            Message(msg_type=MessageType.AUTH_CHALLENGE, payload={"challenge": hex(challenge)})
        )
        if DEBUG:
            logger.debug(f"[SERVER] Sfida inviata a {username}: {hex(challenge)[:20]}...")

        return

    async def handle_auth_response(self, msg: Message):
        if self.ctx.is_session_empty:
            if DEBUG:
                logger.error("[SERVER] Risposta di autenticazione senza sessione attiva")
            await self.ctx.send(Error(msg_type=ErrorType.SESSION_NOT_FOUND))
            return

        try:
            msg.validate_message({"response": str})
        except ValidationError as e:
            await self.ctx.send(Error(msg_type=ErrorType.MALFORMED_MESSAGE))
            if DEBUG:
                logger.error(f"[SERVER] Errore di validazione {e}")
            return

        data = msg.payload

        res_hex = data["response"]

        try:
            res = int(res_hex, 16)
        except (ValueError, TypeError):
            logger.error(f"[SERVER]: Errore di conversione: {e}")
            await self.ctx.send(Error(msg_type=ErrorType.MALFORMED_MESSAGE))
            return

        public_keys = self.ctx.session.user.public_keys

        authenticated = False
        logged_pk = None
        for pk in public_keys:
            self.schnorr_verifier.public_key = int(pk.pk, 16)
            if self.schnorr_verifier.check(res):
                authenticated = True
                logged_pk = pk
                break

        if authenticated:
            await self.ctx.send(
                Message(
                    msg_type=MessageType.AUTH_ACCEPTED,
                    payload={"username": self.ctx.session.user.username},
                )
            )
            self.ctx.update_session(logged_pk=logged_pk, login_time=datetime.datetime.now())
            await UserService.update_user_login(logged_pk, True)

            if DEBUG:
                logger.debug(
                    f"[SERVER] User {self.ctx.session.user.username} autenticato dal dispositivo {self.ctx.session.logged_pk.device_name}"
                )
        else:
            await self.ctx.send(Message(msg_type=MessageType.AUTH_REJECTED))
            if DEBUG:
                logger.debug("[SERVER] Autenticazione rifiutata")

        return

    async def handle_assoc_request(self, msg: Message):
        token_length = 32

        try:
            msg.validate_message({"pk": str, "device": str})
        except ValidationError as e:
            self.ctx.send(Error(msg_type=ErrorType.MALFORMED_MESSAGE))
            if DEBUG:
                logger.error(f"[SERVER] Errore di validazione {e}")
            return

        data = msg.payload

        pk = data["pk"]
        device_name = data["device"]

        token = generate_token(token_length, pk, device_name)
        if DEBUG:
            logger.debug(f"[SERVER] Hashed Token: {token}")

        self.ctx.send(Message(msg_type=MessageType.ASSOC_SEND_TOKEN, payload={"token": token}))

        temp_token = TempToken(token, pk, device_name)
        temp_token.insert_temp_token()

        register_connection(token, self.ctx)
        if DEBUG:
            logger.debug(f"[SERVER] Salvata tupla: {token} - {pk[:20]}...")

        return

    def handle_assoc_confirm(self, msg: Message):
        try:
            msg.validate_message({"token": str})
        except ValidationError as e:
            self.ctx.send(Error(msg_type=ErrorType.MALFORMED_MESSAGE))
            if DEBUG:
                logger.error(f"[SERVER] Errore di validazione {e}")
            return

        data = msg.payload

        token = data["token"]
        temp_token = TempToken.find_pk_by_id(token)

        if not temp_token:
            self.ctx.send(Error(msg_type=ErrorType.UNAUTHORIZED_ACTION))
            if DEBUG:
                logger.error(f"[SERVER] Errore: {ErrorType.UNAUTHORIZED_ACTION.message()}")
            return

        pk, device_name = temp_token.pk, temp_token.device_name

        if not self.ctx.session.is_authenticated():
            self.ctx.send(Error(msg_type=ErrorType.SESSION_NOT_FOUND))
            if DEBUG:
                logger.error(f"[SERVER] Errore: {ErrorType.SESSION_NOT_FOUND.message()}")
            return

        devices = self.ctx.session.user.devices
        logged_device = self.ctx.session.logged_device

        for device in devices:
            if device["device_name"] == logged_device and not device["main_device"]:
                self.ctx.send(Error(msg_type=ErrorType.NO_MAIN_DEVICE))
                if DEBUG:
                    logger.error(f"[SERVER] Errore: {ErrorType.NO_MAIN_DEVICE.message()}")
                return

        if temp_token.is_expired:
            self.ctx.send(Error(msg_type=ErrorType.TOKEN_INVALID_OR_EXPIRED))
            TempToken.delete_one(token)
            if DEBUG:
                logger.error(f"[SERVER] Errore: {ErrorType.TOKEN_INVALID_OR_EXPIRED.message()}")
            return

        user = self.ctx.session.user

        user.update_user_with_device(pk, device_name)

        self.ctx.update_session(user=user)

        TempToken.delete_one(token)

        # Verifica che il secondo dispositivo non si sia scollegato nel mentre, altrimenti annulla accoppiamento
        # e dal database viene cancellata la coppia tempo_token

        s_ctx = get_connection(token)

        if not s_ctx:
            self.ctx.send(Error(msg_type=ErrorType.ASSOC_REJECTED))
            if DEBUG:
                logger.debug(f"[SERVER] {ErrorType.message(ErrorType.ASSOC_REJECTED)}")
            return

        # Send ACCEPT message to main device
        self.ctx.send(Message(msg_type=MessageType.AUTH_ACCEPTED))
        if DEBUG:
            logger.debug(
                f"[SERVER] Dispositivo associato a {user._id}: {device_name} ({pk[:20]}...)"
            )

        # Send ACCEPT message to second device
        # TODO: thread lock?
        s_ctx.update_session(
            user=user, logged_device=device_name, login_time=datetime.datetime.now()
        )
        s_ctx.send(Message(msg_type=MessageType.AUTH_ACCEPTED, payload={"username": user._id}))

        return

    def handle_devices_request(self):
        if self.ctx.is_session_empty:
            self.ctx.send(Error(msg_type=ErrorType.SESSION_NOT_FOUND))
            if DEBUG:
                logger.debug("[SERVER] Richiesta dispositivi senza sessione attiva")
            return

        user = self.ctx.session.user

        devices = user.get_user_devices()

        devices_info = [
            {
                "device_name": device["device_name"],
                "main_device": device.get("main_device"),
                "logged": device.get("logged"),
            }
            for device in devices
        ]

        self.ctx.send(Message(msg_type=MessageType.DEVICE_RES, payload={"devices": devices_info}))
        if DEBUG:
            logger.debug(f"[SERVER] Lista dispositivi inviata a {user._id}")

        return

    async def handle_logout(self):
        # se session presente, invalida e chiudi
        if not self.ctx.is_session_empty:
            await self.ctx.send(Message(msg_type=MessageType.LOGGED_OUT))
            await UserService.update_user_login(self.ctx.session.logged_pk, False)
            self.ctx.clear_session()
            if DEBUG:
                logger.debug("[SERVER] Logout effettuato con successo")
        else:
            self.ctx.send(Error(msg_type=ErrorType.SESSION_NOT_FOUND))
            if DEBUG:
                logger.debug(f"[SERVER] Errore: {ErrorType.SESSION_NOT_FOUND.message()}")
        return

    # ---------------- client handler ----------------

    async def client_handler(self):
        logger.info(f"[SERVER] Connessione avviata per {self.ctx.addr}")
        try:
            while True:
                msg = await self.ctx.receive()
                if msg is None:
                    logger.info(f"[SERVER] Connessione chiusa dal client {self.ctx.addr}")
                    break

                msg_type = msg.msg_type

                if msg_type == MessageType.HANDSHAKE_REQ:
                    await self.handle_handshake()
                elif msg_type == MessageType.REGISTRATION_REQ:
                    await self.handle_registration(msg)
                elif msg_type == MessageType.AUTH_COMMITMENT:
                    await self.handle_auth_request(msg)
                elif msg_type == MessageType.AUTH_RESPONSE:
                    await self.handle_auth_response(msg)
                elif msg_type == MessageType.ASSOC_REQ:
                    await self.handle_assoc_request(msg)
                elif msg_type == MessageType.ASSOC_RECV_TOKEN:
                    self.handle_assoc_confirm(msg)
                elif msg_type == MessageType.DEVICE_REQ:
                    self.handle_devices_request()
                elif msg_type == MessageType.LOGOUT:
                    await self.handle_logout()
                else:
                    logger.info(f"[SERVER] Tipo messaggio sconosciuto: {msg_type.log_message}")
        except Exception as e:
            await safe_close(self.ctx)
            logger.error(f"[SERVER] Errore nella coroutine per {self.ctx.addr}: {e}")
        finally:
            if not self.ctx._closed:
                await safe_close(self.ctx)
            logger.info(f"[SERVER] Coroutine terminata per {self.ctx.addr}")


# ---------------- main ----------------


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    db = Database(db_name="SchnorrAuthServer")
    await db.init([User, PublicKey, HashedUser])

    task = asyncio.current_task()

    addr = writer.get_extra_info("peername")

    if DEBUG:
        logger.debug(f"[SERVER] Task {task.get_name()} gestisce {addr}")

    server = Server(reader, writer, db)
    await server.client_handler() 


async def main():
    with open("config.json", "r", encoding="utf-8") as f:
        config = json.load(f)

    server = await asyncio.start_server(
        lambda r, w: asyncio.create_task(handle_client(r, w), name="ClientTask"),
        config["host"],
        config["port"],
    )
    
    logger.info(f"[SERVER] Server in ascolto su {config["host"]}:{config["port"]}")
    
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
