import asyncio
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path

# Ensure project root is in sys.path for internal imports
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.append(str(project_root))

from schnorr_protocol import SchnorrVerifier, GroupType, MessageType, ErrorType, Message, Error, encode_message, decode_message
from schnorr_protocol.exceptions import ValidationError

from common.logger import Logger
from utils.context import ConnContext, GlobalSessionPairing
from models import Pairing, User, HashedUser, PublicKey

from services.user_services import UserService
from services.public_key_services import PublicKeyServices
from services.pairing_services import PairingServices
from utils.db import Database

from Crypto.Hash import RIPEMD160

DEBUG = True

logger = Logger()

class Server:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.ctx = ConnContext(reader, writer)
        self.schnorr_verifier = None

    async def send(self, message: Message | Error, ctx: ConnContext = None) -> None:
        try:
            if ctx is None:
                ctx = self.ctx
            await ctx.send(encode_message(message))
            
        except Exception as e:
            logger.error(f"[SERVER] Errore durante l'invio: {e}")
            self.close()
    
    async def receive(self, timeout: float = 300.0) -> Message | Error | None:
        try:
            data = await asyncio.wait_for(self.ctx.receive(), timeout=timeout)
        except Exception as e:
            logger.error(f"[SERVER] Errore durante il ricevimento: {e}")
            return None
        return decode_message(data)

    async def close(self):
        try:
            if not self.ctx.is_session_empty:
                await UserService.update_user_login(self.ctx.session.logged_pk, False)
            logger.info(f"[SERVER] Connessione chiusa con il client {self.ctx.addr}")
            await self.ctx.close()
        except Exception as e:
            logger.error(f"[SERVER] Errore durante la chiusura di {self.ctx.addr}: {e}")

    async def _validate_message(self, msg: Message, fields: dict) -> bool:
        try:
            msg.validate_message(fields)
        except ValidationError as e:
            await self.send(Error(msg_type=ErrorType.MALFORMED_MESSAGE))
            if DEBUG:
                logger.error(f"[SERVER] Errore di validazione: {e}")
            await self.close()
            return False
        return True
        
    async def handle_handshake(self) -> bool:
        handshake_res = Message(
            msg_type=MessageType.HANDSHAKE_RES,
            payload={"crypto_groups": GroupType.get_all_groups_str()},
        )

        if DEBUG:
            logger.debug(f"[SERVER] Inviata risposta di handshake {handshake_res.to_log()}")

        await self.send(handshake_res)

        msg = await self.receive()
        if msg is None:
            await self.close()
            return

        if msg.msg_type == MessageType.HANDSHAKE_OK:
            if not await self._validate_message(msg, {"group_id": str}):
                return

            data = msg.payload
            group_id = data["group_id"]
            self.schnorr_verifier = SchnorrVerifier(group_id=GroupType(group_id))

            logger.info(f"[SERVER] Handshake andato a buon fine con {self.ctx.addr}")
            if DEBUG:
                logger.debug(f"[SERVER] Gruppo crittografico scelto: {group_id}")
                
        if msg.msg_type == MessageType.HANDSHAKE_NOK:
            logger.info(
                f"[SERVER] Handshake non andato a buon fine con {self.ctx.addr}, chiudo la connessione..."
            )
            await self.close()

        return
    
    async def handle_registration(self, msg: Message):
        if not await self._validate_message(msg, {"username": str, "device": str, "public_key": str}):
            return

        data = msg.payload

        username = data["username"]
        device_name = data["device"]
        pk_raw = data["public_key"]

        self.schnorr_verifier.public_key = int(pk_raw, 16)
        pk_hash = hashlib.sha256(str(self.schnorr_verifier.public_key).encode()).hexdigest()

        user = await UserService.get_user(pk_hash)

        if user:
            await self.send(Error(msg_type=ErrorType.USERNAME_ALREADY_EXISTS))
            if DEBUG:
                logger.debug(f"[SERVER] Registrazione fallita: username '{username}' già esistente")
            await self.close()
            return

        pk = await PublicKeyServices.create_public_key(
            pk=pk_raw, hash_pk=pk_hash, device_name=device_name, logged=True
        )

        user = await UserService.create_user(username=username, pk=pk)

        self.ctx.update_session(user=user, logged_pk=pk, login_time=datetime.now(), hash_pk=pk_hash)

        await self.send(
            Message(msg_type=MessageType.REGISTERED, payload={"username": username})
        )

        if DEBUG:
            logger.debug(f"[SERVER] Utente registrato: {username}")

        return

    async def handle_auth_request(self, msg: Message):
        if not await self._validate_message(msg, {"username": str, "public_key_temp": str, "pk_hash": str}):
            return

        data = msg.payload

        username = data["username"]
        temp_pk_hex = data["public_key_temp"]
        pk_hash = data["pk_hash"]
        user = await UserService.get_user(pk_hash)

        if not user:
            await self.send(
                Message(msg_type=MessageType.AUTH_REJECTED, payload={"challenge": ""})
            )
            if DEBUG:
                logger.debug(f"[SERVER] Autenticazione fallita: username '{username}' non trovato")
            await self.close()
            return

        try:
            temp_pk = int(temp_pk_hex, 16)
            self.schnorr_verifier.public_key_temp = temp_pk
        except (ValueError, TypeError) as e:
            logger.error(f"[SERVER]: Errore di conversione: {e}")
            await self.send(Error(msg_type=ErrorType.MALFORMED_MESSAGE))
            await self.close()
            return

        challenge = self.schnorr_verifier.challenge  # Genera la challenge (int)

        self.ctx.update_session(temp_pk=temp_pk, user=user, challenge=challenge, hash_pk = pk_hash)

        await self.send(
            Message(msg_type=MessageType.AUTH_CHALLENGE, payload={"challenge": hex(challenge)})
        )
        if DEBUG:
            logger.debug(f"[SERVER] Sfida inviata a {username}: {hex(challenge)[:20]}...")

        return
    
    async def handle_auth_response(self, msg: Message):
        if self.ctx.is_session_empty:
            if DEBUG:
                logger.error("[SERVER] Risposta di autenticazione senza sessione attiva")
            await self.send(Error(msg_type=ErrorType.SESSION_NOT_FOUND))
            await self.close()
            return

        if not await self._validate_message(msg, {"response": str}):
            return

        data = msg.payload

        res_hex = data["response"]

        try:
            res = int(res_hex, 16)
        except (ValueError, TypeError) as e:
            logger.error(f"[SERVER]: Errore di conversione: {e}")
            await self.send(Error(msg_type=ErrorType.MALFORMED_MESSAGE))
            await self.close()
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
            await self.send(
                Message(
                    msg_type=MessageType.AUTH_ACCEPTED,
                    payload={"username": self.ctx.session.user.username},
                )
            )
            self.ctx.update_session(logged_pk=logged_pk, login_time=datetime.now())
            await UserService.update_user_login(logged_pk, True)

            if DEBUG:
                logger.debug(
                    f"[SERVER] User {self.ctx.session.user.username} autenticato dal dispositivo {self.ctx.session.logged_pk.device_name}"
                )
        else:
            await self.send(Message(msg_type=MessageType.AUTH_REJECTED,  payload={"username":""}))
            if DEBUG:
                logger.debug("[SERVER] Autenticazione rifiutata")

        return

    async def handle_assoc_request(self, msg: Message):
        if not await self._validate_message(msg, {"pk": str, "device": str}):
            return

        data = msg.payload

        pk = data["pk"]
        device_name = data["device"]
        
        
        hash_pk = hashlib.sha256(str(int(pk, 16)).encode())
        
        ripemd160_pk = RIPEMD160.new()

        ripemd160_pk.update(hash_pk.digest())
        
        pk = await PublicKeyServices.create_public_key(pk, hash_pk.hexdigest(), device_name, False)

        p = await PairingServices.create_pairing(f"0x{ripemd160_pk.hexdigest()}", pk)

        print(f"[SERVER] {ripemd160_pk.hexdigest()}")

        await GlobalSessionPairing.register_connection(p, self.ctx)

        return
    
    async def handle_assoc_confirm(self, msg: Message):
        if not await self._validate_message(msg, {"public_key_temp": str, "response": str, "message": str}):
            return
        
        data = msg.payload

        sign = {"public_key_temp": int(data["public_key_temp"], 16), "response": int(data["response"], 16)}

        result = self.schnorr_verifier.verify_sign(sign, data["message"])

        if not result:
            await self.send(Message(msg_type=MessageType.AUTH_REJECTED))
            if DEBUG:
                logger.debug("[SERVER] Autenticazione rifiutata")
            return

        pairing = await PairingServices.get_pairing_by_prefix(data["message"])
        if not pairing:
            await self.send(Error(msg_type=ErrorType.UNAUTHORIZED_ACTION))
            if DEBUG:
                logger.error(f"[SERVER] Errore: {ErrorType.UNAUTHORIZED_ACTION.message()}")
            await self.close()
            return

        if not self.ctx.session.is_authenticated():
            await self.send(Error(msg_type=ErrorType.SESSION_NOT_FOUND))
            if DEBUG:
                logger.error(f"[SERVER] Errore: {ErrorType.SESSION_NOT_FOUND.message()}")
            await self.close()
            return

        if pairing.is_expired:
            await self.send(Error(msg_type=ErrorType.TOKEN_INVALID_OR_EXPIRED))
            await PairingServices.delete_one(pairing)
            if DEBUG:
                logger.error(f"[SERVER] Errore: {ErrorType.TOKEN_INVALID_OR_EXPIRED.message()}")
            await self.close()
            return

        hash_pk = self.ctx.session.hash_pk
        pk = pairing.pk
        user = await UserService.add_new_publickey(hash_pk=hash_pk, new_pk=pk)

        if not user:
            await self.send(Error(msg_type=ErrorType.UNKNOWN_ERROR))
            await PairingServices.delete_one(pairing)
            if DEBUG:
                logger.error(f"[SERVER] Errore: {ErrorType.UNKNOWN_ERROR.message()}")
            await self.close()
            return
        
        self.ctx.update_session(user=user)

        await PairingServices.delete_one(pairing)
        await UserService.update_user_login(pk, True)
        
        # Verifica che il secondo dispositivo non si sia scollegato nel mentre, altrimenti annulla accoppiamento
        # e dal database viene cancellata la coppia temp_token

        s_ctx = await GlobalSessionPairing.get_connection(pairing)
        
        if not s_ctx:
            await self.send(Error(msg_type=ErrorType.ASSOC_REJECTED))
            if DEBUG:
                logger.debug(f"[SERVER] {ErrorType.message(ErrorType.ASSOC_REJECTED)}")
            await self.close()
            return

        # Send ACCEPT message to main device
        await self.send(Message(msg_type=MessageType.AUTH_ACCEPTED))
        if DEBUG:
            logger.debug(f"[SERVER] Dispositivo associato a {user.username}: {pk.device_name})")

        # Send ACCEPT message to second device
        s_ctx.update_session(user=user)
        s_ctx.update_session(logged_pk=pk, login_time=datetime.now())
        
        await self.send(Message(msg_type=MessageType.AUTH_ACCEPTED, payload={"username": user.username}), ctx=s_ctx)

        return
    
    async def handle_devices_request(self):
        if self.ctx.is_session_empty:
            await self.send(Error(msg_type=ErrorType.SESSION_NOT_FOUND))
            if DEBUG:
                logger.debug("[SERVER] Richiesta dispositivi senza sessione attiva")
            return

        user = self.ctx.session.user

        devices = await UserService.get_devices(user)

        devices_info = [
            {
                "device_name": device.device_name,
                "logged": device.logged,
            }
            for device in devices
        ]

        await self.send(Message(msg_type=MessageType.DEVICE_RES, payload={"devices": devices_info}))
        if DEBUG:
            logger.debug(f"[SERVER] Lista dispositivi inviata a {user.username}")

        return

    async def handle_logout(self):
        if not self.ctx.is_session_empty:
            await self.send(Message(msg_type=MessageType.LOGGED_OUT))
            await UserService.update_user_login(self.ctx.session.logged_pk, False)
            self.ctx.clear_session()
            if DEBUG:
                logger.debug("[SERVER] Logout effettuato con successo")
        else:
            await self.send(Error(msg_type=ErrorType.SESSION_NOT_FOUND))
            if DEBUG:
                logger.debug(f"[SERVER] Errore: {ErrorType.SESSION_NOT_FOUND.message()}")
            await self.close()
        return
    
    async def client_handler(self):
        logger.info(f"[SERVER] Connessione avviata per {self.ctx.addr}")
        try:
            while True:
                msg = await self.receive()
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
                elif msg_type == MessageType.ASSOC_CONFIRM:
                    await self.handle_assoc_confirm(msg)
                elif msg_type == MessageType.DEVICE_REQ:
                    await self.handle_devices_request()
                elif msg_type == MessageType.LOGOUT:
                    await self.handle_logout()
                else:
                    logger.info(f"[SERVER] Tipo messaggio sconosciuto: {msg_type.log_message}")
        except Exception as e:
            await self.close()
            logger.error(f"[SERVER] Errore nella coroutine per {self.ctx.addr}: {e}")
        finally:
            if not self.ctx._closed:
                await self.close()
            logger.info(f"[SERVER] Coroutine terminata per {self.ctx.addr}")

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):

    task = asyncio.current_task()

    addr = writer.get_extra_info("peername")

    if DEBUG:
        logger.debug(f"[SERVER] Task {task.get_name()} gestisce {addr}")

    server = Server(reader, writer)
    try:
        await server.client_handler()
    except asyncio.CancelledError:
        # cleanup on forced cancel
        await server.close()
        raise
    finally:
        await server.close()
    
async def main():
    with open("config.json", "r", encoding="utf-8") as f:
        config = json.load(f)

    client_tasks = set()

    db = Database(db_name="SchnorrAuthServer")
    await db.init([User, PublicKey, HashedUser, Pairing])

    async def client_connected(reader, writer):
        task = asyncio.create_task(handle_client(reader, writer))
        client_tasks.add(task)
        task.add_done_callback(client_tasks.discard)

    server = await asyncio.start_server(
        client_connected,
        config["host"],
        config["port"],
    )

    logger.info(f"[SERVER] Server in ascolto su {config['host']}:{config['port']}")

    async with server:
        try:
            await server.serve_forever()
        except asyncio.CancelledError:
            logger.info("[SERVER] Arresto manuale del server")
            for t in client_tasks:
                t.cancel()
            await asyncio.gather(*client_tasks, return_exceptions=True)
            raise

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("[SERVER] Arresto manuale del server")