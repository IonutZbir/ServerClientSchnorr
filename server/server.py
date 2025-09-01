import hashlib
import json
import os
import random
import socket
import sys
import threading
import datetime
from pathlib import Path


# Ensure project root is in sys.path for internal imports
project_root = Path(__file__).resolve().parent.parent
sys.path.append(str(project_root))

# Schnorr Protocol
from schnorr_protocol import *

from utils.context import ConnContext
from schnorr_protocol.exceptions import ValidationError
from common.logger import Logger

from models.temp_token import *
from models.user import *

DEBUG = True

logger = Logger()

# --- Struttura globale per le connessioni attive ---
active_connections = {}
connections_lock = threading.Lock()


def register_connection(identifier: str, ctx: ConnContext):
    with connections_lock:
        active_connections[identifier] = ctx


def get_connection(identifier) -> ConnContext:
    with connections_lock:
        return active_connections.get(identifier)


def remove_connection(identifier):
    with connections_lock:
        active_connections.pop(identifier, None)


def generate_token(token_length: int, pk: str, device_name: str) -> str:
    nonce = os.urandom(16).hex()
    token_raw = f"{pk}{device_name or ''}{nonce}"
    token = hashlib.sha256(token_raw.encode()).hexdigest()[:token_length]
    return token


def safe_close(ctx: ConnContext):
    try:
        ctx.close()
        logger.info(f"[SERVER] Connessione chiusa con il client {ctx.addr}")
    except Exception as e:
        logger.error(f"[SERVER] Errore durante la chiusura di {ctx.addr}: {e}")


# ---------- handlers ----------


def handle_handshake(ctx: ConnContext, schnorr_verifier: SchnorrVerifier):
    ctx.send(
        Message(
            msg_type=MessageType.HANDSHAKE_RES, payload={"group_id": schnorr_verifier.crypto_group}
        )
    )

    msg = ctx.receive()

    if msg is None:
        logger.info(f"[SERVER] Nessun messaggio ricevuto, chiudo la connessione...")
        safe_close(ctx)
        return

    if msg.msg_type == MessageType.HANDSHAKE_OK:
        logger.info(f"[SERVER] Handshake andato a buon fine con {ctx.addr}")

    if msg.msg_type == MessageType.HANDSHAKE_NOK:
        logger.info(
            f"[SERVER] Handshake non andato a buon fine con {ctx.addr}, chiudo la connessione..."
        )
        safe_close(ctx)

    return


def handle_registration(ctx: ConnContext, msg: Message, schnorr_verifier: SchnorrVerifier):
    try:
        msg.validate_message({"username": str, "device": str, "public_key": str})
    except ValidationError as e:
        ctx.send(Error(msg_type=ErrorType.MALFORMED_MESSAGE))
        if DEBUG:
            logger.error(f"[SERVER] Errore di validazione: {e}")
        return

    data = msg.payload

    username = data["username"]
    device_name = data["device"]
    pk = data["public_key"]

    schnorr_verifier.public_key = int(pk, 16)

    if User.find_user_by_id(username):
        ctx.send(Error(msg_type=ErrorType.USERNAME_ALREADY_EXISTS))
        if DEBUG:
            logger.debug(f"[SERVER] Registrazione fallita: username '{username}' già esistente")
        return

    user = User(username)
    user.add_device(Device(pk, device_name))

    user.insert_user()

    ctx.update_session(user=user, logged_device=device_name, login_time=datetime.datetime.now())

    ctx.send(Message(msg_type=MessageType.REGISTERED, payload={"username": username}))

    if DEBUG:
        logger.debug(f"[SERVER] Utente registrato: {username}")

    return


def handle_auth_request(ctx: ConnContext, msg: Message, schnorr_verifier: SchnorrVerifier):
    try:
        msg.validate_message({"username": str, "public_key_temp": str})
    except ValidationError as e:
        ctx.send(Error(msg_type=ErrorType.MALFORMED_MESSAGE))
        if DEBUG:
            logger.error(f"[SERVER] Errore di validazione {e}")
        return

    data = msg.payload

    username = data["username"]
    temp_pk_hex = data["public_key_temp"]

    user = User.find_user_by_id(username)

    if not user:
        ctx.send(Message(msg_type=MessageType.AUTH_REJECTED))
        if DEBUG:
            logger.debug(f"[SERVER] Autenticazione fallita: username '{username}' non trovato")
        return

    try:
        temp_pk = int(temp_pk_hex, 16)
        schnorr_verifier.public_key_temp = temp_pk
    except (ValueError, TypeError) as e:
        logger.error(f"[SERVER]: Errore di conversione: {e}")
        ctx.send(Error(msg_type=ErrorType.MALFORMED_MESSAGE))
        return

    challenge = schnorr_verifier.challenge  # Genera la challenge (int)

    ctx.update_session(temp_pk=temp_pk, user=user, challenge=challenge)

    ctx.send(Message(msg_type=MessageType.AUTH_CHALLENGE, payload={"challenge": hex(challenge)}))
    if DEBUG:
        logger.debug(f"[SERVER] Sfida inviata a {username}: {hex(challenge)[:20]}...")

    return


def handle_auth_response(ctx: ConnContext, msg: Message, schnorr_verifier: SchnorrVerifier):
    if ctx.is_session_empty:
        if DEBUG:
            logger.error("[SERVER] Risposta di autenticazione senza sessione attiva")
        ctx.send(Error(msg_type=ErrorType.SESSION_NOT_FOUND))
        return

    try:
        msg.validate_message({"response": str})
    except ValidationError as e:
        ctx.send(Error(msg_type=ErrorType.MALFORMED_MESSAGE))
        if DEBUG:
            logger.error(f"[SERVER] Errore di validazione {e}")
        return

    data = msg.payload

    res_hex = data["response"]

    try:
        res = int(res_hex, 16)
    except (ValueError, TypeError):
        logger.error(f"[SERVER]: Errore di conversione: {e}")
        ctx.send(Error(msg_type=ErrorType.MALFORMED_MESSAGE))
        return

    devices = ctx.session.user.devices

    authenticated = False
    matched_device = None
    for device in devices:

        if schnorr_verifier.check(res):
            authenticated = True
            matched_device = device
            break

    if authenticated:
        ctx.send(Message(msg_type=MessageType.AUTH_ACCEPTED, payload={"username": ctx.session.user._id}))
        ctx.update_session(
            logged_device=matched_device["device_name"], login_time=datetime.datetime.now()
        )
        ctx.session.user.update_user_login(ctx.session.logged_device)

        if DEBUG:
            logger.debug(
                f"[SERVER] User {ctx.session.user._id} autenticato dal dispositivo {ctx.session.logged_device}"
                if matched_device
                else "'unknown'"
            )
    else:
        ctx.send(Message(msg_type=MessageType.AUTH_REJECTED))
        if DEBUG:
            logger.debug("[SERVER] Autenticazione rifiutata")

    return

def handle_assoc_request(ctx: ConnContext, msg: Message):
    token_length = 32

    try:
        msg.validate_message({"pk": str, "device": str})
    except ValidationError as e:
        ctx.send(Error(msg_type=ErrorType.MALFORMED_MESSAGE))
        if DEBUG:
            logger.error(f"[SERVER] Errore di validazione {e}")
        return

    data = msg.payload

    pk = data["pk"]
    device_name = data["device"]

    token = generate_token(token_length, pk, device_name)
    if DEBUG:
        logger.debug(f"[SERVER] Hashed Token: {token}")

    ctx.send(Message(msg_type=MessageType.ASSOC_SEND_TOKEN, payload={"token": token}))

    temp_token = TempToken(token, pk, device_name)
    temp_token.insert_temp_token()

    register_connection(token, ctx)
    if DEBUG:
        logger.debug(f"[SERVER] Salvata tupla: {token} - {pk[:20]}...")

    return

def handle_assoc_confirm(ctx: ConnContext, msg: Message):
    try:
        msg.validate_message({"token": str})
    except ValidationError as e:
        ctx.send(Error(msg_type=ErrorType.MALFORMED_MESSAGE))
        if DEBUG:
            logger.error(f"[SERVER] Errore di validazione {e}")
        return

    data = msg.payload

    token = data["token"]
    temp_token = TempToken.find_pk_by_id(token)

    if not temp_token:
        ctx.send(Error(msg_type=ErrorType.UNAUTHORIZED_ACTION))
        if DEBUG:
            logger.error(f"[SERVER] Errore: {ErrorType.UNAUTHORIZED_ACTION.message()}")
        return

    pk, device_name = temp_token.pk, temp_token.device_name

    if not ctx.session.is_authenticated():
        ctx.send(Error(msg_type=ErrorType.SESSION_NOT_FOUND))
        if DEBUG:
            logger.error(f"[SERVER] Errore: {ErrorType.SESSION_NOT_FOUND.message()}")
        return

    devices = ctx.session.user.devices
    logged_device = ctx.session.logged_device

    for device in devices:
        if device["device_name"] == logged_device and not device["main_device"]:
            ctx.send(Error(msg_type=ErrorType.NO_MAIN_DEVICE))
            if DEBUG:
                logger.error(f"[SERVER] Errore: {ErrorType.NO_MAIN_DEVICE.message()}")
            return

    if temp_token.is_expired:
        ctx.send(Error(msg_type=ErrorType.TOKEN_INVALID_OR_EXPIRED))
        TempToken.delete_one(token)
        if DEBUG:
            logger.error(f"[SERVER] Errore: {ErrorType.TOKEN_INVALID_OR_EXPIRED.message()}")
        return

    user = ctx.session.user

    user.update_user_with_device(pk, device_name)

    ctx.update_session(user=user)

    TempToken.delete_one(token)

    # Verifica che il secondo dispositivo non si sia scollegato nel mentre, altrimenti annulla accoppiamento
    # e dal database viene cancellata la coppia tempo_token

    s_ctx = get_connection(token)

    if not s_ctx:
        ctx.send(Error(msg_type=ErrorType.ASSOC_REJECTED))
        if DEBUG:
            logger.debug(f"[SERVER] {ErrorType.message(ErrorType.ASSOC_REJECTED)}")
        return
        
    # Send ACCEPT message to main device
    ctx.send(Message(msg_type=MessageType.AUTH_ACCEPTED))
    if DEBUG:
        logger.debug(f"[SERVER] Dispositivo associato a {user._id}: {device_name} ({pk[:20]}...)")

    # Send ACCEPT message to second device
    # TODO: thread lock?
    s_ctx.update_session(user=user, logged_device=device_name, login_time=datetime.datetime.now())
    s_ctx.send(Message(msg_type=MessageType.AUTH_ACCEPTED, payload={"username": user._id}))

    return

def handle_devices_request(ctx: ConnContext):
    if ctx.is_session_empty:
        ctx.send(Error(msg_type=ErrorType.SESSION_NOT_FOUND))
        if DEBUG:
            logger.debug("[SERVER] Richiesta dispositivi senza sessione attiva")
        return

    user = ctx.session.user
    devices = user.devices

    # Rimuovi eventuali chiavi sensibili prima di inviare
    devices_info = [
        {
            "device_name": device["device_name"],
            "main_device": device.get("main_device", False),
            "logged": device.get("logged"),
        }
        for device in devices
    ]

    ctx.send(Message(msg_type=MessageType.DEVICES_RESPONSE, payload={"devices": devices_info}))
    if DEBUG:
        logger.debug(f"[SERVER] Lista dispositivi inviata a {user._id}")

    return

def handle_logout(ctx: ConnContext):
    # se session presente, invalida e chiudi
    if not ctx.is_session_empty:
        ctx.send(Message(msg_type=MessageType.LOGGED_OUT))
        user = ctx.session.user
        user.update_user_loggedout(ctx.session.logged_device)
        ctx.clear_session()
        if DEBUG:
            logger.debug("[SERVER] Logout effettuato con successo")
    else:
        ctx.send(Error(msg_type=ErrorType.SESSION_NOT_FOUND))
        if DEBUG:
            logger.debug(f"[SERVER] Errore: {ErrorType.SESSION_NOT_FOUND.message()}")
    return


# ---------------- client handler ----------------


def client_handler(ctx: ConnContext, schnorr_verifier: SchnorrVerifier):
    logger.info(f"[SERVER] Thread avviato per {ctx.addr}")
    try:
        while True:
            msg = ctx.receive()
            if msg is None:
                logger.info(f"[SERVER] Connessione chiusa dal client {ctx.addr}")
                break
            
            msg_type = msg.msg_type

            if msg_type == MessageType.HANDSHAKE_REQ:
                handle_handshake(ctx, schnorr_verifier)
            elif msg_type == MessageType.REGISTRATION_REQ:
                handle_registration(ctx, msg)
            elif msg_type == MessageType.AUTH_COMMITMENT:
                handle_auth_request(ctx, msg, schnorr_verifier)
            elif msg_type == MessageType.AUTH_RESPONSE:
                handle_auth_response(ctx, msg, schnorr_verifier)
            elif msg_type == MessageType.ASSOC_REQ:
                handle_assoc_request(ctx, msg)
            elif msg_type == MessageType.ASSOC_RECV_TOKEN:
                handle_assoc_confirm(ctx, msg)
            elif msg_type == MessageType.DEVICE_REQ:
                handle_devices_request(ctx, msg)
            elif msg_type == MessageType.LOGOUT:
                handle_logout(ctx)
            else:
                logger.info(f"[SERVER] Tipo messaggio sconosciuto: {msg_type.log_message}")
    except Exception as e:
        logger.error(f"[SERVER] Errore nel thread per {ctx.addr}: {e}")
    finally:
        if not ctx._closed:
            safe_close(ctx)
        logger.info(f"[SERVER] Thread terminato per {ctx.addr}")


# ---------------- main ----------------


def main():
    with open("config.json", "r", encoding="utf-8") as f:
        config = json.load(f)

    HOST = config["host"]
    PORT = config["port"]
    GROUP_ID = config["group_id"]

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        logger.info(f"[SERVER] In ascolto su {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            ctx = ConnContext(conn, addr)
            schnorr_verifier = SchnorrVerifier(GroupType(GROUP_ID))
            t = threading.Thread(target=client_handler, args=(ctx, schnorr_verifier))
            t.daemon = True
            t.start()


if __name__ == "__main__":
    main()
