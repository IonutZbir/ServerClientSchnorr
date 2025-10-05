import argparse
import socket
import sys
from pathlib import Path

import getpass

import cryptography

# Ensure project root is in sys.path for internal imports
project_root = Path(__file__).resolve().parent.parent
sys.path.append(str(project_root))

from schnorr_protocol import *
from common.logger import Logger
from common.hash import hash_public_key_SHA256

from utils.utils import get_device_name, create_qr_code, Device, MnemonicHash
from utils.key_manager import KeyManager
from utils.client_connection import ClientConnection

from Crypto.Hash import RIPEMD160

DEBUG = False

logger = Logger()


class User:
    def __init__(self):
        self._username = None
        self._logged = False
        self._password = None

    @property
    def username(self):
        return self._username

    @username.setter
    def username(self, value):
        self._username = value

    @property
    def logged(self):
        return self._logged

    @logged.setter
    def logged(self, value):
        self._logged = value

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, value):
        self._password = value


class ClientApp:
    def __init__(self, client_conn: ClientConnection):
        self.client_conn = client_conn
        self.schnorr_prover = None

        self.user = User()

        self.password = None

        if not self._handshake():
            sys.exit(1)

        if DEBUG:
            logger.debug("[CLIENT] Handshake andato a buon fine...")

    def _send(self, message: Message | Error) -> bool:
        try:
            self.client_conn.send(message)
        except Exception as e:
            logger.warning(f"[CLIENT] Errore nell'invio di dati al server... {e}")
            return False
        return True

    def _handshake(self) -> bool:
        handshake_msg = Message(msg_type=MessageType.HANDSHAKE_REQ)

        if DEBUG:
            logger.debug(f"[CLIENT] Inviata richiesta di handshake")

        if not self._send(handshake_msg):
            return False

        if DEBUG:
            logger.debug("[CLIENT] Handshake fase 1 - Request")

        response = wait_for_response(
            self.client_conn, {MessageType.HANDSHAKE_RES}, {"crypto_groups": list}
        )

        if response is None:
            return False

        crypto_groups = set(response.payload["crypto_groups"])

        my_crypto_groups = GroupType.get_all_groups_obj()

        group_id = None
        for mcg in my_crypto_groups:
            if mcg.group_id in crypto_groups:
                group_id = mcg
                break

        if DEBUG:
            logger.debug("[CLIENT] Handshake fase 2 - Response")

        if group_id is None:
            if not self._send(Message(msg_type=MessageType.HANDSHAKE_NOK)):
                return False
            if DEBUG:
                logger.debug("[CLIENT] Handshake fase 3 - Handshake NOK")
            return False

        self.schnorr_prover = SchnorrProver(group_id)

        if not self._send(
            Message(msg_type=MessageType.HANDSHAKE_OK, payload={"group_id": group_id.group_id})
        ):
            return False

        return True

    def _register(self, username: str) -> bool:

        self.schnorr_prover.gen_keys()  # generate private key and public key

        device_name = get_device_name()

        req_msg = Message(
            msg_type=MessageType.REGISTRATION_REQ,
            payload={
                "username": username,
                "public_key": hex(self.schnorr_prover.public_key),
                "device": device_name,
            },
        )

        if not self._send(req_msg):
            return False

        if DEBUG:
            logger.debug(f"[CLIENT] Inviata richiesta di registrazione: {req_msg.to_log()}")

        response = wait_for_response(self.client_conn, {MessageType.REGISTERED})

        if response is None:
            return False

        logger.info(f"[CLIENT] {MessageType.AUTH_ACCEPTED.message()}")
        logger.info(f"[CLIENT] Benvenuto {username}!")

        KeyManager.save_private_key(username, self.schnorr_prover.alpha, self.password)
        self.user.username = username
        self.user.password = self.password
        self.user.logged = True
        return True

    def auth(self) -> bool:

        # 1. L'utente inserisce l'username per l'autenticazione
        # 2. Se in locale non viene trovata la chiave allora manda la richiesta di registrazione
        # 3. Se in locale viene trovata la chiave allora manda al richiesta di autenticazione

        username = input("[INPUT] Inserisci uno username per l'autenticazione: ").strip()
        try:
            self.schnorr_prover.alpha = KeyManager.load_private_key(username, self.password)
        except FileNotFoundError:
            if DEBUG:
                logger.debug(
                    "[CLIENT] Chiave privata dell'utente non trovata, procedo con la registrazione..."
                )
            return self._register(username)
        except cryptography.exceptions.InvalidTag:
            logger.warning("[CLIENT] Password errata!!")
            return

        # L'utente è registrato
        hash_pk = hash_public_key_SHA256(self.schnorr_prover.public_key)
        public_key_temp = hex(self.schnorr_prover.public_key_temp)

        auth_req_msg = Message(
            msg_type=MessageType.AUTH_COMMITMENT,
            payload={
                "public_key_temp": public_key_temp,
                "username": username,
                "hash_pk": hash_pk.hexdigest(),
            },
        )

        if not self._send(auth_req_msg):
            return False

        if DEBUG:
            logger.debug(f"[CLIENT] Inviata richiesta di autenticazione: {auth_req_msg.to_log()}")

        response = wait_for_response(
            self.client_conn,
            {MessageType.AUTH_CHALLENGE, MessageType.AUTH_REJECTED},
            {"challenge": str},
        )
        if response is None:
            return False

        if response.msg_type == MessageType.AUTH_REJECTED:
            logger.info(f"[CLIENT] {MessageType.AUTH_REJECTED.message()}!")
            return False

        challenge = response.payload.get("challenge")
        if DEBUG:
            logger.debug(f"[CLIENT] Ricevuto challenge: {challenge[:20]}...")

        auth_resp = hex(self.schnorr_prover.response(int(challenge, 16)))

        auth_resp_msg = Message(msg_type=MessageType.AUTH_RESPONSE, payload={"response": auth_resp})

        if not self._send(auth_resp_msg):
            return False

        response = wait_for_response(
            self.client_conn,
            {MessageType.AUTH_ACCEPTED, MessageType.AUTH_REJECTED},
            {"username": str},
        )

        if response is None:
            return False

        if response.msg_type == MessageType.AUTH_ACCEPTED:
            self.user.username = username
            self.user.password = self.password
            self.user.logged = True
            logger.info(f"[CLIENT] {MessageType.AUTH_ACCEPTED.message()}!")
            logger.info(f"[CLIENT] Benvenuto {response.payload.get("username")}!")
            return True
        elif response.msg_type == MessageType.AUTH_REJECTED:
            logger.info(f"[CLIENT] {MessageType.AUTH_REJECTED.message()}!")
            return False

    def assoc(self) -> bool:
        device_name = get_device_name()

        self.schnorr_prover.gen_keys()

        hash_pk = hash_public_key_SHA256(self.schnorr_prover.public_key)

        ripemd160_pk = RIPEMD160.new()

        ripemd160_pk.update(hash_pk.digest())

        words = MnemonicHash.hash_to_words(ripemd160_pk.digest())

        assoc_req_msg = Message(
            msg_type=MessageType.ASSOC_REQ,
            payload={"device": device_name, "pk": hex(self.schnorr_prover.public_key)},
        )

        # Invio della richiesta di associazione
        if not self._send(assoc_req_msg):
            return False

        if DEBUG:
            logger.debug(
                f"[CLIENT] Inviata richiesta di associazione del dispositivo: {assoc_req_msg.to_log()}"
            )

        logger.info(f"[CLIENT] Parole da inserire dal dispositivo master:\n{", ".join(words)} ")
        # create_qr_code(ripemd160_pk.hexdigest())

        # Secondo step: attendere conferma di associazione
        response = wait_for_response(
            self.client_conn, {MessageType.AUTH_ACCEPTED}, {"username": str}
        )
        if response is None:
            return False

        username = response.payload.get("username")

        self.user.username = username
        self.user.password = self.password
        self.user.logged = True
        KeyManager.save_private_key(username, self.schnorr_prover.alpha, self.password)
        logger.info(f"[CLIENT] {MessageType.AUTH_ACCEPTED.message()}!")
        logger.info(f"[CLIENT] Benvenuto {username}!")
        return True

    def confirm_assoc(self) -> bool:
        words = (
            input("[INPUT] Inserisci le parole richieste (word1, word2, ...): ").strip().split(", ")
        )

        prefix = MnemonicHash.words_to_hash(words, 20)

        hex_prefix = hex(int.from_bytes(prefix, "big"))

        # il device master deve inviare la firma, insieme al messaggio che sta firmando
        # il messaggio rappresenta l'hash della chiave pubblica con ripemd160

        sign = self.schnorr_prover.sign_message_encoded(hex_prefix)
        sign["message"] = hex_prefix
        assoc_sign_msg = Message(msg_type=MessageType.ASSOC_CONFIRM, payload=sign)

        if not self._send(assoc_sign_msg):
            return False

        if DEBUG:
            logger.debug(f"[CLIENT] Inviata firma con l'hash: {assoc_sign_msg.to_log()}")

        response = wait_for_response(
            self.client_conn, {MessageType.AUTH_ACCEPTED, MessageType.AUTH_REJECTED}
        )

        if response is None:
            return False

        if response.msg_type == MessageType.AUTH_REJECTED:
            logger.info("[CLIENT] Abbinamento annullato!")
            return False

        logger.info(f"[CLIENT] Abbinamento avvenuto con successo!")
        return True

    def show_devices(self) -> bool:
        msg_req = Message(msg_type=MessageType.DEVICE_REQ)

        if not self._send(msg_req):
            return False

        response = wait_for_response(self.client_conn, {MessageType.DEVICE_RES}, {"devices": list})

        if response is None:
            return False

        devices = response.payload["devices"]

        for i, dev in enumerate(devices):
            device = Device(device_name=dev["device_name"], logged=dev["logged"])
            logger.info(f"Dispositivi associati:\n{'-'*20}\n{i+1}. {device}\n{'-'*20}")

        return True

    def change_password(self, new_password: str) -> bool:
        try:
            KeyManager.change_password(self.user.username, self.user.password, new_password)
        except Exception as e:
            if DEBUG:
                logger.debug(f"[CLIENT] Errore nel cambiamento della password: {e}")
            logger.info("[CLIENT] Non è stato possibile cambiare la password")
            return False
        self.password = new_password
        self.user.password = new_password
        logger.info("[CLIENT] Password cambiata con successo!")
        return True

    def log_out(self) -> bool:

        if not self._send(Message(msg_type=MessageType.LOGOUT)):
            return False

        response = wait_for_response(self.client_conn, {MessageType.LOGGED_OUT})

        if response is None:
            return False

        self.user = User()

        logger.info("[CLIENT] Logout effettuato con successo.")
        return True


def wait_for_response(
    client: ClientConnection, expected_types: set[MessageType], required_fields: dict = None
) -> Message | Error | None:
    while True:
        try:
            msg = client.receive()
        except ConnectionResetError as e:
            logger.error("[CLIENT] Connessione resettata dal server")

        if msg is None:
            logger.warning("[CLIENT] Connessione chiusa o messaggio vuoto.")
            return None

        if isinstance(msg, Message) and msg.msg_type in expected_types:
            if required_fields is not None:
                try:
                    msg.validate_message(required_fields)
                except ValidationError as e:
                    logger.warning(f"[CLIENT]: Errore di validazione: {e}")
                    return None
            return msg
        elif isinstance(msg, Error):
            err = ErrorType.from_code(msg.msg_type.code)
            logger.warning(f"[CLIENT] Errore: {err.message()}")
        else:
            logger.warning(f"Tipo di messaggio atteso: {expected_types}, ricevuto {msg.msg_type}.")


def not_logged_menu() -> str:
    menu = (
        "\n[MENÙ] Seleziona un'opzione:\n"
        "  [I] Imposta una password\n"
        "  [A] Accedi\n"
        "  [D] Richiedi abbinamento dispositivo\n"
        "  [Q] Esci\n"
    )
    return menu


def logged_menu() -> str:
    menu = (
        "\n[MENÙ] Seleziona un'opzione:\n"
        "  [C] Conferma abbinamento dispositivo\n"
        "  [D] Visualizza dispositivi associati\n"
        "  [P] Cambia password\n"
        "  [L] Log out\n"
        "  [Q] Esci\n"
    )
    return menu


def parse_args():
    parser = argparse.ArgumentParser(
        description="Client di autenticazione con protocollo di Schnorr"
    )

    parser.add_argument("-i", "--ip", type=str, required=False, help="Indirizzo IP del server")
    parser.add_argument("-p", "--port", type=int, required=False, help="Porta del server")
    parser.add_argument(
        "-d", "--debug", action="store_true", help="Abilita il logging in modalità debug"
    )

    parser.add_argument("-g", "--gui", action="store_true", help="Avvia il client in modalità GUI")

    return parser.parse_args()


# --- MAIN ---
def main():

    args = parse_args()

    ip = args.ip
    port = args.port
    gui = args.gui

    global DEBUG
    DEBUG = args.debug

    if not ip:
        ip = "127.0.0.1"

    if not port:
        port = 65432

    if gui:
        # gui()
        pass

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((ip, port))
        logger.info(f"[CLIENT] Connesso a {ip}:{port}")

        client_conn = ClientConnection(sock)
        app = ClientApp(client_conn)

        logged_in = False

        # Azioni per il menu NON loggato
        def set_password():
            app.password = getpass.getpass("")

        actions_not_logged = {
            "I": set_password,
            "A": app.auth,
            "D": app.assoc,
            "Q": lambda: sys.exit(logger.info("[CLIENT] Uscita dal client.")),
        }

        # Azioni per il menu loggato
        actions_logged = {
            "D": app.show_devices,
            "C": app.confirm_assoc,
            "P": lambda: app.change_password(getpass.getpass("")),
            "L": app.log_out,
            "Q": lambda: sys.exit(logger.info("[CLIENT] Uscita dal client.")),
        }

        while True:
            if not logged_in:
                print(not_logged_menu())
                ans = input("[INPUT] Inserisci la tua scelta: ").strip().upper()
                action = actions_not_logged.get(ans)
                if action:
                    success = action()
                    if success:
                        logged_in = True
                else:
                    logger.warning("[CLIENT] Input non valido.")
            else:
                print(logged_menu())
                ans = input("[INPUT] Inserisci la tua scelta: ").strip().upper()
                action = actions_logged.get(ans)
                if action:
                    success = action()
                    if not success:
                        logged_in = False
                    if ans == "L" and success:
                        logged_in = False
                else:
                    logger.warning("[CLIENT] Input non valido.")


if __name__ == "__main__":
    main()
