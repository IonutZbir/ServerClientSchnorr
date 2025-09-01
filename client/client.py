import argparse
import socket
import sys
from pathlib import Path

# Ensure project root is in sys.path for internal imports
project_root = Path(__file__).resolve().parent.parent
sys.path.append(str(project_root))

from schnorr_protocol import *
from common.logger import Logger

from utils.utils import get_device_name, create_qr_code, Device
from utils.key_manager import KeyManager
from utils.client_connection import ClientConnection

DEBUG = False

logger = Logger()


class ClientApp:
    def __init__(self, client_conn: ClientConnection):
        self.client_conn = client_conn
        self.schnorr_prover = None

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
            logger.debug(f"[CLIENT] Inviata richiesta di handshake: {handshake_msg.to_log()}")
        
        if not self._send(handshake_msg):
            return False

        if DEBUG:
            logger.debug("[CLIENT] Handshake fase 1 - Request")

        response = wait_for_response(
            self.client_conn, {MessageType.HANDSHAKE_RES}, {"group_id": str}
        )

        if response is None:
            return False

        if DEBUG:
            logger.debug("[CLIENT] Handshake fase 2 - Response")

        group_id = GroupType(response.payload.get("group_id"))
        logger.info(f"[CLIENT] Gruppo selezionato dal server: {group_id}")

        try:
            self.schnorr_prover = SchnorrProver(group_id)
        except Exception as e:
            if not self._send(Message(msg_type=MessageType.HANDSHAKE_NOK)):
                return False
            if DEBUG:
                logger.debug("[CLIENT] Handshake fase 3 - Handshake NOK")
            logger.warning(f"[CLIENT] Errore durante l'inizializzazione del prover: {e}")
            return False

        if not self._send(Message(msg_type=MessageType.HANDSHAKE_OK)):
            return False

        return True

    def register(self) -> bool:
        username = input("[INPUT] Inserisci uno username per la registrazione: ").strip()

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

        logger.info(f"[CLIENT] {MessageType.REGISTERED.message()}")
        KeyManager.save_private_key(username, self.schnorr_prover.alpha)
        return True

    def auth(self) -> bool:
        username = input("[INPUT] Inserisci uno username per l'autenticazione: ").strip()
        try:
            self.schnorr_prover.alpha = KeyManager.load_private_key(username)
        except Exception as e:
            if DEBUG:
                logger.warning(f"[CLIENT] Errore nel caricameto della chiave {e}")
            logger.info("[CLIENT] È richiesto registrarsi prima!")
            return False

        public_key_temp = hex(self.schnorr_prover.public_key_temp)

        auth_req_msg = Message(
            msg_type=MessageType.AUTH_COMMITMENT,
            payload={"public_key_temp": public_key_temp, "username": username},
        )

        if not self._send(auth_req_msg):
            return False

        if DEBUG:
            logger.info(f"[CLIENT] Inviata richiesta di autenticazione: {auth_req_msg.to_log()}")

        response = wait_for_response(
            self.client_conn, {MessageType.AUTH_CHALLENGE,  MessageType.AUTH_REJECTED}, {"challenge": str}
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
            self.client_conn, {MessageType.AUTH_ACCEPTED, MessageType.AUTH_REJECTED}
        )

        if response is None:
            return False

        if response.msg_type == MessageType.AUTH_ACCEPTED:
            logger.info(f"[CLIENT] {MessageType.AUTH_ACCEPTED.message()}!")
            logger.info(f"[CLIENT] Benvenuto {response.payload.get("username")}!")
            return True
        elif response.msg_type == MessageType.AUTH_REJECTED:
            logger.info(f"[CLIENT] {MessageType.AUTH_REJECTED.message()}!")
            return False

    def assoc(self) -> bool:
        device_name = get_device_name()

        self.schnorr_prover.gen_keys()

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

        # Primo step: attendere il token da mostrare come QR
        response = wait_for_response(
            self.client_conn, {MessageType.ASSOC_SEND_TOKEN}, {"token": str}
        )

        if response is None:
            return False

        token = response.payload.get("token")
        logger.info(f"[CLIENT] Token ricevuto: {token}")
        create_qr_code(token)

        # Secondo step: attendere conferma di associazione
        response = wait_for_response(
            self.client_conn, {MessageType.AUTH_ACCEPTED}, {"username": str}
        )
        if response is None:
            return False

        logger.info("[CLIENT] Associazione completata, login effettuato!")
        logger.info(f"[CLIENT] Benvenuto {response.payload.get("username")}!")
        KeyManager.save_private_key(response.payload.get("username"), self.schnorr_prover.alpha)
        return True

    def confirm_assoc(self) -> bool:
        ans = input("[INPUT] Inserisci codice di abbinamento: ").strip()

        assoc_token_msg = Message(msg_type=MessageType.ASSOC_RECV_TOKEN, payload={"token": ans})

        if not self._send(assoc_token_msg):
            return False

        if DEBUG:
            logger.debug(
                f"[CLIENT] Inviato token di verifica: {assoc_token_msg.to_log()}"
            )

        response = wait_for_response(self.client_conn, {MessageType.AUTH_ACCEPTED})

        if response is None:
            return False

        logger.info("[CLIENT] Abbinamento confermato con successo.")
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
            device = Device(device_name=dev["device_name"], main_device=dev["main_device"], logged=dev["logged"])
            logger.info(f"Dispositivi associati:\n{'-'*20}\n{i+1}. {device}\n{'-'*20}")
        
        return True        
        

    def log_out(self) -> bool:

        if not self._send(Message(msg_type=MessageType.LOGOUT)):
            return False

        response = wait_for_response(self.client_conn, {MessageType.LOGGED_OUT})

        if response is None:
            return False

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

        if msg.msg_type in expected_types and isinstance(msg, Message):
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
        return None


def not_logged_menu() -> str:
    menu = (
        "\n[MENÙ] Seleziona un'opzione:\n"
        "  [R] Registrati\n"
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
        actions_not_logged = {
            "R": app.register,
            "A": app.auth,
            "D": app.assoc,
            "Q": lambda: sys.exit(logger.info("[CLIENT] Uscita dal client.")),
        }

        # Azioni per il menu loggato
        actions_logged = {
            "D": app.show_devices,
            "C": app.confirm_assoc,
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
                    if ans == "L" and success:
                        logged_in = False
                else:
                    logger.warning("[CLIENT] Input non valido.")


if __name__ == "__main__":
    main()
