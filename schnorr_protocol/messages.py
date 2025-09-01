from enum import Enum


class MessageType(Enum):
    # --- Handshake ---
    HANDSHAKE_REQ = (1, "HANDSHAKE_REQ", "Richiesta handshake")
    HANDSHAKE_RES = (2, "HANDSHAKE_RES", "Risposta handshake")
    HANDSHAKE_OK = (3, "HANDSHAKE_OK", "Handshake completato con successo")
    HANDSHAKE_NOK = (4, "HANDSHAKE_NOK", "Handshake fallito")

    # --- Registrazione ---
    REGISTRATION_REQ = (5, "REGISTRATION_REQ", "Ricevuta richiesta di registrazione")
    REGISTERED = (6, "REGISTERED", "Utente registrato con successo")

    # --- Autenticazione ---
    AUTH_COMMITMENT = (7, "AUTH_COMMITMENT", "Invio commitment per autenticazione")
    AUTH_CHALLENGE = (8, "AUTH_CHALLENGE", "Invio sfida per autenticazione")
    AUTH_RESPONSE = (9, "AUTH_RESPONSE", "Ricevuta risposta autenticazione")
    AUTH_ACCEPTED = (10, "AUTH_ACCEPTED", "Autenticazione accettata")
    AUTH_REJECTED = (11, "AUTH_REJECTED", "Autenticazione rifiutata")

    # --- Associazione ---
    ASSOC_REQ = (12, "ASSOC_REQ", "Richiesta abbinamento dispositivo")
    ASSOC_SEND_TOKEN = (13, "ASSOC_SEND_TOKEN", "Invio token di abbinamento")
    ASSOC_RECV_TOKEN = (14, "ASSOC_RECV_TOKEN", "Ricezione token di abbinamento")

    # --- Log out ---
    LOGOUT = (15, "LOGOUT", "Richiesta di logout")
    LOGGED_OUT = (16, "LOGGED_OUT", "Logout effettuato")

    # --- Richiesta dati ---
    DEVICE_REQ = (17, "DEVICE_REQ", "Richiesta elenco dispositivi")
    DEVICE_RES = (18, "DEVICE_RES", "Risposta elenco dispositivi")

    def __init__(self, code, label, log_message):
        self.code = code
        self.label = label
        self.log_message = log_message

    @classmethod
    def from_code(cls, code):
        for item in cls:
            if item.code == code:
                return item
        return None

    def __str__(self):
        return self.label

    def message(self):
        return self.log_message
