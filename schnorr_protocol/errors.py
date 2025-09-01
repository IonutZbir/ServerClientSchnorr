from enum import Enum


class ErrorType(Enum):
    # --- Registrazione ---
    USERNAME_ALREADY_EXISTS = (0, "USERNAME_ALREADY_EXISTS", "Username già esistente")
    USERNAME_NOT_FOUND = (1, "USERNAME_NOT_FOUND", "Username non trovato")
    INVALID_USERNAME_FORMAT = (2, "INVALID_USERNAME_FORMAT", "Formato username non valido")
    MISSING_CREDENTIALS = (3, "MISSING_CREDENTIALS", "Credenziali mancanti o incomplete")

    # --- Handshake ---
    UNSUPPORTED_GROUP = (10, "UNSUPPORTED_GROUP", "Gruppo crittografico non supportato")
    HANDSHAKE_FAILED = (11, "HANDSHAKE_FAILED", "Handshake non riuscito")

    # --- Autenticazione ---
    INVALID_RESPONSE = (20, "INVALID_RESPONSE", "Risposta di autenticazione non valida")
    AUTH_TIMEOUT = (21, "AUTH_TIMEOUT", "Timeout durante la fase di autenticazione")
    AUTH_REJECTED = (22, "AUTH_REJECTED", "Autenticazione rifiutata")

    # --- Associazione dispositivi ---
    NO_MAIN_DEVICE = (
        30,
        "NO_MAIN_DEVICE",
        "L'abbinamento deve essere confermato dal dispositivo principale",
    )
    DEVICE_ALREADY_REGISTERED = (
        31,
        "DEVICE_ALREADY_REGISTERED",
        "Il dispositivo risulta già registrato",
    )
    TOKEN_INVALID_OR_EXPIRED = (32, "TOKEN_INVALID_OR_EXPIRED", "Token non valido o scaduto")
    ASSOC_REJECTED = (
        33,
        "ASSOC_REJECTED",
        "Richiesta di associazione rifiutata dal dispositivo principale",
    )

    # --- Gestione dispositivi ---
    DEVICE_NOT_FOUND = (40, "DEVICE_NOT_FOUND", "Dispositivo non trovato")
    DEVICE_LIMIT_EXCEEDED = (41, "DEVICE_LIMIT_EXCEEDED", "Limite massimo di dispositivi raggiunto")

    # --- Sessione / Logout ---
    SESSION_NOT_FOUND = (50, "SESSION_NOT_FOUND", "Sessione non trovata")
    SESSION_EXPIRED = (51, "SESSION_EXPIRED", "Sessione scaduta")

    # --- Errori generici ---
    MALFORMED_MESSAGE = (60, "MALFORMED_MESSAGE", "Messaggio malformato o campi mancanti")
    UNAUTHORIZED_ACTION = (61, "UNAUTHORIZED_ACTION", "Azione non autorizzata")
    UNKNOWN_ERROR = (62, "UNKNOWN_ERROR", "Errore sconosciuto")

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
