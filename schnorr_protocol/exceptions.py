from .errors import ErrorType

# Ancora non c'è la compatibilità totale con tutte le eccezioni

class ValidationError(Exception):
    """Messaggio ricevuto non valido o con campi mancanti."""
    def __init__(self, message: str = "Messaggio non valido o con campi mancanti."):
        super().__init__(message)


class UnsupportedMessageTypeError(Exception):
    """Tipo di messaggio non riconosciuto dal server."""
    def __init__(self, message: str = "Tipo di messaggio non riconosciuto dal server."):
        super().__init__(message)


class AuthenticationError(Exception):
    """Autenticazione fallita (credenziali errate o assenti)."""
    def __init__(self, message: str = "Autenticazione fallita: credenziali errate o assenti."):
        super().__init__(message)


class AuthorizationError(Exception):
    """Accesso negato: permessi insufficienti per l'operazione."""
    def __init__(self, message: str = "Accesso negato: permessi insufficienti."):
        super().__init__(message)


class TokenExpiredError(Exception):
    """Il token è scaduto."""
    def __init__(self, message: str = "Il token è scaduto."):
        super().__init__(message)


class TokenNotFoundError(Exception):
    """Token non trovato nel database."""
    def __init__(self, message: str = "Token non trovato nel database."):
        super().__init__(message)


class ProtocolError(Exception):
    """Violazione del protocollo o sequenza di messaggi non valida."""
    def __init__(self, message: str = "Violazione del protocollo o sequenza di messaggi non valida."):
        super().__init__(message)


class ConnectionClosedError(Exception):
    """Connessione chiusa inaspettatamente dal client."""
    def __init__(self, message: str = "Connessione chiusa inaspettatamente dal client."):
        super().__init__(message)


class ConnectionAlreadyClosed(Exception):
    """Connessione chiusa tra client e server."""
    def __init__(self, message: str = "La connessione è già chiusa tra client e server."):
        super().__init__(message)


def exception_to_error_type(exc: Exception) -> ErrorType:
    """
    Mappa un'eccezione personalizzata a un ErrorType definito nel protocollo.
    """
    if isinstance(exc, ValidationError):
        return ErrorType.MALFORMED_MESSAGE
    if isinstance(exc, UnsupportedMessageTypeError):
        return ErrorType.UNKNOWN_ERROR
    if isinstance(exc, AuthenticationError):
        return ErrorType.AUTH_REJECTED
    if isinstance(exc, AuthorizationError):
        return ErrorType.UNAUTHORIZED_ACTION
    if isinstance(exc, TokenExpiredError):
        return ErrorType.TOKEN_INVALID_OR_EXPIRED
    if isinstance(exc, TokenNotFoundError):
        return ErrorType.TOKEN_INVALID_OR_EXPIRED
    if isinstance(exc, ProtocolError):
        return ErrorType.MALFORMED_MESSAGE
    if isinstance(exc, ConnectionClosedError):
        return ErrorType.AUTH_TIMEOUT

    # Default
    return ErrorType.UNKNOWN_ERROR
