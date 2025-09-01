from dataclasses import dataclass
import json
from typing import Protocol

from attrs import field

from .errors import ErrorType
from .messages import MessageType
from .exceptions import ValidationError

class MessageKind(Protocol):
    code: int
    label: str

    def message(self) -> str: ...


@dataclass
class BaseMessage:
    msg_type: MessageKind
    payload: dict = field(default=dict)

    def validate_message(self, required_fields: dict):
        if not isinstance(self.payload, dict):
            raise ValidationError("Messaggio non valido: non è un dizionario")

        for field, expected_type in required_fields.items():
            value = self.payload.get(field)
            if value is None:
                raise ValidationError(f"Campo mancante: {field}")
            if not isinstance(value, expected_type):
                raise ValidationError(
                    f"Il campo {field} deve essere {expected_type.__name__}"
                )

    def __str__(self):
        return f"<Message {self.msg_type} {self.payload}>"

    def to_log(self):
        return f"[{self.msg_type.label}] {self.msg_type.message()} - {self.payload}"


@dataclass
class Message(BaseMessage):
    msg_type: MessageType


@dataclass
class Error(BaseMessage):
    msg_type: ErrorType
    
    def __str__(self):
        return f"<Error {self.msg_type} {self.payload}>"


def encode_message(message: Message | Error) -> str:
    """
    Converte un Message o Error in una stringa JSON da inviare.
    """
    return json.dumps(
        {
            "type": message.msg_type.code,
            "payload": message.payload,
            "is_error": isinstance(message, Error),
        }
    ).encode()


def decode_message(raw: str) -> Message | Error:
    """
    Converte una stringa JSON ricevuta in un oggetto Message o Error.
    """
    data = json.loads(raw)

    if data.get("is_error", False):
        err_type = ErrorType.from_code(data["type"])
        return Error(msg_type=err_type, payload=data["payload"])
    else:
        msg_type = MessageType.from_code(data["type"])
        return Message(msg_type=msg_type, payload=data["payload"])

# CLIENT
# msg = Message(msg_type=MessageType.HANDSHAKE_REQ, payload={"username": "alice"})
# encoded = encode_message(msg)
# print(encoded)
# -> {"type": 12, "payload": {"username": "alice"}, "is_error": false}

# SERVER
# received = decode_message(encoded)
# print(received)        # <Message HANDSHAKE_REQ {'username': 'alice'}>
# print(received.to_log())  
# [HANDSHAKE_REQ] Richiesta handshake - {'username': 'alice'}

# CLIENT
# err = Error(msg_type=ErrorType.USER_NOT_FOUND, payload={"username": "bob"})
# encoded = encode_message(err)
# print(encoded)
# -> {"type": 7, "payload": {"username": "bob"}, "is_error": true}

# SERVER
# received = decode_message(encoded)
# print(received)        # <Error USER_NOT_FOUND {'username': 'bob'}>
# print(received.to_log())
# [USER_NOT_FOUND] Username non trovato - {'username': 'bob'}
