from pathlib import Path

import os
import cryptography
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class KeyManager:
    HOME_PATH = Path.home()
    SCHNORR_DIR = HOME_PATH / ".schnorr"

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        """Deriva una chiave AES-256 a partire dalla password."""
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
        )
        return kdf.derive(password.encode())

    @classmethod
    def _load_private_key(cls, username: str) -> int:
        """Carica la chiave privata dal file, lancia l'eccezione "FileNotFoundError" se non la trova."""
        privkey_path = cls.SCHNORR_DIR / f"{username}_privkey.pem"
        try:
            with open(privkey_path, "r") as f:
                return int(f.read())
        except FileNotFoundError as e:
            raise e

    @classmethod
    def _save_private_key(cls, username: str, key: int) -> None:
        """Salva la chiave privata su file."""
        cls.SCHNORR_DIR.mkdir(parents=True, exist_ok=True)
        privkey_path = cls.SCHNORR_DIR / f"{username}_privkey.pem"
        with open(privkey_path, "w") as f:
            f.write(str(key))

    @classmethod
    def save_private_key(cls, username: str, key: int, password: str = None) -> None:
        """Salva la chiave privata cifrata su file con AES-256-GCM."""
        cls.SCHNORR_DIR.mkdir(parents=True, exist_ok=True)
        privkey_path = cls.SCHNORR_DIR / f"{username}_privkey.pem"

        # L'utente non ha impostato una password, allora la chiave verrà salvata senza dover cifrare il file
        if not password:
            cls._save_private_key(username, key)
            return

        # Dati da cifrare
        data = str(key).encode()

        # Genera salt e nonce
        salt = os.urandom(16)
        nonce = os.urandom(12)

        # Deriva chiave e cifra
        aesgcm = AESGCM(cls._derive_key(password, salt))
        ciphertext = aesgcm.encrypt(nonce, data, None)

        # Salva salt + nonce + ciphertext
        with open(privkey_path, "wb") as f:
            f.write(salt + nonce + ciphertext)

    @classmethod
    def load_private_key(cls, username: str, password: str = None) -> int:
        """Carica e decifra la chiave privata da file. Lancia FileNotFoundError se non esiste."""
        privkey_path = cls.SCHNORR_DIR / f"{username}_privkey.pem"

        # L'utente non ha impostato una password, allora il file è in chiaro quindi lo leggo direttamente
        if not password:
            return cls._load_private_key(username)

        with open(privkey_path, "rb") as f:
            blob = f.read()

        salt, nonce, ciphertext = blob[:16], blob[16:28], blob[28:]

        aesgcm = AESGCM(cls._derive_key(password, salt))

        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        return int(plaintext.decode())

    @classmethod
    def change_password(cls, username: str, old_password: str, new_password: str) -> None:
        """Cambia la password con cui è cifrata la chiave privata."""

        # Decifra la chiave privata con la vecchia password
        try:
            privkey = cls.load_private_key(username, old_password)
        except (FileNotFoundError, cryptography.exceptions.InvalidTag) as e:
            raise e

        # Ricifra la chiave con la nuova password
        cls.save_private_key(username, privkey, new_password)


if __name__ == "__main__":
    KeyManager.save_private_key("pippo", 12131231311313, "mario12")

    key = KeyManager.load_private_key("pippo", "maro12")

    print(key)


# import os
# import cryptography
# from pathlib import Path
# from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
# from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# class KeyManager:
#     HOME_PATH = Path.home()
#     SCHNORR_DIR = HOME_PATH / ".schnorr"

#     @staticmethod
#     def _derive_key(password: str, salt: bytes) -> bytes:
#         """Deriva una chiave AES-256 a partire dalla password."""
#         ...
    
#     @classmethod
#     def save_private_key(cls, username: str, key: int, password: str = None) -> None:
#         """Salva la chiave privata cifrata su file con AES-256-GCM."""
#         cls.SCHNORR_DIR.mkdir(parents=True, exist_ok=True)
#         privkey_path = cls.SCHNORR_DIR / f"{username}_privkey.pem"

#         if not password:
#             cls._save_private_key(username, key)
#             return

#         data = str(key).encode()
#         salt = os.urandom(16)
#         nonce = os.urandom(12)
#         aesgcm = AESGCM(cls._derive_key(password, salt))
#         ciphertext = aesgcm.encrypt(nonce, data, None)
#         with open(privkey_path, "wb") as f:
#             f.write(salt + nonce + ciphertext)

#     @classmethod
#     def load_private_key(cls, username: str, password: str = None) -> int:
#         """Carica e decifra la chiave privata da file."""
#         privkey_path = cls.SCHNORR_DIR / f"{username}_privkey.pem"

#         if not password:
#             return cls._load_private_key(username)

#         with open(privkey_path, "rb") as f:
#             blob = f.read()
#         salt, nonce, ciphertext = blob[:16], blob[16:28], blob[28:]
#         aesgcm = AESGCM(cls._derive_key(password, salt))
#         plaintext = aesgcm.decrypt(nonce, ciphertext, None)
#         return int(plaintext.decode())