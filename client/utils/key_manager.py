from pathlib import Path
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import cryptography.exceptions

class KeyManager:
    HOME_PATH = Path.home()
    SCHNORR_DIR = HOME_PATH / ".schnorr"

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        """Deriva una chiave AES-256 (32 byte) usando PBKDF2-HMAC-SHA256"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        return kdf.derive(password.encode())

    @classmethod
    def _load_private_key(cls, username: str) -> int:
        privkey_path = cls.SCHNORR_DIR / f"{username}_privkey.pem"
        with open(privkey_path, "r") as f:
            return int(f.read())

    @classmethod
    def _save_private_key(cls, username: str, key: int) -> None:
        cls.SCHNORR_DIR.mkdir(parents=True, exist_ok=True)
        privkey_path = cls.SCHNORR_DIR / f"{username}_privkey.pem"
        with open(privkey_path, "w") as f:
            f.write(str(key))

    @classmethod
    def save_private_key(cls, username: str, key: int, password: str = None) -> None:
        cls.SCHNORR_DIR.mkdir(parents=True, exist_ok=True)
        privkey_path = cls.SCHNORR_DIR / f"{username}_privkey.pem"

        if not password:
            cls._save_private_key(username, key)
            return

        data = str(key).encode()
        salt = os.urandom(16)   # 16 byte salt (come nel Dart)
        nonce = os.urandom(12)  # 12 byte nonce per AES-GCM

        derived = cls._derive_key(password, salt)
        aesgcm = AESGCM(derived)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        # ciphertext in cryptography include il tag (tag è 16 byte alla fine)

        # Salvo salt + nonce + ciphertext (ciphertext include tag)
        with open(privkey_path, "wb") as f:
            f.write(salt + nonce + ciphertext)

    @classmethod
    def load_private_key(cls, username: str, password: str = None) -> int:
        privkey_path = cls.SCHNORR_DIR / f"{username}_privkey.pem"

        if not password:
            return cls._load_private_key(username)

        with open(privkey_path, "rb") as f:
            blob = f.read()

        if len(blob) < 16 + 12 + 16:
            raise ValueError("File troppo corto o corrotto")

        salt = blob[:16]
        nonce = blob[16:28]
        ciphertext_with_tag = blob[28:]  # ciphertext + tag

        derived = cls._derive_key(password, salt)
        aesgcm = AESGCM(derived)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        except cryptography.exceptions.InvalidTag as e:
            # Password errata o file corrotto
            raise

        return int(plaintext.decode())

    @classmethod
    def change_password(cls, username: str, old_password: str, new_password: str) -> None:
        privkey = cls.load_private_key(username, old_password)
        cls.save_private_key(username, privkey, new_password)


if __name__ == "__main__":
    KeyManager.save_private_key("pippo", 12131231311313, "mario12")

    key = KeyManager.load_private_key("pippo", "mario12")
    print("Chiave caricata:", key)
