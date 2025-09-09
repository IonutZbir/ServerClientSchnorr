from pathlib import Path

import os
import cryptography
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class KeyManager:
    CONFIG_PATH = Path.home() / ".config"
    SCHNORR_DIR = CONFIG_PATH / "schnorr"
    DEFAULT_SECRET = "chiave_predefinita_sicura"

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
    def save_private_key(cls, username: str, key: int, password: str = None) -> None:
        """Salva la chiave privata cifrata su file con AES-256-GCM."""
        cls.SCHNORR_DIR.mkdir(parents=True, exist_ok=True)
        privkey_path = cls.SCHNORR_DIR / f"{username}_privkey.pem"

        # Dati da cifrare
        data = str(key).encode()

        # Genera salt e nonce
        salt = os.urandom(16)
        nonce = os.urandom(12)

        # Deriva chiave e cifra
        
        if not password:
            password = cls.DEFAULT_SECRET
        
        aesgcm = AESGCM(cls._derive_key(password, salt))
        ciphertext = aesgcm.encrypt(nonce, data, None)

        # Salva salt + nonce + ciphertext
        with open(privkey_path, "wb") as f:
            f.write(salt + nonce + ciphertext)

    @classmethod
    def load_private_key(cls, username: str, password: str = None) -> int:
        """Carica e decifra la chiave privata da file. Lancia FileNotFoundError se non esiste."""
        privkey_path = cls.SCHNORR_DIR / f"{username}_privkey.pem"

        with open(privkey_path, "rb") as f:
            blob = f.read()

        salt, nonce, ciphertext = blob[:16], blob[16:28], blob[28:]

        if not password:
            password = cls.DEFAULT_SECRET

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

        print(f"Password aggiornata per {username}")

if __name__ == "__main__":
    KeyManager.save_private_key("pippo", 12131231311313, "mario12")
    
    key = KeyManager.load_private_key("pippo", "maro12")
    
    print(key)