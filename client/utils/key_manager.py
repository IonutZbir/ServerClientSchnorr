from pathlib import Path

# TODO: maggiore sicurezza

class KeyManager:
    CONFIG_PATH = Path.home() / ".config"
    SCHNORR_DIR = CONFIG_PATH / "schnorr"

    @classmethod
    def load_private_key(cls, username: str) -> int:
        """Carica la chiave privata dal file, lancia l'eccezione "FileNotFoundError" se non la trova."""
        privkey_path = cls.SCHNORR_DIR / f"{username}_privkey.txt"
        try:
            with open(privkey_path, "r") as f:
                return int(f.read())
        except FileNotFoundError as e:
            raise e

    @classmethod
    def save_private_key(cls, username: str, key: int) -> None:
        """Salva la chiave privata su file."""
        cls.SCHNORR_DIR.mkdir(parents=True, exist_ok=True)
        privkey_path = cls.SCHNORR_DIR / f"{username}_privkey.txt"
        with open(privkey_path, "w") as f:
            f.write(str(key))