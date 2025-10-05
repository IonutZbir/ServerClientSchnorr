import hashlib
import platform

import qrcode
import distro

from mnemonic import Mnemonic

def get_linux_device_model():
    try:
        with open("/sys/devices/virtual/dmi/id/product_name", "r") as f:
            model = f.readline().strip()
        with open("/sys/devices/virtual/dmi/id/sys_vendor", "r") as f:
            manufacturer = f.readline().strip()
        return manufacturer, model
    except Exception as e:
        return None, None


def get_device_name() -> str:
    manuf, model = get_linux_device_model()
    dis = distro.name(pretty=True)
    out = f"{manuf} {model} - {dis} - {platform.machine()}"
    
    if model == "System Product Name":
        out = f"{manuf} - {dis} - {platform.machine()}"
    
    return out

def create_qr_code(token: str) -> None:
    """Crea e mostra un QR code dal token dato."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(token)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.show()
      

class Device:
    def __init__(self, device_name: str, logged: bool = True):
        self.device_name = device_name
        self.logged = logged

    def __str__(self):
        return f"{self.device_name}\nOnline: {'Sì' if self.logged else 'No'}"

class MnemonicHash:
    mnemo = Mnemonic("italian")
    wordlist = mnemo.wordlist

    @classmethod
    def hash_to_words(cls, digest: bytes) -> list[str]:
        """
        Converte tutto il digest in una sequenza di parole BIP-39.
        Usa tutti i bit disponibili, anche se non multiplo di 11.
        L'ultima parola userà solo i bit disponibili (resto viene azzerato).
        """
        digest_int = int.from_bytes(digest, byteorder="big")
        total_bits = len(digest) * 8

        words = []
        full_words = total_bits // 11
        remaining_bits = total_bits % 11

        # parole intere
        for i in range(full_words):
            shift = total_bits - 11 * (i + 1)
            idx = (digest_int >> shift) & ((1 << 11) - 1)
            words.append(cls.wordlist[idx])

        # ultima parola parziale (se avanzano bit)
        if remaining_bits > 0:
            idx = digest_int & ((1 << remaining_bits) - 1)
            idx <<= (11 - remaining_bits)
            words.append(cls.wordlist[idx])

        return words

    @classmethod
    def words_to_hash(cls, words: list[str], digest_len_bytes: int) -> bytes:
        """
        Ricostruisce tutti i bit come bytes dai mnemonici.
        digest_len_bytes: numero di byte atteso nel digest originale.
        """
        total_bits = digest_len_bytes * 8
        full_words = total_bits // 11
        remaining_bits = total_bits % 11

        attese = full_words + (1 if remaining_bits > 0 else 0)
        if len(words) != attese:
            raise ValueError(f"Numero parole non corretto: attese {attese}.")

        digest_int = 0

        for i, w in enumerate(words):
            try:
                idx = cls.wordlist.index(w)
            except ValueError:
                raise ValueError(f"Parola non valida: {w}")

            if i < full_words:
                digest_int = (digest_int << 11) | idx
            else:
                idx >>= (11 - remaining_bits)
                digest_int = (digest_int << remaining_bits) | idx

        return digest_int.to_bytes(digest_len_bytes, byteorder="big")

    @classmethod
    def verify_words_against_digest_bytes(cls, words: list[str], digest: bytes) -> bool:
        """
        Verifica che le parole corrispondano a tutti i bit di `digest`.
        """
        digest_bytes = cls.words_to_hash(words, len(digest))
        return digest_bytes == digest

if __name__ == "__main__":
    digest = hashlib.sha256("ionut".encode()).digest() # slave
    
    words = MnemonicHash.hash_to_words(digest)
    
    hex_66bit_slave = hex(int.from_bytes(digest, "big") >> (len(digest)*8 - 66))
    print("Slave:", hex_66bit_slave)
    
    prefix = MnemonicHash.words_to_hash(words)
    
    hex_66bit = hex(int.from_bytes(prefix, "big"))
    print("Master:", hex_66bit)
    
    ok = MnemonicHash.verify_words_against_digest_bytes(words, digest)
    print("Verifica:", ok)