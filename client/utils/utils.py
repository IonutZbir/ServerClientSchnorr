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
    def hash_to_words(cls, digest: bytes, num_bits: int = 66) -> list[str]:
        """
        Converte un hash esadecimale in una sequenza di parole BIP-39.
        Usa i primi `num_bits` dell'hash (MSB).
        """
        
        if num_bits % 11 != 0:
            raise ValueError("num_bits deve essere multiplo di 11 per avere parole intere.")

        # converte bytes -> intero (MSB first)
        digest_int = int.from_bytes(digest, byteorder="big")
        total_bits = len(digest) * 8
        if num_bits > total_bits:
            raise ValueError("num_bits maggiore del numero di bit del digest fornito.")

        # prendi i primi (più significativi) num_bits
        prefix_int = digest_int >> (total_bits - num_bits)

        # dividi in blocchi da 11 bit (dall'MSB al LSB)
        words = []
        for i in range(num_bits // 11):
            shift = num_bits - 11 * (i + 1)
            idx = (prefix_int >> shift) & ((1 << 11) - 1) 
            words.append(cls.wordlist[idx])

        return words
    
    @classmethod
    def words_to_hash(cls, words: list[str], num_bits: int = 66) -> bytes:
        """
        Dalle parole ricava i primi num_bits come bytes. Restituisce ceil(num_bits/8) bytes;
        l'ultimo byte avrà eventuali bit di padding in LSB a 0.
        """

        if num_bits % 11 != 0:
            raise ValueError("num_bits deve essere multiplo di 11.")
        if len(words) != num_bits // 11:
            raise ValueError(f"Numero parole non corretto: attese {num_bits//11}.")

        prefix_int = 0
        for w in words:
            try:
                idx = cls.wordlist.index(w)
            except ValueError:
                raise ValueError(f"Parola non valida: {w}")
            prefix_int = (prefix_int << 11) | idx

        # ora prefix_int contiene esattamente num_bits significativi (MSB aligned)
        num_bytes = (num_bits + 7) // 8  # ceil(num_bits/8)
        
        # converti a bytes, left-pad per ottenere num_bytes (big-endian)
        prefix_bytes = prefix_int.to_bytes(num_bytes, byteorder="big")

        # Nota: gli ultimi (8*num_bytes - num_bits) bit sono padding a 0 nel LSB dell'ultimo byte
        return prefix_bytes

    @classmethod
    def verify_words_against_digest_bytes(cls, words: list[str], digest: bytes, num_bits: int = 66) -> bool:
        """
        Verifica che le parole corrispondano ai primi `num_bits` di `digest` (bytes).
        Confronto fatto su interi per precisione.
        """
        digest_int = int.from_bytes(digest, byteorder="big")
        total_bits = len(digest) * 8
        if num_bits > total_bits:
            return False

        expected_prefix_int = digest_int >> (total_bits - num_bits)

        # ricava prefix_int dalle parole
        prefix_int = 0
        for w in words:
            idx = cls.wordlist.index(w)
            prefix_int = (prefix_int << 11) | idx

        return prefix_int == expected_prefix_int

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