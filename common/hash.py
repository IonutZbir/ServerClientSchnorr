import hashlib

def hash_public_key_SHA256(public_key: int) -> 'hashlib.Hash':
    """
    To hash the public key, convert it from int to bytes and then pass it to sha256

    Args:
        public_key (int): the public key to hash

    Returns:
        hashlib._Hash: return the HASH object (SHA256)
    """
    
    if type(public_key) is not int:
        raise TypeError("La chiave pubblica deve essere INT per poterla hashare!")
    
    pk_bytes = public_key.to_bytes((public_key.bit_length() + 7) // 8)
    return hashlib.sha256(pk_bytes)  # HASH OBJECT