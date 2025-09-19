from models import User, PublicKey, HashedUser

class PublicKeyServices:
    @staticmethod
    async def create_public_key(pk: str, hash_pk: str, device_name: str, logged: bool) -> PublicKey:
        pk = PublicKey(pk=pk, hash_pk=hash_pk, device_name=device_name, logged=logged)
        await pk.insert()
        return pk
    
    