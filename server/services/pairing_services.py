from models import User, PublicKey, HashedUser, Pairing
from beanie import PydanticObjectId

class PairingServices:
    @staticmethod
    async def create_pairing(prefix_hash_pk: str, pk: PublicKey) -> Pairing:
        p = Pairing(prefix_hash_pk=prefix_hash_pk, pk=pk)
        await p.insert()
        return p

    @staticmethod
    async def get_pairing_by_prefix(prefix_hash_pk: str) -> Pairing | None:
        p = await Pairing.find_one(Pairing.prefix_hash_pk == prefix_hash_pk)
        if not p:
            return None
        
        # Ricavo la pk dall'ObjectId contenuto nel Link
        pk_id: PydanticObjectId = p.pk.ref.id
        pk = await PublicKey.get(pk_id)
        if not pk:
            return None
        p.pk = pk
        return p
    
    @staticmethod
    async def delete_one(p: Pairing):
        if not isinstance(p.pk, PublicKey):
            p = await Pairing.get(p.id, fetch_links=True)
        if p.pk:
            await p.pk.delete()
        await p.delete()      
    