from models import User, PublicKey, HashedUser
from beanie import PydanticObjectId


class UserService:
    @staticmethod
    async def create_user(username: str, pk: PublicKey) -> User:
        # Creo un nuovo utente con la prima public key
        user = User(username=username, public_keys=[pk])
        await user.insert()

        # Creo la mappatura hash_pk -> user
        hu = HashedUser(hask_pk=pk.hash_pk, user=user)
        await hu.insert()
        return user

    @staticmethod
    async def get_user(hash_pk: str) -> User | None:
        hu = await HashedUser.find_one(HashedUser.hask_pk == hash_pk)
        if not hu:
            return None

        # Ricavo lo User dall'ObjectId contenuto nel Link
        user_id: PydanticObjectId = hu.user.ref.id
        user = await User.get(user_id)
        if not user:
            return None

        # Risolvo le public keys manualmente
        pk_ids = [link.ref.id for link in user.public_keys]
        public_keys: list[PublicKey] = []
        for pk_id in pk_ids:
            pk = await PublicKey.get(pk_id)
            if pk:
                public_keys.append(pk)

        user.public_keys = public_keys
        return user

    @staticmethod
    async def add_new_publickey(hash_pk: str, new_pk: PublicKey) -> User | None:
        hu = await HashedUser.find_one(HashedUser.hask_pk == hash_pk)
        if not hu:
            return None

        user_id: PydanticObjectId = hu.user.ref.id
        user = await User.get(user_id)
        if not user:
            return None

        # aggiungo la nuova pk e salvo
        user.public_keys.append(new_pk)
        await user.save()

        # aggiorno anche la mappatura hash_pk -> user
        new_hu = HashedUser(hask_pk=new_pk.hash_pk, user=user)
        await new_hu.insert()

        return await UserService.get_user(hash_pk)  # ritorna user completo

    @staticmethod
    async def update_user_login(public_key_used: PublicKey, logged: bool):
        public_key_used.logged = logged
        await public_key_used.save()

    async def get_devices(user: User):
        user = await User.get(user.id)
        pk_ids = [link.ref.id for link in user.public_keys]
        public_keys: list[PublicKey] = []
        for pk_id in pk_ids:
            pk = await PublicKey.get(pk_id)
            if pk:
                public_keys.append(pk)

        return public_keys