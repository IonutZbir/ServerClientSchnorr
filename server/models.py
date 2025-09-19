from typing import List
from beanie import Document, Link
from datetime import datetime, timedelta

from pydantic import Field

class PublicKey(Document):
    pk: str
    hash_pk: str
    device_name: str
    logged: bool

class User(Document):
    username: str
    public_keys: List[Link[PublicKey]]
    created_at: datetime = datetime.now()

class HashedUser(Document):
    hask_pk: str
    user: Link[User]

class Pairing(Document):
    prefix_hash_pk: str
    pk: Link[PublicKey]
    created_at: datetime = Field(default_factory=datetime.now)
    expiry: datetime = Field(default_factory=lambda: datetime.now() + timedelta(minutes=10))
    
    @property
    def is_expired(self):
        return datetime.now() > self.expiry

    # def add_device(self, dev: Device):
    #     self.devices.append(dev.to_dict())

    # def to_dict(self):
    #     return {
    #         "_id": self._id,
    #         "username": self.username,
    #         "devices": self.devices,
    #         "created_at": self.created_at,
    #     }

    # def insert_user(self):
    #     self.collection.insert_one(self.to_dict())

    # def update_user_with_device(self, pk: str, device_name: str):
    #     device = Device(pk, device_name, main_device=False, logged=True)
    #     self.add_device(device)
    #     self.collection.update_one(
    #         {"_id": self._id},
    #         {"$set": {"devices": self.devices}}
    #     )

    # def update_user_loggedout(self, device_name: str):
    #     self.collection.update_one(
    #         {"_id": self._id , "devices.device_name": device_name},
    #         {"$set": {"devices.$.logged": False}}
    #     )

    # def update_user_login(self, device_name: str):
    #     self.collection.update_one(
    #         {"_id": self._id, "devices.device_name": device_name},
    #         {"$set": {"devices.$.logged": True}}
    #     )

    # @classmethod
    # def from_dict(cls, data: dict):
    #     user = cls(data["_id"])
    #     user.devices = data.get("devices", [])
    #     user.created_at = data.get("created_at", datetime.datetime.now().isoformat())
    #     return user

    # @classmethod
    # def find_user_by_id(cls, id: str) -> "User | None":
    #     data = cls.collection.find_one({"_id": id})
    #     return cls.from_dict(data) if data else None

    
    # def get_user_devices(self):
    #     user_data = self.collection.find_one({"_id": self._id}, {"devices": 1, "_id": 0})
    #     return user_data.get("devices", []) if user_data else []
    
    
    
