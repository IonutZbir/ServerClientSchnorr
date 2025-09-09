from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie, Document

class Database:
    def __init__(self, uri: str = "mongodb://localhost:27017", db_name: str = "my_database"):
        self.client = AsyncIOMotorClient(uri)
        self.db = self.client[db_name]

    async def init(self, models: list[type[Document]]):
        await init_beanie(database=self.db, document_models=models)