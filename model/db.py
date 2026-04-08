import os

from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()


class MongoConnection:
    def __init__(self) -> None:
        mongo_uri = os.getenv("MONGO_URI") or "mongodb://127.0.0.1:27017/"
        database_name = os.getenv("MONGO_DB_NAME") or "secure_system_75"

        self.client = MongoClient(mongo_uri)
        self.db = self.client[database_name]
        self.users = self.db["users"]
        self.data = self.db["data"]
        self.messages = self.db["messages"]
        self.shared_files = self.db["shared_files"]


mongo = MongoConnection()
