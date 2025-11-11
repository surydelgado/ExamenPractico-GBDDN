from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()

def get_mongo():
    try:
        client = MongoClient(os.getenv("MONGO_URI"))
        return client[os.getenv("MONGO_DATABASE")]
    except Exception as e:
        print(f"Error de conexión a MongoDB: {e}")
        return None
