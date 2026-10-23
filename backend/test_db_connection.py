
import os
from pathlib import Path

from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import PyMongoError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

uri = os.getenv("MONGODB_URI")
database_name = os.getenv("MONGODB_DATABASE")

if not uri or not database_name:
    print("Configuration missing. Check your local .env file.")
else:
    try:
        with MongoClient(uri, serverSelectionTimeoutMS=10000) as client:
            client.admin.command("ping")
            print("MongoDB Atlas connection successful!")
            print(f"Database configured: {database_name}")
    except PyMongoError as e:
        print("MongoDB connection failed.")
        print("Error details:", repr(e))
