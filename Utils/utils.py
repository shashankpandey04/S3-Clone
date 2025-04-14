from pymongo import MongoClient
import os
from dotenv import load_dotenv
import secrets
from werkzeug.utils import secure_filename


load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")

client = MongoClient(MONGO_URI)
db = client["mini_s3"]
buckets_col = db["buckets"]
files_col = db["files"]
users_col = db["users"]

BASE_STORAGE = "storage"

def generate_api_key():
    return secrets.token_hex(32)

def get_user_by_api_key(api_key):
    return users_col.find_one({"api_keys": api_key})

def get_bucket_path(name, owner_id):
    return os.path.join(BASE_STORAGE, f"{secure_filename(name)}_{owner_id}")

def bucket_exists(name, owner_id):
    return buckets_col.find_one({"name": name, "owner_id": owner_id}) is not None