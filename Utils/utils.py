from pymongo import MongoClient
import os
from dotenv import load_dotenv
import secrets
from werkzeug.utils import secure_filename
from bson import ObjectId


load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")

client = MongoClient(MONGO_URI)
db = client["mini_s3"]
buckets_col = db["buckets"]
files_col = db["files"]
users_col = db["users"]
api_col = db["api"]

BASE_STORAGE = "storage"

def generate_api_key():
    return secrets.token_hex(32)

def get_user_by_api_key(api_key):
    return users_col.find_one({"api_keys": api_key})

def get_bucket_path(name, owner_id):
    return os.path.join(BASE_STORAGE, f"{secure_filename(name)}_{owner_id}")

def bucket_exists(name, owner_id):
    return buckets_col.find_one({"name": name, "owner_id": owner_id}) is not None

def map_api_access(access_list):
    """
    Maps a list of access levels to a unique integer value.
    Access levels can include 'READ', 'WRITE', and 'DELETE'.
    The resulting integer is a combination of these levels:
    0: No access
    1: Read access
    2: Write access
    3: Delete access
    4: Read and Write access
    5: Read and Delete access
    6: Write and Delete access
    7: Full access (Read, Write, Delete)
    """
    access_map = {
        "READ": 1,
        "WRITE": 2,
        "DELETE": 4
    }
    access_value = 0
    for access in access_list:
        access_value |= access_map.get(access.upper(), 0)
    return access_value

def check_api_access(api_key, operation):
    """
    Checks if the given API key has the required access level for the specified operation.
    The operation is converted to uppercase and matched against the access levels stored in the database.
    """
    operation = operation.upper()
    access_map = {
        "READ": 1,
        "WRITE": 2,
        "DELETE": 4
    }

    api_data = api_col.find_one({"api_key": api_key})
    if not api_data:
        return False

    required_access = access_map.get(operation, 0)
    if required_access == 0:
        return False

    return (api_data["access_level"] & required_access) == required_access
