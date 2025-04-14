from flask import Flask, request, jsonify, Blueprint, render_template
from werkzeug.utils import secure_filename
from bson import ObjectId
from functools import wraps
import os
import datetime
from Utils.utils import buckets_col, files_col, users_col, get_user_by_api_key, bucket_exists, get_bucket_path
from dotenv import load_dotenv

api_router = Blueprint("api", __name__)
load_dotenv()

# ==== API AUTHENTICATION ====
def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({"error": "API key required"}), 401
        
        user = get_user_by_api_key(api_key)
        if not user:
            return jsonify({"error": "Invalid API key"}), 401
        
        # Set the user_id for the API call
        request.user_id = str(user["_id"])
        return f(*args, **kwargs)
    return decorated_function

# ==== API ROUTES ====
@api_router.route("/", methods=["GET"])
def api_root():
    return render_template("api.html")

@api_router.route("/buckets", methods=["GET"])
@require_api_key
def api_list_buckets():
    user_id = request.user_id
    buckets = list(buckets_col.find({"owner_id": user_id}, {"_id": 0}))
    return jsonify(buckets), 200

@api_router.route("/buckets", methods=["POST"])
@require_api_key
def api_create_bucket():
    user_id = request.user_id
    data = request.json
    name = data.get("name")
    
    if not name:
        return jsonify({"error": "Bucket name is required"}), 400
    
    if bucket_exists(name, user_id):
        return jsonify({"error": "Bucket already exists"}), 400
    
    os.makedirs(get_bucket_path(name, user_id), exist_ok=True)
    buckets_col.insert_one({
        "name": name,
        "owner_id": user_id,
        "created_at": datetime.datetime.now()
    })
    users_col.update_one({"_id": ObjectId(user_id)}, {"$push": {"recent_activity": {"action": "create_bucket", "bucket": name, "timestamp": datetime.datetime.now(), "files": "Bucket created"}}})
    return jsonify({"message": "Bucket created", "name": name}), 201

@api_router.route("/buckets/<bucket>", methods=["DELETE"])
@require_api_key
def api_delete_bucket(bucket):
    user_id = request.user_id
    info = buckets_col.find_one({"name": bucket, "owner_id": user_id})
    if not info:
        return jsonify({"error": "Bucket not found"}), 404
    
    path = get_bucket_path(bucket, user_id)
    for f in os.listdir(path):
        os.remove(os.path.join(path, f))
    os.rmdir(path)
    buckets_col.delete_one({"name": bucket, "owner_id": user_id})
    files_col.delete_many({"bucket": bucket, "owner_id": user_id})
    users_col.update_one({"_id": ObjectId(user_id)}, {"$push": {"recent_activity": {"action": "delete_bucket", "bucket": bucket, "timestamp": datetime.datetime.now(), "files": "All files deleted"}}})
    return jsonify({"message": "Bucket deleted"}), 200

@api_router.route("/buckets/<bucket>/files", methods=["GET"])
@require_api_key
def api_list_files(bucket):
    user_id = request.user_id
    if not bucket_exists(bucket, user_id):
        return jsonify({"error": "Bucket not found"}), 404
    
    files = list(files_col.find({"bucket": bucket, "owner_id": user_id}, {"_id": 0}))
    return jsonify(files), 200

@api_router.route("/buckets/<bucket>/files", methods=["POST"])
@require_api_key
def api_upload_file(bucket):
    user_id = request.user_id
    if not bucket_exists(bucket, user_id):
        return jsonify({"error": "Bucket not found"}), 404
    
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
        
    file = request.files['file']
    is_public = request.form.get("is_public", "false").lower() == "true"
    filename = secure_filename(file.filename)
    path = get_bucket_path(bucket, user_id)
    full_path = os.path.join(path, filename)
    file.save(full_path)
    
    files_col.insert_one({
        "bucket": bucket,
        "filename": filename,
        "path": full_path,
        "is_public": is_public,
        "uploaded_at": datetime.datetime.now(),
        "content_type": file.content_type,
        "owner_id": user_id
    })
    users_col.update_one({"_id": ObjectId(user_id)}, {"$push": {"recent_activity": {"action": "upload_file", "bucket": bucket, "filename": filename, "timestamp": datetime.datetime.now(), "files": f"{filename} uploaded"}}})
    return jsonify({"message": "File uploaded", "url": f"/files/{user_id}/{bucket}/{filename}"}), 201

@api_router.route("/buckets/<bucket>/files/<filename>", methods=["DELETE"])
@require_api_key
def api_delete_file(bucket, filename):
    user_id = request.user_id
    path = get_bucket_path(bucket, user_id)
    file_path = os.path.join(path, filename)
    
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404
        
    os.remove(file_path)
    files_col.delete_one({"bucket": bucket, "filename": filename, "owner_id": user_id})
    users_col.update_one({"_id": ObjectId(user_id)}, {"$push": {"recent_activity": {"action": "delete_file", "bucket": bucket, "filename": filename, "timestamp": datetime.datetime.now(), "files": filename}}})
    return jsonify({"message": "File deleted"}), 200
