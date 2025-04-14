from flask import Flask, request, jsonify, send_from_directory, render_template, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from functools import wraps
import os
import datetime
import secrets
from bson import ObjectId
from dotenv import load_dotenv

from Utils.utils import (buckets_col, files_col, 
    users_col, generate_api_key, get_bucket_path, 
    bucket_exists, api_col, map_api_access, check_api_access)
from API.api import api_router

load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")
SECRET_KEY = os.getenv("SECRET_KEY")
if not MONGO_URI or not SECRET_KEY:
    raise ValueError("MONGO_URI and SECRET_KEY must be set in .env file")

# ==== CONFIG ====
app = Flask(__name__)
app.secret_key = SECRET_KEY
BASE_STORAGE = "storage"
os.makedirs(BASE_STORAGE, exist_ok=True)

# ==== LOGIN MANAGER ====
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

app.register_blueprint(api_router, url_prefix="/api")
class User(UserMixin):
    def __init__(self, id, firstname, lastname, email, company, created_at):
        self.id = str(id)
        self.firstname = firstname
        self.lastname = lastname
        self.email = email
        self.company = company
        self.created_at = created_at
        self.api_keys = []

@login_manager.user_loader
def load_user(user_id):
    try:
        user_data = users_col.find_one({"_id": ObjectId(user_id)})
        if user_data:
            user = User(
                id=user_data["_id"],
                firstname=user_data["firstname"],
                lastname=user_data["lastname"],
                email=user_data["email"],
                company=user_data["company"],
                created_at=user_data["created_at"]
            )
            user.api_keys = user_data.get("api_keys", [])
            return user
        return None
    except Exception as e:
        print(f"Error loading user: {e}")
        return None

# ==== AUTH ROUTES ====
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        firstname = request.form["firstname"]
        lastname = request.form["lastname"]
        email = request.form["email"]
        password = request.form["password"]
        company = request.form["company"]
        if not firstname or not lastname or not email or not password or not company:
            flash("All fields are required.", "error")
            return redirect(url_for("register"))
        if users_col.find_one({"email": email}):
            flash("Email already registered.", "error")
            return redirect(url_for("register"))
        if len(firstname) < 2 or len(lastname) < 2:
            return redirect(url_for("register"))
        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "error")
            return redirect(url_for("register"))
        if " " in password:
            flash("Password cannot contain spaces.", "error")
            return redirect(url_for("register"))
        users_col.insert_one({
            "firstname": firstname,
            "lastname": lastname,
            "email": email,
            "password": password,
            "company": company,
            "created_at": datetime.datetime.now(),
            "api_keys": []
        })
        doc = users_col.find_one({"email": email})
        if not doc:
            flash("User registration failed.", "error")
            return redirect(url_for("register"))
        user = User(
            id=doc["_id"],
            firstname=doc["firstname"],
            lastname=doc["lastname"],
            email=doc["email"],
            company=doc["company"],
            created_at=doc["created_at"]
        )
        user.api_keys = doc.get("api_keys", [])
        login_user(user)
        return redirect(url_for("dashboard"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        doc = users_col.find_one({"email": email, "password": password})
        if not doc:
            flash("Invalid credentials.", "error")
            return redirect(url_for("login"))
        user = User(
            id=doc["_id"],
            firstname=doc["firstname"],
            lastname=doc["lastname"],
            email=doc["email"],
            company=doc["company"],
            created_at=doc["created_at"]
        )
        user.api_keys = doc.get("api_keys", [])
        login_user(user)
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/buckets", methods=["POST"])
@login_required
def create_bucket():
    user_id = current_user.id
    name = request.json.get("name")
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
    return jsonify({"message": "Bucket created."}), 201

@app.route("/buckets", methods=["GET"])
@login_required
def list_buckets():
    user_id = current_user.id
    buckets = list(buckets_col.find({"owner_id": user_id}, {"_id": 0}))
    return jsonify(buckets), 200

@app.route("/buckets/<bucket>", methods=["DELETE"])
@login_required
def delete_bucket(bucket):
    user_id = current_user.id
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
    return jsonify({"message": "Bucket deleted."}), 200

# ==== FILE ROUTES ====
@app.route("/upload/<bucket>", methods=["POST"])
@login_required
def upload_file(bucket):
    user_id = current_user.id
    if not bucket:
        return jsonify({"error": "Bucket name is required"}), 400
    if not bucket_exists(bucket, user_id):
        return jsonify({"error": "Bucket does not exist"}), 404
    bucket_info = buckets_col.find_one({"name": bucket, "owner_id": user_id})
    if not bucket_info:
        return jsonify({"error": "Bucket not found"}), 404
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded."}), 400
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
    return jsonify({"message": "File uploaded.", "url": f"/files/{user_id}/{bucket}/{filename}"}), 201

@app.route("/buckets/<bucket>/files", methods=["GET"])
@login_required
def list_files(bucket):
    user_id = current_user.id
    if not bucket:
        return jsonify({"error": "Bucket name is required"}), 400
    if not bucket_exists(bucket, user_id):
        return jsonify({"error": "Bucket does not exist"}), 404
    bucket_info = buckets_col.find_one({"name": bucket, "owner_id": user_id})
    if not bucket_info:
        return jsonify({"error": "Bucket not found."}), 404
    files = list(files_col.find({"bucket": bucket, "owner_id": user_id}, {"_id": 0}))
    return jsonify(files), 200

@app.route("/files/<bucket>/<filename>", methods=["DELETE"])
@login_required
def delete_file(bucket, filename):
    user_id = current_user.id
    if not bucket:
        return jsonify({"error": "Bucket name is required"}), 400
    path = get_bucket_path(bucket, user_id)
    file_path = os.path.join(path, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        files_col.delete_one({"bucket": bucket, "filename": filename, "owner_id": user_id})
        users_col.update_one({"_id": ObjectId(user_id)}, {"$push": {"recent_activity": {"action": "delete_file", "bucket": bucket, "filename": filename, "timestamp": datetime.datetime.now(), "files": filename}}})
        return jsonify({"message": "File deleted."}), 200
    return jsonify({"error": "File not found."}), 404

# ==== PUBLIC FILE ACCESS ====
@app.route("/files/<owner_id>/<bucket>/<filename>", methods=["GET"])
def serve_file(owner_id, bucket, filename):
    file_doc = files_col.find_one({
        "bucket": bucket,
        "filename": filename,
        "owner_id": owner_id
    })
    if not file_doc:
        return jsonify({"error": "File not found"}), 404
    if not file_doc.get("is_public", False):
        return jsonify({"error": "File is not public"}), 403
    path = get_bucket_path(bucket, owner_id)
    return send_from_directory(path, filename)

# ==== UI ROUTES (OPTIONAL) ====
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/mybuckets")
@login_required
def allbuckets():
    user_id = current_user.id
    buckets = list(buckets_col.find({"owner_id": user_id}, {"_id": 0}))
    for bucket in buckets:
        files = list(files_col.find({"bucket": bucket["name"], "owner_id": user_id}, {"_id": 0}))
        bucket["files"] = files
    return render_template("s3.html", buckets=buckets)

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        firstname = request.form["firstname"]
        lastname = request.form["lastname"]
        email = request.form["email"]
        company = request.form["company"]
        if not firstname or not lastname or not email or not company:
            flash("All fields are required.", "error")
            return redirect(url_for("settings"))
        users_col.update_one({"_id": ObjectId(current_user.id)}, {"$set": {
            "firstname": firstname,
            "lastname": lastname,
            "email": email,
            "company": company
        }})
        flash("Settings updated successfully.", "success")
        return redirect(url_for("settings"))
    if request.method == "GET":
        user_id = current_user.id
        user = users_col.find_one({"_id": ObjectId(user_id)})
        if not user:
            flash("User not found.", "error")
            return redirect(url_for("settings"))
        return render_template("settings.html", user=user)
    return render_template("settings.html")

@app.route("/dashboard")
@login_required
def dashboard():
    user_id = current_user.id
    user = users_col.find_one({"_id": ObjectId(user_id)})
    total_files = files_col.count_documents({"owner_id": user_id})
    total_buckets = buckets_col.count_documents({"owner_id": user_id})
    storage_used = sum(os.path.getsize(os.path.join(get_bucket_path(bucket["name"], user_id), f)) for bucket in buckets_col.find({"owner_id": user_id}) for f in os.listdir(get_bucket_path(bucket["name"], user_id)))
    storage_used = round(storage_used / (1024 * 1024), 2)
    user["total_files"] = total_files
    user["total_buckets"] = total_buckets
    user["storage_used"] = storage_used
    return render_template("dashboard.html", user=user)

@app.route("/api/keys", methods=["GET", "POST"])
@login_required
def api_keys():
    user_id = current_user.id
    if request.method == "POST":
        if len(current_user.api_keys) >= 5:
            return jsonify({"error": "Maximum number of API keys reached."}), 400
        if not user_id:
            return jsonify({"error": "User not found."}), 404
        
        if request.json.get("delete"):
            api_key = request.json.get("api_key")
            if not api_key:
                return jsonify({"error": "API key is required."}), 400
            access_list = request.json.get("access_list", [])
            if not access_list:
                return jsonify({"error": "Access list is required."}), 400
            if not isinstance(access_list, list):
                return jsonify({"error": "Access list must be a list."}), 400
            if not all(isinstance(access, str) for access in access_list):
                return jsonify({"error": "Access list must contain strings."}), 400
            access_level = map_api_access(access_list)
            api_col.insert_one({
                "api_key": api_key,
                "owner_id": user_id,
                "access_level": access_level,
                "created_at": datetime.datetime.now()
            })
            if api_key in current_user.api_keys:
                users_col.update_one({"_id": ObjectId(user_id)}, {"$pull": {"api_keys": api_key}})
                users_col.update_one({"_id": ObjectId(user_id)}, {"$push": {"recent_activity": {"action": "delete_api_key", "api_key": api_key, "timestamp": datetime.datetime.now(), "files": "API key deleted"}}})
                return jsonify({"message": "API key deleted."}), 200
            return jsonify({"error": "API key not found."}), 404
        if request.json.get("regenerate"):
            api_key = request.json.get("api_key")
            if not api_key:
                return jsonify({"error": "API key is required."}), 400
            access_list = request.json.get("access_list", [])
            if not access_list:
                return jsonify({"error": "Access list is required."}), 400
            if api_key in current_user.api_keys:
                new_key = generate_api_key()
                users_col.update_one({"_id": ObjectId(user_id)}, {"$set": {"api_keys.$[elem]": new_key}}, array_filters=[{"elem": api_key}])
                users_col.update_one({"_id": ObjectId(user_id)}, {"$push": {"recent_activity": {"action": "regenerate_api_key", "api_key": new_key, "timestamp": datetime.datetime.now(), "files": "API Key Regenerated"}}})
                api_col.update_one({"api_key": api_key}, {"$set": {"api_key": new_key}})
                api_col.update_one({"api_key": new_key}, {"$set": {"access_level": map_api_access(access_list)}})
                return jsonify({"api_key": new_key}), 200
            return jsonify({"error": "API key not found."}), 404
        if request.json.get("create"):
            if len(current_user.api_keys) >= 5:
                return jsonify({"error": "Maximum number of API keys reached."}), 400
            if not user_id:
                return jsonify({"error": "User not found."}), 404
            access_list = request.json.get("access_list", [])
            if not access_list:
                return jsonify({"error": "Access list is required."}), 400
            if not isinstance(access_list, list):
                return jsonify({"error": "Access list must be a list."}), 400
            new_key = generate_api_key()
            users_col.update_one({"_id": ObjectId(user_id)}, {"$push": {"api_keys": new_key}})
            users_col.update_one({"_id": ObjectId(user_id)}, {"$push": {"recent_activity": {"action": "create_api_key", "api_key": new_key, "timestamp": datetime.datetime.now(), "files": "API Key Created"}}})
            api_col.insert_one({
                "api_key": new_key,
                "owner_id": user_id,
                "access_level": map_api_access(access_list),
                "created_at": datetime.datetime.now()
            })
            return jsonify({"api_key": new_key}), 201
        if request.json.get("list"):
            api_keys = current_user.api_keys
            return jsonify({"api_keys": api_keys}), 200
    user = users_col.find_one({"_id": ObjectId(user_id)})
    keys = user.get("api_keys", [])
    api_data_list = api_col.find({"api_key": {"$in": keys}})
    key_permissions = {entry["api_key"]: entry.get("access_level", 0) for entry in api_data_list}
    return render_template("api_keys.html", api_keys=user["api_keys"], user=user, key_permissions=key_permissions)

@app.route("/delete_account", methods=["POST"])
@login_required
def delete_account():
    user_id = current_user.id
    if not user_id:
        return jsonify({"error": "User not found."}), 404
    user = users_col.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({"error": "User not found."}), 404
    name = user["firstname"]
    owner_id = user["_id"]
    if not name or not owner_id:
        return jsonify({"error": "User not found."}), 404
    users_col.delete_one({"_id": ObjectId(user_id)})
    buckets_col.delete_many({"owner_id": user_id})
    files_col.delete_many({"owner_id": user_id})
    flash("Account deleted successfully.", "success")
    logout_user()
    return redirect(url_for("home"))

# ==== RUN APP ====
if __name__ == "__main__":
    app.run(debug=True, port=5000, host="0.0.0.0")
