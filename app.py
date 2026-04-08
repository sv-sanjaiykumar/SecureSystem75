import os
from io import BytesIO
from datetime import datetime, timezone
from functools import wraps

import bcrypt
from bson.binary import Binary
from bson import ObjectId
from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, send_file, session, url_for
from werkzeug.utils import secure_filename

load_dotenv()

from crypto_utils import build_user_key, decrypt_bytes, decrypt_value, encrypt_bytes, encrypt_value
from model.db import mongo

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "change-this-flask-secret")
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

MAX_FILE_SIZE = 1024 * 1024


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return mongo.users.find_one({"_id": ObjectId(user_id)})


def sanitize_form_value(field_name: str, min_length: int = 1) -> str:
    value = request.form.get(field_name, "").strip()
    if len(value) < min_length:
        raise ValueError(f"{field_name.replace('_', ' ').title()} is required.")
    return value


def fetch_user_records():
    return list(mongo.data.find({"user_id": session["user_id"]}).sort("timestamp", -1))


def split_data_records(records):
    text_records = [record for record in records if record.get("data_type", "text") == "text"]
    file_records = [record for record in records if record.get("data_type") == "file"]
    return text_records, file_records


def fetch_received_messages():
    received_messages = []
    for message in mongo.messages.find({"receiver_id": session["user_id"]}).sort("timestamp", -1):
        sender = mongo.users.find_one({"_id": ObjectId(message["sender_id"])})
        message["sender_name"] = sender["username"] if sender else "Unknown"
        received_messages.append(message)
    return received_messages


def fetch_shared_files():
    shared_files = []
    for shared_file in mongo.shared_files.find({"receiver_id": session["user_id"]}).sort("timestamp", -1):
        sender = mongo.users.find_one({"_id": ObjectId(shared_file["sender_id"])})
        shared_file["sender_name"] = sender["username"] if sender else "Unknown"
        shared_files.append(shared_file)
    return shared_files


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        try:
            username = sanitize_form_value("username", 3)
            email = sanitize_form_value("email", 5).lower()
            password = sanitize_form_value("password", 8)
        except ValueError as exc:
            flash(str(exc), "error")
            return render_template("register.html")

        if mongo.users.find_one({"$or": [{"username": username}, {"email": email}]}):
            flash("Username or email already exists.", "error")
            return render_template("register.html")

        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        result = mongo.users.insert_one(
            {
                "username": username,
                "email": email,
                "password_hash": password_hash,
                "created_at": datetime.now(timezone.utc),
            }
        )

        session["user_id"] = str(result.inserted_id)
        session["username"] = username
        flash("Registration successful. Welcome to SecureSystem 75.", "success")
        return redirect(url_for("dashboard"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = mongo.users.find_one({"username": username})
        if not user or not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        session["user_id"] = str(user["_id"])
        session["username"] = user["username"]
        flash("Login successful.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    encrypted_items = fetch_user_records()
    text_records, file_records = split_data_records(encrypted_items)
    received_messages = fetch_received_messages()
    shared_files = fetch_shared_files()

    return render_template(
        "dashboard.html",
        user=user,
        text_records=text_records,
        file_records=file_records,
        received_messages=received_messages,
        shared_files=shared_files,
    )


@app.route("/encrypt", methods=["GET", "POST"])
@login_required
def encrypt_data():
    users = list(
        mongo.users.find({"_id": {"$ne": ObjectId(session["user_id"])}}, {"username": 1}).sort("username", 1)
    )

    if request.method == "POST":
        action = request.form.get("action", "store")

        if action == "message":
            plain_text = request.form.get("plain_text", "").strip()
            if not plain_text:
                flash("Please provide a message to encrypt.", "error")
                return render_template("encrypt.html", users=users)

            receiver_id = request.form.get("receiver_id", "")
            receiver = mongo.users.find_one({"_id": ObjectId(receiver_id)}) if ObjectId.is_valid(receiver_id) else None
            if not receiver:
                flash("Please choose a valid receiver.", "error")
                return render_template("encrypt.html", users=users)

            receiver_key = build_user_key(str(receiver["_id"]))
            encrypted_message = encrypt_value(plain_text, receiver_key)
            mongo.messages.insert_one(
                {
                    "sender_id": session["user_id"],
                    "receiver_id": str(receiver["_id"]),
                    "encrypted_message": encrypted_message,
                    "timestamp": datetime.now(timezone.utc),
                }
            )
            flash("Encrypted message sent successfully.", "success")
            return redirect(url_for("dashboard"))

        if action == "file":
            uploaded_file = request.files.get("secure_file")
            if not uploaded_file or not uploaded_file.filename:
                flash("Please choose a file to encrypt.", "error")
                return render_template("encrypt.html", users=users)

            file_name = secure_filename(uploaded_file.filename)
            file_bytes = uploaded_file.read()

            if not file_name:
                flash("Invalid file name.", "error")
                return render_template("encrypt.html", users=users)

            if not file_bytes:
                flash("Uploaded file is empty.", "error")
                return render_template("encrypt.html", users=users)

            if len(file_bytes) > MAX_FILE_SIZE:
                flash("File must be 1 MB or smaller.", "error")
                return render_template("encrypt.html", users=users)

            user_key = build_user_key(session["user_id"])
            encrypted_file = encrypt_bytes(file_bytes, user_key)
            mongo.data.insert_one(
                {
                    "user_id": session["user_id"],
                    "data_type": "file",
                    "file_name": file_name,
                    "content_type": uploaded_file.content_type or "application/octet-stream",
                    "original_size": len(file_bytes),
                    "encrypted_blob": Binary(encrypted_file),
                    "timestamp": datetime.now(timezone.utc),
                }
            )
            flash("File encrypted and stored securely in MongoDB.", "success")
            return redirect(url_for("dashboard"))

        if action == "shared_file":
            receiver_id = request.form.get("receiver_id", "")
            receiver = mongo.users.find_one({"_id": ObjectId(receiver_id)}) if ObjectId.is_valid(receiver_id) else None
            if not receiver:
                flash("Please choose a valid receiver.", "error")
                return render_template("encrypt.html", users=users)

            uploaded_file = request.files.get("shared_secure_file")
            if not uploaded_file or not uploaded_file.filename:
                flash("Please choose a file to share.", "error")
                return render_template("encrypt.html", users=users)

            file_name = secure_filename(uploaded_file.filename)
            file_bytes = uploaded_file.read()

            if not file_name:
                flash("Invalid file name.", "error")
                return render_template("encrypt.html", users=users)

            if not file_bytes:
                flash("Uploaded file is empty.", "error")
                return render_template("encrypt.html", users=users)

            if len(file_bytes) > MAX_FILE_SIZE:
                flash("Shared file must be 1 MB or smaller.", "error")
                return render_template("encrypt.html", users=users)

            receiver_key = build_user_key(str(receiver["_id"]))
            encrypted_file = encrypt_bytes(file_bytes, receiver_key)
            mongo.shared_files.insert_one(
                {
                    "sender_id": session["user_id"],
                    "receiver_id": str(receiver["_id"]),
                    "file_name": file_name,
                    "content_type": uploaded_file.content_type or "application/octet-stream",
                    "original_size": len(file_bytes),
                    "encrypted_blob": Binary(encrypted_file),
                    "timestamp": datetime.now(timezone.utc),
                }
            )
            flash("Encrypted file shared successfully.", "success")
            return redirect(url_for("dashboard"))

        plain_text = request.form.get("plain_text", "").strip()
        if not plain_text:
            flash("Please provide text to encrypt.", "error")
            return render_template("encrypt.html", users=users)

        user_key = build_user_key(session["user_id"])
        encrypted_text = encrypt_value(plain_text, user_key)
        mongo.data.insert_one(
            {
                "user_id": session["user_id"],
                "data_type": "text",
                "encrypted_text": encrypted_text,
                "timestamp": datetime.now(timezone.utc),
            }
        )
        flash("Data encrypted and stored securely.", "success")
        return redirect(url_for("dashboard"))

    return render_template("encrypt.html", users=users)


@app.route("/decrypt", methods=["GET", "POST"])
@login_required
def decrypt_data():
    records = fetch_user_records()
    text_records, file_records = split_data_records(records)
    messages = fetch_received_messages()
    shared_files = fetch_shared_files()

    decrypted_output = None
    output_type = None
    decrypted_file = None

    if request.method == "POST":
        record_type = request.form.get("record_type", "data")
        record_id = request.form.get("record_id", "")

        if not ObjectId.is_valid(record_id):
            flash("Invalid record selected.", "error")
            return render_template(
                "decrypt.html",
                text_records=text_records,
                file_records=file_records,
                messages=messages,
                shared_files=shared_files,
            )

        if record_type == "message":
            record = mongo.messages.find_one({"_id": ObjectId(record_id), "receiver_id": session["user_id"]})
            if not record:
                flash("Message not found.", "error")
                return render_template(
                    "decrypt.html",
                    text_records=text_records,
                    file_records=file_records,
                    messages=messages,
                    shared_files=shared_files,
                )

            receiver_key = build_user_key(session["user_id"])
            decrypted_output = decrypt_value(record["encrypted_message"], receiver_key)
            output_type = "message"
        elif record_type == "file":
            record = mongo.data.find_one(
                {"_id": ObjectId(record_id), "user_id": session["user_id"], "data_type": "file"}
            )
            if not record:
                flash("Encrypted file not found.", "error")
                return render_template(
                    "decrypt.html",
                    text_records=text_records,
                    file_records=file_records,
                    messages=messages,
                    shared_files=shared_files,
                )

            decrypted_file = {
                "id": str(record["_id"]),
                "name": record["file_name"],
                "size": record.get("original_size", 0),
                "download_route": "download_decrypted_file",
            }
            output_type = "file"
        elif record_type == "shared_file":
            record = mongo.shared_files.find_one({"_id": ObjectId(record_id), "receiver_id": session["user_id"]})
            if not record:
                flash("Shared file not found.", "error")
                return render_template(
                    "decrypt.html",
                    text_records=text_records,
                    file_records=file_records,
                    messages=messages,
                    shared_files=shared_files,
                )

            decrypted_file = {
                "id": str(record["_id"]),
                "name": record["file_name"],
                "size": record.get("original_size", 0),
                "download_route": "download_shared_file",
            }
            output_type = "shared_file"
        else:
            record = mongo.data.find_one({"_id": ObjectId(record_id), "user_id": session["user_id"], "data_type": "text"})
            if not record:
                flash("Encrypted data not found.", "error")
                return render_template(
                    "decrypt.html",
                    text_records=text_records,
                    file_records=file_records,
                    messages=messages,
                    shared_files=shared_files,
                )

            user_key = build_user_key(session["user_id"])
            decrypted_output = decrypt_value(record["encrypted_text"], user_key)
            output_type = "data"

        flash("Decryption completed successfully.", "success")

    return render_template(
        "decrypt.html",
        text_records=text_records,
        file_records=file_records,
        messages=messages,
        shared_files=shared_files,
        decrypted_output=decrypted_output,
        decrypted_file=decrypted_file,
        output_type=output_type,
    )


@app.route("/download/<record_id>")
@login_required
def download_decrypted_file(record_id):
    if not ObjectId.is_valid(record_id):
        flash("Invalid file selected.", "error")
        return redirect(url_for("decrypt_data"))

    record = mongo.data.find_one({"_id": ObjectId(record_id), "user_id": session["user_id"], "data_type": "file"})
    if not record:
        flash("Encrypted file not found.", "error")
        return redirect(url_for("decrypt_data"))

    user_key = build_user_key(session["user_id"])
    decrypted_file = decrypt_bytes(bytes(record["encrypted_blob"]), user_key)
    file_stream = BytesIO(decrypted_file)
    file_stream.seek(0)

    return send_file(
        file_stream,
        as_attachment=True,
        download_name=record["file_name"],
        mimetype=record.get("content_type", "application/octet-stream"),
    )


@app.route("/download/shared/<record_id>")
@login_required
def download_shared_file(record_id):
    if not ObjectId.is_valid(record_id):
        flash("Invalid shared file selected.", "error")
        return redirect(url_for("decrypt_data"))

    record = mongo.shared_files.find_one({"_id": ObjectId(record_id), "receiver_id": session["user_id"]})
    if not record:
        flash("Shared file not found.", "error")
        return redirect(url_for("decrypt_data"))

    receiver_key = build_user_key(session["user_id"])
    decrypted_file = decrypt_bytes(bytes(record["encrypted_blob"]), receiver_key)
    file_stream = BytesIO(decrypted_file)
    file_stream.seek(0)

    return send_file(
        file_stream,
        as_attachment=True,
        download_name=record["file_name"],
        mimetype=record.get("content_type", "application/octet-stream"),
    )


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


@app.errorhandler(413)
def request_entity_too_large(_error):
    flash("The uploaded file is too large. Please upload a file below 1 MB.", "error")
    return redirect(url_for("encrypt_data"))


if __name__ == "__main__":
    app.run(debug=True)
