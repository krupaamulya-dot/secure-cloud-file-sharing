
import os
import uuid
import json
import base64

from flask import Blueprint, request, jsonify, g

from encryption.crypto_utils import (encrypt_file,decrypt_file,rsa_encrypt,rsa_decrypt
)

from database.db import (get_user_keys,save_file_record,get_user_file,create_file_share,get_file_share,revoke_file_share,get_user,get_file_record
)

from backend.auth import auth_required
from flask import send_file
from io import BytesIO
from datetime import datetime, timedelta, timezone

from encryption.crypto_utils import decrypt_file
from database.db import get_user_file

file_bp = Blueprint("files", __name__)

UPLOAD_FOLDER = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "uploads"
)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@file_bp.route("/api/files/upload", methods=["POST"])
@auth_required
def upload_file():

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    uploaded_file = request.files["file"]

    if not uploaded_file.filename:
        return jsonify({"error": "No filename provided"}), 400

    file_data = uploaded_file.read()

    if not file_data:
        return jsonify({"error": "Empty files are not allowed"}), 400

    user_id = g.current_user["user_id"]

    # Retrieve the logged-in user's RSA keys
    user_keys = get_user_keys(user_id)

    if not user_keys:
        return jsonify({"error": "RSA keys not found"}), 404

    # Encrypt file using the user's public key
    encrypted_data = encrypt_file(
        file_data,
        user_keys["public_key"]
    )

    file_id = str(uuid.uuid4())

    storage_path = os.path.join(
        UPLOAD_FOLDER,
        file_id + ".json"
    )

    # Save encrypted file
    with open(storage_path, "w", encoding="utf-8") as f:
        json.dump(encrypted_data, f)

    # Save file ownership and metadata
    save_file_record(
        file_id,
        user_id,
        uploaded_file.filename,
        storage_path,
        encrypted_data["sha256"]
    )

    return jsonify({
        "message": "File encrypted and uploaded successfully",
        "file_id": file_id,
        "filename": uploaded_file.filename,
        "sha256": encrypted_data["sha256"]
    }), 201



@file_bp.route("/api/files/<file_id>/download", methods=["GET"])
@auth_required
def download_file(file_id):

    user_id = g.current_user["user_id"]

    # Check whether the requester owns the file
    file_record = get_user_file(file_id, user_id)
    is_owner = file_record is not None

    if not is_owner:
        # Check whether the requester has sharing permission
        share = get_file_share(file_id, user_id)

        if not share:
            return jsonify({
                "error": "File not found or access denied"
            }), 404

        file_record = get_file_record(file_id)

        if not file_record:
            return jsonify({"error": "File not found"}), 404

    # Retrieve the requester's RSA private key
    user_keys = get_user_keys(user_id)

    if not user_keys:
        return jsonify({"error": "RSA keys not found"}), 404

    try:
        # Read encrypted file
        with open(file_record["storage_path"], "r", encoding="utf-8") as f:
            encrypted_data = json.load(f)

        # For recipients, use their recipient-specific encrypted AES key
        if not is_owner:
            encrypted_data["encrypted_key"] = share["encrypted_aes_key"]

        # Decrypt file and verify SHA-256 integrity
        decrypted_data = decrypt_file(
            encrypted_data,
            user_keys["private_key"]
        )

    except (OSError, ValueError, KeyError, TypeError):
        return jsonify({
            "error": "File decryption or integrity verification failed"
        }), 400

    return send_file(
        BytesIO(decrypted_data),
        as_attachment=True,
        download_name=file_record["filename"]
    )



@file_bp.route("/api/files/<file_id>/share", methods=["POST"])
@auth_required
def share_file(file_id):

    owner_id = g.current_user["user_id"]

    # Verify file ownership
    file_record = get_user_file(file_id, owner_id)

    if not file_record:
        return jsonify({"error": "File not found or access denied"}), 404

    data = request.get_json(silent=True) or {}
    recipient_email = data.get("email", "").strip().lower()
    expires_in_minutes = data.get("expires_in_minutes", 60)

    if not recipient_email:
        return jsonify({"error": "Recipient email is required"}), 400

    # Validate expiry duration
    if (
        isinstance(expires_in_minutes, bool)
        or not isinstance(expires_in_minutes, int)
        or not 1 <= expires_in_minutes <= 10080
    ):
        return jsonify({
            "error": "Expiry must be between 1 and 10080 minutes"
        }), 400

    # Calculate expiry time in UTC
    expires_at = (
        datetime.now(timezone.utc) + timedelta(minutes=expires_in_minutes)
    ).strftime("%Y-%m-%d %H:%M:%S")

    # Find recipient
    from database.db import get_connection

    connection = get_connection()

    try:
        recipient = connection.execute("""
            SELECT user_id FROM users
            WHERE email = ? AND account_status = 'active'
        """, (recipient_email,)).fetchone()
    finally:
        connection.close()

    if not recipient:
        return jsonify({"error": "Recipient user not found"}), 404

    recipient_id = recipient["user_id"]

    if recipient_id == owner_id:
        return jsonify({"error": "You cannot share a file with yourself"}), 400

    # Retrieve owner's and recipient's RSA keys
    owner_keys = get_user_keys(owner_id)
    recipient_keys = get_user_keys(recipient_id)

    if not owner_keys or not recipient_keys:
        return jsonify({"error": "RSA keys not found"}), 404

    try:
        # Load encrypted file
        with open(file_record["storage_path"], "r", encoding="utf-8") as f:
            encrypted_data = json.load(f)

        # Recover original AES key using owner's private key
        encrypted_aes_key = base64.b64decode(
            encrypted_data["encrypted_key"]
        )

        aes_key = rsa_decrypt(
            encrypted_aes_key,
            owner_keys["private_key"]
        )

        # Encrypt AES key for recipient
        recipient_encrypted_key = rsa_encrypt(
            aes_key,
            recipient_keys["public_key"]
        )

        recipient_encrypted_key_b64 = base64.b64encode(
            recipient_encrypted_key
        ).decode("utf-8")

    except (OSError, ValueError, KeyError):
        return jsonify({"error": "Unable to prepare secure file sharing"}), 400

    # Create sharing permission with expiry
    share_id = str(uuid.uuid4())

    create_file_share(
        share_id,
        file_id,
        owner_id,
        recipient_id,
        recipient_encrypted_key_b64,
        expires_at
    )

    return jsonify({
        "message": "File shared successfully",
        "share_id": share_id,
        "shared_with": recipient_email,
        "expires_at": expires_at,
        "expires_in_minutes": expires_in_minutes
    }), 201


@file_bp.route("/api/files/shares/<share_id>/revoke", methods=["POST"])
@auth_required
def revoke_share(share_id):

    owner_id = g.current_user["user_id"]

    revoked = revoke_file_share(share_id, owner_id)

    if not revoked:
        return jsonify({
            "error": "Share not found or access denied"
        }), 404

    return jsonify({
        "message": "File sharing revoked successfully"
    }), 200
