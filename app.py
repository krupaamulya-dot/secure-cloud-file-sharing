
import uuid
import os


from flask import Flask, jsonify, request


from database.db import (
    initialize_database,
    create_user,
    authenticate_user,
    save_user_keys
)

from encryption.crypto_utils import generate_rsa_keys


from backend.file_routes import file_bp

from backend.auth import (
    generate_token,
    auth_required,
    admin_required
)

app = Flask(__name__)

app.register_blueprint(file_bp)

# Initialize database
initialize_database()


@app.route("/")
def home():
    return jsonify({
        "message": "Secure Cloud File Sharing System",
        "status": "Application is running"
    })


@app.route("/health")
def health():
    return jsonify({"status": "healthy"})


@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({
            "error": "Email and password are required."
        }), 400

    if len(password) < 8:
        return jsonify({
            "error": "Password must contain at least 8 characters."
        }), 400

    user_id = str(uuid.uuid4())

    created = create_user(
        user_id,
        email,
        password,
        role="user"
    )

    if not created:
        return jsonify({
            "error": "Email already registered."
        }), 409


    private_key, public_key = generate_rsa_keys()

    save_user_keys(
        user_id,
        public_key,
        private_key
    )

    return jsonify({
        "message": "User registered successfully.",
        "user_id": user_id
    }), 201


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({
            "error": "Email and password are required."
        }), 400

    user = authenticate_user(email, password)

    if not user:
        return jsonify({
            "error": "Invalid email or password."
        }), 401

    token = generate_token(
        user["user_id"],
        user["role"]
    )

    return jsonify({
        "message": "Login successful.",
        "token": token,
        "user": user
    }), 200


@app.route("/api/me", methods=["GET"])
@auth_required
def current_user():
    from flask import g

    return jsonify({
        "message": "Authenticated successfully.",
        "user_id": g.current_user["user_id"],
        "role": g.current_user["role"]
    })


@app.route("/api/admin", methods=["GET"])
@auth_required
@admin_required
def admin_dashboard():
    return jsonify({
        "message": "Administrator access granted."
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)