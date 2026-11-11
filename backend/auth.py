
import os
import jwt

from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import request, jsonify, g
from dotenv import load_dotenv

load_dotenv()

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRY_HOURS = 24


def generate_token(user_id, role):
    """Generate a JWT token valid for 24 hours."""

    if not JWT_SECRET_KEY:
        raise RuntimeError("JWT_SECRET_KEY is not configured.")

    payload = {
        "user_id": str(user_id),
        "role": role,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(
            hours=TOKEN_EXPIRY_HOURS
        )
    }

    token = jwt.encode(
        payload,
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM
    )

    return token


def verify_token(token):
    """Verify JWT token and return its payload."""

    if not JWT_SECRET_KEY:
        raise RuntimeError("JWT_SECRET_KEY is not configured.")

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM]
        )

        return payload

    except jwt.ExpiredSignatureError:
        return None

    except jwt.InvalidTokenError:
        return None


def auth_required(function):
    """Protect routes that require authentication."""

    @wraps(function)
    def wrapper(*args, **kwargs):

        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({
                "error": "Authentication token is missing."
            }), 401

        token = auth_header.split(" ", 1)[1].strip()

        if not token:
            return jsonify({
                "error": "Authentication token is missing."
            }), 401

        payload = verify_token(token)

        if payload is None:
            return jsonify({
                "error": "Invalid or expired token."
            }), 401

        if (
            not payload.get("user_id")
            or payload.get("role") not in ("admin", "user")
        ):
            return jsonify({
                "error": "Invalid token claims."
            }), 401

        g.current_user = payload

        return function(*args, **kwargs)

    return wrapper


def admin_required(function):
    """Restrict access to administrators only."""

    @wraps(function)
    def wrapper(*args, **kwargs):

        if not hasattr(g, "current_user"):
            return jsonify({
                "error": "Authentication required."
            }), 401

        if g.current_user.get("role") != "admin":
            return jsonify({
                "error": "Administrator access required."
            }), 403

        return function(*args, **kwargs)

    return wrapper
