
import sqlite3
import os
from dotenv import load_dotenv
from cryptography.fernet import Fernet, InvalidToken
from datetime import datetime, timezone

from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

def get_private_key_cipher():
    """Create Fernet cipher using the master encryption key."""

    master_key = os.getenv("PRIVATE_KEY_ENCRYPTION_KEY")

    if not master_key:
        raise RuntimeError(
            "PRIVATE_KEY_ENCRYPTION_KEY is missing from .env"
        )

    return Fernet(master_key.encode())


DATABASE_PATH = os.path.join(
    os.path.dirname(__file__),
    "secure_share.db"
)


def get_connection():
    """Create a database connection."""

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():
    """Create users table if it does not exist."""

    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
            account_status TEXT DEFAULT 'active'
        )
    """)


    connection.execute("""
        CREATE TABLE IF NOT EXISTS files (
            file_id TEXT PRIMARY KEY,
            owner_id TEXT NOT NULL,
            filename TEXT NOT NULL,
            storage_path TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_id) REFERENCES users(user_id)
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS user_keys (
            user_id TEXT PRIMARY KEY,
            public_key BLOB NOT NULL,
            private_key BLOB NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(user_id)
        )
    """)


    connection.execute("""
        CREATE TABLE IF NOT EXISTS file_shares (
            share_id TEXT PRIMARY KEY,
            file_id TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            shared_with TEXT NOT NULL,
            permission TEXT DEFAULT 'read',
            expires_at TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (file_id) REFERENCES files(file_id),
            FOREIGN KEY (owner_id) REFERENCES users(user_id),
            FOREIGN KEY (shared_with) REFERENCES users(user_id)
        )
    """)

   
    # Add recipient-specific encrypted AES key if not already present
    columns = [
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(file_shares)"
        ).fetchall()
    ]

    if "encrypted_aes_key" not in columns:
        connection.execute("""
            ALTER TABLE file_shares
            ADD COLUMN encrypted_aes_key BLOB
        """)
 

    connection.commit()
    connection.close()


def create_user(user_id, email, password, role="user"):
    """Register a new user with a hashed password."""

    if role not in ("admin", "user"):
        raise ValueError("Invalid user role.")

    password_hash = generate_password_hash(password)

    connection = get_connection()

    try:
        connection.execute("""
            INSERT INTO users (
                user_id, email, password_hash, role
            )
            VALUES (?, ?, ?, ?)
        """, (user_id, email, password_hash, role))

        connection.commit()
        return True

    except sqlite3.IntegrityError:
        return False

    finally:
        connection.close()


def authenticate_user(email, password):
    """Verify user email and password."""

    connection = get_connection()

    try:
        user = connection.execute("""
            SELECT * FROM users
            WHERE email = ?
            AND account_status = 'active'
        """, (email,)).fetchone()

        if user and check_password_hash(
            user["password_hash"], password
        ):
            return {
                "user_id": user["user_id"],
                "email": user["email"],
                "role": user["role"]
            }

        return None

    finally:
        connection.close()


def get_user(user_id):
    """Retrieve user information."""

    connection = get_connection()

    try:
        user = connection.execute("""
            SELECT user_id, email, role, account_status
            FROM users
            WHERE user_id = ?
        """, (user_id,)).fetchone()

        return dict(user) if user else None
    finally:
        connection.close()



def save_user_keys(user_id, public_key, private_key):
    """Store public key and encrypted private key."""

    connection = get_connection()

    try:
        cipher = get_private_key_cipher()

        encrypted_private_key = cipher.encrypt(
            bytes(private_key)
        )

        connection.execute("""
            INSERT OR REPLACE INTO user_keys (
                user_id, public_key, private_key
            )
            VALUES (?, ?, ?)
        """, (
            user_id,
            public_key,
            encrypted_private_key
        ))

        connection.commit()
        return True

    finally:
        connection.close()


def get_user_keys(user_id):
    """Retrieve RSA keys and migrate existing plaintext private keys."""

    connection = get_connection()

    try:
        keys = connection.execute("""
            SELECT public_key, private_key
            FROM user_keys
            WHERE user_id = ?
        """, (user_id,)).fetchone()

        if not keys:
            return None

        public_key = keys["public_key"]
        stored_private_key = bytes(keys["private_key"])

        cipher = get_private_key_cipher()

        # Migrate an existing plaintext PEM private key
        if stored_private_key.startswith(b"-----BEGIN"):
            private_key = stored_private_key

            encrypted_private_key = cipher.encrypt(private_key)

            connection.execute("""
                UPDATE user_keys
                SET private_key = ?
                WHERE user_id = ?
            """, (encrypted_private_key, user_id))

            connection.commit()

        else:
            # Decrypt an already protected private key
            try:
                private_key = cipher.decrypt(stored_private_key)

            except InvalidToken as error:
                raise RuntimeError(
                    "Private key decryption failed. "
                    "Check the master encryption key."
                ) from error

        return {
            "public_key": public_key,
            "private_key": private_key
        }

    finally:
        connection.close()


def save_file_record(file_id, owner_id, filename, storage_path, sha256):
    """Save uploaded file metadata in the database."""

    connection = get_connection()

    try:
        connection.execute("""
            INSERT INTO files (
                file_id, owner_id, filename, storage_path, sha256
            )
            VALUES (?, ?, ?, ?, ?)
        """, (file_id, owner_id, filename, storage_path, sha256))

        connection.commit()
        return True

    finally:
        connection.close()


def get_file_record(file_id):
    """Retrieve uploaded file metadata."""

    connection = get_connection()

    try:
        file_record = connection.execute("""
            SELECT *
            FROM files
            WHERE file_id = ?
        """, (file_id,)).fetchone()

        return dict(file_record) if file_record else None

    finally:
        connection.close()


def get_user_file(file_id, owner_id):
    """Retrieve a file only if it belongs to the requesting user."""

    connection = get_connection()

    try:
        file_record = connection.execute("""
            SELECT *
            FROM files
            WHERE file_id = ? AND owner_id = ?
        """, (file_id, owner_id)).fetchone()

        return dict(file_record) if file_record else None

    finally:
        connection.close()



def create_file_share(
    share_id,
    file_id,
    owner_id,
    shared_with,
    encrypted_aes_key,
    expires_at=None
):
    """Create a file-sharing permission with a recipient-specific AES key."""

    connection = get_connection()

    try:
        connection.execute("""
            INSERT INTO file_shares (
                share_id,
                file_id,
                owner_id,
                shared_with,
                encrypted_aes_key,
                expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            share_id,
            file_id,
            owner_id,
            shared_with,
            encrypted_aes_key,
            expires_at
        ))

        connection.commit()
        return True

    finally:
        connection.close()




def get_file_share(file_id, shared_with):
    connection = get_connection()

    try:
        share = connection.execute("""
            SELECT * FROM file_shares
            WHERE file_id = ? AND shared_with = ?
            ORDER BY created_at DESC, rowid DESC
            LIMIT 1
        """, (file_id, shared_with)).fetchone()

        if not share:
            return None

        share = dict(share)

        # Reject revoked or invalid shares
        if not share["is_active"] or not share["encrypted_aes_key"]:
            return None

        # Reject expired shares
        if share["expires_at"]:
            current_time = datetime.now(timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            if share["expires_at"] <= current_time:
                return None

        return share

    finally:
        connection.close()





def revoke_file_share(share_id, owner_id):
    """Revoke a sharing permission."""

    connection = get_connection()

    try:
        cursor = connection.execute("""
            UPDATE file_shares
            SET is_active = 0
            WHERE share_id = ? AND owner_id = ?
        """, (share_id, owner_id))

        connection.commit()
        return cursor.rowcount > 0

    finally:
        connection.close()
