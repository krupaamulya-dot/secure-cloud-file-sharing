
import os
import base64
import hashlib
import hmac

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.exceptions import InvalidTag


def generate_rsa_keys():
    """Generate a 2048-bit RSA public-private key pair."""

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem


def aes_encrypt(file_data):
    """Encrypt file data using AES-256-GCM."""

    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)

    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, file_data, None)

    return ciphertext, aes_key, nonce


def rsa_encrypt(aes_key, public_key_pem):
    """Encrypt AES key using RSA-2048-OAEP."""

    public_key = serialization.load_pem_public_key(public_key_pem)

    encrypted_key = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_key


def rsa_decrypt(encrypted_key, private_key_pem):
    """Recover AES key using RSA private key."""

    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None
    )

    aes_key = private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return aes_key


def sha256_hash(file_data):
    """Generate SHA-256 hash of original file."""

    return hashlib.sha256(file_data).hexdigest()


def encrypt_file(file_data, public_key_pem):
    """Complete AES-256-GCM and RSA hybrid encryption pipeline."""

    ciphertext, aes_key, nonce = aes_encrypt(file_data)

    encrypted_key = rsa_encrypt(aes_key, public_key_pem)

    file_hash = sha256_hash(file_data)

    return {
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
        "sha256": file_hash
    }



def decrypt_file(encrypted_data, private_key_pem):
    """Decrypt both new AES-GCM and legacy AES-CBC files."""

    ciphertext = base64.b64decode(encrypted_data["ciphertext"])
    encrypted_key = base64.b64decode(encrypted_data["encrypted_key"])

    aes_key = rsa_decrypt(encrypted_key, private_key_pem)

    # New AES-256-GCM format
    if "nonce" in encrypted_data:

        nonce = base64.b64decode(encrypted_data["nonce"])
        aesgcm = AESGCM(aes_key)

        try:
            file_data = aesgcm.decrypt(nonce, ciphertext, None)
        except InvalidTag as error:
            raise ValueError(
                "File authentication failed. Data may have been modified."
            ) from error

    # Older AES-256-CBC format
    elif "iv" in encrypted_data:

        iv = base64.b64decode(encrypted_data["iv"])

        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv)
        )

        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        file_data = unpadder.update(padded_data) + unpadder.finalize()

    else:
        raise ValueError("Unsupported encryption format")

    # Verify original file hash
    calculated_hash = sha256_hash(file_data)

    if not hmac.compare_digest(calculated_hash, encrypted_data["sha256"]):
        raise ValueError("File integrity verification failed!")

    return file_data
