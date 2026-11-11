
import base64

from encryption.crypto_utils import (
    generate_rsa_keys,
    encrypt_file,
    decrypt_file,
    rsa_encrypt
)

# Sample file content
original_data = b"This is my Secure Cloud File Sharing Project!"

# Generate RSA keys
private_key, public_key = generate_rsa_keys()
print("RSA keys generated successfully!")

# Encrypt the file
encrypted_data = encrypt_file(original_data, public_key)
print("AES-256-GCM encryption successful!")

# Decrypt the file
decrypted_data = decrypt_file(encrypted_data, private_key)
print("File decryption successful!")

# Verify original and decrypted data
assert original_data == decrypted_data
print("SUCCESS: Original and decrypted files match!")

# Test tamper detection
tampered_data = encrypted_data.copy()

ciphertext = bytearray(
    base64.b64decode(tampered_data["ciphertext"])
)

ciphertext[0] ^= 1

tampered_data["ciphertext"] = base64.b64encode(
    ciphertext
).decode("utf-8")

try:
    decrypt_file(tampered_data, private_key)
    print("ERROR: Tampering was not detected!")

except ValueError:
    print("SUCCESS: Tampered file was rejected!")



# Test backward compatibility with older AES-CBC files
import os
import base64
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

print("\nTesting legacy AES-CBC compatibility...")

legacy_data = b"This is an older AES-CBC encrypted file."

legacy_key = os.urandom(32)
legacy_iv = os.urandom(16)

padder = padding.PKCS7(algorithms.AES.block_size).padder()
padded_data = padder.update(legacy_data) + padder.finalize()

cipher = Cipher(
    algorithms.AES(legacy_key),
    modes.CBC(legacy_iv)
)

encryptor = cipher.encryptor()
legacy_ciphertext = encryptor.update(padded_data) + encryptor.finalize()

legacy_encrypted_key = rsa_encrypt(legacy_key, public_key)

legacy_encrypted_data = {
    "ciphertext": base64.b64encode(legacy_ciphertext).decode("utf-8"),
    "iv": base64.b64encode(legacy_iv).decode("utf-8"),
    "encrypted_key": base64.b64encode(legacy_encrypted_key).decode("utf-8"),
    "sha256": hashlib.sha256(legacy_data).hexdigest()
}

legacy_decrypted = decrypt_file(legacy_encrypted_data, private_key)

assert legacy_decrypted == legacy_data

print("SUCCESS: Legacy AES-CBC file decrypted correctly!")
