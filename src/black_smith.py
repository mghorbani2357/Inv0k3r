import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Constants
SALT_SIZE = 16
NONCE_SIZE = 12  # GCM standard
KEY_SIZE = 32    # 256-bit AES
PBKDF2_ITERATIONS = 200_000

def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derive a secure 256-bit key from the password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt_file(input_path: str, password: str):
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password.encode(), salt)
    nonce = os.urandom(NONCE_SIZE)

    aesgcm = AESGCM(key)

    with open(input_path, 'rb') as f:
        plaintext = f.read()

    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    return salt + nonce + ciphertext


def decrypt_file(encrypted_path: str,  password: str):
    with open(encrypted_path, 'rb') as f:
        data = f.read()

    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = data[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(password.encode(), salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        print(f"Decryption failed: incorrect password or corrupted file.", file=sys.stderr)
        exit(1)

    return plaintext

