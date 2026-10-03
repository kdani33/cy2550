import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    """
    Encrypts a file using AES-256-GCM with a PBKDF2-derived key.
    
    Format of output file:
    [16 bytes Salt] + [12 bytes Nonce] + [Ciphertext + Tag]
    """
    # 1. Generate a secure random 16-byte salt
    salt = os.urandom(16)
    
    # 2. Derive a 256-bit (32-byte) key using PBKDF2-HMAC-SHA256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    key = kdf.derive(password.encode("utf-8"))
    
    # 3. Generate a 96-bit (12-byte) random nonce for GCM
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    
    # 4. Read source data and encrypt
    with open(input_path, "rb") as f:
        data = f.read()
        
    ciphertext = aesgcm.encrypt(nonce, data, associated_data=None)
    
    # 5. Write [Salt][Nonce][Ciphertext] to output
    with open(output_path, "wb") as f:
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext)


# I used Gemini 
# Prompt: “Write me a Python function that encrypts a file with AES.”
