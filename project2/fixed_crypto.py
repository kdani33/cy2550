
import os
import tempfile
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
 
MAGIC = b"CY2550v1"               # Fix defect 4
MIN_PASSWORD_LEN = 12             # Fix defect 2
MAX_FILE_SIZE = 1024 ** 3         # Fix defect 5
 
 
def _derive_key(password: str, salt: bytes) -> bytes:
    # Fix defect 3
    kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))
 
 
def _write_private(path: str, data: bytes) -> None:
    # FIX defect  5: write to a temp file only the owner can read (mode 0600),
    # then rename it into place so a crash never leaves a partial file.
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise
 
 
def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    """
    Encrypts a file using AES-256-GCM with a scrypt-derived key.
    Format of output file:
    [8 bytes Magic] + [16 bytes Salt] + [12 bytes Nonce] + [Ciphertext + Tag]
    """
    # Fix defect  2: reject empty or short passwords
    if len(password) < MIN_PASSWORD_LEN:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LEN} characters.")
 
    # Fix defect 5: refuse files too large to hold in memory
    if os.path.getsize(input_path) > MAX_FILE_SIZE:
        raise ValueError("File is too large (limit 1 GiB).")
 
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
 
    with open(input_path, "rb") as f:
        data = f.read()
 
    # Fix defect 4: the header is authenticated as associated data
    header = MAGIC + salt + nonce
    ciphertext = aesgcm.encrypt(nonce, data, associated_data=header)
 
    _write_private(output_path, header + ciphertext)
 
 
def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    """
    FIX 1: decryption. The GCM tag is verified before any plaintext is written.
    """
    with open(input_path, "rb") as f:
        blob = f.read()
 
    if not blob.startswith(MAGIC) or len(blob) < 36 + 16:
        raise ValueError("Not a file produced by encrypt_file.")
 
    header = blob[:36]            # 8 magic + 16 salt + 12 nonce
    salt = header[8:24]
    nonce = header[24:36]
    ciphertext = blob[36:]
 
    key = _derive_key(password, salt)
    try:
        data = AESGCM(key).decrypt(nonce, ciphertext, associated_data=header)
    except InvalidTag:
        raise ValueError("Decryption failed: wrong password or modified file.") from None
 
    _write_private(output_path, data)
 
 
if __name__ == "__main__":
    # Round trip demo 
    password = "correct horse battery staple"
 
    with open("demo_plain.txt", "w") as f:
        f.write("This file was encrypted and decrypted by fixed_crypto.py\n")
 
    encrypt_file("demo_plain.txt", "demo_plain.enc", password)
    decrypt_file("demo_plain.enc", "demo_back.txt", password)
 
    same = open("demo_plain.txt", "rb").read() == open("demo_back.txt", "rb").read()
    print("Round trip matches original:", same)
 
    try:
        decrypt_file("demo_plain.enc", "demo_back.txt", "the wrong password!")
    except ValueError as e:
        print("Wrong password rejected:", e)
