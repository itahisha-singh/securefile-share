import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)  # 32 bytes = AES-256
    return kdf.derive(passphrase.encode())


def encrypt_bytes(data: bytes, passphrase: str, aad: str):
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(passphrase, salt)
    ciphertext = AESGCM(key).encrypt(nonce, data, aad.encode())
    return salt, nonce, ciphertext


def decrypt_bytes(ciphertext: bytes, passphrase: str, salt: bytes,
                  nonce: bytes, aad: str) -> bytes:
    key = derive_key(passphrase, salt)
    # Raises cryptography.exceptions.InvalidTag if key is wrong or data changed
    return AESGCM(key).decrypt(nonce, ciphertext, aad.encode())