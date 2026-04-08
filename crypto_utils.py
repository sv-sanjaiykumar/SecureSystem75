import base64
import hashlib
import os

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def build_user_key(user_identifier: str) -> bytes:
    master_secret = os.getenv("APP_ENCRYPTION_SECRET", "change-this-secret-before-production")
    return hashlib.sha256(f"{master_secret}:{user_identifier}".encode("utf-8")).digest()


def encrypt_bytes(raw_bytes: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(12))
    cipher_bytes, tag = cipher.encrypt_and_digest(raw_bytes)
    return cipher.nonce + tag + cipher_bytes


def decrypt_bytes(payload: bytes, key: bytes) -> bytes:
    nonce = payload[:12]
    tag = payload[12:28]
    cipher_bytes = payload[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(cipher_bytes, tag)


def encrypt_value(plain_text: str, key: bytes) -> str:
    payload = encrypt_bytes(plain_text.encode("utf-8"), key)
    return base64.b64encode(payload).decode("utf-8")


def decrypt_value(encoded_payload: str, key: bytes) -> str:
    payload = base64.b64decode(encoded_payload.encode("utf-8"))
    return decrypt_bytes(payload, key).decode("utf-8")
