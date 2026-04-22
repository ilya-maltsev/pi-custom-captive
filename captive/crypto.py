"""Symmetric encrypt/decrypt for short-lived secrets in session cookies.

Uses Fernet (AES-128-CBC + HMAC-SHA256) with a key derived from
Django's SECRET_KEY.  The session backend is signed_cookies — data is
HMAC-signed but NOT encrypted, so sensitive values (e.g. a password
held between login steps) must be encrypted before being stored.
"""
import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings


def _fernet():
    key = base64.urlsafe_b64encode(
        hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    )
    return Fernet(key)


def encrypt(plaintext: str) -> str:
    """Return a Fernet-encrypted, URL-safe base64 token (str)."""
    return _fernet().encrypt(plaintext.encode()).decode('ascii')


def decrypt(token: str) -> str:
    """Decrypt a token produced by ``encrypt``.  Raises ValueError on
    tampered or expired data."""
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as e:
        raise ValueError('decrypt failed') from e
