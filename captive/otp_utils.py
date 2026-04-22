"""Helpers for TOTP generation, verification, and otpauth:// URI handling.

Authenticator apps (Google Authenticator, Authy, 2FAS, …) render the URI as
``ISSUER: LABEL`` in the account list. PI returns a URI whose issuer is
``privacyIDEA`` and whose label is the token serial (e.g. ``TOTP000F8E8``),
which is not useful for end users. We rewrite both to operator-friendly values
driven by env vars + a per-user PI attribute.
"""
import base64
import hashlib
import hmac
import os
import re
import struct
import time
from urllib.parse import urlparse, parse_qs, urlencode, quote


def sanitize_for_serial(name):
    """Return ``name`` stripped down to uppercase ASCII letters+digits.

    Used to derive a readable, deterministic token serial from a username. The
    portal enforces one TOTP per user (lockout), so a per-user-deterministic
    serial is unique across enrolments for *that* user. Callers must ensure
    their usernames don't collide once special characters are stripped — e.g.
    ``a.b`` and ``ab`` both yield ``AB``."""
    return re.sub(r'[^A-Za-z0-9]', '', str(name or '')).upper()


def customize_otpauth(original_uri, issuer, label):
    """Replace ``issuer=`` and the path label in an ``otpauth://totp/…`` URI.

    - ``issuer`` becomes the ``issuer`` query param AND the prefix before the
      colon in the path segment.
    - ``label`` becomes the part after the colon.

    Returns the rewritten URI, or the original if parsing fails.
    """
    if not original_uri or not (issuer or label):
        return original_uri
    try:
        parsed = urlparse(original_uri)
        q = parse_qs(parsed.query, keep_blank_values=True)
        flat = {k: v[0] if v else '' for k, v in q.items()}
        flat['issuer'] = issuer
        new_label_path = f'{quote(issuer, safe="")}:{quote(label, safe="")}'
        new_query = urlencode(flat, doseq=False, quote_via=quote)
        return f'{parsed.scheme}://{parsed.netloc}/{new_label_path}?{new_query}'
    except Exception:
        return original_uri


def extract_secret(otpauth_uri):
    """Pull the base32 ``secret=`` value out of an otpauth URI. Empty on any
    parse error."""
    if not otpauth_uri:
        return ''
    try:
        q = parse_qs(urlparse(otpauth_uri).query)
        return q.get('secret', [''])[0]
    except Exception:
        return ''


def pretty_secret(secret, group=4):
    """Return the secret grouped for easier manual entry: ``ABCD EFGH IJKL``.

    Authenticator apps accept the grouped form (spaces are ignored)."""
    if not secret:
        return ''
    return ' '.join(secret[i:i + group] for i in range(0, len(secret), group))


def generate_totp_secret(length=20):
    """Generate a random TOTP secret, returned as a base32 string."""
    return base64.b32encode(os.urandom(length)).decode('ascii')


def secret_to_hex(base32_secret):
    """Convert a base32 secret to hex string for PI's ``otpkey`` parameter."""
    return base64.b32decode(base32_secret).hex()


def build_otpauth_uri(secret, issuer, label, algorithm='SHA1', digits=6, period=30):
    """Build an ``otpauth://totp/…`` URI from scratch."""
    return (
        f'otpauth://totp/{quote(issuer, safe="")}:{quote(label, safe="")}'
        f'?secret={secret}&issuer={quote(issuer, safe="")}'
        f'&algorithm={algorithm}&digits={digits}&period={period}'
    )


def verify_totp(secret, otp, algorithm='sha1', digits=6, period=30, window=1):
    """Verify a TOTP code against a base32 secret locally. Returns True on match."""
    try:
        key = base64.b32decode(secret)
    except Exception:
        return False
    hash_func = getattr(hashlib, algorithm, hashlib.sha1)
    now = int(time.time())
    for offset in range(-window, window + 1):
        counter = (now // period) + offset
        msg = struct.pack('>Q', counter)
        h = hmac.new(key, msg, hash_func).digest()
        o = h[-1] & 0x0F
        code = struct.unpack('>I', h[o:o + 4])[0] & 0x7FFFFFFF
        code = code % (10 ** digits)
        if str(code).zfill(digits) == otp:
            return True
    return False
