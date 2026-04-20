"""Helpers for customising the otpauth:// URI that the authenticator app reads.

Authenticator apps (Google Authenticator, Authy, 2FAS, …) render the URI as
``ISSUER: LABEL`` in the account list. PI returns a URI whose issuer is
``privacyIDEA`` and whose label is the token serial (e.g. ``TOTP000F8E8``),
which is not useful for end users. We rewrite both to operator-friendly values
driven by env vars + a per-user PI attribute.
"""
import re
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
