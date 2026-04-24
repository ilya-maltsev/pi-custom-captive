"""Session decorator for admin area.

All management views require ``admin_required`` — the admin must have a
valid JWT in the session (obtained via challenge-response login).  2FA is
completed during login itself, so no separate step-up is needed.
"""
import base64
import json
import logging
from datetime import datetime, timezone, timedelta
from functools import wraps

from django.contrib import messages
from django.shortcuts import redirect
from django.utils.translation import gettext as _

from .pi_client import PISessionInvalid

log = logging.getLogger('captive')


def _jwt_expired(token, skew_seconds=60):
    """Return True if the JWT's exp claim is in the past (or within skew).

    A malformed token is treated as expired so the user is bounced to login
    instead of hitting the API and getting a 500.
    """
    try:
        payload_b64 = token.split('.')[1]
        payload_b64 += '=' * (-len(payload_b64) % 4)
        exp = json.loads(base64.urlsafe_b64decode(payload_b64))['exp']
        exp_at = datetime.fromtimestamp(exp, tz=timezone.utc)
    except Exception:
        return True
    return datetime.now(timezone.utc) >= exp_at - timedelta(seconds=skew_seconds)


def admin_required(view_func):
    """Require a logged-in admin session with an unexpired JWT."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        token = request.session.get('admin_token')
        if not token:
            return redirect('admin_login')
        if _jwt_expired(token):
            username = request.session.get('admin_username', '?')
            log.info('admin JWT expired user=%s — flushing session', username)
            request.session.flush()
            messages.info(request, _('Your session has expired. Please sign in again.'))
            return redirect('admin_login')
        try:
            return view_func(request, *args, **kwargs)
        except PISessionInvalid:
            username = request.session.get('admin_username', '?')
            log.info('PI rejected admin JWT user=%s — flushing session', username)
            request.session.flush()
            messages.info(request, _('Your session is no longer valid. Please sign in again.'))
            return redirect('admin_login')
    return wrapper
