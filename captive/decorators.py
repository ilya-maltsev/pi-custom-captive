"""Session decorators for admin area.

Two tiers:

- ``admin_required``     — any logged-in admin (password step passed).
- ``admin_2fa_required`` — admin who has also passed the TOTP step-up.
                           Required for mutations (enable / disable / delete).
"""
from functools import wraps

from django.contrib import messages
from django.shortcuts import redirect
from django.utils.translation import gettext as _


def admin_required(view_func):
    """Require a logged-in admin session."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.session.get('admin_token'):
            return redirect('admin_login')
        return view_func(request, *args, **kwargs)
    return wrapper


def admin_2fa_required(view_func):
    """Require a logged-in admin whose session is TOTP-elevated."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.session.get('admin_token'):
            return redirect('admin_login')
        if not request.session.get('admin_2fa_ok'):
            messages.error(request, _('Unlock management with your TOTP first.'))
            return redirect('admin_otp')
        return view_func(request, *args, **kwargs)
    return wrapper
