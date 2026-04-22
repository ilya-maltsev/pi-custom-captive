"""Session decorator for admin area.

All management views require ``admin_required`` — the admin must have a
valid JWT in the session (obtained via challenge-response login).  2FA is
completed during login itself, so no separate step-up is needed.
"""
from functools import wraps

from django.shortcuts import redirect


def admin_required(view_func):
    """Require a logged-in admin session."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.session.get('admin_token'):
            return redirect('admin_login')
        return view_func(request, *args, **kwargs)
    return wrapper
