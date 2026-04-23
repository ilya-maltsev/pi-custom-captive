"""Session decorators for admin area.

``admin_required`` — logged-in admin (password + OTP completed at login).
All management actions (enable / disable / delete) require this decorator.
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
