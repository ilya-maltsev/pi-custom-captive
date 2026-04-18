"""Session decorators for admin area."""
from functools import wraps

from django.shortcuts import redirect


def admin_required(view_func):
    """Require a completed admin 2FA session. Redirect to admin login otherwise."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.session.get('admin_token') or not request.session.get('admin_2fa_ok'):
            return redirect('admin_login')
        return view_func(request, *args, **kwargs)
    return wrapper
