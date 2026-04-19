from django.conf import settings


def session_info(request):
    return {
        'admin_authenticated': bool(request.session.get('admin_token')),
        'admin_username': request.session.get('admin_username', ''),
        'admin_2fa_ok': bool(request.session.get('admin_2fa_ok')),
        'admin_has_totp': bool(request.session.get('admin_has_totp')),
        'pi_realm': settings.PI_REALM,
        'mtls_enabled': settings.MTLS_ENABLED,
    }
