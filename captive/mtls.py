"""Optional mTLS header-auth support.

When ``MTLS_ENABLED`` is set, the captive portal does not prompt the user for
an AD/LDAP password on the user flow. Instead it trusts identity passed in
request headers by an upstream nginx that has already verified the client's
TLS certificate. Typical nginx snippet::

    # http { } scope
    map $ssl_client_s_dn $captive_mtls_user {
        default "";
        "~(?:^|,)1\\.2\\.643\\.3\\.131\\.1\\.1=(?<v>[^,]+)"  $v;
    }

    # server { listen 445 ssl } for the captive portal
    ssl_verify_client on;
    ssl_client_certificate /etc/nginx/ssl/user-ca.pem;
    ssl_ocsp on;
    ssl_ocsp_cache shared:captive_ocsp:10m;

    location / {
        proxy_set_header X-SSL-User   "";                    # clamp inbound
        proxy_set_header X-SSL-User   $captive_mtls_user;    # then set from nginx
        proxy_set_header X-SSL-Verify $ssl_client_verify;
        proxy_pass http://captive_server;
    }

Security model: the portal MUST only be reachable via a trusted nginx that
strips any inbound ``X-SSL-*`` headers from user requests. Do NOT expose
gunicorn (:8000) directly when ``MTLS_ENABLED=true``.
"""
from django.conf import settings


def mtls_extract(request):
    """Return (username, error). ``username`` is ``None`` if mTLS is disabled
    or verification failed; ``error`` is a short message explaining the
    rejection (``None`` when no error)."""
    if not settings.MTLS_ENABLED:
        return None, None

    verify = request.META.get(settings.MTLS_VERIFY_HEADER, '')
    user = (request.META.get(settings.MTLS_USER_HEADER, '') or '').strip()

    if verify != settings.MTLS_REQUIRED_VERIFY_VALUE:
        return None, f'client certificate verification failed ({verify or "missing"})'
    if not user:
        return None, 'client certificate does not carry a recognized user identifier'
    return user, None
