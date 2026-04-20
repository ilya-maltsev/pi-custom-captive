import logging.handlers
import os
import socket
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'django-insecure-dev-key-change-in-production')
DEBUG = os.environ.get('DJANGO_DEBUG', 'True').lower() in ('true', '1', 'yes')
ALLOWED_HOSTS = os.environ.get('DJANGO_ALLOWED_HOSTS', '*').split(',')
CSRF_TRUSTED_ORIGINS = os.environ.get(
    'CSRF_TRUSTED_ORIGINS',
    'http://127.0.0.1:8000,http://localhost:8000,http://127.0.0.1:6000,http://localhost:6000'
).split(',')

INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'captive',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.messages.context_processors.messages',
                'captive.context_processors.session_info',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'

# Session stored in signed cookie — no DB required.
SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

from django.utils.translation import gettext_lazy as _

LANGUAGE_CODE = 'ru'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True

LANGUAGES = [
    ('ru', _('Russian')),
    ('en', _('English')),
]

LOCALE_PATHS = [
    BASE_DIR / 'locale',
]

STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# --- privacyIDEA connection ---------------------------------------------------
PI_API_URL = os.environ.get('PI_API_URL', 'https://localhost:8443')
PI_VERIFY_SSL = os.environ.get('PI_VERIFY_SSL', 'false').lower() in ('true', '1', 'yes')
PI_REALM = os.environ.get('PI_REALM', 'defrealm')

# --- otpauth:// customisation -------------------------------------------------
# These control what the user's authenticator app (Google Authenticator,
# Authy, 2FAS, …) shows as the account label. The app renders "ISSUER: LABEL".
# ISSUER replaces the PI default "privacyIDEA" (e.g. "VPN-GATE1").
# LABEL_ATTR names a PI user attribute whose value becomes the per-account
# label — typically the username, but can be any attribute PI returns from
# /user/ for the logged-in user (e.g. "email", "givenname", "mobile").
OTPAUTH_ISSUER = os.environ.get('OTPAUTH_ISSUER', 'privacyIDEA')
OTPAUTH_LABEL_ATTR = os.environ.get('OTPAUTH_LABEL_ATTR', 'username')

# Optional prefix for the PI token serial. When set, the portal assembles
# {PREFIX}-{SANITIZED(user.<TOKEN_SERIAL_SUFFIX>)}-{SHORT_HASH}, where the
# middle segment is the sanitized value of a PI user attribute named by
# TOKEN_SERIAL_SUFFIX (uppercase [A-Z0-9] only), and SHORT_HASH is 6 random
# hex chars. No trailing hyphen on the prefix — separators are inserted by
# the code.
# Empty TOKEN_SERIAL_PREFIX  = PI auto-generates (default TOTPXXXXXXXX).
# Example: TOKEN_SERIAL_PREFIX=VPN-GATE1 + TOKEN_SERIAL_SUFFIX=username
#          yields VPN-GATE1-LATRSTR-3A7F2B.
TOKEN_SERIAL_PREFIX = os.environ.get('TOKEN_SERIAL_PREFIX', '')

# Name of the PI user attribute whose value forms the middle segment of the
# serial. Pick any attribute PI returns from /user/ for the logged-in user:
# ``username`` (default, no extra PI call needed), ``email``, ``givenname``,
# ``mobile``, or any custom_* attribute. Set to empty string to omit the
# middle segment entirely (serial becomes {PREFIX}-{SHORT_HASH}). Only
# effective when TOKEN_SERIAL_PREFIX is also set.
TOKEN_SERIAL_SUFFIX = os.environ.get('TOKEN_SERIAL_SUFFIX', 'username')

# --- Optional mTLS header-auth ------------------------------------------------
# When enabled, the USER flow skips the password step and trusts identity
# carried in a header set by an upstream nginx that has already verified the
# client's TLS certificate. Header names below are in Django META form
# (HTTP_ prefix, dashes -> underscores, uppercased).
MTLS_ENABLED = os.environ.get('MTLS_ENABLED', 'false').lower() in ('true', '1', 'yes')
MTLS_USER_HEADER = os.environ.get('MTLS_USER_HEADER', 'HTTP_X_SSL_USER')
MTLS_VERIFY_HEADER = os.environ.get('MTLS_VERIFY_HEADER', 'HTTP_X_SSL_VERIFY')
MTLS_REQUIRED_VERIFY_VALUE = os.environ.get('MTLS_REQUIRED_VERIFY_VALUE', 'SUCCESS')

# --- Logging -----------------------------------------------------------------
SYSLOG_ENABLED = os.environ.get('SYSLOG_ENABLED', 'false').lower() in ('true', '1', 'yes')
SYSLOG_HOST = os.environ.get('SYSLOG_HOST', '')
SYSLOG_PORT = int(os.environ.get('SYSLOG_PORT', '514'))
SYSLOG_PROTO = os.environ.get('SYSLOG_PROTO', 'udp').lower()
SYSLOG_FACILITY = os.environ.get('SYSLOG_FACILITY', 'local2')
SYSLOG_TAG = os.environ.get('SYSLOG_TAG', 'pi-custom-captive')
SYSLOG_LEVEL = os.environ.get('SYSLOG_LEVEL', 'INFO').upper()

_captive_handlers = ['console']
_logging_handlers = {
    'console': {
        'class': 'logging.StreamHandler',
    },
}

if SYSLOG_ENABLED and SYSLOG_HOST:
    _logging_handlers['syslog'] = {
        'level': SYSLOG_LEVEL,
        'class': 'logging.handlers.SysLogHandler',
        'address': (SYSLOG_HOST, SYSLOG_PORT),
        'socktype': (socket.SOCK_STREAM if SYSLOG_PROTO == 'tcp'
                     else socket.SOCK_DGRAM),
        'facility': logging.handlers.SysLogHandler.facility_names.get(
            SYSLOG_FACILITY, logging.handlers.SysLogHandler.LOG_LOCAL2),
        'formatter': 'syslog',
    }
    _captive_handlers.append('syslog')

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'syslog': {
            'format': SYSLOG_TAG + ': [%(levelname)s] %(name)s: %(message)s',
        },
    },
    'handlers': _logging_handlers,
    'loggers': {
        'captive': {
            'handlers': _captive_handlers,
            'level': os.environ.get('DJANGO_LOG_LEVEL', 'INFO'),
        },
    },
}
