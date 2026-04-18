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
PI_SERVICE_USER = os.environ.get('PI_SERVICE_USER', '')
PI_SERVICE_PASSWORD = os.environ.get('PI_SERVICE_PASSWORD', '')

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
