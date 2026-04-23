"""Project-local middleware."""
from django.conf import settings


class ForceDefaultLanguageMiddleware:
    """Make ``LANGUAGE_CODE`` win over ``Accept-Language`` for first-time visitors.

    Django's ``LocaleMiddleware`` resolves the language as:
      1. ``django_language`` cookie (set by ``set_language`` when the user
         clicks the topbar switcher),
      2. ``Accept-Language`` HTTP header (sent by the browser),
      3. ``settings.LANGUAGE_CODE`` (fallback).

    Step 2 means a user with an English browser lands on the English UI even
    when ``DJANGO_LANGUAGE_CODE=ru``. Strip ``Accept-Language`` when the user
    has no explicit choice yet so step 3 wins. Once the user toggles the
    switcher, the cookie is set and this middleware is a no-op.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if settings.LANGUAGE_COOKIE_NAME not in request.COOKIES:
            request.META.pop('HTTP_ACCEPT_LANGUAGE', None)
        return self.get_response(request)
