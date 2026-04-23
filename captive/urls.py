from django.conf import settings
from django.urls import path

from . import views

_ap = settings.ADMIN_URL_PREFIX
_p = (_ap + '/') if _ap else ''

urlpatterns = [
    # User self-enrollment
    path('', views.user_login, name='user_login'),
    path('locked/', views.user_locked, name='user_locked'),
    path('enroll/', views.user_enroll, name='user_enroll'),
    path('done/', views.user_done, name='user_done'),

    # Admin area — prefix configurable via CAPTIVE_ADMIN_PREFIX.
    path(f'{_p}login/', views.admin_login, name='admin_login'),
    path(f'{_p}enroll/', views.admin_enroll, name='admin_enroll'),
    path(f'{_p}logout/', views.admin_logout, name='admin_logout'),
    path(f'{_p}', views.admin_home, name='admin_home'),
    path(f'{_p}token/<str:serial>/delete/',
         views.admin_token_delete, name='admin_token_delete'),
    path(f'{_p}token/<str:serial>/toggle/',
         views.admin_token_toggle, name='admin_token_toggle'),
]
