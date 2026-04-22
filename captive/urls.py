from django.urls import path
from . import views

urlpatterns = [
    # User self-enrollment
    path('', views.user_login, name='user_login'),
    path('locked/', views.user_locked, name='user_locked'),
    path('enroll/', views.user_enroll, name='user_enroll'),
    path('done/', views.user_done, name='user_done'),

    # Admin area
    path('admin/login/', views.admin_login, name='admin_login'),
    path('admin/otp/', views.admin_otp, name='admin_otp'),
    path('admin/enroll/', views.admin_enroll, name='admin_enroll'),
    path('admin/logout/', views.admin_logout, name='admin_logout'),
    path('admin/', views.admin_home, name='admin_home'),
    path('admin/user/<str:username>/', views.admin_user_tokens, name='admin_user_tokens'),
    path('admin/user/<str:username>/token/<str:serial>/delete/',
         views.admin_token_delete, name='admin_token_delete'),
    path('admin/user/<str:username>/token/<str:serial>/toggle/',
         views.admin_token_toggle, name='admin_token_toggle'),
]
