"""Captive portal views.

User flow:
    / (user_login)      POST username + AD/LDAP password -> /validate/check
                        If user has >=1 active TOTP token -> user_locked
                        Else -> user_enroll
    /enroll             GET shows QR + OTP input
                        POST verifies OTP -> user_done
    /done               confirmation page

Admin flow:
    /admin/login        POST username + password -> /auth
                        Checks user has >=1 active TOTP token (else reject)
                        -> /admin/otp
    /admin/otp          POST 6-digit OTP -> /validate/check
                        -> /admin/
    /admin/             search user -> /admin/user/<username>/
    /admin/user/<u>/    list TOTP tokens with enable/disable/delete actions
"""
import base64
import io
import logging

import qrcode
from django.conf import settings
from django.contrib import messages
from django.http import HttpResponseBadRequest
from django.shortcuts import render, redirect
from django.urls import reverse
from django.utils.translation import gettext as _
from django.views.decorators.http import require_POST

from .decorators import admin_required
from .pi_client import PIClient, PIClientError

log = logging.getLogger('captive')


def _client_ip(request):
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    return xff.split(',')[0].strip() if xff else request.META.get('REMOTE_ADDR', '?')


def _service_client():
    """PIClient authenticated with the service account from env."""
    if not settings.PI_SERVICE_USER or not settings.PI_SERVICE_PASSWORD:
        raise PIClientError('PI_SERVICE_USER / PI_SERVICE_PASSWORD not configured')
    c = PIClient()
    c.authenticate(settings.PI_SERVICE_USER, settings.PI_SERVICE_PASSWORD)
    return c


def _qr_data_uri(otpauth):
    """Render an otpauth:// URI as a data: URI PNG (base64)."""
    if not otpauth:
        return ''
    img = qrcode.make(otpauth)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return 'data:image/png;base64,' + base64.b64encode(buf.getvalue()).decode('ascii')


# =============================================================================
# USER FLOW
# =============================================================================

def user_login(request):
    """Step 1: user authenticates with AD/LDAP password via /validate/check."""
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        if not username or not password:
            messages.error(request, _('Username and password are required.'))
            return render(request, 'captive/user_login.html')

        realm = settings.PI_REALM
        ip = _client_ip(request)
        log.info('user_login attempt user=%s@%s from=%s', username, realm, ip)

        pi = PIClient()
        try:
            ok = pi.validate_check(username, password, realm=realm)
        except PIClientError as e:
            log.warning('user_login validate_check error user=%s@%s from=%s err=%s',
                        username, realm, ip, e)
            messages.error(request, _('Authentication failed.'))
            return render(request, 'captive/user_login.html')

        if not ok:
            log.warning('user_login denied user=%s@%s from=%s', username, realm, ip)
            messages.error(request, _('Authentication failed.'))
            return render(request, 'captive/user_login.html')

        # Password OK. Check lockout via service account.
        try:
            svc = _service_client()
            locked = svc.has_active_totp(username, realm=realm)
        except PIClientError as e:
            log.error('user_login service lookup error user=%s@%s: %s', username, realm, e)
            messages.error(request, _('Service unavailable. Contact administrator.'))
            return render(request, 'captive/user_login.html')

        if locked:
            log.info('user_login locked user=%s@%s from=%s (already has TOTP)',
                     username, realm, ip)
            request.session['locked_user'] = username
            return redirect('user_locked')

        request.session['enroll_user'] = username
        log.info('user_login ok user=%s@%s from=%s -> enroll', username, realm, ip)
        return redirect('user_enroll')

    return render(request, 'captive/user_login.html')


def user_locked(request):
    username = request.session.pop('locked_user', '')
    return render(request, 'captive/user_locked.html', {'username': username})


def user_enroll(request):
    username = request.session.get('enroll_user')
    if not username:
        return redirect('user_login')

    realm = settings.PI_REALM
    ip = _client_ip(request)

    # GET: initialize token and show QR.
    if request.method == 'GET':
        # Idempotency: reuse existing init in session (refresh-safe).
        enroll_data = request.session.get('enroll_data')
        if not enroll_data:
            try:
                svc = _service_client()
                # Double-check lockout (user could have been enrolled in another tab).
                if svc.has_active_totp(username, realm=realm):
                    request.session.flush()
                    request.session['locked_user'] = username
                    return redirect('user_locked')
                enroll_data = svc.init_totp(username, realm)
            except PIClientError as e:
                log.error('user_enroll init error user=%s@%s: %s', username, realm, e)
                messages.error(request, _('Failed to create token. Contact administrator.'))
                return redirect('user_login')
            request.session['enroll_data'] = enroll_data
            log.info('user_enroll init user=%s@%s serial=%s from=%s',
                     username, realm, enroll_data.get('serial', '?'), ip)

        qr = _qr_data_uri(enroll_data.get('otpauth', ''))
        return render(request, 'captive/user_enroll.html', {
            'username': username,
            'serial': enroll_data.get('serial', ''),
            'otpauth': enroll_data.get('otpauth', ''),
            'qr_data_uri': qr,
        })

    # POST: verify OTP.
    otp = request.POST.get('otp', '').strip()
    if not otp.isdigit() or len(otp) != 6:
        messages.error(request, _('Enter the 6-digit code from your authenticator app.'))
        return redirect('user_enroll')

    try:
        pi = PIClient()
        ok = pi.validate_check(username, otp, realm=realm)
    except PIClientError as e:
        log.warning('user_enroll verify error user=%s@%s: %s', username, realm, e)
        messages.error(request, _('Verification failed.'))
        return redirect('user_enroll')

    if not ok:
        log.warning('user_enroll verify denied user=%s@%s from=%s', username, realm, ip)
        messages.error(request, _('Incorrect code. Try again.'))
        return redirect('user_enroll')

    serial = (request.session.get('enroll_data') or {}).get('serial', '?')
    log.info('user_enroll verified user=%s@%s serial=%s from=%s', username, realm, serial, ip)
    request.session.flush()
    request.session['done_user'] = username
    return redirect('user_done')


def user_done(request):
    username = request.session.pop('done_user', '')
    if not username:
        return redirect('user_login')
    return render(request, 'captive/user_done.html', {'username': username})


# =============================================================================
# ADMIN FLOW
# =============================================================================

def admin_login(request):
    """Step 1 of admin login: password via PI /auth."""
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        if not username or not password:
            messages.error(request, _('Username and password are required.'))
            return render(request, 'captive/admin_login.html')

        ip = _client_ip(request)
        pi = PIClient()
        try:
            token = pi.authenticate(username, password)
        except PIClientError as e:
            log.warning('admin_login /auth denied user=%s from=%s: %s', username, ip, e)
            messages.error(request, _('Authentication failed.'))
            return render(request, 'captive/admin_login.html')

        # Enforce 2FA: the admin must have at least one active TOTP token.
        try:
            svc = _service_client()
            if not svc.has_active_totp(username):
                log.warning('admin_login no TOTP user=%s from=%s', username, ip)
                messages.error(request, _('Admin 2FA (TOTP) is required. Contact another administrator.'))
                return render(request, 'captive/admin_login.html')
        except PIClientError as e:
            log.error('admin_login service lookup error user=%s: %s', username, e)
            messages.error(request, _('Service unavailable.'))
            return render(request, 'captive/admin_login.html')

        request.session['admin_token'] = token
        request.session['admin_username'] = username
        request.session['admin_2fa_ok'] = False
        log.info('admin_login password ok user=%s from=%s -> otp', username, ip)
        return redirect('admin_otp')

    return render(request, 'captive/admin_login.html')


def admin_otp(request):
    """Step 2 of admin login: verify TOTP."""
    username = request.session.get('admin_username')
    if not username or not request.session.get('admin_token'):
        return redirect('admin_login')

    if request.method == 'POST':
        otp = request.POST.get('otp', '').strip()
        if not otp.isdigit() or len(otp) != 6:
            messages.error(request, _('Enter the 6-digit code.'))
            return render(request, 'captive/admin_otp.html', {'username': username})
        ip = _client_ip(request)
        try:
            pi = PIClient()
            ok = pi.validate_check(username, otp)
        except PIClientError as e:
            log.warning('admin_otp error user=%s: %s', username, e)
            messages.error(request, _('Verification failed.'))
            return render(request, 'captive/admin_otp.html', {'username': username})
        if not ok:
            log.warning('admin_otp denied user=%s from=%s', username, ip)
            messages.error(request, _('Incorrect code.'))
            return render(request, 'captive/admin_otp.html', {'username': username})
        request.session['admin_2fa_ok'] = True
        log.info('admin_otp ok user=%s from=%s', username, ip)
        return redirect('admin_home')

    return render(request, 'captive/admin_otp.html', {'username': username})


def admin_logout(request):
    username = request.session.get('admin_username', '?')
    request.session.flush()
    log.info('admin_logout user=%s', username)
    return redirect('admin_login')


def _admin_client(request):
    token = request.session.get('admin_token')
    if not token:
        raise PIClientError('Admin session missing')
    c = PIClient()
    c.set_token(token, username=request.session.get('admin_username'))
    return c


@admin_required
def admin_home(request):
    target = request.GET.get('user', '').strip()
    if target:
        return redirect('admin_user_tokens', username=target)
    return render(request, 'captive/admin_home.html', {
        'page': 'home',
    })


@admin_required
def admin_user_tokens(request, username):
    realm = settings.PI_REALM
    try:
        ac = _admin_client(request)
        tokens = ac.list_tokens(username, realm=realm, type_='totp')
    except PIClientError as e:
        messages.error(request, str(e))
        return redirect('admin_home')
    return render(request, 'captive/admin_user_tokens.html', {
        'page': 'home',
        'target_user': username,
        'realm': realm,
        'tokens': tokens,
    })


@admin_required
@require_POST
def admin_token_delete(request, username, serial):
    ip = _client_ip(request)
    try:
        ac = _admin_client(request)
        ac.delete_token(serial)
        log.info('admin_token_delete admin=%s target=%s serial=%s from=%s',
                 request.session.get('admin_username'), username, serial, ip)
        messages.success(request, _('Token %(s)s deleted.') % {'s': serial})
    except PIClientError as e:
        messages.error(request, str(e))
    return redirect('admin_user_tokens', username=username)


@admin_required
@require_POST
def admin_token_toggle(request, username, serial):
    enable = request.POST.get('action') == 'enable'
    ip = _client_ip(request)
    try:
        ac = _admin_client(request)
        ac.set_token_active(serial, enable)
        log.info('admin_token_toggle admin=%s target=%s serial=%s enable=%s from=%s',
                 request.session.get('admin_username'), username, serial, enable, ip)
        messages.success(request,
                         _('Token %(s)s enabled.') % {'s': serial} if enable
                         else _('Token %(s)s disabled.') % {'s': serial})
    except PIClientError as e:
        messages.error(request, str(e))
    return redirect('admin_user_tokens', username=username)
