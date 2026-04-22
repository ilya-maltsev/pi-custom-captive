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
import json
import logging
import secrets

import qrcode
from django.conf import settings
from django.contrib import messages
from django.http import HttpResponseBadRequest
from django.shortcuts import render, redirect
from django.urls import reverse
from django.utils.translation import gettext as _
from django.views.decorators.http import require_POST

from .decorators import admin_required, admin_2fa_required
from .mtls import mtls_extract
from .otp_utils import (customize_otpauth, extract_secret, pretty_secret,
                        sanitize_for_serial, generate_totp_secret,
                        secret_to_hex, build_otpauth_uri, verify_totp)
from .pi_client import PIClient, PIClientError

log = logging.getLogger('captive')


def _client_ip(request):
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    return xff.split(',')[0].strip() if xff else request.META.get('REMOTE_ADDR', '?')


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
    """Step 1: user authenticates with their own credentials.

    The portal no longer uses a service account. After ``/auth`` succeeds, the
    resulting user JWT is stored in the session and every subsequent PI call
    (lockout check, token init) runs on that JWT — PI auto-scopes to the
    caller.
    """
    realm = settings.PI_REALM
    ip = _client_ip(request)

    if settings.MTLS_ENABLED:
        # mTLS identification yields a username but not a PI JWT. Without a
        # user JWT there is no way to list or enrol tokens as the user — and
        # the previous "service-account proxy" pattern has been removed. Ask
        # the user to fall back to the password form until a PI-impersonation
        # path is added.
        return render(request, 'captive/user_mtls_error.html', {
            'reason': _('mTLS self-enrolment is not available in this build. '
                        'Please use the password form.'),
        }, status=501)

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        if not username or not password:
            messages.error(request, _('Username and password are required.'))
            return render(request, 'captive/user_login.html')

        log.info('user_login attempt user=%s@%s from=%s', username, realm, ip)

        pi = PIClient()
        try:
            user_jwt = pi.authenticate(username, password, realm=realm)
        except PIClientError as e:
            log.warning('user_login auth denied user=%s@%s from=%s: %s',
                        username, realm, ip, e)
            messages.error(request, _('Authentication failed.'))
            return render(request, 'captive/user_login.html')

        # Lockout check on the USER'S OWN JWT — PI auto-scopes to the caller.
        try:
            locked = pi.has_active_totp()
        except PIClientError as e:
            log.error('user_login token-list error user=%s@%s: %s',
                      username, realm, e)
            messages.error(request, _('Service unavailable. Please try again.'))
            return render(request, 'captive/user_login.html')

        if locked:
            log.info('user_login locked user=%s@%s from=%s (already has TOTP)',
                     username, realm, ip)
            request.session['locked_user'] = username
            return redirect('user_locked')

        # Resolve label (for authenticator-app account line) and serial-suffix
        # (for PI token serial middle segment) from PI user attributes. A
        # single /user/ lookup covers both when either asks for a non-username
        # attr; the default ('username') needs no extra call.
        label_attr  = settings.OTPAUTH_LABEL_ATTR or 'username'
        suffix_attr = settings.TOKEN_SERIAL_SUFFIX  # '' means "omit this segment"

        need_info = (
            (label_attr and label_attr != 'username')
            or (suffix_attr and suffix_attr != 'username')
        )
        info = None
        if need_info:
            try:
                info = pi.get_user_info(username=username, realm=realm) or {}
            except PIClientError as e:
                log.info('user_login user_info lookup failed user=%s@%s: %s',
                         username, realm, e)

        def _resolve_attr(attr_name, fallback):
            if not attr_name:
                return ''
            if attr_name == 'username':
                return username
            val = (info or {}).get(attr_name)
            if not val:
                log.info('user_login attr=%s not found on user=%s@%s; using fallback',
                         attr_name, username, realm)
                return fallback
            return str(val)

        label = _resolve_attr(label_attr, fallback=username)
        serial_suffix_raw = _resolve_attr(suffix_attr, fallback=username)

        request.session['enroll_user'] = username
        request.session['enroll_token'] = user_jwt
        request.session['enroll_label'] = label
        request.session['enroll_serial_suffix'] = serial_suffix_raw
        log.info('user_login ok user=%s@%s from=%s label=%s serial_suffix=%s -> enroll',
                 username, realm, ip, label, serial_suffix_raw)
        return redirect('user_enroll')

    return render(request, 'captive/user_login.html')


def user_locked(request):
    username = request.session.pop('locked_user', '')
    return render(request, 'captive/user_locked.html', {'username': username})


def user_enroll(request):
    username = request.session.get('enroll_user')
    user_jwt = request.session.get('enroll_token')
    if not username or not user_jwt:
        return redirect('user_login')

    realm = settings.PI_REALM
    ip = _client_ip(request)

    pi = PIClient()
    pi.set_token(user_jwt, username=username)

    # GET: generate secret locally, show QR. No PI call yet.
    if request.method == 'GET':
        enroll_data = request.session.get('enroll_data')
        if not enroll_data:
            try:
                if pi.has_active_totp():
                    request.session.flush()
                    request.session['locked_user'] = username
                    return redirect('user_locked')
            except PIClientError as e:
                log.error('user_enroll token-list error user=%s@%s: %s',
                          username, realm, e)
                messages.error(request, _('Service unavailable. Please try again.'))
                return redirect('user_login')

            secret = generate_totp_secret()
            label = request.session.get('enroll_label') or username
            otpauth = build_otpauth_uri(secret, settings.OTPAUTH_ISSUER, label)

            serial_override = None
            if settings.TOKEN_SERIAL_PREFIX:
                short_hash = secrets.token_hex(3).upper()
                suffix_raw = request.session.get('enroll_serial_suffix') or ''
                sanitized = sanitize_for_serial(suffix_raw)
                parts = [settings.TOKEN_SERIAL_PREFIX]
                if sanitized:
                    parts.append(sanitized)
                parts.append(short_hash)
                serial_override = '-'.join(parts)

            enroll_data = {
                'secret': secret,
                'otpauth': otpauth,
                'serial': serial_override or '',
            }
            request.session['enroll_data'] = enroll_data
            log.info('user_enroll secret generated user=%s@%s label=%s issuer=%s from=%s',
                     username, realm, label, settings.OTPAUTH_ISSUER, ip)

        qr = _qr_data_uri(enroll_data.get('otpauth', ''))
        return render(request, 'captive/user_enroll.html', {
            'username': username,
            'serial': enroll_data.get('serial', ''),
            'otpauth': enroll_data.get('otpauth', ''),
            'qr_data_uri': qr,
            'secret': enroll_data.get('secret', ''),
            'secret_pretty': pretty_secret(enroll_data.get('secret', '')),
            'otpauth_issuer': settings.OTPAUTH_ISSUER,
            'otpauth_label': request.session.get('enroll_label') or username,
        })

    # POST: verify OTP locally, then create token in PI.
    otp = request.POST.get('otp', '').strip()
    if not otp.isdigit() or len(otp) != 6:
        messages.error(request, _('Enter the 6-digit code from your authenticator app.'))
        return redirect('user_enroll')

    enroll_data = request.session.get('enroll_data') or {}
    secret = enroll_data.get('secret', '')

    if not verify_totp(secret, otp):
        log.warning('user_enroll verify denied user=%s@%s from=%s', username, realm, ip)
        messages.error(request, _('Incorrect code. Try again.'))
        return redirect('user_enroll')

    # OTP verified — now create the token in PI.
    try:
        hex_key = secret_to_hex(secret)
        serial = enroll_data.get('serial') or None
        result = pi.init_totp(serial=serial, otpkey=hex_key)
        final_serial = result.get('serial', '?')
    except PIClientError as e:
        log.error('user_enroll token create error user=%s@%s: %s', username, realm, e)
        messages.error(request, _('Failed to create token. Contact administrator.'))
        return redirect('user_enroll')

    log.info('user_enroll ok user=%s@%s serial=%s from=%s', username, realm, final_serial, ip)
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
    """Admin login — password only. Mutations require a subsequent TOTP
    step-up via /admin/otp/. Any valid PI admin can see the read-only area."""
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

        # Extract admin realm from JWT for use in enrollment.
        admin_realm = ''
        try:
            payload_b64 = token.split('.')[1]
            payload_b64 += '=' * (-len(payload_b64) % 4)
            jwt_payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            admin_realm = jwt_payload.get('realm', '')
        except Exception:
            log.warning('admin_login JWT decode failed user=%s', username)

        # Does the admin have a TOTP token? If not, force enrollment.
        has_totp = False
        try:
            has_totp = pi.has_active_totp(username=username)
        except PIClientError as e:
            log.warning('admin_login token lookup failed user=%s: %s', username, e)

        request.session['admin_token'] = token
        request.session['admin_username'] = username
        request.session['admin_realm'] = admin_realm
        request.session['admin_2fa_ok'] = False
        request.session['admin_has_totp'] = has_totp
        log.info('admin_login password ok user=%s from=%s has_totp=%s',
                 username, ip, has_totp)

        if not has_totp:
            return redirect('admin_enroll')
        return redirect('admin_home')

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


@admin_required
def admin_enroll(request):
    """Force TOTP enrollment for admins who have no token."""
    username = request.session.get('admin_username')
    ip = _client_ip(request)

    pi = PIClient()
    pi.set_token(request.session['admin_token'], username=username)

    # Already has a token — skip straight to home.
    try:
        if pi.has_active_totp(username=username):
            request.session['admin_has_totp'] = True
            return redirect('admin_home')
    except PIClientError:
        pass

    # GET: generate secret locally, show QR. No PI call yet.
    if request.method == 'GET':
        enroll_data = request.session.get('admin_enroll_data')
        if not enroll_data:
            secret = generate_totp_secret()
            otpauth = build_otpauth_uri(secret, settings.OTPAUTH_ISSUER, username)
            enroll_data = {
                'secret': secret,
                'otpauth': otpauth,
            }
            request.session['admin_enroll_data'] = enroll_data
            log.info('admin_enroll secret generated user=%s from=%s', username, ip)

        qr = _qr_data_uri(enroll_data.get('otpauth', ''))
        return render(request, 'captive/admin_enroll.html', {
            'username': username,
            'otpauth': enroll_data.get('otpauth', ''),
            'qr_data_uri': qr,
            'secret': enroll_data.get('secret', ''),
            'secret_pretty': pretty_secret(enroll_data.get('secret', '')),
            'otpauth_issuer': settings.OTPAUTH_ISSUER,
        })

    # POST: verify OTP locally, then create token in PI.
    otp = request.POST.get('otp', '').strip()
    if not otp.isdigit() or len(otp) != 6:
        messages.error(request, _('Enter the 6-digit code from your authenticator app.'))
        return redirect('admin_enroll')

    enroll_data = request.session.get('admin_enroll_data') or {}
    secret = enroll_data.get('secret', '')

    if not verify_totp(secret, otp):
        log.warning('admin_enroll verify denied user=%s from=%s', username, ip)
        messages.error(request, _('Incorrect code. Try again.'))
        return redirect('admin_enroll')

    # OTP verified — now create the token in PI.
    admin_realm = request.session.get('admin_realm', '') or None
    try:
        hex_key = secret_to_hex(secret)
        result = pi.init_totp(realm=admin_realm, otpkey=hex_key)
        final_serial = result.get('serial', '?')
    except PIClientError as e:
        log.error('admin_enroll token create error user=%s: %s', username, e)
        messages.error(request, _('Failed to create token. Contact administrator.'))
        return redirect('admin_enroll')

    log.info('admin_enroll ok user=%s serial=%s from=%s', username, final_serial, ip)
    request.session.flush()
    messages.success(request, _('TOTP enrolled successfully. Please log in again with your password and OTP code.'))
    return redirect('admin_login')


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
    if not request.session.get('admin_has_totp'):
        return redirect('admin_enroll')
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


@admin_2fa_required
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


@admin_2fa_required
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
