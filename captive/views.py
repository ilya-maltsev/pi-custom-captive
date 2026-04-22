"""Captive portal views.

User flow:
    / (user_login)      POST username + AD/LDAP password -> /validate/check
                        If user has >=1 active TOTP token -> user_locked
                        Else -> user_enroll
    /enroll             GET shows QR + OTP input
                        POST verifies OTP -> user_done
    /done               confirmation page

Admin flow (challenge-response, no credentials in session):
    /admin/login        Step 1: POST username + password
                            -> /validate/check triggers challenge
                            -> re-render with OTP field (password in
                               encrypted hidden field, transaction_id)
                        passOnNoToken: no token -> /admin/enroll
                        Step 2: POST OTP + encrypted password + transaction_id
                            -> /auth with password+OTP -> JWT
                            -> /admin/ (fully authenticated)
    /admin/otp          Session step-up only: OTP -> /validate/check
                            -> /admin/ (mutations unlocked)
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

from .crypto import encrypt, decrypt
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

def _extract_realm(token):
    """Extract realm from a PI JWT payload.  Returns '' on failure."""
    try:
        payload_b64 = token.split('.')[1]
        payload_b64 += '=' * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64)).get('realm', '')
    except Exception:
        return ''


def admin_login(request):
    """Admin login — two-step challenge-response, no credentials in session.

    Step 1 (POST username + password):
        /validate/check with password triggers a challenge and returns a
        ``transaction_id``.  If passOnNoToken → auth succeeds immediately.
        Otherwise the page re-renders with an OTP field; the password
        round-trips through an encrypted hidden form field.

    Step 2 (POST OTP + encrypted password + transaction_id):
        /auth with password+OTP → JWT → admin session established.
    """
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        otp = request.POST.get('otp', '').strip()
        transaction_id = request.POST.get('transaction_id', '')
        encrypted_pw = request.POST.get('encrypted_password', '')

        ip = _client_ip(request)
        pi = PIClient()

        # ----- Step 2: OTP submitted (challenge answer) ---------------------
        if transaction_id and otp and encrypted_pw:
            try:
                password = decrypt(encrypted_pw)
            except (ValueError, TypeError):
                log.warning('admin_login step2 decrypt failed user=%s', username)
                messages.error(request, _('Session expired. Please start over.'))
                return render(request, 'captive/admin_login.html')

            if not otp.isdigit() or len(otp) != 6:
                messages.error(request, _('Enter the 6-digit code.'))
                return render(request, 'captive/admin_login.html', {
                    'step': 'otp',
                    'username': username,
                    'encrypted_password': encrypted_pw,
                    'transaction_id': transaction_id,
                })

            # Authenticate with password+OTP via /auth to obtain JWT.
            try:
                token = pi.authenticate(username, password + otp)
            except PIClientError as e:
                log.warning('admin_login step2 auth denied user=%s from=%s: %s',
                            username, ip, e)
                messages.error(request, _('Authentication failed.'))
                return render(request, 'captive/admin_login.html', {
                    'step': 'otp',
                    'username': username,
                    'encrypted_password': encrypted_pw,
                    'transaction_id': transaction_id,
                })

            admin_realm = _extract_realm(token)
            request.session['admin_token'] = token
            request.session['admin_username'] = username
            request.session['admin_realm'] = admin_realm
            request.session['admin_2fa_ok'] = True
            request.session['admin_has_totp'] = True
            log.info('admin_login 2fa ok user=%s from=%s', username, ip)

            _reset_admin_totp_failcount(pi, username, admin_realm)
            return redirect('admin_home')

        # ----- Step 1: username + password (trigger challenge) --------------
        password = request.POST.get('password', '')
        if not username or not password:
            messages.error(request, _('Username and password are required.'))
            return render(request, 'captive/admin_login.html')

        try:
            check = pi.validate_check(username, password)
        except PIClientError as e:
            log.warning('admin_login step1 denied user=%s from=%s: %s',
                        username, ip, e)
            messages.error(request, _('Authentication failed.'))
            return render(request, 'captive/admin_login.html')

        if check['value']:
            # Password-only auth succeeded → passOnNoToken, no TOTP yet.
            try:
                token = pi.authenticate(username, password)
            except PIClientError as e:
                log.warning('admin_login auth failed user=%s from=%s: %s',
                            username, ip, e)
                messages.error(request, _('Authentication failed.'))
                return render(request, 'captive/admin_login.html')

            admin_realm = _extract_realm(token)
            has_totp = False
            try:
                has_totp = pi.has_active_totp(username=username)
            except PIClientError as e:
                log.warning('admin_login token lookup failed user=%s: %s',
                            username, e)

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

        if check.get('transaction_id'):
            # Challenge triggered — password valid, OTP required.
            log.info('admin_login challenge triggered user=%s from=%s txn=%s',
                     username, ip, check['transaction_id'])
            return render(request, 'captive/admin_login.html', {
                'step': 'otp',
                'username': username,
                'encrypted_password': encrypt(password),
                'transaction_id': check['transaction_id'],
            })

        # No challenge, no success → wrong password.
        log.warning('admin_login denied user=%s from=%s', username, ip)
        messages.error(request, _('Authentication failed.'))
        return render(request, 'captive/admin_login.html')

    return render(request, 'captive/admin_login.html')


def _reset_admin_totp_failcount(pi, username, realm):
    """Best-effort reset of fail counters on all admin TOTP tokens."""
    try:
        tokens = pi.list_tokens(username=username, realm=realm or None,
                                type_='totp')
        for t in tokens:
            serial = t.get('serial')
            if serial:
                try:
                    pi.reset_failcount(serial)
                except PIClientError as e:
                    log.warning('reset_failcount failed serial=%s: %s',
                                serial, e)
    except PIClientError as e:
        log.warning('reset_failcount token list failed user=%s: %s',
                    username, e)


def admin_otp(request):
    """Session step-up — validate OTP for an already-authenticated admin.

    Unlocks mutations (enable / disable / delete tokens).  Login completion
    is now handled entirely by ``admin_login`` via challenge-response.
    """
    username = request.session.get('admin_username')
    if not username or not request.session.get('admin_token'):
        return redirect('admin_login')

    if request.method == 'POST':
        otp = request.POST.get('otp', '').strip()
        if not otp.isdigit() or len(otp) != 6:
            messages.error(request, _('Enter the 6-digit code.'))
            return render(request, 'captive/admin_otp.html', {
                'username': username,
            })

        ip = _client_ip(request)
        try:
            pi = PIClient()
            check = pi.validate_check(username, otp)
        except PIClientError as e:
            log.warning('admin_otp stepup error user=%s: %s', username, e)
            messages.error(request, _('Verification failed.'))
            return render(request, 'captive/admin_otp.html', {
                'username': username,
            })
        if not check['value']:
            log.warning('admin_otp stepup denied user=%s from=%s',
                        username, ip)
            messages.error(request, _('Incorrect code.'))
            return render(request, 'captive/admin_otp.html', {
                'username': username,
            })
        request.session['admin_2fa_ok'] = True
        log.info('admin_otp stepup ok user=%s from=%s', username, ip)

        ac = _admin_client(request)
        _reset_admin_totp_failcount(ac, username,
                                    request.session.get('admin_realm', ''))
        return redirect('admin_home')

    return render(request, 'captive/admin_otp.html', {
        'username': username,
    })


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

    admin_realm = request.session.get('admin_realm', '') or None

    # GET: generate secret locally, show QR. No PI call yet.
    if request.method == 'GET':
        enroll_data = request.session.get('admin_enroll_data')
        if not enroll_data:
            secret = generate_totp_secret()

            # Resolve label and serial suffix from PI user attributes
            # (same logic as user enrollment).
            label_attr = settings.OTPAUTH_LABEL_ATTR or 'username'
            suffix_attr = settings.TOKEN_SERIAL_SUFFIX

            need_info = (
                (label_attr and label_attr != 'username')
                or (suffix_attr and suffix_attr != 'username')
            )
            info = None
            if need_info:
                try:
                    info = pi.get_user_info(username=username,
                                            realm=admin_realm) or {}
                except PIClientError as e:
                    log.info('admin_enroll user_info lookup failed user=%s: %s',
                             username, e)

            def _resolve(attr_name, fallback):
                if not attr_name:
                    return ''
                if attr_name == 'username':
                    return username
                val = (info or {}).get(attr_name)
                if not val:
                    return fallback
                return str(val)

            label = _resolve(label_attr, fallback=username)
            otpauth = build_otpauth_uri(secret, settings.OTPAUTH_ISSUER, label)

            serial_override = None
            if settings.TOKEN_SERIAL_PREFIX:
                short_hash = secrets.token_hex(3).upper()
                suffix_raw = _resolve(suffix_attr, fallback=username)
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
                'label': label,
            }
            request.session['admin_enroll_data'] = enroll_data
            log.info('admin_enroll secret generated user=%s from=%s label=%s',
                     username, ip, label)

        qr = _qr_data_uri(enroll_data.get('otpauth', ''))
        return render(request, 'captive/admin_enroll.html', {
            'username': username,
            'serial': enroll_data.get('serial', ''),
            'otpauth': enroll_data.get('otpauth', ''),
            'qr_data_uri': qr,
            'secret': enroll_data.get('secret', ''),
            'secret_pretty': pretty_secret(enroll_data.get('secret', '')),
            'otpauth_issuer': settings.OTPAUTH_ISSUER,
            'otpauth_label': enroll_data.get('label', username),
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

    # OTP verified — now create the token in PI and assign it.
    try:
        hex_key = secret_to_hex(secret)
        serial = enroll_data.get('serial') or None
        result = pi.init_totp(serial=serial, realm=admin_realm, otpkey=hex_key)
        final_serial = result.get('serial', '?')
    except PIClientError as e:
        log.error('admin_enroll token create error user=%s: %s', username, e)
        messages.error(request, _('Failed to create token. Contact administrator.'))
        return redirect('admin_enroll')

    try:
        pi.assign_token(final_serial, username, realm=admin_realm)
    except PIClientError as e:
        log.error('admin_enroll token assign error user=%s serial=%s: %s',
                  username, final_serial, e)

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
