"""Narrow privacyIDEA REST API client.

Only the endpoints required by the captive portal are exposed:

  /auth                              - admin/service login (JWT)
  /token (GET)                       - list tokens for a user
  /token/init (POST)                 - enroll TOTP for a user
  /token/<serial> (DELETE)           - delete + unassign a token
  /token/enable / /token/disable     - toggle token active state
  /validate/check (POST)             - verify OTP (no auth required)
"""
import base64
import json
import logging
from datetime import datetime, timezone, timedelta
from urllib.parse import quote

import requests
from django.conf import settings

log = logging.getLogger('captive')


_SECRET_SUBSTRINGS = (
    'password', 'pass',
    'authorization', 'cookie',
    'token', 'secret', 'otp', 'otpkey',
    'pi-authorization',
)


def _is_secret_key(name):
    n = str(name).lower()
    return any(s in n for s in _SECRET_SUBSTRINGS)


def _redact_mapping(items):
    if items is None:
        return {}
    try:
        iterator = items.items() if hasattr(items, 'items') else items
    except Exception:
        return {}
    return {k: ('***' if _is_secret_key(k) else v) for k, v in iterator}


def _redact_json_body(text):
    if not text:
        return text
    try:
        obj = json.loads(text)
    except Exception:
        return text

    def walk(node):
        if isinstance(node, dict):
            return {k: ('***' if _is_secret_key(k) else walk(v))
                    for k, v in node.items()}
        if isinstance(node, list):
            return [walk(x) for x in node]
        return node

    return json.dumps(walk(obj), separators=(',', ':'))


class PIClientError(Exception):
    pass


class PIClient:
    """Stateless helper that authenticates with PI and calls its REST API."""

    def __init__(self, base_url=None, verify_ssl=None):
        self.base_url = (base_url or settings.PI_API_URL).rstrip('/')
        self.verify_ssl = verify_ssl if verify_ssl is not None else settings.PI_VERIFY_SSL
        self._token = None
        self._token_exp = None
        self._username = None
        self._password = None

    # --- HTTP core -----------------------------------------------------------

    def _request(self, method, url, **kwargs):
        headers = kwargs.get('headers', {}) or {}
        params = kwargs.get('params')
        data = kwargs.get('data')
        log.debug('PI HTTP >>> %s %s headers=%s params=%s body=%s',
                  method, url,
                  _redact_mapping(headers),
                  _redact_mapping(params) if params else None,
                  _redact_mapping(data) if data else None)
        resp = requests.request(method, url, **kwargs)
        log.debug('PI HTTP <<< %s %s body=%s',
                  resp.status_code, resp.reason,
                  _redact_json_body(resp.text))
        return resp

    def _headers(self):
        if not self._token:
            raise PIClientError('Not authenticated.')
        return {'PI-Authorization': self._token}

    # --- authentication ------------------------------------------------------

    def authenticate(self, username, password, realm=None):
        """Obtain a JWT from PI using password credentials."""
        data = {'username': username, 'password': password}
        if realm:
            data['realm'] = realm
        resp = self._request(
            'POST',
            f'{self.base_url}/auth',
            data=data,
            verify=self.verify_ssl, timeout=15,
        )
        try:
            data = resp.json()
        except ValueError:
            raise PIClientError(f'Invalid response from PI (HTTP {resp.status_code})')
        result = data.get('result', {})
        if not result.get('status') or not result.get('value'):
            msg = result.get('error', {}).get('message', 'Authentication failed')
            log.warning('PI auth failed user=%s: %s', username, msg)
            raise PIClientError(msg)
        token = result['value']['token']
        self._token = token
        self._username = username
        self._password = password
        payload_b64 = token.split('.')[1]
        payload_b64 += '=' * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        self._token_exp = datetime.fromtimestamp(payload['exp'], tz=timezone.utc)
        log.info('PI auth success user=%s', username)
        return token

    def auth(self, username=None, password=None, transaction_id=None, realm=None):
        """POST /auth — supports challenge-response via transaction_id.

        Step 1 (trigger): ``auth(username, password, realm=…)``
        Step 2 (answer):  ``auth(username, password=otp, transaction_id=tid)``

        Returns one of:
          {'token': <JWT>}                       — authentication complete
          {'transaction_id': <tid>, 'message',
           'multi_challenge'}                    — challenge triggered, OTP required
        Raises ``PIClientError`` on authentication failure or transport error.

        On success, the returned JWT is also cached on the client so subsequent
        instance methods (list_tokens, etc.) work without another call.
        """
        data = {}
        if username:
            data['username'] = username
        if password is not None:
            data['password'] = password
        if transaction_id:
            data['transaction_id'] = transaction_id
        if realm:
            data['realm'] = realm
        resp = self._request(
            'POST',
            f'{self.base_url}/auth',
            data=data,
            verify=self.verify_ssl, timeout=15,
        )
        try:
            body = resp.json()
        except ValueError:
            raise PIClientError(f'Invalid response from PI (HTTP {resp.status_code})')
        result = body.get('result', {})
        if not result.get('status'):
            msg = result.get('error', {}).get('message', 'Authentication failed')
            log.warning('PI /auth user=%s tx=%s failed: %s',
                        username, transaction_id, msg)
            raise PIClientError(msg)
        detail = body.get('detail', {}) or {}
        # Challenge path: status=true, value falsy, transaction_id in detail.
        if not result.get('value'):
            tx = detail.get('transaction_id')
            if tx:
                log.info('PI /auth challenge triggered user=%s tx=%s', username, tx)
                return {
                    'transaction_id': tx,
                    'message': detail.get('message', ''),
                    'multi_challenge': detail.get('multi_challenge', []),
                }
            raise PIClientError('Authentication failed')
        # Success path: result.value is the token envelope.
        value = result.get('value') or {}
        token = value.get('token') if isinstance(value, dict) else None
        if not token:
            raise PIClientError('Authentication failed (no token in response)')
        self._token = token
        self._username = username
        self._password = password if transaction_id is None else None
        payload_b64 = token.split('.')[1]
        payload_b64 += '=' * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        self._token_exp = datetime.fromtimestamp(payload['exp'], tz=timezone.utc)
        log.info('PI /auth success user=%s', username)
        return {'token': token}

    def _ensure_auth(self):
        if not self._token:
            raise PIClientError('Not authenticated.')
        if datetime.now(timezone.utc) >= self._token_exp - timedelta(minutes=5):
            if self._username and self._password:
                self.authenticate(self._username, self._password)
            else:
                raise PIClientError('JWT expired and no credentials stored for refresh.')

    def set_token(self, token, username=None):
        """Reuse a JWT obtained elsewhere (e.g. stored in a session)."""
        self._token = token
        self._username = username
        self._token_exp = datetime.now(timezone.utc) + timedelta(minutes=55)

    # --- tokens --------------------------------------------------------------

    def list_tokens(self, username=None, realm=None, type_=None, active=None):
        """Return tokens visible to the current JWT.

        If ``username`` is None, PI auto-scopes to the JWT caller (the user
        flow uses this to list their own tokens). Pass ``username`` only when
        the caller is an admin looking up someone else."""
        self._ensure_auth()
        params = {}
        if username:
            params['user'] = username
        if realm:
            params['realm'] = realm
        if type_:
            params['type'] = type_
        if active is not None:
            params['active'] = 'true' if active else 'false'
        resp = self._request(
            'GET',
            f'{self.base_url}/token/',
            params=params,
            headers=self._headers(),
            verify=self.verify_ssl, timeout=15,
        )
        data = resp.json()
        if not data.get('result', {}).get('status'):
            raise PIClientError('Failed to list tokens')
        return data['result']['value'].get('tokens', [])

    def get_user_info(self, username=None, realm=None):
        """Return the first matching user dict from PI's /user/ endpoint, or
        None if PI responded with no matches / an error.

        Works for a user JWT: the default PI user-scope policy lets a logged-in
        user list their own profile (resolver attributes like ``email``,
        ``givenname``, ``mobile``, plus any custom attributes). Works for an
        admin JWT too — pass ``username`` + ``realm`` to target a given user.
        """
        self._ensure_auth()
        params = {}
        if username:
            params['username'] = username
        if realm:
            params['realm'] = realm
        resp = self._request(
            'GET',
            f'{self.base_url}/user/',
            params=params,
            headers=self._headers(),
            verify=self.verify_ssl, timeout=15,
        )
        try:
            data = resp.json()
        except ValueError:
            return None
        result = data.get('result', {})
        if not result.get('status'):
            return None
        users = result.get('value') or []
        return users[0] if users else None

    def has_active_totp(self, username=None, realm=None):
        """True if at least one active TOTP token exists for the scope.

        When ``username`` is None, checks the JWT caller's own tokens."""
        tokens = self.list_tokens(username=username, realm=realm, type_='totp', active=True)
        return len(tokens) > 0

    def init_totp(self, username=None, realm=None, serial=None, otpkey=None):
        """Enroll a new TOTP token.

        When called with a user's JWT and no ``username``, PI enrols for the
        JWT caller. When called with an admin JWT, pass ``username``+``realm``
        to target a specific user. Pass ``serial`` to override PI's
        auto-generated serial (the caller is responsible for uniqueness).

        When ``otpkey`` is provided (hex-encoded secret), PI uses it instead
        of generating a new key. This allows the caller to generate the
        secret locally, verify OTP before creating the token.

        Returns a dict with:
          serial   - token serial
        """
        self._ensure_auth()
        data = {
            'type': 'totp',
            'hashlib': 'sha1',
            'otplen': '6',
            'timeStep': '30',
            'description': 'self-enrolled via captive portal',
        }
        if otpkey:
            data['otpkey'] = otpkey
        else:
            data['genkey'] = '1'
        if username:
            data['user'] = username
        if realm:
            data['realm'] = realm
        if serial:
            data['serial'] = serial
        resp = self._request(
            'POST',
            f'{self.base_url}/token/init',
            data=data,
            headers=self._headers(),
            verify=self.verify_ssl, timeout=15,
        )
        body = resp.json()
        result = body.get('result', {})
        if not result.get('status'):
            msg = result.get('error', {}).get('message', 'Failed to enroll token')
            log.warning('PI /token/init user=%s@%s failed: %s', username, realm, msg)
            raise PIClientError(msg)
        detail = body.get('detail', {}) or {}
        googleurl = detail.get('googleurl', {}) or {}
        log.info('PI /token/init ok user=%s@%s serial=%s',
                 username, realm, detail.get('serial', '?'))
        return {
            'serial': detail.get('serial', ''),
            'otpauth': googleurl.get('value', ''),
        }

    def delete_token(self, serial):
        """Delete a token (PI DELETE also unassigns it from the user)."""
        self._ensure_auth()
        resp = self._request(
            'DELETE',
            f'{self.base_url}/token/{quote(serial)}',
            headers=self._headers(),
            verify=self.verify_ssl, timeout=15,
        )
        data = resp.json()
        result = data.get('result', {})
        if not result.get('status'):
            msg = result.get('error', {}).get('message', 'Failed to delete token')
            raise PIClientError(msg)
        log.info('PI token deleted serial=%s', serial)
        return result.get('value', 0)

    def set_token_active(self, serial, enabled):
        """Enable or disable a token."""
        self._ensure_auth()
        action = 'enable' if enabled else 'disable'
        resp = self._request(
            'POST',
            f'{self.base_url}/token/{action}',
            data={'serial': serial},
            headers=self._headers(),
            verify=self.verify_ssl, timeout=15,
        )
        data = resp.json()
        result = data.get('result', {})
        if not result.get('status'):
            msg = result.get('error', {}).get('message', f'Failed to {action} token')
            raise PIClientError(msg)
        log.info('PI token %sd serial=%s', action, serial)
        return result.get('value', 0)

    def reset_failcount(self, serial):
        """POST /token/reset — clear the fail counter after successful auth."""
        self._ensure_auth()
        resp = self._request(
            'POST',
            f'{self.base_url}/token/reset',
            data={'serial': serial},
            headers=self._headers(),
            verify=self.verify_ssl, timeout=15,
        )
        data = resp.json()
        result = data.get('result', {})
        if not result.get('status'):
            msg = result.get('error', {}).get('message', 'Failed to reset failcount')
            raise PIClientError(msg)
        log.info('PI token failcount reset serial=%s', serial)
        return result.get('value', 0)

    def assign_token(self, serial, username, realm=None):
        """POST /token/assign — explicitly assign a token to a user."""
        self._ensure_auth()
        data = {'serial': serial, 'user': username}
        if realm:
            data['realm'] = realm
        resp = self._request(
            'POST',
            f'{self.base_url}/token/assign',
            data=data,
            headers=self._headers(),
            verify=self.verify_ssl, timeout=15,
        )
        body = resp.json()
        result = body.get('result', {})
        if not result.get('status'):
            msg = result.get('error', {}).get('message', 'Failed to assign token')
            raise PIClientError(msg)
        log.info('PI token assigned serial=%s user=%s@%s', serial, username, realm)
        return result.get('value', True)

    # --- validation (no JWT required) ----------------------------------------

    def validate_check(self, username=None, password='', realm=None,
                       transaction_id=None):
        """POST /validate/check — supports challenge-response.

        Step 1 (trigger):  ``validate_check(username, password, realm=…)``
        Step 2 (answer):   ``validate_check(password=otp, transaction_id=tid)``

        Returns a dict:
          value          – True if authentication succeeded
          transaction_id – challenge transaction ID (present when a challenge
                           was triggered, i.e. password valid but OTP required)
          message        – human-readable message from PI
          multi_challenge – list of per-token challenge details
        """
        data = {'pass': password}
        if username:
            data['user'] = username
        if realm:
            data['realm'] = realm
        if transaction_id:
            data['transaction_id'] = transaction_id
        resp = self._request(
            'POST',
            f'{self.base_url}/validate/check',
            data=data,
            verify=self.verify_ssl, timeout=15,
        )
        try:
            body = resp.json()
        except ValueError:
            raise PIClientError(f'Invalid response from PI (HTTP {resp.status_code})')
        result = body.get('result', {})
        if not result.get('status'):
            msg = result.get('error', {}).get('message', 'validate/check failed')
            raise PIClientError(msg)
        detail = body.get('detail', {}) or {}
        return {
            'value': bool(result.get('value')),
            'transaction_id': detail.get('transaction_id'),
            'message': detail.get('message', ''),
            'multi_challenge': detail.get('multi_challenge', []),
        }
