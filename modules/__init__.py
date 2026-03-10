"""
Shared utilities used across all modules.
Centralizes API helpers, credential access, rate limiting, etc.
"""

import os
import time
import threading
import requests
from functools import wraps
from flask import session, jsonify

# ─── Meraki API Helpers ───────────────────────────────────────

BASE_URL = "https://api.meraki.com/api/v1"

_api_key_counter = 0
_api_key_lock = threading.Lock()


def get_meraki_api_keys():
    """Get all Meraki API keys from session or env vars.
    Env vars: MERAKI_API_KEY, MERAKI_API_KEY2
    """
    keys = []
    # Session first
    for k in ['api_key', 'api_key_2']:
        if session.get(k):
            keys.append(session[k])
    # Fallback to env
    if not keys:
        for env in ['MERAKI_API_KEY', 'MERAKI_API_KEY2']:
            val = os.getenv(env)
            if val:
                keys.append(val)
    return keys


def get_next_meraki_key():
    """Round-robin API key selection for rate limit distribution."""
    global _api_key_counter
    keys = get_meraki_api_keys()
    if not keys:
        return None
    with _api_key_lock:
        key = keys[_api_key_counter % len(keys)]
        _api_key_counter += 1
    return key


def meraki_headers(api_key=None):
    """Build Meraki API headers."""
    if api_key is None:
        api_key = get_next_meraki_key()
    if not api_key:
        return None
    return {
        "X-Cisco-Meraki-API-Key": api_key,
        "Content-Type": "application/json"
    }


def get_meraki_dashboard_key():
    """Get a Meraki API key for SDK-based operations.
    Uses the same keys as REST — MERAKI_API_KEY / MERAKI_API_KEY2.
    """
    keys = get_meraki_api_keys()
    return keys[0] if keys else None


def require_meraki_key(f):
    """Decorator to ensure at least one Meraki API key is present."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not get_meraki_api_keys():
            return jsonify({"error": "Meraki API key not configured. Go to Settings."}), 401
        return f(*args, **kwargs)
    return decorated


def require_meraki_dashboard_key(f):
    """Decorator to ensure Meraki Dashboard API key is present."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not get_meraki_dashboard_key():
            return jsonify({"error": "Meraki Dashboard API key not configured. Go to Settings."}), 401
        return f(*args, **kwargs)
    return decorated


# ─── Cisco SSH Helpers ────────────────────────────────────────

def get_cisco_credentials():
    """Get Cisco SSH credentials from session or env vars."""
    return {
        "username": session.get('cisco_user') or os.getenv('CISCO_USER', ''),
        "password": session.get('cisco_pass') or os.getenv('CISCO_PW', ''),
        "enable": session.get('cisco_enable') or os.getenv('CISCO_PW', ''),
    }


def require_cisco_creds(f):
    """Decorator to ensure Cisco credentials are present."""
    @wraps(f)
    def decorated(*args, **kwargs):
        creds = get_cisco_credentials()
        if not creds['username'] or not creds['password']:
            return jsonify({"error": "Cisco SSH credentials not configured. Go to Settings."}), 401
        return f(*args, **kwargs)
    return decorated


# ─── Rate-Limited API Caller ──────────────────────────────────

def meraki_api_call(method, url, retries=3, delay=0.3, **kwargs):
    """Make a Meraki API call with retry logic and rate limiting."""
    headers = meraki_headers()
    if not headers:
        raise Exception("No Meraki API key configured")

    for attempt in range(retries):
        try:
            resp = requests.request(method, url, headers=headers, **kwargs)
            if resp.status_code == 429:
                wait = delay * (attempt + 1) * 5
                time.sleep(wait)
                continue
            resp.raise_for_status()
            time.sleep(delay)
            return resp.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429 and attempt < retries - 1:
                time.sleep(delay * (attempt + 1) * 5)
                continue
            raise
    raise Exception("Max retries exceeded")
