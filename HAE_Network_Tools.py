#!/usr/bin/env python3
"""
Network Operations Toolkit — Unified Flask Application
=======================================================
Consolidates Meraki API tools, Cisco CLI tools, credential auditing,
and bulk sync operations into a single web-based platform.

Usage:
    python app.py

All dependencies are auto-installed on first run.

Author: Karlos — Helena Agri-Enterprises Network Engineering
"""

import os
import sys
import subprocess

# ── Auto-install dependencies before importing anything ───────
def _check_and_install():
    """Check for required packages and install any that are missing."""
    required = {
        'flask': 'flask',
        'requests': 'requests',
        'meraki': 'meraki',
        'netmiko': 'netmiko',
        'openpyxl': 'openpyxl',
    }
    # Optional but useful — don't fail if these can't install
    optional = {
        'pysnmp': 'pysnmp',
        'ping3': 'ping3',
    }

    missing = []
    for import_name, pip_name in required.items():
        try:
            __import__(import_name)
        except ImportError:
            missing.append(pip_name)

    missing_optional = []
    for import_name, pip_name in optional.items():
        try:
            __import__(import_name)
        except ImportError:
            missing_optional.append(pip_name)

    if missing or missing_optional:
        print("=" * 60)
        print("  Network Operations Toolkit — First Run Setup")
        print("=" * 60)

    if missing:
        print(f"\n  Missing required packages: {', '.join(missing)}")
        print("  Installing automatically...\n")
        for pkg in missing:
            print(f"  Installing {pkg}...", end=" ", flush=True)
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", pkg],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                print("✓")
            except subprocess.CalledProcessError:
                print("✗")
                print(f"\n  ERROR: Failed to install {pkg}.")
                print(f"  Please install manually: pip install {pkg}")
                sys.exit(1)

    if missing_optional:
        print(f"\n  Optional packages: {', '.join(missing_optional)}")
        for pkg in missing_optional:
            print(f"  Installing {pkg}...", end=" ", flush=True)
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", pkg],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                print("✓")
            except subprocess.CalledProcessError:
                print("(skipped)")

    if missing or missing_optional:
        print("\n" + "=" * 60)
        print("  Setup complete — starting toolkit...")
        print("=" * 60 + "\n")


_check_and_install()

# ── Now safe to import third-party packages ───────────────────
import json
import secrets
import time
import threading
from datetime import datetime
from flask import Flask, render_template, jsonify, request, session, send_file, redirect, url_for

# Import module blueprints
from modules.meraki_tools.routes import meraki_bp
from modules.cisco_cli.routes import cisco_bp
from modules.credential_audit.routes import audit_bp
from modules.meraki_sync.routes import sync_bp
from modules.cisco_inventory.routes import inventory_bp

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Register blueprints
app.register_blueprint(meraki_bp, url_prefix='/meraki')
app.register_blueprint(cisco_bp, url_prefix='/cisco')
app.register_blueprint(audit_bp, url_prefix='/audit')
app.register_blueprint(sync_bp, url_prefix='/sync')
app.register_blueprint(inventory_bp, url_prefix='/inventory')

# ─── Module Registry ─────────────────────────────────────────
MODULES = [
    {
        "id": "meraki",
        "name": "Meraki Dashboard",
        "icon": "cloud",
        "description": "Device management, status, LLDP/CDP, IMEI lookup, client info, CSV exports",
        "url": "/meraki",
        "color": "#00D4AA",
    },
    {
        "id": "cisco",
        "name": "Cisco CLI Tools",
        "icon": "terminal",
        "description": "Network scanning, SSH verification, bulk config push across switches",
        "url": "/cisco",
        "color": "#60A5FA",
    },
    {
        "id": "audit",
        "name": "Credential Audit",
        "icon": "shield",
        "description": "Multi-protocol credential scanning with automated SSH remediation",
        "url": "/audit",
        "color": "#FBBF24",
    },
    {
        "id": "sync",
        "name": "Meraki Sync",
        "icon": "refresh",
        "description": "Bulk RADIUS, DNS, and SSID sync across all org networks",
        "url": "/sync",
        "color": "#A78BFA",
    },
    {
        "id": "inventory",
        "name": "Cisco Inventory",
        "icon": "layers",
        "description": "Stack-aware Cisco switch inventory with Excel export (version, members, hardware)",
        "url": "/inventory",
        "color": "#FB923C",
    },
]


# ─── Shared Credential Management ────────────────────────────

@app.route('/')
def index():
    return render_template('index.html', modules=MODULES)


@app.route('/api/credentials', methods=['GET'])
def get_credentials():
    """Return which credential sets are configured (not the actual values)."""
    from modules import get_meraki_api_keys
    creds = {
        "meraki_keys": len(get_meraki_api_keys()),
        "cisco_user": bool(session.get('cisco_user') or os.getenv('CISCO_USER')),
        "cisco_pass": bool(session.get('cisco_pass') or os.getenv('CISCO_PW')),
    }
    return jsonify(creds)


@app.route('/api/credentials', methods=['POST'])
def set_credentials():
    """Store credentials in session."""
    data = request.json
    updated = []

    # Meraki API keys (matches env vars MERAKI_API_KEY, MERAKI_API_KEY2)
    for key_name in ['api_key', 'api_key_2']:
        if key_name in data and data[key_name].strip():
            session[key_name] = data[key_name].strip()
            updated.append(key_name)

    # Cisco SSH credentials
    if 'cisco_user' in data:
        session['cisco_user'] = data['cisco_user'].strip()
        updated.append('cisco_user')
    if 'cisco_pass' in data:
        session['cisco_pass'] = data['cisco_pass'].strip()
        updated.append('cisco_pass')
    if 'cisco_enable' in data:
        session['cisco_enable'] = data['cisco_enable'].strip()
        updated.append('cisco_enable')

    # Break-glass credentials
    if 'breakglass_user' in data:
        session['breakglass_user'] = data['breakglass_user'].strip()
        updated.append('breakglass_user')
    if 'breakglass_pass' in data:
        session['breakglass_pass'] = data['breakglass_pass'].strip()
        updated.append('breakglass_pass')

    # TACACS credentials
    if 'tacacs_user' in data:
        session['tacacs_user'] = data['tacacs_user'].strip()
        updated.append('tacacs_user')
    if 'tacacs_pass' in data:
        session['tacacs_pass'] = data['tacacs_pass'].strip()
        updated.append('tacacs_pass')

    # RADIUS secret
    if 'radius_secret' in data:
        session['radius_secret'] = data['radius_secret'].strip()
        updated.append('radius_secret')

    return jsonify({"success": True, "updated": updated})


@app.route('/api/credentials/clear', methods=['POST'])
def clear_credentials():
    """Clear all stored credentials."""
    keys_to_clear = [
        'api_key', 'api_key_2',
        'cisco_user', 'cisco_pass', 'cisco_enable',
        'breakglass_user', 'breakglass_pass',
        'tacacs_user', 'tacacs_pass', 'radius_secret',
    ]
    for key in keys_to_clear:
        session.pop(key, None)
    return jsonify({"success": True, "message": "All credentials cleared"})


@app.route('/settings')
def settings():
    return render_template('settings.html', modules=MODULES)


# ─── Shared Utilities ─────────────────────────────────────────

@app.template_filter('datetime')
def format_datetime(value, fmt='%Y-%m-%d %H:%M'):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except Exception:
            return value
    return value.strftime(fmt)


@app.errorhandler(404)
def not_found(e):
    return render_template('404.html', modules=MODULES), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500


# ─── Heartbeat / Auto-shutdown for windowless (.pyw) mode ─────
_last_heartbeat = None
_heartbeat_lock = threading.Lock()


@app.route('/api/heartbeat', methods=['POST'])
def heartbeat():
    """Browser pings this to signal it's still open."""
    global _last_heartbeat
    with _heartbeat_lock:
        _last_heartbeat = time.time()
    return jsonify({"ok": True})


@app.route('/api/shutdown', methods=['POST'])
def shutdown():
    """Graceful shutdown triggered by browser."""
    os._exit(0)


def _heartbeat_watchdog(timeout=15):
    """Background thread: if no heartbeat for `timeout` seconds, shut down."""
    global _last_heartbeat
    import time as _time
    while True:
        _time.sleep(5)
        with _heartbeat_lock:
            if _last_heartbeat and (_time.time() - _last_heartbeat > timeout):
                print("[SHUTDOWN] No browser heartbeat — exiting.")
                os._exit(0)


if __name__ == '__main__':
    import webbrowser
    import threading
    import time

    # Start heartbeat watchdog
    threading.Thread(target=_heartbeat_watchdog, daemon=True).start()

    # Open browser after a short delay so Flask has time to start
    threading.Timer(1.2, lambda: webbrowser.open('http://127.0.0.1:5000')).start()

    app.run(debug=True, host='127.0.0.1', port=5000, use_reloader=False)
