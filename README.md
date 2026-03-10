# Network Operations Toolkit

Unified Flask web application consolidating all HAE/HII Cisco and Meraki network automation tools into a single browser-based platform.

## Modules

| Module | Description | Original Script |
|--------|-------------|----------------|
| **Meraki Dashboard** | Device management, status, LLDP/CDP, IMEI, clients, CSV export | `My_Meraki_App.py` |
| **Cisco CLI Tools** | Network scanning, SSH verification, bulk config push | `Cisco_Config_Tool.py` |
| **Credential Audit** | Multi-protocol credential scanning + SSH remediation | `Credential_Audit_Tool-v4_.py` |
| **Meraki Sync** | Bulk RADIUS & DNS sync across all org networks | `meraki_radius_sync.py`, `meraki_dns_sync.py` |

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables (optional — can also configure in Settings UI)
export MERAKI_API_KEY="your_meraki_api_key"
export MERAKI_DASHBOARD_API_KEY="your_dashboard_key"
export CISCO_USER="your_ssh_username"
export CISCO_PW="your_ssh_password"
export Radius_Sec="your_radius_secret"

# Run the app
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

## Project Structure

```
network-toolkit/
├── app.py                              # Main Flask app + credential vault
├── requirements.txt
├── modules/
│   ├── __init__.py                     # Shared utilities, API helpers, decorators
│   ├── meraki_tools/
│   │   ├── __init__.py
│   │   └── routes.py                   # Meraki Dashboard blueprint
│   ├── cisco_cli/
│   │   ├── __init__.py
│   │   └── routes.py                   # Cisco CLI Tools blueprint
│   ├── credential_audit/
│   │   ├── __init__.py
│   │   └── routes.py                   # Credential Audit blueprint
│   └── meraki_sync/
│       ├── __init__.py
│       └── routes.py                   # RADIUS & DNS Sync blueprint
├── templates/
│   ├── base.html                       # Master layout (sidebar, theme, shared JS)
│   ├── index.html                      # Dashboard
│   ├── settings.html                   # Credential vault UI
│   ├── 404.html
│   ├── meraki/index.html               # Meraki Dashboard UI
│   ├── cisco/index.html                # Cisco CLI Tools UI
│   ├── audit/index.html                # Credential Audit UI
│   └── sync/index.html                # RADIUS & DNS Sync UI
└── data/                               # CSV exports, scan logs
```

## Credential Management

Credentials can be configured two ways:

1. **Environment Variables** (fallback) — Set before running the app
2. **Settings UI** (`/settings`) — Stored in browser session, cleared on restart

The Settings page supports all credential types:
- Meraki REST API keys (up to 3 for round-robin rate limiting)
- Meraki Dashboard SDK key (for sync tools)
- Cisco SSH username/password/enable
- Break-glass credentials (for remediation)
- TACACS credentials (for remediation verification)
- RADIUS shared secret

## Architecture Notes

- **Blueprints**: Each module is a Flask Blueprint with its own route prefix
- **Async Jobs**: Long-running operations (scans, syncs, pushes) run in background threads with polling endpoints
- **Rate Limiting**: Meraki API calls include built-in retry logic with exponential backoff on 429s
- **Multi-Key Load Balancing**: Meraki REST tools rotate through up to 3 API keys
- **No External Dependencies for UI**: Pure HTML/CSS/JS with no frontend build step — dark themed to match existing tools

## Adding New Modules

1. Create `modules/your_module/__init__.py` and `routes.py`
2. Define a Flask Blueprint in `routes.py`
3. Register it in `app.py` with `app.register_blueprint()`
4. Add an entry to the `MODULES` list in `app.py`
5. Create `templates/your_module/index.html` extending `base.html`
