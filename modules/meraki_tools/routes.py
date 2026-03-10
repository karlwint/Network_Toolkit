"""
Meraki Dashboard Tools — Blueprint
Ported from My_Meraki_App.py with shared credential management.
"""

import csv
import io
from datetime import datetime
from flask import Blueprint, render_template, jsonify, request, session, send_file
from modules import (
    BASE_URL, meraki_headers, get_meraki_api_keys, get_next_meraki_key,
    require_meraki_key, meraki_api_call
)
import requests as http_requests

meraki_bp = Blueprint('meraki', __name__, template_folder='../../templates')


# ─── API Functions ────────────────────────────────────────────

def get_organizations():
    headers = meraki_headers()
    if not headers:
        raise Exception("API key not configured")
    resp = http_requests.get(f"{BASE_URL}/organizations", headers=headers)
    resp.raise_for_status()
    return resp.json()


def get_devices(org_id):
    headers = meraki_headers()
    resp = http_requests.get(f"{BASE_URL}/organizations/{org_id}/devices", headers=headers)
    resp.raise_for_status()
    return resp.json()


def get_lldp_cdp_neighbors(serial):
    headers = meraki_headers()
    resp = http_requests.get(f"{BASE_URL}/devices/{serial}/lldpCdp", headers=headers)
    resp.raise_for_status()
    return resp.json()


def get_device_status(serial, org_id):
    headers = meraki_headers()
    resp = http_requests.get(
        f"{BASE_URL}/organizations/{org_id}/devices/statuses",
        headers=headers, params={"serials[]": serial}
    )
    resp.raise_for_status()
    statuses = resp.json()
    return statuses[0] if statuses else {"error": "Device status not found"}


def get_device_details(serial):
    headers = meraki_headers()
    resp = http_requests.get(f"{BASE_URL}/devices/{serial}", headers=headers)
    resp.raise_for_status()
    return resp.json()


def get_device_cellular_info(serial):
    headers = meraki_headers()
    try:
        resp = http_requests.get(f"{BASE_URL}/devices/{serial}/cellular/sims", headers=headers)
        resp.raise_for_status()
        data = resp.json()
        if data.get('sims') and len(data['sims']) > 0:
            sim = data['sims'][0]
            return {'imei': sim.get('imei'), 'iccid': sim.get('iccid'),
                    'status': sim.get('status'), 'slot': sim.get('slot')}
    except Exception:
        pass
    try:
        resp = http_requests.get(f"{BASE_URL}/devices/{serial}/cellularGateway/settings", headers=headers)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        pass
    raise Exception("Unable to retrieve cellular information")


def get_device_clients(serial):
    headers = meraki_headers()
    resp = http_requests.get(
        f"{BASE_URL}/devices/{serial}/clients",
        headers=headers, params={"timespan": 86400}
    )
    resp.raise_for_status()
    return resp.json()


# ─── Routes ───────────────────────────────────────────────────

@meraki_bp.route('/')
def meraki_index():
    has_key = len(get_meraki_api_keys()) > 0
    return render_template('meraki/index.html', has_api_key=has_key,
                           key_count=len(get_meraki_api_keys()))


@meraki_bp.route('/api/organizations')
@require_meraki_key
def api_organizations():
    try:
        return jsonify(get_organizations())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@meraki_bp.route('/api/devices/<org_id>')
@require_meraki_key
def api_devices(org_id):
    try:
        return jsonify(get_devices(org_id))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@meraki_bp.route('/api/org-networks/<org_id>')
@require_meraki_key
def api_networks(org_id):
    """Get all networks for an org using the Meraki SDK for automatic pagination."""
    try:
        import meraki
        api_key = get_meraki_api_keys()[0]
        dashboard = meraki.DashboardAPI(api_key, suppress_logging=True)
        networks = dashboard.organizations.getOrganizationNetworks(org_id, total_pages='all')
        return jsonify(networks)
    except Exception as e:
        print(f"[ERROR] Networks endpoint failed: {type(e).__name__}: {e}")
        return jsonify({"error": str(e)}), 500


@meraki_bp.route('/api/action', methods=['POST'])
@require_meraki_key
def api_action():
    try:
        data = request.json
        action = data.get('action')
        serials = data.get('serials', [])
        org_id = data.get('org_id')

        if not org_id:
            return jsonify({"error": "Organization ID required"}), 400

        results = []

        # Pre-fetch org devices for IMEI lookups
        if action in ('imei', 'full_info') and org_id:
            org_devices = get_devices(org_id)
            device_map = {d['serial']: d for d in org_devices}

        for serial in serials:
            try:
                if action == 'lldp_cdp':
                    result = get_lldp_cdp_neighbors(serial)
                elif action == 'status':
                    result = get_device_status(serial, org_id)
                elif action == 'location':
                    info = get_device_details(serial)
                    result = {"latitude": info.get('lat'), "longitude": info.get('lng'),
                              "address": info.get('address'), "name": info.get('name')}
                elif action == 'imei':
                    if serial in device_map:
                        d = device_map[serial]
                        imei = d.get('imei')
                        result = {"imei": imei or "Not available", "model": d.get('model'),
                                  "name": d.get('name'), "serial": serial,
                                  "note": "" if imei else "IMEI not populated"}
                    else:
                        info = get_device_details(serial)
                        result = {"imei": info.get('imei', 'Not available'),
                                  "model": info.get('model')}
                elif action == 'clients':
                    clients = get_device_clients(serial)
                    result = {"clients": clients, "total_clients": len(clients)}
                elif action == 'full_info':
                    result = {}
                    if serial in device_map:
                        d = device_map[serial]
                        result["basic_info"] = {
                            "name": d.get('name'), "model": d.get('model'),
                            "serial": d.get('serial'), "mac": d.get('mac'),
                            "imei": d.get('imei', 'N/A'), "lanIp": d.get('lanIp'),
                            "productType": d.get('productType'), "firmware": d.get('firmware'),
                            "networkId": d.get('networkId'), "tags": d.get('tags'),
                        }
                    try:
                        info = get_device_details(serial)
                        result["location"] = {"latitude": info.get('lat'),
                                              "longitude": info.get('lng'),
                                              "address": info.get('address')}
                    except Exception as e:
                        result["location"] = {"error": str(e)}
                    try:
                        result["status"] = get_device_status(serial, org_id)
                    except Exception as e:
                        result["status"] = {"error": str(e)}
                    try:
                        result["lldp_cdp_neighbors"] = get_lldp_cdp_neighbors(serial)
                    except Exception as e:
                        result["lldp_cdp_neighbors"] = {"error": str(e)}
                else:
                    result = {"error": "Unknown action"}

                results.append({"serial": serial, "data": result})
            except Exception as e:
                results.append({"serial": serial, "data": {"error": str(e)}})

        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@meraki_bp.route('/api/export-csv', methods=['POST'])
@require_meraki_key
def export_csv():
    """Export collected data to CSV — preserves all original export logic."""
    try:
        data = request.json
        action = data.get('action')
        results = data.get('results', [])
        output = io.StringIO()
        writer = csv.writer(output)

        if action == 'status':
            writer.writerow(['Serial', 'Name', 'Status', 'Model', 'Public IP',
                             'LAN IP', 'Last Reported', 'Network ID'])
            for item in results:
                d = item.get('data', {})
                if 'error' in d:
                    writer.writerow([item['serial'], 'ERROR', d['error'],
                                     '', '', '', '', ''])
                else:
                    writer.writerow([item['serial'], d.get('name', 'N/A'),
                                     d.get('status'), d.get('model'),
                                     d.get('publicIp'), d.get('lanIp'),
                                     d.get('lastReportedAt'), d.get('networkId')])

        elif action == 'lldp_cdp':
            writer.writerow(['Serial', 'Source Interface', 'Neighbor Device',
                             'Neighbor Port', 'Neighbor Platform'])
            for item in results:
                d = item.get('data', {})
                if 'error' in d:
                    writer.writerow([item['serial'], 'ERROR', d['error'], '', ''])
                    continue
                ports = d.get('ports', {})
                if not ports:
                    writer.writerow([item['serial'], 'No neighbors found', '', '', ''])
                    continue
                for port_name, neighbors in ports.items():
                    if neighbors.get('lldp'):
                        lldp = neighbors['lldp']
                        writer.writerow([item['serial'], port_name,
                                         lldp.get('systemName', 'N/A'),
                                         lldp.get('portId', 'N/A'),
                                         lldp.get('systemDescription', 'N/A')])
                    elif neighbors.get('cdp'):
                        cdp = neighbors['cdp']
                        writer.writerow([item['serial'], port_name,
                                         cdp.get('deviceId', 'N/A'),
                                         cdp.get('portId', 'N/A'),
                                         cdp.get('platform', 'N/A')])

        elif action == 'full_info':
            writer.writerow(['Serial', 'Name', 'Model', 'MAC', 'IMEI', 'Product Type',
                             'Firmware', 'Status', 'Public IP', 'LAN IP', 'Last Reported',
                             'Address', 'Latitude', 'Longitude', 'Network ID', 'Tags'])
            for item in results:
                d = item.get('data', {})
                if 'error' in d:
                    writer.writerow([item['serial'], 'ERROR'] + [''] * 14)
                else:
                    b = d.get('basic_info', {})
                    s = d.get('status', {})
                    loc = d.get('location', {})
                    writer.writerow([
                        item['serial'], b.get('name'), b.get('model'), b.get('mac'),
                        b.get('imei'), b.get('productType'), b.get('firmware'),
                        s.get('status'), s.get('publicIp'), b.get('lanIp'),
                        s.get('lastReportedAt'), loc.get('address'),
                        loc.get('latitude'), loc.get('longitude'),
                        b.get('networkId'),
                        ', '.join(b.get('tags', [])) if b.get('tags') else 'N/A'
                    ])
        else:
            return jsonify({"error": f"Unknown action: {action}"}), 400

        output.seek(0)
        byte_output = io.BytesIO(output.getvalue().encode('utf-8'))
        byte_output.seek(0)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        return send_file(byte_output, mimetype='text/csv', as_attachment=True,
                         download_name=f'meraki_{action}_{ts}.csv')
    except Exception as e:
        return jsonify({"error": str(e)}), 500
