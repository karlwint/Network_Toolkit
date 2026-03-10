"""
Meraki Sync Tools — Blueprint
Bulk RADIUS and DNS sync with org/network selection and editable server IPs.
"""

import os
import time
import threading
import json
from datetime import datetime
from flask import Blueprint, render_template, jsonify, request, session
from modules import (get_meraki_dashboard_key, require_meraki_dashboard_key,
                     require_meraki_key)

sync_bp = Blueprint('sync', __name__, template_folder='../../templates')

_sync_jobs = {}
_sync_lock = threading.Lock()


class SyncJob:
    def __init__(self, job_id, sync_type):
        self.id = job_id
        self.sync_type = sync_type
        self.status = "pending"
        self.progress = 0
        self.total = 0
        self.updated = []
        self.skipped = []
        self.errors = []
        self.no_match = []
        self.log = []
        self.cancel_event = threading.Event()

    def to_dict(self):
        return {
            "id": self.id, "sync_type": self.sync_type,
            "status": self.status, "progress": self.progress, "total": self.total,
            "updated": len(self.updated), "skipped": len(self.skipped),
            "errors": len(self.errors), "no_match": len(self.no_match),
            "log": self.log[-100:],
            "details": {"updated": self.updated[-20:], "errors": self.errors[-20:]},
        }


def get_dashboard(api_key):
    import meraki
    return meraki.DashboardAPI(api_key, suppress_logging=True)


def api_call(func, *args, delay=0.3, retries=3, **kwargs):
    import meraki
    for attempt in range(retries):
        try:
            result = func(*args, **kwargs)
            time.sleep(delay)
            return result
        except meraki.APIError as e:
            if e.status == 429:
                time.sleep(5 * (attempt + 1))
            elif e.status == 400:
                return None
            else:
                raise
    return None


# ─── Routes ───────────────────────────────────────────────────

@sync_bp.route('/')
def sync_index():
    from modules import get_meraki_api_keys
    has_key = bool(get_meraki_api_keys())
    return render_template('sync/index.html', has_key=has_key)


@sync_bp.route('/api/radius-sync', methods=['POST'])
@require_meraki_dashboard_key
def start_radius_sync():
    data = request.json
    org_id = data.get('org_id')
    selected_ids = data.get('network_ids', [])
    target_ssid = data.get('target_ssid', 'hccuser')
    radius_servers = data.get('radius_servers', [])
    acct_servers = data.get('acct_servers', [])
    radius_secret = (data.get('radius_secret')
                     or session.get('radius_secret')
                     or os.environ.get('Radius_Sec'))

    if not org_id:
        return jsonify({"error": "Organization not selected"}), 400
    if not radius_servers:
        return jsonify({"error": "No RADIUS auth servers provided"}), 400
    if not radius_secret:
        return jsonify({"error": "RADIUS secret not configured. Set it in Settings."}), 400

    auth_servers = [{"host": s["host"], "port": s["port"], "secret": radius_secret}
                    for s in radius_servers]
    accounting_servers = [{"host": s["host"], "port": s["port"], "secret": radius_secret}
                          for s in acct_servers]

    job_id = "radius_" + datetime.now().strftime('%Y%m%d_%H%M%S')
    job = SyncJob(job_id, "radius")
    job.status = "running"
    with _sync_lock:
        _sync_jobs[job_id] = job

    api_key = get_meraki_dashboard_key()

    def run_radius_sync():
        dashboard = get_dashboard(api_key)
        job.log.append(f"Target SSID: {target_ssid}")
        job.log.append(f"Auth servers: {', '.join(s['host']+':'+str(s['port']) for s in radius_servers)}")
        if acct_servers:
            job.log.append(f"Acct servers: {', '.join(s['host']+':'+str(s['port']) for s in acct_servers)}")

        networks = api_call(dashboard.organizations.getOrganizationNetworks,
                            org_id, total_pages='all')
        relevant = [n for n in networks
                    if 'wireless' in n.get('productTypes', [])
                    or 'appliance' in n.get('productTypes', [])]

        if selected_ids:
            sel = set(selected_ids)
            relevant = [n for n in relevant if n['id'] in sel]

        job.total = len(relevant)
        job.log.append(f"Syncing {len(relevant)} network(s)")

        for i, network in enumerate(relevant, 1):
            if job.cancel_event.is_set():
                break
            net_id, net_name = network['id'], network['name']
            found = False

            if 'wireless' in network.get('productTypes', []):
                try:
                    ssids = api_call(dashboard.wireless.getNetworkWirelessSsids, net_id)
                    if ssids:
                        for ssid in ssids:
                            if ssid.get('name', '').lower() == target_ssid.lower():
                                try:
                                    api_call(dashboard.wireless.updateNetworkWirelessSsid,
                                             net_id, ssid['number'],
                                             radiusServers=auth_servers,
                                             radiusAccountingServers=accounting_servers)
                                    job.updated.append({"network": net_name, "type": "MR"})
                                    job.log.append(f"  ✅ {net_name} — MR SSID updated")
                                    found = True
                                except Exception as e:
                                    job.errors.append({"network": net_name, "error": str(e)})
                                break
                except Exception:
                    pass

            if 'appliance' in network.get('productTypes', []):
                try:
                    ssids = api_call(dashboard.appliance.getNetworkApplianceSsids, net_id)
                    if ssids:
                        for ssid in ssids:
                            if ssid.get('name', '').lower() == target_ssid.lower():
                                try:
                                    api_call(dashboard.appliance.updateNetworkApplianceSsid,
                                             net_id, ssid['number'],
                                             radiusServers=auth_servers,
                                             radiusAccountingServers=accounting_servers)
                                    job.updated.append({"network": net_name, "type": "MX"})
                                    job.log.append(f"  ✅ {net_name} — MX SSID updated")
                                    found = True
                                except Exception as e:
                                    job.errors.append({"network": net_name, "error": str(e)})
                                break
                except Exception:
                    pass

            if not found:
                job.no_match.append(net_name)
            job.progress = i

        job.status = "complete"
        job.log.append(f"\n{'='*50}")
        job.log.append(f"RADIUS Sync Complete — {len(job.updated)} updated, "
                       f"{len(job.errors)} errors, {len(job.no_match)} no match")

    threading.Thread(target=run_radius_sync, daemon=True).start()
    return jsonify({"job_id": job_id})


@sync_bp.route('/api/dns-sync', methods=['POST'])
@require_meraki_dashboard_key
def start_dns_sync():
    data = request.json
    org_id = data.get('org_id')
    selected_ids = data.get('network_ids', [])
    target_vlans = data.get('target_vlans', [])
    dns_servers = data.get('dns_servers', '')

    if not org_id:
        return jsonify({"error": "Organization not selected"}), 400
    if not target_vlans:
        return jsonify({"error": "No target VLANs specified"}), 400
    if not dns_servers.strip():
        return jsonify({"error": "No DNS servers provided"}), 400

    job_id = "dns_" + datetime.now().strftime('%Y%m%d_%H%M%S')
    job = SyncJob(job_id, "dns")
    job.status = "running"
    with _sync_lock:
        _sync_jobs[job_id] = job

    api_key = get_meraki_dashboard_key()

    def run_dns_sync():
        dashboard = get_dashboard(api_key)
        job.log.append(f"Target VLANs: {target_vlans}")
        job.log.append(f"DNS Servers: {dns_servers.replace(chr(10), ', ')}")

        networks = api_call(dashboard.organizations.getOrganizationNetworks,
                            org_id, total_pages='all')
        mx_networks = [n for n in networks if 'appliance' in n.get('productTypes', [])]

        if selected_ids:
            sel = set(selected_ids)
            mx_networks = [n for n in mx_networks if n['id'] in sel]

        job.total = len(mx_networks)
        job.log.append(f"Syncing {len(mx_networks)} MX network(s)")

        for i, network in enumerate(mx_networks, 1):
            if job.cancel_event.is_set():
                break
            net_id, net_name = network['id'], network['name']

            try:
                settings = api_call(dashboard.appliance.getNetworkApplianceVlansSettings, net_id)
                if not settings or not settings.get('vlansEnabled', False):
                    job.skipped.append({"network": net_name, "reason": "VLANs not enabled"})
                    job.progress = i
                    continue
            except Exception as e:
                job.errors.append({"network": net_name, "error": str(e)})
                job.progress = i
                continue

            try:
                vlans = api_call(dashboard.appliance.getNetworkApplianceVlans, net_id)
                if not vlans:
                    job.progress = i
                    continue
                vlan_ids = {v['id'] for v in vlans}
            except Exception as e:
                job.errors.append({"network": net_name, "error": str(e)})
                job.progress = i
                continue

            for vlan_id in target_vlans:
                if vlan_id not in vlan_ids:
                    job.skipped.append({"network": net_name, "reason": f"VLAN {vlan_id} not found"})
                    continue
                try:
                    api_call(dashboard.appliance.updateNetworkApplianceVlan,
                             net_id, vlan_id, dnsNameservers=dns_servers)
                    job.updated.append({"network": net_name, "vlan": vlan_id})
                    job.log.append(f"  ✅ {net_name} — VLAN {vlan_id} DNS updated")
                except Exception as e:
                    job.errors.append({"network": net_name, "error": str(e)})

            job.progress = i

        job.status = "complete"
        job.log.append(f"\n{'='*50}")
        job.log.append(f"DNS Sync Complete — {len(job.updated)} updated, "
                       f"{len(job.skipped)} skipped, {len(job.errors)} errors")

    threading.Thread(target=run_dns_sync, daemon=True).start()
    return jsonify({"job_id": job_id})


@sync_bp.route('/api/job/<job_id>')
def get_sync_job(job_id):
    with _sync_lock:
        job = _sync_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job.to_dict())


@sync_bp.route('/api/job/<job_id>/cancel', methods=['POST'])
def cancel_sync_job(job_id):
    with _sync_lock:
        job = _sync_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    job.cancel_event.set()
    return jsonify({"success": True})
