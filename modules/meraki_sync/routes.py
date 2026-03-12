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


@sync_bp.route('/api/network-configs', methods=['POST'])
@require_meraki_dashboard_key
def get_network_configs():
    """Fetch current RADIUS, DNS, and DHCP configs for selected networks."""
    data = request.json
    org_id = data.get('org_id')
    network_ids = data.get('network_ids', [])
    
    if not org_id:
        return jsonify({"error": "Organization not selected"}), 400
    if not network_ids:
        return jsonify({"error": "No networks selected"}), 400
    
    api_key = get_meraki_dashboard_key()
    dashboard = get_dashboard(api_key)
    
    configs = []
    all_vlans = set()
    
    for net_id in network_ids:
        try:
            # Get network info
            network = api_call(dashboard.networks.getNetwork, net_id)
            if not network:
                continue
                
            net_config = {
                "id": net_id,
                "name": network.get('name', 'Unknown'),
                "productTypes": network.get('productTypes', []),
                "radius": {},
                "vlans": []
            }
            
            # Get RADIUS config if wireless/appliance
            if 'wireless' in network.get('productTypes', []):
                try:
                    ssids = api_call(dashboard.wireless.getNetworkWirelessSsids, net_id)
                    if ssids:
                        for ssid in ssids:
                            if ssid.get('name'):
                                net_config['radius'][f"MR-{ssid.get('name')}"] = {
                                    "authServers": ssid.get('radiusServers', []),
                                    "acctServers": ssid.get('radiusAccountingServers', [])
                                }
                except Exception:
                    pass
            
            if 'appliance' in network.get('productTypes', []):
                try:
                    ssids = api_call(dashboard.appliance.getNetworkApplianceSsids, net_id)
                    if ssids:
                        for ssid in ssids:
                            if ssid.get('name'):
                                net_config['radius'][f"MX-{ssid.get('name')}"] = {
                                    "authServers": ssid.get('radiusServers', []),
                                    "acctServers": ssid.get('radiusAccountingServers', [])
                                }
                except Exception:
                    pass
                
                # Get VLAN configs
                try:
                    vlan_settings = api_call(dashboard.appliance.getNetworkApplianceVlansSettings, net_id)
                    if vlan_settings and vlan_settings.get('vlansEnabled'):
                        vlans = api_call(dashboard.appliance.getNetworkApplianceVlans, net_id)
                        if vlans:
                            for vlan in vlans:
                                vlan_id = vlan.get('id')
                                all_vlans.add(vlan_id)
                                net_config['vlans'].append({
                                    "id": vlan_id,
                                    "name": vlan.get('name', ''),
                                    "dnsNameservers": vlan.get('dnsNameservers', ''),
                                    "dhcpDnsServers": vlan.get('dhcpDnsServers', '')
                                })
                except Exception:
                    pass
            
            configs.append(net_config)
            
        except Exception as e:
            configs.append({
                "id": net_id,
                "name": "Error loading",
                "error": str(e),
                "radius": {},
                "vlans": []
            })
    
    return jsonify({
        "configs": configs,
        "availableVlans": sorted(list(all_vlans))
    })


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


@sync_bp.route('/api/dhcp-sync', methods=['POST'])
@require_meraki_dashboard_key
def start_dhcp_sync():
    data = request.json
    org_id = data.get('org_id')
    selected_ids = data.get('network_ids', [])
    vlan_settings = data.get('vlan_settings', {})  # {vlan_id: {dns_servers, lease_time}}
    
    if not org_id:
        return jsonify({"error": "Organization not selected"}), 400
    if not vlan_settings:
        return jsonify({"error": "No VLAN settings provided"}), 400

    job_id = "dhcp_" + datetime.now().strftime('%Y%m%d_%H%M%S')
    job = SyncJob(job_id, "dhcp")
    job.status = "running"
    with _sync_lock:
        _sync_jobs[job_id] = job

    api_key = get_meraki_dashboard_key()

    def run_dhcp_sync():
        dashboard = get_dashboard(api_key)
        job.log.append(f"Updating {len(vlan_settings)} VLAN(s)")

        networks = api_call(dashboard.organizations.getOrganizationNetworks,
                            org_id, total_pages='all')
        mx_networks = [n for n in networks if 'appliance' in n.get('productTypes', [])]

        if selected_ids:
            sel = set(selected_ids)
            mx_networks = [n for n in mx_networks if n['id'] in sel]

        job.total = len(mx_networks) * len(vlan_settings)
        job.log.append(f"Syncing across {len(mx_networks)} network(s)")

        progress = 0
        for network in mx_networks:
            if job.cancel_event.is_set():
                break
            net_id, net_name = network['id'], network['name']

            try:
                settings = api_call(dashboard.appliance.getNetworkApplianceVlansSettings, net_id)
                if not settings or not settings.get('vlansEnabled', False):
                    job.skipped.append({"network": net_name, "reason": "VLANs not enabled"})
                    progress += len(vlan_settings)
                    job.progress = progress
                    continue
            except Exception as e:
                job.errors.append({"network": net_name, "error": str(e)})
                progress += len(vlan_settings)
                job.progress = progress
                continue

            try:
                vlans = api_call(dashboard.appliance.getNetworkApplianceVlans, net_id)
                if not vlans:
                    progress += len(vlan_settings)
                    job.progress = progress
                    continue
                vlan_ids = {v['id'] for v in vlans}
            except Exception as e:
                job.errors.append({"network": net_name, "error": str(e)})
                progress += len(vlan_settings)
                job.progress = progress
                continue

            for vlan_id, vlan_config in vlan_settings.items():
                vlan_id = int(vlan_id)
                if vlan_id not in vlan_ids:
                    job.skipped.append({"network": net_name, "reason": f"VLAN {vlan_id} not found"})
                    progress += 1
                    job.progress = progress
                    continue
                
                try:
                    update_params = {}
                    dns_servers_raw = vlan_config.get('dns_servers', '').strip()
                    lease_time = vlan_config.get('lease_time', '').strip()
                    
                    # Default to 4 hours if no lease time specified
                    if not lease_time:
                        lease_time = '4 hours'
                    
                    # Format DNS servers - convert newlines to proper format
                    if dns_servers_raw:
                        # Split by newlines, strip whitespace, filter empty lines
                        dns_list = [ip.strip() for ip in dns_servers_raw.split('\n') if ip.strip()]
                        # Join with newline (Meraki expects newline-separated string)
                        dns_servers = '\n'.join(dns_list)
                        update_params['dhcpDnsServers'] = dns_servers
                    
                    update_params['dhcpLeaseTime'] = lease_time
                    
                    job.log.append(f"  Updating VLAN {vlan_id} with params: {update_params}")
                    api_call(dashboard.appliance.updateNetworkApplianceVlan,
                             net_id, vlan_id, **update_params)
                    update_msg = []
                    if dns_servers_raw:
                        update_msg.append(f"DNS: {', '.join(dns_list)}")
                    update_msg.append(f"Lease: {lease_time}")
                    job.updated.append({"network": net_name, "vlan": vlan_id})
                    job.log.append(f"  ✅ {net_name} — VLAN {vlan_id} ({', '.join(update_msg)})")
                        
                except Exception as e:
                    job.errors.append({"network": net_name, "vlan": vlan_id, "error": str(e)})
                    job.log.append(f"  ❌ {net_name} — VLAN {vlan_id} ERROR: {str(e)}")
                
                progress += 1
                job.progress = progress

        job.status = "complete"
        job.log.append(f"\n{'='*50}")
        job.log.append(f"DHCP Sync Complete — {len(job.updated)} updated, "
                       f"{len(job.skipped)} skipped, {len(job.errors)} errors")

    threading.Thread(target=run_dhcp_sync, daemon=True).start()
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
