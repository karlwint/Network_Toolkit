"""
Client Locator — Find clients by MAC/IP/Hostname and map topology
Uses hub route tables to quickly identify spoke networks before searching
"""

import re
import os
import socket
import subprocess
import ipaddress
from flask import Blueprint, render_template, request, jsonify
from modules import (
    meraki_api_call, BASE_URL, get_cisco_credentials,
    require_meraki_key, require_cisco_creds
)
from netmiko import ConnectHandler

client_locator_bp = Blueprint('client_locator', __name__)


# ─── Hub Configuration ────────────────────────────────────────────

HUB_DEVICES = {
    'HAE': [
        {'name': 'HAE-Hub-01', 'serial': 'Q2TW-C7CG-WD5N'},
        {'name': 'HAE-AWS_Hub01', 'serial': 'Q2CZ-47DP-PUD4'},
        {'name': 'HAE-AWS_Hub02', 'serial': 'Q2CZ-2XEW-6NCN'},
    ],
    'HII': [
        {'name': 'HII-Hub-01', 'serial': 'Q2TW-4P9B-6WFX'},
        {'name': 'HII-AWS_Hub01', 'serial': 'Q2CZ-LZLL-3L36'},
        {'name': 'HII-AWS_Hub02', 'serial': 'Q2CZ-4EWK-GRJ3'},
    ]
}


# ─── Helper Functions ─────────────────────────────────────────────

def normalize_mac(mac):
    """Normalize MAC address to standard format (XX:XX:XX:XX:XX:XX)."""
    if not mac:
        return None
    # Remove all separators and convert to uppercase
    clean = re.sub(r'[.:\-\s]', '', mac.upper())
    if len(clean) != 12:
        return None
    # Insert colons
    return ':'.join(clean[i:i+2] for i in range(0, 12, 2))


def extract_ip_from_query(query):
    """Extract IP address from query string."""
    # Match IPv4 pattern
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    match = re.search(ip_pattern, query)
    return match.group(0) if match else None


def get_oui_vendor(mac):
    """Lookup vendor from MAC OUI (first 3 octets)."""
    if not mac:
        return "Unknown"
    try:
        oui = mac.replace(':', '')[:6].upper()
        # Simple vendor lookup - extend this with a proper OUI database if needed
        common_vendors = {
            '00D0BA': 'Apple',
            '001B63': 'Apple', 
            '00506C': 'Apple',
            '001C0E': 'Cisco',
            '0050F2': 'Microsoft',
            '00E04C': 'Realtek',
            '0090FB': 'Cisco Meraki',
        }
        return common_vendors.get(oui, f"Unknown (OUI: {oui})")
    except Exception:
        return "Unknown"


def test_port_open(ip, port, timeout=1):
    """Test if a TCP port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def ping_host(ip, count=2, timeout=2):
    """Ping a host and return status + latency."""
    try:
        # Use subprocess for cross-platform ping
        param = '-n' if os.name == 'nt' else '-c'
        timeout_param = '-w' if os.name == 'nt' else '-W'
        
        cmd = ['ping', param, str(count), timeout_param, str(timeout * 1000), ip]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        
        if result.returncode == 0:
            # Extract latency from output (simplified)
            output = result.stdout
            time_match = re.search(r'time[=<](\d+\.?\d*)', output, re.IGNORECASE)
            latency = float(time_match.group(1)) if time_match else None
            return {"reachable": True, "latency_ms": latency}
        return {"reachable": False, "latency_ms": None}
    except Exception as e:
        return {"reachable": False, "error": str(e)}


def find_spoke_from_ip(ip, org_name):
    """Query hub route tables (static + learned) to identify which spoke network contains this IP."""
    hubs = HUB_DEVICES.get(org_name, [])
    
    for hub in hubs:
        try:
            target_ip = ipaddress.ip_address(ip)
            all_routes = []
            
            # Get static routes
            try:
                static_routes = meraki_api_call('GET', 
                    f"{BASE_URL}/devices/{hub['serial']}/appliance/uplinks/staticRoutes"
                )
                all_routes.extend(static_routes)
            except Exception:
                pass
            
            # Get BGP learned routes
            try:
                bgp_routes = meraki_api_call('GET',
                    f"{BASE_URL}/devices/{hub['serial']}/appliance/uplinks/bgp/routes"
                )
                all_routes.extend(bgp_routes)
            except Exception:
                pass
            
            # Check if IP falls within any route's subnet
            for route in all_routes:
                subnet_str = route.get('subnet')
                if subnet_str:
                    try:
                        network = ipaddress.ip_network(subnet_str, strict=False)
                        if target_ip in network:
                            # Found the spoke network
                            return {
                                'hub': hub['name'],
                                'hub_serial': hub['serial'],
                                'subnet': subnet_str,
                                'next_hop': route.get('gatewayIp') or route.get('nextHop'),
                            }
                    except Exception:
                        continue
        except Exception:
            continue
    
    return None


def search_network_for_client(network_id, query, is_mac=False):
    """Search a specific Meraki network for a client."""
    try:
        # Get clients from this network
        clients = meraki_api_call('GET', 
            f"{BASE_URL}/networks/{network_id}/clients",
            params={'timespan': 86400}  # Last 24 hours
        )
        
        results = []
        for client in clients:
            # Check if query matches
            match = False
            if is_mac:
                match = query.lower() in client.get('mac', '').lower()
            else:
                # Search IP or description
                match = (query.lower() in client.get('ip', '').lower() or
                        query.lower() in client.get('description', '').lower())
            
            if match:
                # Get device info
                device_info = {}
                if client.get('recentDeviceSerial'):
                    try:
                        device = meraki_api_call('GET',
                            f"{BASE_URL}/devices/{client['recentDeviceSerial']}"
                        )
                        device_info = {
                            'name': device.get('name'),
                            'model': device.get('model'),
                            'serial': device.get('serial'),
                            'management_ip': device.get('lanIp'),
                        }
                    except Exception:
                        pass
                
                results.append({
                    'source': 'meraki',
                    'network_id': network_id,
                    'mac': client.get('mac'),
                    'ip': client.get('ip'),
                    'description': client.get('description', ''),
                    'vlan': client.get('vlan'),
                    'last_seen': client.get('lastSeen'),
                    'device': device_info,
                    'switch_port': client.get('switchport'),
                })
        
        return results
    except Exception as e:
        return []


def get_org_networks(org_id):
    """Get all networks for an organization."""
    try:
        return meraki_api_call('GET', f"{BASE_URL}/organizations/{org_id}/networks")
    except Exception:
        return []


def search_cisco_switches(mac, switches):
    """Search for MAC address on Cisco switches via SSH."""
    if not switches:
        return []
    
    creds = get_cisco_credentials()
    normalized_mac = normalize_mac(mac)
    
    # Convert to various formats Cisco might use
    mac_formats = [
        normalized_mac,  # XX:XX:XX:XX:XX:XX
        normalized_mac.replace(':', ''),  # XXXXXXXXXXXX
        '.'.join([normalized_mac.replace(':', '')[i:i+4] for i in range(0, 12, 4)]),  # XXXX.XXXX.XXXX
    ]
    
    results = []
    
    for switch_ip in switches:
        try:
            device = {
                'device_type': 'cisco_ios',
                'host': switch_ip,
                'username': creds['username'],
                'password': creds['password'],
                'secret': creds['enable'],
            }
            
            with ConnectHandler(**device) as conn:
                conn.enable()
                
                # Get hostname
                hostname_output = conn.send_command('show running-config | include hostname')
                hostname = hostname_output.split()[-1] if hostname_output else switch_ip
                
                # Search MAC table
                for mac_fmt in mac_formats:
                    output = conn.send_command(f'show mac address-table | include {mac_fmt}')
                    if output and 'DYNAMIC' in output.upper():
                        # Parse output (format: VLAN MAC_ADDR TYPE PORTS)
                        lines = output.strip().split('\n')
                        for line in lines:
                            parts = line.split()
                            if len(parts) >= 4:
                                vlan = parts[0]
                                interface = parts[-1]
                                
                                # Get interface status
                                int_output = conn.send_command(f'show interface {interface}')
                                
                                # Parse interface details
                                status = "up" if "up" in int_output.lower() else "down"
                                speed_match = re.search(r'(\d+[MG]b/s)', int_output)
                                speed = speed_match.group(1) if speed_match else "Unknown"
                                
                                results.append({
                                    'source': 'cisco',
                                    'switch_ip': switch_ip,
                                    'switch_name': hostname,
                                    'interface': interface,
                                    'vlan': vlan,
                                    'status': status,
                                    'speed': speed,
                                })
                                break
                        if results:
                            break
        except Exception as e:
            continue
    
    return results


def get_cdp_lldp_neighbors(switch_ip):
    """Get CDP and LLDP neighbors from a switch."""
    creds = get_cisco_credentials()
    neighbors = []
    
    try:
        device = {
            'device_type': 'cisco_ios',
            'host': switch_ip,
            'username': creds['username'],
            'password': creds['password'],
            'secret': creds['enable'],
        }
        
        with ConnectHandler(**device) as conn:
            conn.enable()
            
            # Try CDP first
            try:
                cdp_output = conn.send_command('show cdp neighbors detail')
                if cdp_output:
                    # Parse CDP neighbors
                    entries = cdp_output.split('-------------------------')
                    for entry in entries:
                        if 'Device ID' in entry:
                            device_id = re.search(r'Device ID:\s*(.+)', entry)
                            ip_match = re.search(r'IP address:\s*(.+)', entry)
                            platform = re.search(r'Platform:\s*(.+?),', entry)
                            local_int = re.search(r'Interface:\s*(.+?),', entry)
                            remote_int = re.search(r'Port ID.*:\s*(.+)', entry)
                            
                            if device_id:
                                neighbors.append({
                                    'protocol': 'CDP',
                                    'device_id': device_id.group(1).strip(),
                                    'ip_address': ip_match.group(1).strip() if ip_match else None,
                                    'platform': platform.group(1).strip() if platform else None,
                                    'local_interface': local_int.group(1).strip() if local_int else None,
                                    'remote_interface': remote_int.group(1).strip() if remote_int else None,
                                })
            except Exception:
                pass
            
            # Try LLDP
            try:
                lldp_output = conn.send_command('show lldp neighbors detail')
                if lldp_output:
                    # Parse LLDP neighbors (similar to CDP)
                    entries = lldp_output.split('------------------------------------------------')
                    for entry in entries:
                        if 'System Name' in entry:
                            sys_name = re.search(r'System Name:\s*(.+)', entry)
                            ip_match = re.search(r'Management Address.*:\s*(.+)', entry)
                            local_int = re.search(r'Local Intf:\s*(.+)', entry)
                            remote_int = re.search(r'Port id:\s*(.+)', entry)
                            
                            if sys_name:
                                neighbors.append({
                                    'protocol': 'LLDP',
                                    'device_id': sys_name.group(1).strip(),
                                    'ip_address': ip_match.group(1).strip() if ip_match else None,
                                    'platform': None,
                                    'local_interface': local_int.group(1).strip() if local_int else None,
                                    'remote_interface': remote_int.group(1).strip() if remote_int else None,
                                })
            except Exception:
                pass
    
    except Exception as e:
        pass
    
    return neighbors


# ─── Routes ────────────────────────────────────────────────────────

@client_locator_bp.route('/')
def locator_index():
    """Client Locator main page."""
    return render_template('client_locator/index.html')


@client_locator_bp.route('/api/search', methods=['POST'])
@require_meraki_key
def search_client():
    """Smart search - uses hub route tables to find spoke network, then queries that network's clients."""
    data = request.json
    query = data.get('query', '').strip()
    
    if not query:
        return jsonify({"error": "Search query required"}), 400
    
    results = {
        'query': query,
        'meraki': [],
        'cisco': [],
        'client_info': None,
        'search_path': [],
    }
    
    # Extract IP if present
    ip_address = extract_ip_from_query(query)
    normalized_mac = normalize_mac(query)
    
    try:
        results['search_path'].append("Getting organizations...")
        orgs = meraki_api_call('GET', f"{BASE_URL}/organizations")
        results['search_path'].append(f"Found {len(orgs)} orgs")
        
        # If we have an IP, use hub routing to find the spoke network
        if ip_address:
            results['search_path'].append(f"IP detected: {ip_address}")
            
            for org in orgs:
                org_name = 'HAE' if 'HAE' in org['name'] else 'HII' if 'HII' in org['name'] else None
                
                if org_name:
                    results['search_path'].append(f"Querying {org_name} hub routes")
                    spoke_info = find_spoke_from_ip(ip_address, org_name)
                    
                    if spoke_info:
                        results['search_path'].append(f"Route found via {spoke_info['hub']}: {spoke_info['subnet']}")
                        
                        # Now find which network has this subnet configured
                        results['search_path'].append(f"Getting networks for org {org['name']}")
                        networks = get_org_networks(org['id'])
                        results['search_path'].append(f"Found {len(networks)} networks")
                        
                        target_network = None
                        
                        for network in networks:
                            try:
                                results['search_path'].append(f"Checking VLANs for {network['name']}")
                                
                                # Get network's subnets
                                subnets = meraki_api_call('GET', 
                                    f"{BASE_URL}/networks/{network['id']}/appliance/vlans"
                                )
                                
                                results['search_path'].append(f"Found {len(subnets)} VLANs in {network['name']}")
                                
                                # Check if our spoke subnet matches any VLAN subnet
                                for vlan in subnets:
                                    if vlan.get('subnet') == spoke_info['subnet']:
                                        target_network = network
                                        results['search_path'].append(f"Matched network: {network['name']}")
                                        break
                                
                                if target_network:
                                    break
                            except Exception as e:
                                results['search_path'].append(f"VLAN query failed for {network['name']}: {str(e)}")
                                continue
                        
                        # Search clients in the target network
                        if target_network:
                            results['search_path'].append(f"Searching clients in {target_network['name']}")
                            network_results = search_network_for_client(
                                target_network['id'], 
                                ip_address, 
                                is_mac=False
                            )
                            
                            if network_results:
                                for nr in network_results:
                                    nr['network_name'] = target_network['name']
                                results['meraki'] = network_results
                                results['search_path'].append(f"Client found!")
                                break
                            else:
                                results['search_path'].append(f"No client found in {target_network['name']}")
                        else:
                            results['search_path'].append(f"Could not match spoke subnet to any network")
        
        # Fallback: search all networks if no IP or route lookup failed
        if not results['meraki']:
            results['search_path'].append("Fallback: Searching all networks")
            
            for org in orgs:
                networks = get_org_networks(org['id'])
                results['search_path'].append(f"Searching {len(networks)} networks in {org['name']}")
                
                for network in networks:
                    network_results = search_network_for_client(
                        network['id'], 
                        query, 
                        is_mac=bool(normalized_mac)
                    )
                    
                    if network_results:
                        for nr in network_results:
                            nr['network_name'] = network['name']
                        results['meraki'].extend(network_results)
                        results['search_path'].append(f"Found in {network['name']}")
                        break
                
                if results['meraki']:
                    break
        
        # Extract MAC from results if not already normalized
        if results['meraki'] and not normalized_mac:
            normalized_mac = results['meraki'][0].get('mac')
        
        # Build unified client info
        if results['meraki']:
            source = results['meraki'][0]
            results['client_info'] = {
                'mac': normalized_mac or source.get('mac'),
                'ip': source.get('ip') or ip_address,
                'vendor': get_oui_vendor(normalized_mac or source.get('mac')),
                'vlan': source.get('vlan'),
                'last_seen': source.get('last_seen'),
            }
            
            # Now search Cisco switches using device management IP
            if normalized_mac:
                creds = get_cisco_credentials()
                if creds['username'] and creds['password']:
                    mgmt_ip = source.get('device', {}).get('management_ip')
                    
                    if mgmt_ip:
                        results['search_path'].append(f"Searching Cisco switch: {mgmt_ip}")
                        cisco_results = search_cisco_switches(normalized_mac, [mgmt_ip])
                        results['cisco'] = cisco_results
        
        results['search_path'].append("Search complete")
        return jsonify(results)
    
    except Exception as e:
        import traceback
        results['search_path'].append(f"EXCEPTION: {str(e)}")
        results['search_path'].append(traceback.format_exc())
        return jsonify({"error": str(e), "search_path": results['search_path']}), 500


@client_locator_bp.route('/api/topology', methods=['POST'])
@require_cisco_creds
def build_topology():
    """Build network topology from a starting switch."""
    data = request.json
    start_ip = data.get('switch_ip')
    max_depth = data.get('max_depth', 3)
    
    if not start_ip:
        return jsonify({"error": "Switch IP required"}), 400
    
    try:
        topology = {
            'nodes': [],
            'edges': [],
        }
        
        visited = set()
        queue = [(start_ip, 0)]  # (ip, depth)
        
        while queue and len(visited) < 50:  # Safety limit
            current_ip, depth = queue.pop(0)
            
            if current_ip in visited or depth > max_depth:
                continue
            
            visited.add(current_ip)
            
            # Add current node
            topology['nodes'].append({
                'id': current_ip,
                'label': current_ip,
                'depth': depth,
            })
            
            # Get neighbors
            neighbors = get_cdp_lldp_neighbors(current_ip)
            
            for neighbor in neighbors:
                neighbor_ip = neighbor.get('ip_address')
                if neighbor_ip:
                    # Add edge
                    topology['edges'].append({
                        'from': current_ip,
                        'to': neighbor_ip,
                        'label': f"{neighbor['local_interface']} → {neighbor['remote_interface']}",
                        'protocol': neighbor['protocol'],
                    })
                    
                    # Queue neighbor for exploration
                    if neighbor_ip not in visited:
                        queue.append((neighbor_ip, depth + 1))
        
        return jsonify(topology)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@client_locator_bp.route('/api/services', methods=['POST'])
def check_services():
    """Check which services are available on an IP."""
    data = request.json
    ip = data.get('ip')
    
    if not ip:
        return jsonify({"error": "IP address required"}), 400
    
    try:
        services = {
            'ip': ip,
            'ping': ping_host(ip),
            'ssh': test_port_open(ip, 22, timeout=2),
            'http': test_port_open(ip, 80, timeout=2),
            'https': test_port_open(ip, 443, timeout=2),
            'rdp': test_port_open(ip, 3389, timeout=2),
        }
        
        return jsonify(services)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500
