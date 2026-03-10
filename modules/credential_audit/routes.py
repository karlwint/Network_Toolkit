"""
Credential Audit & Remediation — Blueprint
Web-based port of Credential_Audit_Tool with multi-protocol scanning.
"""

import asyncio
import socket
import ipaddress
import threading
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Blueprint, render_template, jsonify, request, session
from modules import get_cisco_credentials, require_cisco_creds

audit_bp = Blueprint('audit', __name__, template_folder='../../templates')

_audit_jobs = {}
_audit_lock = threading.Lock()


class AuditJob:
    def __init__(self, job_id):
        self.id = job_id
        self.status = "pending"
        self.phase = ""
        self.progress = 0
        self.total = 0
        self.results = []
        self.log = []
        self.cancel_event = threading.Event()
        self.stats = {"alive": 0, "open_ports": 0, "ssh_vuln": 0,
                      "snmp_vuln": 0, "http_vuln": 0, "total_vuln": 0}

    def to_dict(self):
        return {
            "id": self.id, "status": self.status, "phase": self.phase,
            "progress": self.progress, "total": self.total,
            "results": self.results, "log": self.log[-100:],
            "stats": self.stats,
        }


def check_port_sync(ip, port, timeout=0.3):
    """Synchronous port check."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port)) == 0
        sock.close()
        return result
    except Exception:
        return False


def check_ssh(ip, username, password, enable_secret="", device_type="cisco_ios",
              port=22, timeout=10):
    """Check SSH credential acceptance."""
    result = {"ssh_accessible": False, "ssh_hostname": None,
              "ssh_model": None, "ssh_ios_version": None, "ssh_error": None}
    try:
        from netmiko import ConnectHandler
        device = {
            "device_type": device_type, "host": ip,
            "username": username, "password": password,
            "secret": enable_secret or password,
            "port": port, "timeout": timeout,
            "conn_timeout": timeout, "banner_timeout": timeout,
        }
        with ConnectHandler(**device) as conn:
            conn.enable()
            result["ssh_accessible"] = True
            result["ssh_hostname"] = conn.find_prompt().replace("#", "").replace(">", "").strip()
            try:
                ver = conn.send_command("show version", read_timeout=15)
                for line in ver.splitlines():
                    ll = line.lower()
                    if "cisco" in ll and ("software" in ll or "ios" in ll):
                        result["ssh_ios_version"] = line.strip()[:120]
                        break
                for line in ver.splitlines():
                    if "model number" in line.lower():
                        result["ssh_model"] = line.split(":")[-1].strip()
                        break
            except Exception:
                pass
    except Exception as e:
        ename = type(e).__name__
        if "Authentication" in ename:
            result["ssh_error"] = "Auth rejected"
        elif "Timeout" in ename:
            result["ssh_error"] = "Timeout"
        else:
            result["ssh_error"] = str(e)[:120]
    return result


def check_http_basic(ip, username, password, port=80, use_ssl=False, timeout=8):
    """Check HTTP/HTTPS basic auth."""
    import requests as http_req
    import urllib3
    urllib3.disable_warnings()

    scheme = "https" if use_ssl else "http"
    base_url = f"{scheme}://{ip}" if port in (80, 443) else f"{scheme}://{ip}:{port}"
    proto = "https" if use_ssl else "http"
    result = {f"{proto}_accessible": False, f"{proto}_server": None, f"{proto}_error": None}

    try:
        sess = http_req.Session()
        sess.verify = False
        resp = sess.get(f"{base_url}/", auth=(username, password),
                        timeout=timeout, allow_redirects=True)
        result[f"{proto}_server"] = resp.headers.get("Server", "")[:80]
        if resp.status_code == 200:
            body = resp.text[:2000].lower()
            if "login" not in body[:500]:
                result[f"{proto}_accessible"] = True
        elif resp.status_code == 401:
            result[f"{proto}_error"] = "Auth rejected"
    except http_req.exceptions.ConnectionError:
        result[f"{proto}_error"] = "Connection refused"
    except http_req.exceptions.Timeout:
        result[f"{proto}_error"] = "Timeout"
    except Exception as e:
        result[f"{proto}_error"] = str(e)[:120]
    return result


# ─── Routes ───────────────────────────────────────────────────

@audit_bp.route('/')
def audit_index():
    creds = get_cisco_credentials()
    return render_template('audit/index.html',
                           has_creds=bool(creds['username'] and creds['password']))


@audit_bp.route('/api/scan', methods=['POST'])
@require_cisco_creds
def start_audit():
    """Start a multi-protocol credential audit."""
    data = request.json
    networks = data.get('networks', [])
    protocols = data.get('protocols', ['ssh'])
    tcp_timeout = data.get('tcp_timeout', 0.3)
    proto_timeout = data.get('proto_timeout', 10)
    max_threads = data.get('max_threads', 50)
    device_type = data.get('device_type', 'cisco_ios')

    # Generate IPs
    all_ips = []
    for net in networks:
        try:
            n = ipaddress.ip_network(net.strip(), strict=False)
            all_ips.extend(str(ip) for ip in n.hosts())
        except ValueError:
            all_ips.append(net.strip())

    if not all_ips:
        return jsonify({"error": "No valid IPs"}), 400

    # Determine ports to scan based on selected protocols
    ports_to_scan = set()
    if 'ssh' in protocols:
        ports_to_scan.add(22)
    if 'http' in protocols:
        ports_to_scan.add(80)
    if 'https' in protocols:
        ports_to_scan.add(443)
    if 'snmpv2' in protocols or 'snmpv3' in protocols:
        ports_to_scan.add(161)

    job_id = "audit_" + datetime.now().strftime('%Y%m%d_%H%M%S')
    job = AuditJob(job_id)
    job.total = len(all_ips)
    job.status = "running"
    job.phase = "port_scan"

    with _audit_lock:
        _audit_jobs[job_id] = job

    creds = get_cisco_credentials()

    def run_audit():

        # Phase 1: Port scan
        job.log.append(f"[PHASE 1] Scanning {len(all_ips)} IPs on ports {sorted(ports_to_scan)}")
        ip_open_ports = {}

        scan_tasks = [(ip, port) for ip in all_ips for port in ports_to_scan]
        job.total = len(scan_tasks)

        with ThreadPoolExecutor(max_workers=max_threads) as pool:
            futures = {pool.submit(check_port_sync, ip, port, tcp_timeout): (ip, port)
                       for ip, port in scan_tasks}
            for i, future in enumerate(as_completed(futures), 1):
                if job.cancel_event.is_set():
                    break
                ip, port = futures[future]
                try:
                    if future.result():
                        if ip not in ip_open_ports:
                            ip_open_ports[ip] = []
                        ip_open_ports[ip].append(port)
                except Exception:
                    pass
                job.progress = i

        job.stats["open_ports"] = len(ip_open_ports)
        job.log.append(f"[PHASE 1 DONE] {len(ip_open_ports)} hosts with open ports")

        if job.cancel_event.is_set():
            job.status = "cancelled"
            return

        # Phase 2: Protocol verification
        job.phase = "protocol_check"
        targets = list(ip_open_ports.items())
        job.total = len(targets)
        job.progress = 0

        job.log.append(f"[PHASE 2] Checking credentials on {len(targets)} hosts")

        def check_host(ip, open_ports):
            host_result = {
                "ip": ip, "open_ports": open_ports,
                "vulnerable_protocols": [],
            }
            # SSH
            if 22 in open_ports and 'ssh' in protocols:
                ssh = check_ssh(ip, creds['username'], creds['password'],
                                creds['enable'], device_type, timeout=proto_timeout)
                host_result.update(ssh)
                if ssh['ssh_accessible']:
                    host_result['vulnerable_protocols'].append('SSH')

            # HTTP
            if 80 in open_ports and 'http' in protocols:
                http = check_http_basic(ip, creds['username'], creds['password'],
                                        80, False, proto_timeout)
                host_result.update(http)
                if http.get('http_accessible'):
                    host_result['vulnerable_protocols'].append('HTTP')

            # HTTPS
            if 443 in open_ports and 'https' in protocols:
                https = check_http_basic(ip, creds['username'], creds['password'],
                                         443, True, proto_timeout)
                host_result.update(https)
                if https.get('https_accessible'):
                    host_result['vulnerable_protocols'].append('HTTPS')

            return host_result

        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {pool.submit(check_host, ip, ports): ip
                       for ip, ports in targets}
            for i, future in enumerate(as_completed(futures), 1):
                if job.cancel_event.is_set():
                    break
                try:
                    result = future.result()
                    job.results.append(result)
                    vulns = result['vulnerable_protocols']
                    if vulns:
                        job.stats["total_vuln"] += 1
                        job.log.append(f"  [VULNERABLE] {result['ip']} — "
                                       f"{', '.join(vulns)} "
                                       f"({result.get('ssh_hostname', '')})")
                        if 'SSH' in vulns:
                            job.stats["ssh_vuln"] += 1
                        if 'HTTP' in vulns or 'HTTPS' in vulns:
                            job.stats["http_vuln"] += 1
                    else:
                        job.log.append(f"  [CLEAN] {result['ip']}")
                except Exception as e:
                    job.log.append(f"  [ERROR] {e}")
                job.progress = i

        job.status = "complete"
        job.log.append(f"\n[AUDIT COMPLETE] {job.stats['total_vuln']} vulnerable hosts found")

    thread = threading.Thread(target=run_audit, daemon=True)
    thread.start()
    return jsonify({"job_id": job_id, "total_ips": len(all_ips)})


@audit_bp.route('/api/job/<job_id>')
def get_audit_job(job_id):
    with _audit_lock:
        job = _audit_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job.to_dict())


@audit_bp.route('/api/job/<job_id>/cancel', methods=['POST'])
def cancel_audit_job(job_id):
    with _audit_lock:
        job = _audit_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    job.cancel_event.set()
    return jsonify({"success": True})
