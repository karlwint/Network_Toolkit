"""
Cisco CLI Tools — Blueprint
Web-based port of ScannerEngine from Cisco_Config_Tool.py.
Provides network scanning, SSH verification, and bulk config push via web UI.
"""

import socket
import ipaddress
import threading
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Blueprint, render_template, jsonify, request, session
from modules import get_cisco_credentials, require_cisco_creds

cisco_bp = Blueprint('cisco', __name__, template_folder='../../templates')

# In-memory job storage (per-session in production, simplified here)
_jobs = {}
_jobs_lock = threading.Lock()


class ScanJob:
    """Represents a running or completed scan/push job."""
    def __init__(self, job_id):
        self.id = job_id
        self.status = "pending"
        self.progress = 0
        self.total = 0
        self.results = []
        self.log = []
        self.cancel_event = threading.Event()

    def to_dict(self):
        return {
            "id": self.id,
            "status": self.status,
            "progress": self.progress,
            "total": self.total,
            "results": self.results,
            "log": self.log[-50:],  # Last 50 log entries
        }


def check_port(ip, port=22, timeout=1):
    """Check if a TCP port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port)) == 0
        sock.close()
        return result
    except Exception:
        return False


def verify_ssh(ip, username, password, enable_secret, device_type="cisco_ios",
               port=22, timeout=10):
    """Verify SSH access and gather device info via Netmiko."""
    result = {
        "ip": ip, "port_open": True, "ssh_accessible": False,
        "hostname": None, "model": None, "ios_version": None, "error": None,
    }
    try:
        from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
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
            prompt = conn.find_prompt()
            result["hostname"] = prompt.replace("#", "").replace(">", "").strip()
            try:
                ver = conn.send_command("show version", read_timeout=15)
                for line in ver.splitlines():
                    ll = line.lower()
                    if "cisco" in ll and ("software" in ll or "ios" in ll):
                        result["ios_version"] = line.strip()[:120]
                        break
                for line in ver.splitlines():
                    if "model number" in line.lower():
                        result["model"] = line.split(":")[-1].strip() if ":" in line else line.strip()
                        break
                if not result["model"]:
                    for line in ver.splitlines():
                        for prefix in ("WS-C", "C9", "C38", "C29", "C1"):
                            if prefix in line:
                                for part in line.split():
                                    if part.startswith(prefix):
                                        result["model"] = part
                                        break
                                if result["model"]:
                                    break
            except Exception:
                pass
    except Exception as e:
        ename = type(e).__name__
        if "Authentication" in ename:
            result["error"] = "Authentication failed"
        elif "Timeout" in ename:
            result["error"] = "Timeout"
        else:
            result["error"] = str(e)[:150]
    return result


def push_config_to_device(ip, username, password, enable_secret, commands,
                          save=True, device_type="cisco_ios", port=22, timeout=10):
    """Push config commands to a single device."""
    result = {
        "ip": ip, "config_pushed": False, "hostname": None,
        "output": None, "error": None,
    }
    try:
        from netmiko import ConnectHandler
        device = {
            "device_type": device_type, "host": ip,
            "username": username, "password": password,
            "secret": enable_secret or password,
            "port": port, "timeout": timeout, "conn_timeout": timeout,
        }
        with ConnectHandler(**device) as conn:
            conn.enable()
            result["hostname"] = conn.find_prompt().replace("#", "").replace(">", "").strip()
            output = conn.send_config_set(commands, read_timeout=30)
            if save:
                output += "\n" + conn.save_config()
            result["output"] = output
            result["config_pushed"] = True
    except Exception as e:
        result["error"] = str(e)[:150]
    return result


# ─── Routes ───────────────────────────────────────────────────

@cisco_bp.route('/')
def cisco_index():
    creds = get_cisco_credentials()
    return render_template('cisco/index.html',
                           has_creds=bool(creds['username'] and creds['password']))


@cisco_bp.route('/api/scan', methods=['POST'])
@require_cisco_creds
def start_scan():
    """Start a network scan job."""
    data = request.json
    networks = data.get('networks', [])
    ssh_port = data.get('ssh_port', 22)
    tcp_timeout = data.get('tcp_timeout', 1)
    max_threads = data.get('max_threads', 50)

    # Generate IPs
    all_ips = []
    for net in networks:
        try:
            n = ipaddress.ip_network(net.strip(), strict=False)
            all_ips.extend(str(ip) for ip in n.hosts())
        except ValueError:
            # Might be a single IP
            all_ips.append(net.strip())

    if not all_ips:
        return jsonify({"error": "No valid IPs to scan"}), 400

    job_id = datetime.now().strftime('%Y%m%d_%H%M%S')
    job = ScanJob(job_id)
    job.total = len(all_ips)
    job.status = "scanning"

    with _jobs_lock:
        _jobs[job_id] = job

    # Capture credentials NOW while in request context
    creds = get_cisco_credentials()

    # Run scan in background
    def run_scan():
        open_hosts = []
        with ThreadPoolExecutor(max_workers=max_threads) as pool:
            futures = {pool.submit(check_port, ip, ssh_port, tcp_timeout): ip
                       for ip in all_ips}
            for i, future in enumerate(as_completed(futures), 1):
                if job.cancel_event.is_set():
                    break
                ip = futures[future]
                try:
                    is_open = future.result()
                    if is_open:
                        open_hosts.append(ip)
                        job.log.append(f"[PORT OPEN] {ip}:{ssh_port}")
                except Exception:
                    pass
                job.progress = i

        job.log.append(f"\n[SCAN COMPLETE] {len(open_hosts)}/{len(all_ips)} hosts with port {ssh_port} open")

        # Phase 2: SSH verify
        if not job.cancel_event.is_set() and open_hosts:
            job.status = "verifying"
            job.progress = 0
            job.total = len(open_hosts)

            with ThreadPoolExecutor(max_workers=10) as pool:
                futures = {pool.submit(verify_ssh, ip, creds['username'],
                                       creds['password'], creds['enable']): ip
                           for ip in open_hosts}
                for i, future in enumerate(as_completed(futures), 1):
                    if job.cancel_event.is_set():
                        break
                    try:
                        result = future.result()
                        job.results.append(result)
                        status = "OK" if result['ssh_accessible'] else "FAIL"
                        job.log.append(f"[SSH {status}] {result['ip']} — "
                                       f"{result.get('hostname') or result.get('error', 'unknown')}")
                    except Exception as e:
                        job.log.append(f"[ERROR] {futures[future]}: {e}")
                    job.progress = i

        job.status = "complete"

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()

    return jsonify({"job_id": job_id, "total_ips": len(all_ips)})


@cisco_bp.route('/api/verify-direct', methods=['POST'])
@require_cisco_creds
def verify_direct():
    """Verify SSH on specific IPs (skip port scan)."""
    data = request.json
    ips = data.get('ips', [])

    if not ips:
        return jsonify({"error": "No IPs provided"}), 400

    job_id = "direct_" + datetime.now().strftime('%Y%m%d_%H%M%S')
    job = ScanJob(job_id)
    job.total = len(ips)
    job.status = "verifying"

    with _jobs_lock:
        _jobs[job_id] = job

    creds = get_cisco_credentials()

    def run_verify():
        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {pool.submit(verify_ssh, ip.strip(), creds['username'],
                                   creds['password'], creds['enable']): ip
                       for ip in ips}
            for i, future in enumerate(as_completed(futures), 1):
                if job.cancel_event.is_set():
                    break
                try:
                    result = future.result()
                    job.results.append(result)
                    status = "OK" if result['ssh_accessible'] else "FAIL"
                    job.log.append(f"[SSH {status}] {result['ip']} — "
                                   f"{result.get('hostname') or result.get('error')}")
                except Exception as e:
                    job.log.append(f"[ERROR] {e}")
                job.progress = i
        job.status = "complete"

    thread = threading.Thread(target=run_verify, daemon=True)
    thread.start()
    return jsonify({"job_id": job_id, "total": len(ips)})


@cisco_bp.route('/api/push-config', methods=['POST'])
@require_cisco_creds
def push_config():
    """Push config commands to accessible switches."""
    data = request.json
    targets = data.get('targets', [])  # List of IPs
    commands = data.get('commands', [])
    save = data.get('save_config', True)

    if not targets or not commands:
        return jsonify({"error": "Targets and commands required"}), 400

    job_id = "push_" + datetime.now().strftime('%Y%m%d_%H%M%S')
    job = ScanJob(job_id)
    job.total = len(targets)
    job.status = "pushing"

    with _jobs_lock:
        _jobs[job_id] = job

    creds = get_cisco_credentials()

    def run_push():
        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {pool.submit(push_config_to_device, ip, creds['username'],
                                   creds['password'], creds['enable'],
                                   commands, save): ip for ip in targets}
            for i, future in enumerate(as_completed(futures), 1):
                if job.cancel_event.is_set():
                    break
                try:
                    result = future.result()
                    job.results.append(result)
                    status = "OK" if result['config_pushed'] else "FAIL"
                    job.log.append(f"[CONFIG {status}] {result['ip']} "
                                   f"({result.get('hostname') or result.get('error')})")
                except Exception as e:
                    job.log.append(f"[ERROR] {e}")
                job.progress = i
        job.status = "complete"

    thread = threading.Thread(target=run_push, daemon=True)
    thread.start()
    return jsonify({"job_id": job_id, "total": len(targets)})


@cisco_bp.route('/api/job/<job_id>')
def get_job(job_id):
    """Poll job status."""
    with _jobs_lock:
        job = _jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job.to_dict())


@cisco_bp.route('/api/job/<job_id>/cancel', methods=['POST'])
def cancel_job(job_id):
    """Cancel a running job."""
    with _jobs_lock:
        job = _jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    job.cancel_event.set()
    return jsonify({"success": True})
