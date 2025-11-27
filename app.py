from flask import Flask, jsonify, request, send_from_directory, Response
from flask_cors import CORS
import json
import os
from pathlib import Path
from datetime import datetime
import subprocess
import requests

app = Flask(__name__, static_folder='build', static_url_path='')
CORS(app)

# ---------- PATHS / CONSTANTS ----------

BASE_DIR = Path(__file__).resolve().parent
LOGS_DIR = BASE_DIR / 'logs'
CONFIGS_DIR = BASE_DIR / 'configs'
HONEYPOTS_DIR = BASE_DIR / 'honeypots'

PROTOCOLS = ['telnet', 'ssh', 'http', 'mqtt', 'dnp3', 'coap', 'modbus']

# Simple in-memory tracking of running honeypots
running_honeypots = {}

# IP Geolocation cache
ip_location_cache = {}


# ---------- UTILITIES ----------

def get_ip_location(ip):
  """Get location data for an IP address using a simple cache."""
  if ip in ip_location_cache:
    return ip_location_cache[ip]

  try:
    # Using ip-api.com (free tier)
    response = requests.get(
      f'http://ip-api.com/json/{ip}?fields=status,lat,lon,country,city',
      timeout=2
    )
    if response.status_code == 200:
      data = response.json()
      if data.get('status') == 'success':
        location = {
          'lat': data.get('lat', 0),
          'lon': data.get('lon', 0),
          'country': data.get('country', 'Unknown'),
          'city': data.get('city', 'Unknown')
        }
        ip_location_cache[ip] = location
        return location
  except Exception:
    pass

  return {'lat': 0, 'lon': 0, 'country': 'Unknown', 'city': 'Unknown'}


def parse_log_file(log_file):
  """
  Parse a .logs file and return entries.

  We expect typical Python logging format:
    "time - LEVEL - <json or text>"

  If the trailing part is JSON, we parse it; otherwise we skip.
  """
  entries = []
  try:
    with open(log_file, 'r') as f:
      for line in f:
        line = line.strip()
        if not line:
          continue

        entry = None
        # Try full line as JSON
        try:
          entry = json.loads(line)
        except Exception:
          # Try to parse part after the last ' - '
          if ' - ' in line:
            try:
              entry = json.loads(line.split(' - ', maxsplit=2)[-1])
            except Exception:
              entry = None

        if isinstance(entry, dict):
          entries.append(entry)
  except Exception:
    pass
  return entries


def parse_session_file(session_file):
  """
  Parse a session JSON file produced by ssh.py-style scripts.

  ssh.py saves JSON like:
  {
    "session_info": {...},
    "auth_attempts": [...],
    "activity": [...]
  }
  """
  try:
    with open(session_file, 'r') as f:
      data = json.load(f)
  except Exception:
    return []

  entries = []

  if isinstance(data, dict):
    session_info = data.get('session_info', {})

    # Activity entries (commands, connection, disconnect, etc.)
    activity = data.get('activity', [])
    if isinstance(activity, list):
      for item in activity:
        if isinstance(item, dict):
          entry = dict(item)
          entry.setdefault('session', session_info)
          entries.append(entry)

    # Auth attempts
    auth_attempts = data.get('auth_attempts', [])
    if isinstance(auth_attempts, list):
      for item in auth_attempts:
        if isinstance(item, dict):
          entry = dict(item)
          entry.setdefault('session', session_info)
          entry.setdefault('type', 'auth')
          entries.append(entry)

  elif isinstance(data, list):
    # Fallback: treat as a list of dict events
    entries = [e for e in data if isinstance(e, dict)]

  return entries


def get_all_logs():
  """
  Get all honeypot logs.

  Pattern (for every protocol honeypot, like ssh.py):
    - Main log file: logs/<protocol>.logs
      (contains python logging lines, some of which are JSON)
    - Session logs: logs/session_*.json
      (same structure for all protocols; may or may not include 'protocol')
  """
  all_logs = []

  # 1) Main log files: logs/<protocol>.logs
  for protocol in PROTOCOLS:
    log_path = LOGS_DIR / f'{protocol}.logs'
    if log_path.exists():
      entries = parse_log_file(log_path)
      for entry in entries:
        if isinstance(entry, dict):
          entry['protocol'] = protocol
          if 'ip' in entry:
            entry['location'] = get_ip_location(entry['ip'])
          all_logs.append(entry)

  # 2) Session files: logs/session_*.json (protocol-agnostic in filename)
  #    If the honeypot scripts themselves include a 'protocol' field,
  #    we use it; otherwise we set 'protocol' to 'unknown'.
  for session_file in LOGS_DIR.glob('session_*.json'):
    session_data = parse_session_file(session_file)
    if session_data:
      for entry in session_data:
        if isinstance(entry, dict):
          # Derive protocol if present in entry/session; else mark unknown
          protocol = entry.get('protocol')
          if not protocol:
            session_info = entry.get('session', {})
            protocol = session_info.get('protocol', 'unknown')
          entry['protocol'] = protocol

          # Attach location if we have an IP
          ip = entry.get('ip') or entry.get('session', {}).get('ip')
          if ip:
            entry['ip'] = ip
            entry['location'] = get_ip_location(ip)

          all_logs.append(entry)

  # Sort by timestamp (ISO8601 string) descending
  def ts_key(x):
    return x.get('timestamp', '')

  all_logs.sort(key=ts_key, reverse=True)
  return all_logs


def calculate_stats(logs):
  """Calculate statistics from logs."""
  unique_ips = set()
  protocol_counts = {}
  command_count = 0

  for log in logs:
    if 'ip' in log:
      unique_ips.add(log['ip'])

    protocol = log.get('protocol', 'unknown')
    protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

    if log.get('type') == 'command':
      command_count += 1

  active_honeypots = len(running_honeypots)

  return {
    'totalAttacks': len(logs),
    'uniqueIPs': len(unique_ips),
    'activeHoneypots': active_honeypots,
    'commandsLogged': command_count,
    'protocolCounts': protocol_counts
  }


def get_default_config(protocol):
  """
  Default config for a protocol, matching ssh.py pattern:

  - config path in honeypot: ../configs/<protocol>.json
  - log_directory (relative to honeypot script): "../logs"
  - log_file: "<protocol>.logs"
  """
  base_config = {
    'host': '0.0.0.0',
    'hostname': f'{protocol}-honeypot',
    'allow_all_logins': True,
    'allow_pubkey_auth': True,   # relevant for ssh-like honeypots
    'log_directory': '../logs',  # relative to honeypot script
    'log_file': f'{protocol}.logs',
    'valid_credentials': {
      'admin': 'admin',
      'root': 'toor',
      'user': 'password'
    }
  }

  # Protocol-specific defaults (ports)
  port_map = {
    'telnet': 2323,
    'ssh': 2222,
    'http': 8080,
    'mqtt': 1883,
    'dnp3': 20000,
    'coap': 5683,
    'modbus': 502
  }
  base_config['port'] = port_map.get(protocol, 9999)

  # Telnet/SSH-like extras
  if protocol in ['telnet', 'ssh']:
    base_config['banner'] = f'Welcome to {protocol.upper()} Server\n\n'
    base_config['filesystem'] = {
      '/': ['bin', 'etc', 'home', 'var', 'usr', 'tmp'],
      '/home': ['user'],
      '/home/user': ['documents', 'downloads', '.bash_history'],
      '/etc': ['passwd', 'shadow', 'hosts'],
      '/var': ['log', 'www'],
      '/tmp': []
    }
    base_config['files'] = {
      '/etc/passwd': (
        'root:x:0:0:root:/root:/bin/bash\n'
        'user:x:1000:1000::/home/user:/bin/bash'
      ),
      '/etc/hosts': '127.0.0.1 localhost\n192.168.1.1 router'
    }

  return base_config


# ---------- API ROUTES ----------

@app.route('/api/logs')
def api_get_logs():
  """Get all honeypot logs."""
  logs = get_all_logs()
  return jsonify(logs)


@app.route('/api/stats')
def api_get_stats():
  """Get dashboard statistics."""
  logs = get_all_logs()
  stats = calculate_stats(logs)
  return jsonify(stats)


@app.route('/api/configs')
def api_get_configs():
  """Get all honeypot configurations."""
  configs = {}

  for protocol in PROTOCOLS:
    config_file = CONFIGS_DIR / f'{protocol}.json'
    if config_file.exists():
      try:
        with open(config_file, 'r') as f:
          configs[protocol] = json.load(f)
      except Exception:
        configs[protocol] = {}
    else:
      configs[protocol] = get_default_config(protocol)

  return jsonify(configs)


@app.route('/api/configs/<protocol>', methods=['GET', 'PUT'])
def api_handle_config(protocol):
  """Get or update a specific protocol configuration."""
  protocol = protocol.lower()
  config_file = CONFIGS_DIR / f'{protocol}.json'

  if request.method == 'GET':
    if config_file.exists():
      with open(config_file, 'r') as f:
        return jsonify(json.load(f))
    return jsonify(get_default_config(protocol))

  elif request.method == 'PUT':
    config_data = request.json
    CONFIGS_DIR.mkdir(exist_ok=True)
    with open(config_file, 'w') as f:
      json.dump(config_data, f, indent=2)
    return jsonify({'success': True})


@app.route('/api/status')
def api_get_status():
  """Get status of all honeypots."""
  return jsonify(running_honeypots)


@app.route('/api/honeypot/<protocol>/start', methods=['POST'])
def api_start_honeypot(protocol):
  """Start a honeypot process for the given protocol."""
  protocol = protocol.lower()

  if protocol in running_honeypots:
    return jsonify({'error': 'Honeypot already running'}), 400

  honeypot_script = HONEYPOTS_DIR / f'{protocol}.py'
  if not honeypot_script.exists():
    return jsonify({'error': 'Honeypot script not found'}), 404

  try:
    # Start the honeypot in a separate process.
    # The honeypot script itself will read ../configs/<protocol>.json
    process = subprocess.Popen(
      ['python3', str(honeypot_script)],
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
      cwd=HONEYPOTS_DIR  # 👈 key fix: make ../logs and ../configs resolve to main/logs & main/configs
    )
    running_honeypots[protocol] = True

    return jsonify({'success': True, 'message': f'{protocol} honeypot started'})
  except Exception as e:
    return jsonify({'error': str(e)}), 500


@app.route('/api/honeypot/<protocol>/stop', methods=['POST'])
def api_stop_honeypot(protocol):
  """Stop a honeypot (status only; no PID kill logic here)."""
  protocol = protocol.lower()

  if protocol not in running_honeypots:
    return jsonify({'error': 'Honeypot not running'}), 400

  try:
    # In real deployment, track & kill the process by PID.
    del running_honeypots[protocol]
    return jsonify({'success': True, 'message': f'{protocol} honeypot stopped'})
  except Exception as e:
    return jsonify({'error': str(e)}), 500


@app.route('/api/raw-logs')
def api_raw_logs():
  """
  Return raw contents of the main honeypot log file for a protocol.

  Pattern (ssh.py-style for all):
    logs/<protocol>.logs   e.g. logs/ssh.logs
  """
  protocol = request.args.get('protocol', 'ssh').lower()
  log_path = LOGS_DIR / f'{protocol}.logs'

  if not log_path.exists():
    return (
      f"No log file found for protocol '{protocol}' at {log_path}",
      404
    )

  try:
    content = log_path.read_text(errors='ignore')
  except Exception as e:
    return (f"Error reading log file: {e}", 500)

  return Response(content, mimetype='text/plain')


# ---------- FRONTEND (React build) ----------

@app.route('/')
def serve_frontend():
  return send_from_directory(app.static_folder, 'index.html')


@app.route('/<path:path>')
def serve_static(path):
  if os.path.exists(os.path.join(app.static_folder, path)):
    return send_from_directory(app.static_folder, path)
  return send_from_directory(app.static_folder, 'index.html')


# ---------- MAIN ----------

if __name__ == '__main__':
  # Ensure base dirs exist
  LOGS_DIR.mkdir(exist_ok=True)
  CONFIGS_DIR.mkdir(exist_ok=True)

  print("=" * 60)
  print("IoT Honeypot Management System")
  print("=" * 60)
  print("Dashboard: http://localhost:5000")
  print("API Base: http://localhost:5000/api")
  print("=" * 60)

  app.run(host='0.0.0.0', port=5000, debug=True)

