# zombies Client Setup and Connection Guide

## Prerequisites
- Python 3.6+
- Required Python packages:
  - websocket-client
  - Crypto (pycryptodome)
  - psutil (Windows only)
  - secretstorage (Linux only)
  - pywin32 (Windows only)

## Installation

1. Install required packages:

```bash
# If you encounter issues with websocket:
pip uninstall websocket websocket-client -y
pip install websocket-client

# Other packages
pip install pycryptodome psutil
```

For Windows:
```bash
pip install pywin32
```

For Linux:
```bash
pip install secretstorage
```

## Connecting to the Server

### Method 1: Using the Easy Launcher (Recommended)

1. Start the server first (make sure it's running)
2. Run the launcher script:

```bash
python run_client.py
```

3. When prompted, enter the server's IP address (shown in the server console)

### Method 2: Manual Connection

1. Set the environment variable with the server's IP:

On Windows (CMD):
```
set SERVER_IP=192.168.1.x
```

On Windows (PowerShell):
```
$env:SERVER_IP="192.168.1.x"
```

On Linux/Mac:
```
export SERVER_IP=192.168.1.x
```

2. Run the appropriate client for your operating system:

For Windows:
```
python Client/win_client.py
```

For Linux:
```
python Client/client.py
```

## Troubleshooting

If you're having connection issues:

1. Ensure the server is running first
2. Use the correct IP address of the server (check the server console)
3. Make sure there are no firewalls blocking the connection
4. Check that port 8000 is open on the server
5. Run the client with debugging enabled to see more detailed logs: 