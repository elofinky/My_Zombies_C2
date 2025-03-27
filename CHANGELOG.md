# Changelog - Beta 1.1

## Login System Fixes
- Fixed login screen infinite loading issue
- Implemented fixed secret key for Flask app to maintain session state
- Added auto-filled license key in login form for easier access
- Improved error handling and debugging for authentication issues
- Created a login issue fixer script (`fix_login.py`)

## Client Connection Fixes
- Fixed clients not connecting properly to the server
- Added environment variable support for server IP configuration
- Created a launcher script (`run_client.py`) to simplify connecting clients
- Updated Linux client to use dynamic IP detection
- Updated server to display the correct local IP address for client connections
- Added better logging and error messages for connection issues

## Interface Improvements
- Added "Beta 1.1" flag indicator to the web interface
- Improved server startup information display
- Added clear connection instructions in console output

## Documentation
- Added CLIENT_README.md with detailed connection instructions
- Added troubleshooting section for common connection issues
- Updated instructions for both Windows and Linux clients

## Technical Improvements
- Fixed WebSocket connection URLs in client code
- Ensured server listens on all network interfaces (0.0.0.0)
- Improved error handling for failed connections
- Added automatic reconnection logic 