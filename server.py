import socketserver
import threading
import datetime
import csv
import uuid
import re

HOST = 'localhost'
PORT = 5000  # Change this to your desired port
LOG_FILE = 'server_log.csv'
REGEX_PATTERNS = {  # Dictionary to store your regular expressions
    'system_call': r'.*(netstat|ls|pwd).*',
    'security_injection': r'.*(;|\||&).*',  # Basic example, needs refinement
}
ALERT_LEVELS = {  # Map number of matches to alert level (example)
    0: 'Low',
    1: 'Medium',
    2: 'High'
}

REGEX_PATTERNS = {
    'system_call': r'.*(netstat|ls|pwd).*',
    'security_injection': r'.*(;|\||&|`|\\|\'|--|\b(UPDATE|INSERT|DROP|DELETE)\b).*',
    'sql_injection': r".*('|\\|--|\b(UPDATE|INSERT|DROP|DELETE)\b).*",
    'xss_injection': r'.*(<script>|<iframe>|<object>|<embed>|<svg>).*',
    'rfi_inclusion': r'.*(https?://|ftp://).*',
    'path_traversal': r'.*(\.\./|\.\.\\).*',
    'port_scanning': r'.*(nmap|nc|netcat|telnet).*\s+(\d{1,5})',
    'brute_force': r'.*(login|password|username).*',
}


class ConnectionHandler(socketserver.BaseRequestHandler):
    """
    Connection Handler
    """
    def handle(self):
        connection_id = str(uuid.uuid4())  # Generate a unique ID
        log_data = [connection_id, str(datetime.datetime.now())]

        # Receive and log commands from the connection
        commands = []
        while True:
            data = self.request.recv(1024).decode()
            if not data:
                break
            commands.append(data.strip())
            log_data.append(data.strip())  # Log each received command

        # Write connection data to the log file (CSV)
        with open(LOG_FILE, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(log_data)

        # Process received commands (example: basic logging)
        print(f"Connection ID: {connection_id}")
        print(f"Received commands: {', '.join(commands)}")

        # Alert logic based on regex matches (future implementation)
        alert_level = self.check_alerts(commands)  # Placeholder function
        print(f"Alert Level: {alert_level}")

    def check_alerts(self, commands):
        """
        Checks the alerts in the log and assigns the level.
        """
        match_count = 0
        for pattern, regex in REGEX_PATTERNS.items():
            for command in commands:
                if re.search(regex, command):
                    match_count += 1
        return ALERT_LEVELS.get(match_count, 'Unknown')  # Handle no matches


with socketserver.TCPServer((HOST, PORT), ConnectionHandler) as server:
    print(f"Server listening on port {PORT}")
    server.serve_forever()
