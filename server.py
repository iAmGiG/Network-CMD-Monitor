import socketserver
import threading
import datetime
import csv
import uuid
import re
import logging
from logging.handlers import RotatingFileHandler

# Configuration
HOST = '127.0.0.1'
PORT = 5000  # You can choose another port
LOG_FILE = 'server_log.csv'
ALERT_LEVELS = {
    0: 'None',
    1: 'Low',
    2: 'Medium',
    3: 'High',
    4: 'Critical'
}
REGEX_PATTERNS = {
    'system_call': r'.*\b(netstat|ls|pwd)\b.*',
    'security_injection': r'.*[;|\||&|`|\\|\'|\-|\b(UPDATE|INSERT|DROP|DELETE)\b].*',
    'sql_injection': r".*('|\\|--|\b(UPDATE|INSERT|DROP|DELETE)\b).*",
    'xss_injection': r'.*<script>.*|.*<iframe>.*|.*<object>.*|.*<embed>.*|.*<svg>.*',
    'rfi_inclusion': r'.*(https?://|ftp://).*',
    'path_traversal': r'.*(\.\./|\.\.\\).*',
    'port_scanning': r'.*(nmap|nc|netcat|telnet).*\s+(\d{1,5})',
    'brute_force': r'.*(login|password|username).*',
}


def setup_logger():
    """Sets up a logger with rotation."""
    logger = logging.getLogger('CommandLogger')
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(LOG_FILE, maxBytes=10240, backupCount=5)
    formatter = logging.Formatter(
        '%(asctime)s,%(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


logger = setup_logger()


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Handle requests in a separate thread."""
    pass


class ConnectionHandler(socketserver.BaseRequestHandler):
    """
    Handles incoming network connections, logs command data, and evaluates potential threats.
    """

    def handle(self):
        connection_id = str(uuid.uuid4())
        print(f"New connection: {connection_id} from {self.client_address}")
        commands = []
        try:
            while True:
                data = self.request.recv(1024).decode()
                if not data:
                    break
                commands.append(data.strip())
                print(f"Received command: {data.strip()}")
        except Exception as e:
            print(f"Error receiving data: {e}")

        alert_level = self.check_alerts(commands)
        logger.info(f"{connection_id},{','.join(commands)},{alert_level}")

        print(f"Connection closed: {connection_id}")
        print(f"Total commands received: {len(commands)}")
        print(f"Alert Level: {alert_level}")

    def check_alerts(self, commands):
        """
        Checks commands against regex patterns and assigns an alert level based on the number of matches.
        """
        match_count = 0
        for command in commands:
            for pattern_name, regex in REGEX_PATTERNS.items():
                if re.search(regex, command):
                    match_count += 1
                    print(
                        f"Alert triggered by pattern '{pattern_name}': {command}")
                    break  # Optional: break if you want only one match per command to count

        # Determine alert level based on number of matches
        if match_count == 0:
            return 'None'
        elif match_count == 1:
            return 'Low'
        elif match_count <= 3:
            return 'Medium'
        elif match_count <= 5:
            return 'High'
        else:
            return 'Critical'


if __name__ == "__main__":
    server = ThreadedTCPServer((HOST, PORT), ConnectionHandler)
    print(f"Server running on {HOST}:{PORT}")
    server.serve_forever()
