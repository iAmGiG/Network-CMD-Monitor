import socket
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
    """Sets up a logger that writes to a CSV file."""
    logger = logging.getLogger('CommandLogger')
    logger.setLevel(logging.INFO)

    # Create a file handler for writing to the CSV file
    file_handler = logging.FileHandler(LOG_FILE, mode='a')
    file_handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(file_handler)

    # Create a streaming handler for console output
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
    logger.addHandler(console_handler)

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
        self.request.settimeout(100)  # Set timeout for this connection

        connection_id = str(uuid.uuid4())
        print(f"New connection: {connection_id} from {self.client_address}")
        commands = []
        try:
            while True:
                data = self.request.recv(1024).decode()
                if not data:
                    break
                command = data.strip()
                commands.append(command)
                print(f"Received command: {command}")
        except socket.timeout:
            print(f"Connection {connection_id} timed out after 100 seconds of inactivity.")
        except Exception as e:
            print(f"Error receiving data: {e}")

        alert_level = self.check_alerts(commands)
        print(f"Connection closed: {connection_id}")
        print(f"Total commands received: {len(commands)}")
        print(f"Alert Level: {alert_level}")

        # Log all commands in a single line, followed by the alert level
        logger.info(f"{connection_id},{datetime.datetime.now()},'{' '.join(commands)}',{alert_level}")

    def check_alerts(self, commands):
        """
        Checks commands against regex patterns and assigns an alert level based on the number of matches.
        """
        match_count = 0
        for command in commands:
            for pattern_name, regex in REGEX_PATTERNS.items():
                if re.search(regex, command):
                    match_count += 1
                    print(f"Alert triggered by pattern '{pattern_name}': {command}")
                    break  # Optional: break if you want only one match per command to count

        # Determine alert level based on number of matches
        alert_level = ALERT_LEVELS.get(match_count, 'Unknown')
        return alert_level

if __name__ == "__main__":
    server = ThreadedTCPServer((HOST, PORT), ConnectionHandler)
    print(f"Server running on {HOST}:{PORT}")
    with server:
        ip, port = server.server_address
        # Start a thread with the server -- that thread will then start one
        # more thread for each request
        server_thread = threading.Thread(target=server.serve_forever)
        # Exit the server thread when the main thread terminates
        server_thread.daemon = True
        server_thread.start()
        print(f"Server loop running in thread: {server_thread.name}")

        # Server can be shut down cleanly using ctrl-c or similar method
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("Server is shutting down.")
            server.shutdown()
            server.server_close()
            print("Server closed successfully.")
