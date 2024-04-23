import socketserver
import threading
import datetime
import csv
import uuid
import re

HOST = '127.0.0.1'
PORT = 5000  # Change this to your desired port
LOG_FILE = 'server_log.csv'
ALERT_LEVELS = {
    0: 'None',
    1: 'Low',
    2: 'Medium',
    3: 'High',
    4: 'Critical'
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


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Handle requests in a separate thread."""
    pass


class ConnectionHandler(socketserver.BaseRequestHandler):
    """
    Handles incoming network connections, logs command data, and evaluates potential threats based on configured regex patterns.
    """

    def handle(self):
        # Generate a unique ID for the connection
        connection_id = str(uuid.uuid4())
        # Initialize log data with connection ID and timestamp
        log_data = [connection_id, str(datetime.datetime.now())]

        # Receive and log commands from the connection
        commands = []
        try:
            while True:
                data = self.request.recv(1024).decode()
                if not data:
                    break
                commands.append(data.strip())
                log_data.append(data.strip())  # Log each received command
        except Exception as e:
            print(f"Error receiving data: {e}")

        # Write connection data to the log file (CSV)
        self.write_log(log_data)

        # Process received commands and evaluate alerts
        alert_level = self.check_alerts(commands)
        print(f"Connection ID: {connection_id}")
        print(f"Received commands: {', '.join(commands)}")
        print(f"Alert Level: {alert_level}")

    def write_log(self, log_data):
        """Writes log data to a CSV file."""
        with open(LOG_FILE, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(log_data)

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
        # Assigns an alert level based on the number of matches
        return ALERT_LEVELS.get(match_count, 'Unknown')


if __name__ == "__main__":
    server = ThreadedTCPServer((HOST, PORT), ConnectionHandler)
    with server:
        print(f"Server running on {HOST}:{PORT}")
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
            while True:
                pass
        except KeyboardInterrupt:
            server.shutdown()
            server.server_close()
