import socket
import threading
import logging
import json
import os
from datetime import datetime
from pathlib import Path

class FakeFilesystem:
    """Simulates a filesystem for the honeypot"""
    def __init__(self, config):
        self.config = config
        self.cwd = "/home/user"
        self.fs = config.get("filesystem", {
            "/": ["bin", "etc", "home", "var", "usr", "tmp"],
            "/home": ["user"],
            "/home/user": ["documents", "downloads", ".bash_history"],
            "/etc": ["passwd", "shadow", "hosts", "ssh"],
            "/var": ["log", "www"],
            "/tmp": []
        })
        self.files = config.get("files", {
            "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash",
            "/etc/hosts": "127.0.0.1 localhost\n192.168.1.1 router",
            "/home/user/.bash_history": "ls -la\ncat /etc/passwd\nwhoami"
        })
    
    def list_dir(self, path=None):
        target = path if path else self.cwd
        if target in self.fs:
            return self.fs[target]
        return None
    
    def read_file(self, path):
        if path in self.files:
            return self.files[path]
        return f"cat: {path}: No such file or directory"
    
    def change_dir(self, path):
        if path == "..":
            if self.cwd != "/":
                self.cwd = str(Path(self.cwd).parent)
            return True
        elif path.startswith("/"):
            if path in self.fs:
                self.cwd = path
                return True
        else:
            new_path = str(Path(self.cwd) / path)
            if new_path in self.fs:
                self.cwd = new_path
                return True
        return False

class TelnetSession:
    """Handles individual telnet sessions"""
    def __init__(self, client_socket, addr, config, logger):
        self.socket = client_socket
        self.addr = addr
        self.config = config
        self.logger = logger
        self.fs = FakeFilesystem(config)
        self.username = None
        self.authenticated = False
        self.session_log = []
        self.hostname = config.get("hostname", "ubuntu-server")
        self.commands = {
            "ls": self.cmd_ls,
            "pwd": self.cmd_pwd,
            "cd": self.cmd_cd,
            "cat": self.cmd_cat,
            "whoami": self.cmd_whoami,
            "uname": self.cmd_uname,
            "ifconfig": self.cmd_ifconfig,
            "netstat": self.cmd_netstat,
            "ps": self.cmd_ps,
            "echo": self.cmd_echo,
            "help": self.cmd_help,
            "exit": self.cmd_exit,
            "clear": self.cmd_clear,
        }
    
    def send(self, data):
        try:
            self.socket.sendall(data.encode() if isinstance(data, str) else data)
        except:
            pass
    
    def recv(self, size=1024):
        try:
            return self.socket.recv(size).decode('utf-8', errors='ignore')
        except:
            return ""
    
    def log_activity(self, activity_type, data):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "ip": self.addr[0],
            "port": self.addr[1],
            "type": activity_type,
            "data": data
        }
        self.session_log.append(entry)
        self.logger.info(json.dumps(entry))
    
    def authenticate(self):
        """Handle login process"""
        self.send(f"{self.hostname} login: ")
        username = self.recv().strip()
        self.log_activity("username_attempt", username)
        
        self.send("Password: ")
        password = self.recv().strip()
        self.log_activity("password_attempt", password)
        
        # Check against configured credentials (always accept for honeypot)
        valid_creds = self.config.get("valid_credentials", {})
        if username in valid_creds and valid_creds[username] == password:
            self.username = username
            self.authenticated = True
            return True
        
        # Accept any credentials if allow_all is True
        if self.config.get("allow_all_logins", True):
            self.username = username
            self.authenticated = True
            return True
        
        return False
    
    def get_prompt(self):
        return f"{self.username}@{self.hostname}:{self.fs.cwd}$ "
    
    def cmd_ls(self, args):
        files = self.fs.list_dir()
        if files:
            return "  ".join(files) + "\n"
        return "ls: cannot access: No such file or directory\n"
    
    def cmd_pwd(self, args):
        return self.fs.cwd + "\n"
    
    def cmd_cd(self, args):
        if not args:
            return ""
        path = args[0]
        if self.fs.change_dir(path):
            return ""
        return f"cd: {path}: No such file or directory\n"
    
    def cmd_cat(self, args):
        if not args:
            return "cat: missing operand\n"
        return self.fs.read_file(args[0]) + "\n"
    
    def cmd_whoami(self, args):
        return self.username + "\n"
    
    def cmd_uname(self, args):
        return self.config.get("uname_output", "Linux ubuntu-server 5.4.0-42-generic x86_64 GNU/Linux\n")
    
    def cmd_ifconfig(self, args):
        return self.config.get("ifconfig_output", 
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n")
    
    def cmd_netstat(self, args):
        return "Active Internet connections (w/o servers)\n"
    
    def cmd_ps(self, args):
        return self.config.get("ps_output",
            "  PID TTY          TIME CMD\n"
            "    1 ?        00:00:01 systemd\n"
            " 1234 pts/0    00:00:00 bash\n")
    
    def cmd_echo(self, args):
        return " ".join(args) + "\n"
    
    def cmd_help(self, args):
        return "Available commands: " + ", ".join(self.commands.keys()) + "\n"
    
    def cmd_exit(self, args):
        return None
    
    def cmd_clear(self, args):
        return "\033[2J\033[H"
    
    def execute_command(self, cmd_line):
        """Execute a command and return output"""
        parts = cmd_line.strip().split()
        if not parts:
            return ""
        
        cmd = parts[0]
        args = parts[1:]
        
        self.log_activity("command", cmd_line)
        
        if cmd in self.commands:
            return self.commands[cmd](args)
        else:
            return f"{cmd}: command not found\n"
    
    def handle(self):
        """Main session handler"""
        self.log_activity("connection", "New connection established")
        
        # Send banner
        banner = self.config.get("banner", f"Welcome to {self.hostname}\n\n")
        self.send(banner)
        
        # Authenticate
        if not self.authenticate():
            self.send("Login incorrect\n")
            self.log_activity("auth_failed", "Authentication failed")
            return
        
        self.send(f"Last login: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')}\n")
        self.log_activity("auth_success", f"User {self.username} authenticated")
        
        # Main command loop
        while True:
            self.send(self.get_prompt())
            cmd = self.recv()
            
            if not cmd:
                break
            
            result = self.execute_command(cmd)
            if result is None:  # exit command
                break
            
            self.send(result)
        
        self.log_activity("disconnect", "Session ended")
        self.save_session_log()
    
    def save_session_log(self):
        """Save session log to file"""
        log_dir = Path(self.config.get("log_directory", "../logs"))
        log_dir.mkdir(exist_ok=True, parents=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = log_dir / f"session_{self.addr[0]}_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.session_log, f, indent=2)

class TelnetHoneypot:
    """Main honeypot server"""
    def __init__(self, config_file="../configs/telnet.json"):
        self.load_config(config_file)
        self.setup_logging()
        self.running = False
    
    def load_config(self, config_file):
        """Load configuration from file"""
        default_config = {
            "host": "0.0.0.0",
            "port": 2323,
            "hostname": "ubuntu-server",
            "banner": "Ubuntu 20.04.1 LTS\n\n",
            "allow_all_logins": True,
            "valid_credentials": {
                "admin": "admin",
                "root": "toor",
                "user": "password"
            },
            # UPDATED: default logs path
            "log_directory": "../logs",
            "log_file": "telnet.logs",
            "filesystem": {
                "/": ["bin", "etc", "home", "var", "usr", "tmp"],
                "/home": ["user"],
                "/home/user": ["documents", "downloads", ".bash_history"],
                "/etc": ["passwd", "shadow", "hosts", "ssh"],
                "/var": ["log", "www"],
                "/tmp": []
            },
            "files": {
                "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash",
                "/etc/hosts": "127.0.0.1 localhost\n192.168.1.1 router",
                "/home/user/.bash_history": "ls -la\ncat /etc/passwd\nwhoami"
            },
            "uname_output": "Linux ubuntu-server 5.4.0-42-generic #46-Ubuntu SMP x86_64 GNU/Linux\n",
            "ifconfig_output": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.100  netmask 255.255.255.0\n",
            "ps_output": "  PID TTY          TIME CMD\n    1 ?        00:00:01 systemd\n 1234 pts/0    00:00:00 bash\n"
        }
        
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        else:
            # Ensure parent directory exists
            config_path = Path(config_file)
            config_path.parent.mkdir(exist_ok=True, parents=True)
            self.config = default_config
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=2)
            print(f"Created default config file: {config_file}")
    
    def setup_logging(self):
        """Setup logging"""
        log_dir = Path(self.config.get("log_directory", "../logs"))
        log_dir.mkdir(exist_ok=True, parents=True)
        
        log_file = log_dir / self.config.get("log_file", "telnet.logs")
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def handle_client(self, client_socket, addr):
        """Handle a client connection"""
        session = TelnetSession(client_socket, addr, self.config, self.logger)
        try:
            session.handle()
        except Exception as e:
            self.logger.error(f"Error handling client {addr}: {e}")
        finally:
            client_socket.close()
    
    def start(self):
        """Start the honeypot server"""
        self.running = True
        host = self.config.get("host", "0.0.0.0")
        port = self.config.get("port", 2323)
        
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(5)
        
        self.logger.info(f"Telnet honeypot started on {host}:{port}")
        print(f"Telnet honeypot listening on {host}:{port}")
        print(f"Logs will be saved to: {Path(self.config.get('log_directory', '../logs')) / self.config.get('log_file', 'telnet.logs')}")
        print("Press Ctrl+C to stop")
        
        try:
            while self.running:
                client_socket, addr = server.accept()
                self.logger.info(f"New connection from {addr[0]}:{addr[1]}")
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, addr)
                )
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            print("\nShutting down honeypot...")
            self.logger.info("Honeypot shutting down")
        finally:
            server.close()

if __name__ == "__main__":
    honeypot = TelnetHoneypot("../configs/telnet.json")
    honeypot.start()
