import socket
import threading
import logging
import json
import os
import paramiko
from datetime import datetime
from pathlib import Path
import hashlib

class FakeFilesystem:
    """Simulates a filesystem for the honeypot"""
    def __init__(self, config):
        self.config = config
        self.cwd = "/home/user"
        self.fs = config.get("filesystem", {
            "/": ["bin", "etc", "home", "var", "usr", "tmp", "root"],
            "/home": ["user"],
            "/home/user": ["documents", "downloads", ".bash_history", ".ssh"],
            "/etc": ["passwd", "shadow", "hosts", "ssh", "network"],
            "/var": ["log", "www"],
            "/tmp": [],
            "/root": [".ssh", ".bash_history"]
        })
        self.files = config.get("files", {
            "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
            "/etc/hosts": "127.0.0.1 localhost\n::1 localhost\n192.168.1.1 router",
            "/home/user/.bash_history": "ls -la\ncat /etc/passwd\nwhoami\nsudo su\nhistory",
            "/etc/ssh/sshd_config": "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes"
        })
    
    def list_dir(self, path=None):
        target = path if path else self.cwd
        # Handle absolute and relative paths
        if not target.startswith("/"):
            target = os.path.normpath(os.path.join(self.cwd, target))
        
        if target in self.fs:
            return self.fs[target]
        return None
    
    def read_file(self, path):
        if not path.startswith("/"):
            path = os.path.normpath(os.path.join(self.cwd, path))
        
        if path in self.files:
            return self.files[path]
        return None
    
    def change_dir(self, path):
        if path == "..":
            if self.cwd != "/":
                self.cwd = str(Path(self.cwd).parent)
            return True
        elif path == "~":
            self.cwd = "/home/user"
            return True
        elif path.startswith("/"):
            if path in self.fs:
                self.cwd = path
                return True
        else:
            new_path = os.path.normpath(os.path.join(self.cwd, path))
            if new_path in self.fs:
                self.cwd = new_path
                return True
        return False
    
    def file_exists(self, path):
        if not path.startswith("/"):
            path = os.path.normpath(os.path.join(self.cwd, path))
        return path in self.files or path in self.fs

class SSHServer(paramiko.ServerInterface):
    """SSH server interface for authentication"""
    def __init__(self, config, logger, client_addr):
        self.config = config
        self.logger = logger
        self.client_addr = client_addr
        self.event = threading.Event()
        self.username = None
        self.auth_attempts = []
    
    def check_auth_password(self, username, password):
        """Check password authentication"""
        self.username = username
        auth_log = {
            "timestamp": datetime.now().isoformat(),
            "ip": self.client_addr[0],
            "username": username,
            "password": password,
            "auth_type": "password"
        }
        self.auth_attempts.append(auth_log)
        self.logger.info(f"Auth attempt: {json.dumps(auth_log)}")
        
        # Check against configured credentials
        valid_creds = self.config.get("valid_credentials", {})
        if username in valid_creds and valid_creds[username] == password:
            self.logger.info(f"Valid credentials accepted: {username}")
            return paramiko.AUTH_SUCCESSFUL
        
        # Accept any credentials if allow_all is True
        if self.config.get("allow_all_logins", True):
            self.logger.info(f"Accepted (honeypot mode): {username}")
            return paramiko.AUTH_SUCCESSFUL
        
        return paramiko.AUTH_FAILED
    
    def check_auth_publickey(self, username, key):
        """Check public key authentication"""
        self.username = username
        key_hash = hashlib.md5(key.asbytes()).hexdigest()
        auth_log = {
            "timestamp": datetime.now().isoformat(),
            "ip": self.client_addr[0],
            "username": username,
            "key_fingerprint": key_hash,
            "auth_type": "publickey"
        }
        self.auth_attempts.append(auth_log)
        self.logger.info(f"Pubkey auth attempt: {json.dumps(auth_log)}")
        
        if self.config.get("allow_pubkey_auth", True):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED
    
    def get_allowed_auths(self, username):
        """Return allowed authentication methods"""
        methods = ["password"]
        if self.config.get("allow_pubkey_auth", True):
            methods.append("publickey")
        return ",".join(methods)
    
    def check_channel_request(self, kind, chanid):
        """Check channel request"""
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_channel_shell_request(self, channel):
        """Check shell request"""
        self.event.set()
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        """Check PTY request"""
        return True
    
    def check_channel_exec_request(self, channel, command):
        """Check exec request"""
        self.logger.info(f"Exec request: {command}")
        return True

class SSHSession:
    """Handles individual SSH sessions"""
    def __init__(self, client_socket, addr, config, logger, ssh_server):
        self.socket = client_socket
        self.addr = addr
        self.config = config
        self.logger = logger
        self.ssh_server = ssh_server
        self.fs = FakeFilesystem(config)
        self.username = ssh_server.username
        self.session_log = []
        self.hostname = config.get("hostname", "debian-server")
        self.commands = {
            "ls": self.cmd_ls,
            "pwd": self.cmd_pwd,
            "cd": self.cmd_cd,
            "cat": self.cmd_cat,
            "whoami": self.cmd_whoami,
            "uname": self.cmd_uname,
            "ifconfig": self.cmd_ifconfig,
            "ip": self.cmd_ip,
            "netstat": self.cmd_netstat,
            "ps": self.cmd_ps,
            "echo": self.cmd_echo,
            "help": self.cmd_help,
            "exit": self.cmd_exit,
            "logout": self.cmd_exit,
            "clear": self.cmd_clear,
            "id": self.cmd_id,
            "hostname": self.cmd_hostname,
            "history": self.cmd_history,
            "wget": self.cmd_wget,
            "curl": self.cmd_curl,
            "nc": self.cmd_nc,
            "netcat": self.cmd_nc,
            "chmod": self.cmd_chmod,
            "chown": self.cmd_chown,
            "rm": self.cmd_rm,
            "mkdir": self.cmd_mkdir,
            "touch": self.cmd_touch,
            "vi": self.cmd_vi,
            "nano": self.cmd_nano,
            "sudo": self.cmd_sudo,
            "su": self.cmd_su,
        }
        self.command_history = []
    
    def log_activity(self, activity_type, data):
        """Log session activity"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "ip": self.addr[0],
            "port": self.addr[1],
            "username": self.username,
            "type": activity_type,
            "data": data
        }
        self.session_log.append(entry)
        self.logger.info(json.dumps(entry))
    
    def get_prompt(self):
        """Generate command prompt"""
        prompt_char = "#" if self.username == "root" else "$"
        return f"{self.username}@{self.hostname}:{self.fs.cwd}{prompt_char} "
    
    def cmd_ls(self, args):
        flags = [arg for arg in args if arg.startswith("-")]
        paths = [arg for arg in args if not arg.startswith("-")]
        
        path = paths[0] if paths else None
        files = self.fs.list_dir(path)
        
        if files is None:
            return f"ls: cannot access '{path}': No such file or directory\n"
        
        if "-l" in flags or "-la" in flags:
            output = "total 0\n"
            for f in files:
                output += f"drwxr-xr-x 2 {self.username} {self.username} 4096 Jan 15 10:30 {f}\n"
            return output
        return "  ".join(files) + "\n"
    
    def cmd_pwd(self, args):
        return self.fs.cwd + "\n"
    
    def cmd_cd(self, args):
        if not args:
            self.fs.cwd = "/home/user"
            return ""
        path = args[0]
        if self.fs.change_dir(path):
            return ""
        return f"bash: cd: {path}: No such file or directory\n"
    
    def cmd_cat(self, args):
        if not args:
            return "cat: missing operand\n"
        content = self.fs.read_file(args[0])
        if content:
            return content + "\n"
        return f"cat: {args[0]}: No such file or directory\n"
    
    def cmd_whoami(self, args):
        return self.username + "\n"
    
    def cmd_id(self, args):
        if self.username == "root":
            return "uid=0(root) gid=0(root) groups=0(root)\n"
        return f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username})\n"
    
    def cmd_hostname(self, args):
        return self.hostname + "\n"
    
    def cmd_uname(self, args):
        if "-a" in args:
            return self.config.get("uname_output", 
                "Linux debian-server 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2023-01-21) x86_64 GNU/Linux\n")
        return "Linux\n"
    
    def cmd_ifconfig(self, args):
        return self.config.get("ifconfig_output", 
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 192.168.1.50  netmask 255.255.255.0  broadcast 192.168.1.255\n"
            "        inet6 fe80::a00:27ff:fe4e:66a1  prefixlen 64  scopeid 0x20<link>\n")
    
    def cmd_ip(self, args):
        if "addr" in args or "address" in args:
            return "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0\n"
        return "Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n"
    
    def cmd_netstat(self, args):
        return "Active Internet connections (w/o servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\n"
    
    def cmd_ps(self, args):
        if "-aux" in args or "aux" in args:
            return self.config.get("ps_output",
                "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
                "root         1  0.0  0.1 169416 11484 ?        Ss   10:30   0:01 /sbin/init\n"
                "root       234  0.0  0.0  12345  1234 pts/0    S+   10:30   0:00 bash\n")
        return "  PID TTY          TIME CMD\n 1234 pts/0    00:00:00 bash\n"
    
    def cmd_echo(self, args):
        return " ".join(args) + "\n"
    
    def cmd_history(self, args):
        output = ""
        for i, cmd in enumerate(self.command_history[-50:], 1):
            output += f"  {i}  {cmd}\n"
        return output
    
    def cmd_wget(self, args):
        if not args:
            return "wget: missing URL\n"
        url = args[-1]
        self.log_activity("download_attempt", {"tool": "wget", "url": url})
        return f"--2025-01-15 10:30:00--  {url}\nResolving host... failed: Name or service not known.\n"
    
    def cmd_curl(self, args):
        if not args:
            return "curl: try 'curl --help' for more information\n"
        url = args[-1]
        self.log_activity("download_attempt", {"tool": "curl", "url": url})
        return "curl: (6) Could not resolve host\n"
    
    def cmd_nc(self, args):
        if len(args) >= 2:
            self.log_activity("netcat_attempt", {"args": args})
            return "Connection refused\n"
        return "usage: nc [-options] hostname port\n"
    
    def cmd_chmod(self, args):
        if len(args) < 2:
            return "chmod: missing operand\n"
        return ""
    
    def cmd_chown(self, args):
        if len(args) < 2:
            return "chown: missing operand\n"
        return ""
    
    def cmd_rm(self, args):
        if not args:
            return "rm: missing operand\n"
        return ""
    
    def cmd_mkdir(self, args):
        if not args:
            return "mkdir: missing operand\n"
        return ""
    
    def cmd_touch(self, args):
        if not args:
            return "touch: missing file operand\n"
        return ""
    
    def cmd_vi(self, args):
        return "Vi: No terminal database found\n"
    
    def cmd_nano(self, args):
        return "Error opening terminal: unknown.\n"
    
    def cmd_sudo(self, args):
        if not args:
            return "usage: sudo command\n"
        self.log_activity("sudo_attempt", {"command": " ".join(args)})
        # Execute the command as if sudo succeeded
        return self.execute_command(" ".join(args))
    
    def cmd_su(self, args):
        self.log_activity("su_attempt", {"target_user": args[0] if args else "root"})
        return "su: Authentication failure\n"
    
    def cmd_help(self, args):
        return "Available commands: " + ", ".join(sorted(self.commands.keys())) + "\n"
    
    def cmd_exit(self, args):
        return None
    
    def cmd_clear(self, args):
        return "\033[2J\033[H"
    
    def execute_command(self, cmd_line):
        """Execute a command and return output"""
        cmd_line = cmd_line.strip()
        if not cmd_line:
            return ""
        
        self.command_history.append(cmd_line)
        parts = cmd_line.split()
        cmd = parts[0]
        args = parts[1:]
        
        self.log_activity("command", cmd_line)
        
        if cmd in self.commands:
            return self.commands[cmd](args)
        else:
            return f"bash: {cmd}: command not found\n"
    
    def handle(self, channel):
        """Main session handler"""
        self.log_activity("connection", "SSH session established")
        
        # Send welcome message
        channel.send(f"Welcome to {self.hostname}\n")
        channel.send(f"Last login: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')} from {self.addr[0]}\n")
        
        buffer = ""
        
        try:
            while True:
                channel.send(self.get_prompt())
                
                # Read command
                while True:
                    data = channel.recv(1024).decode('utf-8', errors='ignore')
                    if not data:
                        raise Exception("Connection closed")
                    
                    # Handle special characters
                    if '\r' in data or '\n' in data:
                        buffer += data.replace('\r', '').replace('\n', '')
                        break
                    elif data == '\x03':  # Ctrl+C
                        channel.send("^C\n")
                        buffer = ""
                        break
                    elif data == '\x04':  # Ctrl+D (EOF)
                        raise Exception("EOF received")
                    elif data == '\x7f' or data == '\x08':  # Backspace
                        if buffer:
                            buffer = buffer[:-1]
                            channel.send('\b \b')
                        continue
                    else:
                        buffer += data
                        channel.send(data)
                
                if not buffer:
                    continue
                
                # Execute command
                result = self.execute_command(buffer)
                buffer = ""
                
                if result is None:  # exit command
                    channel.send("logout\n")
                    break
                
                channel.send(result)
        
        except Exception as e:
            self.logger.debug(f"Session ended: {e}")
        
        self.log_activity("disconnect", "SSH session ended")
        self.save_session_log()
    
    def save_session_log(self):
        """Save session log to file"""
        # UPDATED: use ../logs as default log directory, same as main logs
        log_dir = Path(self.config.get("log_directory", "../logs"))
        log_dir.mkdir(exist_ok=True, parents=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = log_dir / f"session_{self.addr[0]}_{self.username}_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump({
                "session_info": {
                    "ip": self.addr[0],
                    "port": self.addr[1],
                    "username": self.username,
                    "start": self.session_log[0]["timestamp"] if self.session_log else None,
                    "end": self.session_log[-1]["timestamp"] if self.session_log else None
                },
                "auth_attempts": self.ssh_server.auth_attempts,
                "activity": self.session_log
            }, f, indent=2)

class SSHHoneypot:
    """Main SSH honeypot server"""
    def __init__(self, config_file="../configs/ssh.json"):
        self.load_config(config_file)
        self.setup_logging()
        self.generate_host_key()
        self.running = False
    
    def load_config(self, config_file):
        """Load configuration from file"""
        default_config = {
            "host": "0.0.0.0",
            "port": 2222,
            "hostname": "debian-server",
            "allow_all_logins": True,
            "allow_pubkey_auth": True,
            "valid_credentials": {
                "admin": "admin",
                "root": "toor",
                "user": "password",
                "ubuntu": "ubuntu",
                "pi": "raspberry"
            },
            # UPDATED: logs path
            "log_directory": "../logs",
            "log_file": "ssh.logs",
            "host_key_file": "ssh_host_key",
            "filesystem": {
                "/": ["bin", "etc", "home", "var", "usr", "tmp", "root"],
                "/home": ["user"],
                "/home/user": ["documents", "downloads", ".bash_history", ".ssh"],
                "/etc": ["passwd", "shadow", "hosts", "ssh", "network"],
                "/var": ["log", "www"],
                "/tmp": [],
                "/root": [".ssh", ".bash_history"]
            },
            "files": {
                "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash",
                "/etc/hosts": "127.0.0.1 localhost\n192.168.1.1 router",
                "/home/user/.bash_history": "ls -la\ncat /etc/passwd\nwhoami",
                "/etc/ssh/sshd_config": "Port 22\nPermitRootLogin yes"
            },
            "uname_output": "Linux debian-server 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2023-01-21) x86_64 GNU/Linux\n",
            "ifconfig_output": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.50  netmask 255.255.255.0\n",
            "ps_output": "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1 169416 11484 ?        Ss   10:30   0:01 /sbin/init\n"
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
        # UPDATED: default to ../logs and ensure parents=True
        log_dir = Path(self.config.get("log_directory", "../logs"))
        log_dir.mkdir(exist_ok=True, parents=True)
        
        log_file = log_dir / self.config.get("log_file", "ssh.logs")
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def generate_host_key(self):
        """Generate or load SSH host key"""
        key_file = self.config.get("host_key_file", "ssh_host_key")
        
        if os.path.exists(key_file):
            self.host_key = paramiko.RSAKey.from_private_key_file(key_file)
            self.logger.info(f"Loaded existing host key from {key_file}")
        else:
            self.host_key = paramiko.RSAKey.generate(2048)
            self.host_key.write_private_key_file(key_file)
            self.logger.info(f"Generated new host key and saved to {key_file}")
    
    def handle_client(self, client_socket, addr):
        """Handle a client connection"""
        transport = None
        try:
            transport = paramiko.Transport(client_socket)
            transport.add_server_key(self.host_key)
            
            ssh_server = SSHServer(self.config, self.logger, addr)
            transport.start_server(server=ssh_server)
            
            # Wait for authentication
            channel = transport.accept(20)
            if channel is None:
                self.logger.warning(f"Client {addr[0]} failed to open channel")
                return
            
            self.logger.info(f"Authenticated client {addr[0]} as {ssh_server.username}")
            
            # Handle the session
            session = SSHSession(client_socket, addr, self.config, self.logger, ssh_server)
            session.handle(channel)
            
        except Exception as e:
            self.logger.error(f"Error handling client {addr}: {e}")
        finally:
            try:
                if transport is not None:
                    transport.close()
            except:
                pass
            client_socket.close()
    
    def start(self):
        """Start the SSH honeypot server"""
        self.running = True
        host = self.config.get("host", "0.0.0.0")
        port = self.config.get("port", 2222)
        
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(5)
        
        log_dir = Path(self.config.get("log_directory", "../logs"))
        log_file = log_dir / self.config.get("log_file", "ssh.logs")
        
        self.logger.info(f"SSH honeypot started on {host}:{port}")
        print(f"SSH honeypot listening on {host}:{port}")
        print(f"Logs will be saved to: {log_file}")
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
            print("\nShutting down SSH honeypot...")
            self.logger.info("SSH honeypot shutting down")
        finally:
            server.close()

if __name__ == "__main__":
    # Note: Requires paramiko library
    # Install with: pip install paramiko
    honeypot = SSHHoneypot("../configs/ssh.json")
    honeypot.start()
