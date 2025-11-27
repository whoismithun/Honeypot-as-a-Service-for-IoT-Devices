from flask import Flask, request, render_template_string, jsonify, make_response, redirect
import logging
import json
import os
from datetime import datetime
from pathlib import Path
import hashlib
import base64
from functools import wraps
import ssl

class FakeFilesystem:
    """Simulates a filesystem for the honeypot"""
    def __init__(self, config):
        self.config = config
        self.cwd = "/var/www/html"
        self.fs = config.get("filesystem", {
            "/": ["bin", "etc", "home", "var", "usr", "tmp", "root"],
            "/var": ["www", "log"],
            "/var/www": ["html"],
            "/var/www/html": ["index.html", "admin", "config.php", "uploads"],
            "/etc": ["passwd", "shadow", "hosts", "nginx"],
            "/home": ["admin"],
        })
        self.files = config.get("files", {
            "/var/www/html/index.html": "<html><body><h1>Welcome</h1></body></html>",
            "/var/www/html/config.php": "<?php\n$db_host = 'localhost';\n$db_user = 'admin';\n$db_pass = 'P@ssw0rd123';\n?>",
            "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
        })
    
    def list_dir(self, path=None):
        target = path if path else self.cwd
        if target in self.fs:
            return self.fs[target]
        return None
    
    def read_file(self, path):
        if path in self.files:
            return self.files[path]
        return None
    
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
            new_path = os.path.normpath(os.path.join(self.cwd, path))
            if new_path in self.fs:
                self.cwd = new_path
                return True
        return False

class HTTPHoneypot:
    """Main HTTP honeypot server"""
    def __init__(self, config_file="../configs/http.json"):
        self.app = Flask(__name__)
        self.load_config(config_file)
        self.setup_logging()
        self.fs = FakeFilesystem(self.config)
        self.sessions = {}
        self.setup_routes()
    
    def load_config(self, config_file):
        """Load configuration from file"""
        default_config = {
            "host": "0.0.0.0",
            "port": 8080,
            "ssl_enabled": False,
            "ssl_cert": "cert.pem",
            "ssl_key": "key.pem",
            "server_header": "Apache/2.4.41 (Ubuntu)",
            "hostname": "web-server",
            "allow_all_logins": True,
            "valid_credentials": {
                "admin": "admin",
                "root": "toor",
                "user": "password"
            },
            # UPDATED: log path
            "log_directory": "../logs",
            "log_file": "http.logs",
            "emulate_vulnerabilities": True,
            "filesystem": {
                "/": ["bin", "etc", "home", "var", "usr", "tmp"],
                "/var": ["www", "log"],
                "/var/www": ["html"],
                "/var/www/html": ["index.html", "admin", "config.php", "uploads"],
                "/etc": ["passwd", "shadow", "hosts"],
            },
            "files": {
                "/var/www/html/index.html": "<html><body>Welcome</body></html>",
                "/var/www/html/config.php": "<?php $db_pass = 'P@ssw0rd123'; ?>",
                "/etc/passwd": "root:x:0:0:root:/root:/bin/bash",
            },
            "fake_pages": {
                "/admin": "Admin Login",
                "/login": "User Login",
                "/phpmyadmin": "phpMyAdmin",
                "/wp-admin": "WordPress Admin",
                "/console": "Management Console"
            }
        }
        
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        else:
            # Ensure parent dir exists
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
        
        log_file = log_dir / self.config.get("log_file", "http.logs")
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def log_request(self, endpoint, extra_data=None):
        """Log HTTP request details"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "ip": request.remote_addr,
            "method": request.method,
            "path": request.path,
            "endpoint": endpoint,
            "user_agent": request.headers.get('User-Agent'),
            "headers": dict(request.headers),
            "args": dict(request.args),
            "form": dict(request.form) if request.form else None,
            "json": request.get_json(silent=True),
            "cookies": dict(request.cookies),
        }
        
        if extra_data:
            log_entry.update(extra_data)
        
        self.logger.info(json.dumps(log_entry))
        self.save_attack_log(log_entry)
    
    def save_attack_log(self, log_entry):
        """Save individual attack logs"""
        log_dir = Path(self.config.get("log_directory", "../logs"))
        attacks_dir = log_dir / "attacks"
        attacks_dir.mkdir(exist_ok=True, parents=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ip = log_entry.get("ip", "unknown").replace(".", "_")
        filename = attacks_dir / f"attack_{ip}_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(log_entry, f, indent=2)
    
    def check_auth(self, auth_header):
        """Check HTTP Basic Auth"""
        if not auth_header:
            return None, None
        
        try:
            auth_type, auth_string = auth_header.split(' ', 1)
            if auth_type.lower() != 'basic':
                return None, None
            
            decoded = base64.b64decode(auth_string).decode('utf-8')
            username, password = decoded.split(':', 1)
            
            # Log authentication attempt
            self.log_request("auth_attempt", {
                "username": username,
                "password": password,
                "auth_type": "basic"
            })
            
            # Check credentials
            valid_creds = self.config.get("valid_credentials", {})
            if username in valid_creds and valid_creds[username] == password:
                return username, True
            
            if self.config.get("allow_all_logins", True):
                return username, True
            
            return username, False
        except:
            return None, None
    
    def require_auth(self, f):
        """Decorator for routes requiring authentication"""
        @wraps(f)
        def decorated(*args, **kwargs):
            auth = request.headers.get('Authorization')
            username, authenticated = self.check_auth(auth)
            
            if not authenticated:
                response = make_response('Authentication required', 401)
                response.headers['WWW-Authenticate'] = 'Basic realm="Login Required"'
                self.log_request("auth_failed", {"reason": "no_valid_credentials"})
                return response
            
            return f(username, *args, **kwargs)
        return decorated
    
    def setup_routes(self):
        """Setup all HTTP routes"""
        
        # Override Flask's after_request to add custom headers
        @self.app.after_request
        def add_security_headers(response):
            server_header = self.config.get("server_header", "Apache/2.4.41")
            response.headers['Server'] = server_header
            return response
        
        @self.app.route('/')
        def index():
            self.log_request("index")
            return render_template_string("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Home</title>
                <style>
                    body { font-family: Arial; margin: 40px; }
                    .container { max-width: 800px; margin: 0 auto; }
                    a { color: #0066cc; text-decoration: none; margin: 10px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Welcome to {{ hostname }}</h1>
                    <p>Server is running normally.</p>
                    <hr>
                    <a href="/admin">Admin Panel</a> |
                    <a href="/login">Login</a> |
                    <a href="/shell">Web Shell</a> |
                    <a href="/files">File Manager</a>
                </div>
            </body>
            </html>
            """, hostname=self.config.get("hostname", "Web Server"))
        
        @self.app.route('/admin', methods=['GET', 'POST'])
        @self.require_auth
        def admin(username):
            self.log_request("admin_access", {"username": username})
            return render_template_string("""
            <!DOCTYPE html>
            <html>
            <head><title>Admin Panel</title></head>
            <body>
                <h1>Admin Panel</h1>
                <p>Welcome, {{ username }}!</p>
                <p>Server Status: Online</p>
                <a href="/shell">Web Shell</a>
            </body>
            </html>
            """, username=username)
        
        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            if request.method == 'POST':
                username = request.form.get('username')
                password = request.form.get('password')
                self.log_request("login_attempt", {
                    "username": username,
                    "password": password
                })
                
                valid_creds = self.config.get("valid_credentials", {})
                if self.config.get("allow_all_logins") or (username in valid_creds and valid_creds[username] == password):
                    return redirect('/admin')
                else:
                    return render_template_string(LOGIN_FORM, error="Invalid credentials")
            
            self.log_request("login_page")
            return render_template_string(LOGIN_FORM, error=None)
        
        @self.app.route('/shell', methods=['GET', 'POST'])
        @self.require_auth
        def web_shell(username):
            if request.method == 'POST':
                command = request.form.get('command', '')
                self.log_request("shell_command", {
                    "username": username,
                    "command": command
                })
                output = self.execute_command(command)
                return render_template_string(WEB_SHELL_TEMPLATE, 
                    username=username, 
                    cwd=self.fs.cwd,
                    output=output,
                    command=command)
            
            self.log_request("shell_access", {"username": username})
            return render_template_string(WEB_SHELL_TEMPLATE,
                username=username,
                cwd=self.fs.cwd,
                output="",
                command="")
        
        @self.app.route('/api/exec', methods=['POST'])
        def api_exec():
            """API endpoint for command execution"""
            data = request.get_json() or {}
            command = data.get('cmd') or data.get('command')
            
            self.log_request("api_exec", {"command": command})
            
            if command:
                output = self.execute_command(command)
                return jsonify({"status": "success", "output": output})
            
            return jsonify({"status": "error", "message": "No command provided"}), 400
        
        @self.app.route('/files')
        @self.require_auth
        def file_manager(username):
            self.log_request("file_manager", {"username": username})
            path = request.args.get('path', self.fs.cwd)
            files = self.fs.list_dir(path)
            
            return render_template_string(FILE_MANAGER_TEMPLATE,
                username=username,
                path=path,
                files=files or [])
        
        @self.app.route('/files/read')
        @self.require_auth
        def read_file(username):
            path = request.args.get('path')
            self.log_request("file_read", {"username": username, "path": path})
            
            content = self.fs.read_file(path)
            if content:
                return f"<pre>{content}</pre>"
            return "File not found", 404
        
        @self.app.route('/upload', methods=['GET', 'POST'])
        @self.require_auth
        def upload(username):
            if request.method == 'POST':
                file = request.files.get('file')
                if file:
                    size = len(file.read())
                    self.log_request("file_upload", {
                        "username": username,
                        "filename": file.filename,
                        "content_type": file.content_type,
                        "size": size
                    })
                    return "File uploaded successfully (simulated)"
            
            return render_template_string(UPLOAD_TEMPLATE, username=username)
        
        # Common vulnerable endpoints
        @self.app.route('/phpmyadmin')
        def phpmyadmin():
            self.log_request("phpmyadmin_access")
            return render_template_string("""
            <html><body>
            <h1>phpMyAdmin</h1>
            <form method="post" action="/phpmyadmin/login">
                Username: <input name="username"><br>
                Password: <input type="password" name="password"><br>
                <input type="submit" value="Login">
            </form>
            </body></html>
            """)
        
        @self.app.route('/phpmyadmin/login', methods=['POST'])
        def phpmyadmin_login():
            self.log_request("phpmyadmin_login", {
                "username": request.form.get('username'),
                "password": request.form.get('password')
            })
            return "Invalid credentials"
        
        @self.app.route('/wp-admin')
        @self.app.route('/wp-login.php')
        def wordpress():
            self.log_request("wordpress_access")
            return "WordPress admin page"
        
        @self.app.route('/.env')
        def env_file():
            self.log_request("env_file_access", {"vulnerability": "exposed_env"})
            return """DB_HOST=localhost
DB_DATABASE=webapp
DB_USERNAME=admin
DB_PASSWORD=SuperSecret123!
APP_KEY=base64:randomkey123456789"""
        
        @self.app.route('/config.php')
        def config_php():
            self.log_request("config_access", {"vulnerability": "exposed_config"})
            return self.fs.read_file("/var/www/html/config.php") or "Not found"
        
        # Path traversal test endpoint
        @self.app.route('/download')
        def download():
            filename = request.args.get('file')
            self.log_request("download_attempt", {
                "file": filename,
                "vulnerability": "path_traversal_attempt"
            })
            
            # Simulate path traversal
            if filename and ('../' in filename or filename.startswith('/')):
                content = self.fs.read_file(filename.replace('../', '/'))
                if content:
                    return content
            
            return "File not found", 404
        
        # SQL injection test endpoint
        @self.app.route('/search')
        def search():
            query = request.args.get('q')
            self.log_request("search", {
                "query": query,
                "sql_injection_check": ("'" in query) if query else False
            })
            return f"Search results for: {query}"
        
        # XSS test endpoint
        @self.app.route('/comment', methods=['POST'])
        def comment():
            comment = request.form.get('comment')
            self.log_request("comment_post", {
                "comment": comment,
                "xss_check": ("<script>" in comment) if comment else False
            })
            return f"Comment posted: {comment}"
        
        # Catch-all for scanning attempts
        @self.app.route('/<path:path>')
        def catch_all(path):
            self.log_request("unknown_path", {
                "path": path,
                "scan_attempt": True
            })
            return "Not Found", 404
    
    def execute_command(self, command):
        """Execute simulated shell command"""
        if not command:
            return ""
        
        parts = command.strip().split()
        cmd = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        
        # Simulate common commands
        if cmd == "ls":
            files = self.fs.list_dir(args[0] if args else None)
            return "  ".join(files) if files else "ls: cannot access"
        elif cmd == "pwd":
            return self.fs.cwd
        elif cmd == "cd":
            if args and self.fs.change_dir(args[0]):
                return f"Changed to {self.fs.cwd}"
            return "cd: no such directory"
        elif cmd == "cat":
            if args:
                content = self.fs.read_file(args[0])
                return content if content else "cat: no such file"
            return "cat: missing operand"
        elif cmd == "whoami":
            return "www-data"
        elif cmd == "id":
            return "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
        elif cmd == "uname":
            return "Linux web-server 5.4.0-42-generic x86_64"
        elif cmd in ("wget", "curl"):
            return f"{cmd}: command not found (or blocked by firewall)"
        elif cmd == "ps":
            return "PID   COMMAND\n1234  nginx\n5678  php-fpm"
        else:
            return f"{cmd}: command not found"
    
    def start(self):
        """Start the HTTP honeypot server"""
        host = self.config.get("host", "0.0.0.0")
        port = self.config.get("port", 8080)
        ssl_enabled = self.config.get("ssl_enabled", False)
        
        log_dir = Path(self.config.get("log_directory", "../logs"))
        log_file = log_dir / self.config.get("log_file", "http.logs")
        
        self.logger.info(f"HTTP honeypot started on {host}:{port}")
        print(f"HTTP honeypot listening on {host}:{port}")
        print(f"Logs will be saved to: {log_file}")
        print(f"Access at: http{'s' if ssl_enabled else ''}://{host}:{port}")
        print("Press Ctrl+C to stop")
        
        if ssl_enabled:
            cert = self.config.get("ssl_cert", "cert.pem")
            key = self.config.get("ssl_key", "key.pem")
            
            if not os.path.exists(cert) or not os.path.exists(key):
                print("\n⚠️  SSL enabled but certificates not found!")
                print("Generate with: openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365")
                return
            
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            self.app.run(host=host, port=port, ssl_context=context, threaded=True)
        else:
            self.app.run(host=host, port=port, threaded=True)

# HTML Templates
LOGIN_FORM = """
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body { font-family: Arial; margin: 40px; background: #f0f0f0; }
        .login-box { max-width: 400px; margin: 100px auto; padding: 20px; background: white; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        input { width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; cursor: pointer; }
        .error { color: red; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Login</h2>
        {% if error %}<p class="error">{{ error }}</p>{% endif %}
        <form method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
"""

WEB_SHELL_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Web Shell</title>
    <style>
        body { font-family: 'Courier New', monospace; background: #000; color: #0f0; padding: 20px; }
        .shell { background: #000; padding: 20px; border: 1px solid #0f0; }
        input[type="text"] { width: 80%; background: #000; color: #0f0; border: 1px solid #0f0; padding: 10px; font-family: 'Courier New'; }
        button { background: #0f0; color: #000; border: none; padding: 10px 20px; cursor: pointer; }
        .output { white-space: pre-wrap; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="shell">
        <h2>Web Shell - {{ username }}@{{ cwd }}</h2>
        <form method="post">
            <input type="text" name="command" value="{{ command }}" placeholder="Enter command..." autofocus>
            <button type="submit">Execute</button>
        </form>
        <div class="output">{{ output }}</div>
    </div>
</body>
</html>
"""

FILE_MANAGER_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>File Manager</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        .file { padding: 10px; margin: 5px; background: #f0f0f0; cursor: pointer; }
        .file:hover { background: #e0e0e0; }
    </style>
</head>
<body>
    <h2>File Manager</h2>
    <p>Current path: {{ path }}</p>
    <hr>
    {% for file in files %}
    <div class="file">📁 {{ file }}</div>
    {% endfor %}
</body>
</html>
"""

UPLOAD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Upload</title></head>
<body>
    <h2>File Upload</h2>
    <form method="post" enctype="multipart/form-data">
        <input type="file" name="file">
        <button type="submit">Upload</button>
    </form>
</body>
</html>
"""

if __name__ == "__main__":
    # Note: Requires Flask library
    # Install with: pip install flask
    honeypot = HTTPHoneypot("../configs/http.json")
    honeypot.start()
