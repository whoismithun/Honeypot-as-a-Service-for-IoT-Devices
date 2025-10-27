import socket
import threading
import logging
import json
import os
import struct
import time
from datetime import datetime
from pathlib import Path
from collections import defaultdict

class CoAPPacket:
    """CoAP packet parser and builder"""
    # CoAP Message Types
    CON = 0  # Confirmable
    NON = 1  # Non-confirmable
    ACK = 2  # Acknowledgement
    RST = 3  # Reset
    
    # CoAP Method Codes
    EMPTY = 0
    GET = 1
    POST = 2
    PUT = 3
    DELETE = 4
    
    # CoAP Response Codes
    CREATED = 65         # 2.01
    DELETED = 66         # 2.02
    VALID = 67           # 2.03
    CHANGED = 68         # 2.04
    CONTENT = 69         # 2.05
    BAD_REQUEST = 128    # 4.00
    UNAUTHORIZED = 129   # 4.01
    NOT_FOUND = 132      # 4.04
    METHOD_NOT_ALLOWED = 133  # 4.05
    INTERNAL_ERROR = 160 # 5.00
    NOT_IMPLEMENTED = 161 # 5.01
    
    # CoAP Option Numbers
    URI_PATH = 11
    CONTENT_FORMAT = 12
    URI_QUERY = 15
    OBSERVE = 6
    
    def __init__(self):
        self.version = 1
        self.type = self.CON
        self.token_length = 0
        self.code = 0
        self.message_id = 0
        self.token = b''
        self.options = []
        self.payload = b''
    
    @staticmethod
    def parse(data):
        """Parse CoAP packet from bytes"""
        if len(data) < 4:
            return None
        
        packet = CoAPPacket()
        
        # Parse header
        byte0 = data[0]
        packet.version = (byte0 >> 6) & 0x03
        packet.type = (byte0 >> 4) & 0x03
        packet.token_length = byte0 & 0x0F
        
        packet.code = data[1]
        packet.message_id = struct.unpack('!H', data[2:4])[0]
        
        offset = 4
        
        # Parse token
        if packet.token_length > 0:
            packet.token = data[offset:offset + packet.token_length]
            offset += packet.token_length
        
        # Parse options
        option_number = 0
        while offset < len(data):
            if data[offset] == 0xFF:  # Payload marker
                offset += 1
                break
            
            # Parse option
            delta = (data[offset] >> 4) & 0x0F
            length = data[offset] & 0x0F
            offset += 1
            
            # Extended option delta
            if delta == 13:
                delta = data[offset] + 13
                offset += 1
            elif delta == 14:
                delta = struct.unpack('!H', data[offset:offset+2])[0] + 269
                offset += 2
            
            # Extended option length
            if length == 13:
                length = data[offset] + 13
                offset += 1
            elif length == 14:
                length = struct.unpack('!H', data[offset:offset+2])[0] + 269
                offset += 2
            
            option_number += delta
            option_value = data[offset:offset + length]
            offset += length
            
            packet.options.append((option_number, option_value))
        
        # Parse payload
        if offset < len(data):
            packet.payload = data[offset:]
        
        return packet
    
    def build(self):
        """Build CoAP packet to bytes"""
        # Build header
        byte0 = (self.version << 6) | (self.type << 4) | self.token_length
        header = struct.pack('!BBH', byte0, self.code, self.message_id)
        
        # Add token
        data = header + self.token
        
        # Add options
        prev_option_number = 0
        for option_number, option_value in sorted(self.options):
            delta = option_number - prev_option_number
            length = len(option_value)
            
            # Simple encoding (no extended deltas/lengths for brevity)
            option_header = bytes([(delta << 4) | length])
            data += option_header + option_value
            prev_option_number = option_number
        
        # Add payload
        if self.payload:
            data += b'\xFF' + self.payload
        
        return data
    
    def get_option(self, option_number):
        """Get option values by number"""
        return [value for num, value in self.options if num == option_number]
    
    def get_uri_path(self):
        """Get full URI path from options"""
        path_segments = self.get_option(self.URI_PATH)
        return '/' + '/'.join(seg.decode('utf-8', errors='ignore') for seg in path_segments)
    
    def get_uri_query(self):
        """Get URI query parameters"""
        query_segments = self.get_option(self.URI_QUERY)
        queries = {}
        for seg in query_segments:
            query = seg.decode('utf-8', errors='ignore')
            if '=' in query:
                key, value = query.split('=', 1)
                queries[key] = value
            else:
                queries[query] = ''
        return queries

class IoTDevice:
    """Simulates IoT device with CoAP resources"""
    def __init__(self, config):
        self.config = config
        self.resources = config.get("resources", {
            "/sensor/temp": {"value": "22.5", "type": "sensor", "unit": "celsius", "observable": True},
            "/sensor/humidity": {"value": "45.0", "type": "sensor", "unit": "percent", "observable": True},
            "/sensor/pressure": {"value": "1013.25", "type": "sensor", "unit": "hPa", "observable": True},
            "/actuator/light": {"value": "off", "type": "actuator", "writable": True},
            "/actuator/thermostat": {"value": "20.0", "type": "actuator", "writable": True},
            "/actuator/lock": {"value": "locked", "type": "actuator", "writable": True},
            "/info/device": {"value": "Smart IoT Device v1.0", "type": "info"},
            "/info/firmware": {"value": "v2.3.1", "type": "info"},
            "/admin/shell": {"type": "shell", "writable": True},
            "/admin/config": {"type": "config", "writable": True},
            "/admin/reboot": {"type": "command", "writable": True},
            "/.well-known/core": {"type": "discovery"},
        })
        self.observers = defaultdict(list)
    
    def get_resource(self, path):
        """Get resource by path"""
        if path in self.resources:
            return self.resources[path]
        return None
    
    def set_resource(self, path, value):
        """Set resource value"""
        if path in self.resources:
            resource = self.resources[path]
            if resource.get("writable", False):
                resource["value"] = value
                return True
        return False
    
    def discover_resources(self):
        """Return CoRE Link Format discovery"""
        links = []
        for path, resource in self.resources.items():
            if path == "/.well-known/core":
                continue
            attrs = [f'<{path}>']
            if resource.get("type"):
                attrs.append(f'rt="{resource["type"]}"')
            if resource.get("observable"):
                attrs.append('obs')
            if resource.get("writable"):
                attrs.append('if="actuator"')
            links.append(';'.join(attrs))
        return ','.join(links)
    
    def list_resources(self):
        """List all available resources"""
        return list(self.resources.keys())

class CoAPSession:
    """Handles CoAP requests"""
    def __init__(self, server_socket, addr, data, config, logger, iot_device):
        self.socket = server_socket
        self.addr = addr
        self.data = data
        self.config = config
        self.logger = logger
        self.iot_device = iot_device
        self.session_log = []
    
    def log_activity(self, activity_type, data):
        """Log activity"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "ip": self.addr[0],
            "port": self.addr[1],
            "type": activity_type,
            "data": data
        }
        self.session_log.append(entry)
        self.logger.info(json.dumps(entry))
    
    def send_response(self, request, code, payload=b'', content_format=0):
        """Send CoAP response"""
        response = CoAPPacket()
        response.version = 1
        response.type = CoAPPacket.ACK if request.type == CoAPPacket.CON else CoAPPacket.NON
        response.code = code
        response.message_id = request.message_id
        response.token = request.token
        response.token_length = len(request.token)
        
        if content_format and payload:
            response.options.append((CoAPPacket.CONTENT_FORMAT, struct.pack('!B', content_format)))
        
        response.payload = payload if isinstance(payload, bytes) else payload.encode('utf-8')
        
        try:
            self.socket.sendto(response.build(), self.addr)
        except Exception as e:
            self.logger.error(f"Error sending response: {e}")
    
    def handle_get(self, request, path, query):
        """Handle GET request"""
        self.log_activity("GET", {"path": path, "query": query})
        
        # Discovery request
        if path == "/.well-known/core":
            discovery = self.iot_device.discover_resources()
            self.send_response(request, CoAPPacket.CONTENT, discovery, content_format=40)
            return
        
        # Get resource
        resource = self.iot_device.get_resource(path)
        if resource:
            if "value" in resource:
                value = resource["value"]
                self.send_response(request, CoAPPacket.CONTENT, value)
            else:
                self.send_response(request, CoAPPacket.CONTENT, "OK")
        else:
            self.send_response(request, CoAPPacket.NOT_FOUND, "Resource not found")
    
    def handle_post(self, request, path, query):
        """Handle POST request"""
        payload = request.payload.decode('utf-8', errors='ignore')
        self.log_activity("POST", {"path": path, "query": query, "payload": payload})
        
        # Shell command execution
        if path == "/admin/shell":
            response = self.execute_shell_command(payload)
            self.send_response(request, CoAPPacket.CHANGED, response)
        elif path == "/admin/reboot":
            self.log_activity("reboot", {"command": "reboot"})
            self.send_response(request, CoAPPacket.CHANGED, "Device rebooting...")
        else:
            resource = self.iot_device.get_resource(path)
            if resource:
                self.send_response(request, CoAPPacket.CHANGED, "Resource updated")
            else:
                self.send_response(request, CoAPPacket.NOT_FOUND, "Resource not found")
    
    def handle_put(self, request, path, query):
        """Handle PUT request"""
        payload = request.payload.decode('utf-8', errors='ignore')
        self.log_activity("PUT", {"path": path, "query": query, "payload": payload})
        
        # Update resource
        if self.iot_device.set_resource(path, payload):
            self.send_response(request, CoAPPacket.CHANGED, "Updated")
        else:
            resource = self.iot_device.get_resource(path)
            if resource:
                self.send_response(request, CoAPPacket.METHOD_NOT_ALLOWED, "Resource not writable")
            else:
                self.send_response(request, CoAPPacket.NOT_FOUND, "Resource not found")
    
    def handle_delete(self, request, path, query):
        """Handle DELETE request"""
        self.log_activity("DELETE", {"path": path, "query": query})
        
        resource = self.iot_device.get_resource(path)
        if resource:
            if resource.get("writable"):
                self.send_response(request, CoAPPacket.DELETED, "Deleted")
            else:
                self.send_response(request, CoAPPacket.METHOD_NOT_ALLOWED, "Cannot delete")
        else:
            self.send_response(request, CoAPPacket.NOT_FOUND, "Resource not found")
    
    def execute_shell_command(self, command):
        """Execute shell command"""
        self.log_activity("shell_command", {"command": command})
        
        parts = command.strip().split()
        if not parts:
            return "No command provided"
        
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        # Simulate commands
        if cmd == "help":
            return "Commands: help, status, list, get, set, ps, uname, ifconfig, cat, ls, pwd, whoami"
        
        elif cmd == "status":
            return "System: Online | Uptime: 72h | Memory: 45% | CPU: 12%"
        
        elif cmd == "list":
            resources = self.iot_device.list_resources()
            return "Resources:\n" + "\n".join(resources)
        
        elif cmd == "get":
            if args:
                resource = self.iot_device.get_resource(args[0])
                if resource and "value" in resource:
                    return f"{args[0]}: {resource['value']}"
                return "Resource not found"
            return "Usage: get <path>"
        
        elif cmd == "set":
            if len(args) >= 2:
                path, value = args[0], args[1]
                if self.iot_device.set_resource(path, value):
                    return f"Set {path} = {value}"
                return "Failed to set value"
            return "Usage: set <path> <value>"
        
        elif cmd == "ps":
            return "PID  COMMAND\n  1  coap_server\n  2  sensor_daemon\n  3  actuator_ctrl"
        
        elif cmd == "uname":
            return "Linux coap-device 4.14.0 armv7l GNU/Linux"
        
        elif cmd == "ifconfig":
            return "wlan0: inet 192.168.1.150  netmask 255.255.255.0"
        
        elif cmd == "cat":
            if args:
                file = args[0]
                if file == "/etc/passwd":
                    return "root:x:0:0::/root:/bin/sh\ncoap:x:1000:1000::/home/coap:/bin/sh"
                elif file == "/etc/shadow":
                    return "cat: /etc/shadow: Permission denied"
                elif file == "/proc/cpuinfo":
                    return "processor: ARMv7\nmodel name: Cortex-A7\nBogoMIPS: 38.40"
                return f"cat: {file}: No such file or directory"
            return "Usage: cat <file>"
        
        elif cmd == "ls":
            if args:
                return "bin  etc  home  usr  var  tmp"
            return "admin  sensor  actuator  config"
        
        elif cmd == "pwd":
            return "/home/coap"
        
        elif cmd == "whoami":
            return "coap"
        
        elif cmd == "id":
            return "uid=1000(coap) gid=1000(coap) groups=1000(coap)"
        
        elif cmd == "uptime":
            return "10:23:45 up 3 days,  2:15,  1 user,  load average: 0.12, 0.15, 0.18"
        
        elif cmd == "free":
            return "              total        used        free\nMem:        512000      230400      281600"
        
        elif cmd == "df":
            return "Filesystem     Size  Used Avail Use% Mounted on\n/dev/root       8G  2.1G  5.5G  28% /"
        
        elif cmd == "netstat":
            return "Active Internet connections\nProto Local Address   Foreign Address     State\nudp   0.0.0.0:5683    0.0.0.0:*"
        
        elif cmd == "route":
            return "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\ndefault         192.168.1.1     0.0.0.0         UG    0      0        0 wlan0"
        
        elif cmd == "wget" or cmd == "curl":
            if args:
                url = args[-1]
                self.log_activity("download_attempt", {"tool": cmd, "url": url})
                return f"{cmd}: Unable to resolve host"
            return f"Usage: {cmd} <url>"
        
        elif cmd == "reboot":
            return "Broadcast message: System is going down for reboot NOW!"
        
        elif cmd == "shutdown":
            return "Shutdown scheduled"
        
        else:
            return f"{cmd}: command not found"
    
    def handle(self):
        """Handle CoAP request"""
        try:
            request = CoAPPacket.parse(self.data)
            if not request:
                return
            
            path = request.get_uri_path()
            query = request.get_uri_query()
            
            self.log_activity("request", {
                "type": ["CON", "NON", "ACK", "RST"][request.type],
                "code_class": request.code >> 5,
                "code_detail": request.code & 0x1F,
                "message_id": request.message_id,
                "path": path,
                "query": query
            })
            
            # Route by method
            code_class = request.code >> 5
            code_detail = request.code & 0x1F
            
            if code_class == 0:  # Request
                if code_detail == CoAPPacket.GET:
                    self.handle_get(request, path, query)
                elif code_detail == CoAPPacket.POST:
                    self.handle_post(request, path, query)
                elif code_detail == CoAPPacket.PUT:
                    self.handle_put(request, path, query)
                elif code_detail == CoAPPacket.DELETE:
                    self.handle_delete(request, path, query)
                else:
                    self.send_response(request, CoAPPacket.NOT_IMPLEMENTED, "Method not implemented")
            
            self.save_log()
        
        except Exception as e:
            self.logger.error(f"Error handling request: {e}")
    
    def save_log(self):
        """Save session log"""
        if not self.session_log:
            return
        
        log_dir = Path(self.config.get("log_directory", "logs/coap_honeypot_logs"))
        attacks_dir = log_dir / "requests"
        attacks_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        ip = self.addr[0].replace(".", "_")
        filename = attacks_dir / f"request_{ip}_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump({
                "client": {"ip": self.addr[0], "port": self.addr[1]},
                "activity": self.session_log
            }, f, indent=2)

class CoAPHoneypot:
    """Main CoAP honeypot server"""
    def __init__(self, config_file="coap_honeypot_config.json"):
        self.load_config(config_file)
        self.setup_logging()
        self.iot_device = IoTDevice(self.config)
        self.running = False
    
    def load_config(self, config_file):
        """Load configuration"""
        default_config = {
            "host": "0.0.0.0",
            "port": 5683,
            "device_name": "CoAP IoT Device",
            "log_directory": "logs/coap_honeypot_logs",
            "log_file": "coap_honeypot.log",
            "resources": {
                "/sensor/temp": {"value": "22.5", "type": "sensor", "unit": "celsius", "observable": True},
                "/sensor/humidity": {"value": "45.0", "type": "sensor", "unit": "percent", "observable": True},
                "/sensor/pressure": {"value": "1013.25", "type": "sensor", "unit": "hPa", "observable": True},
                "/sensor/light": {"value": "350", "type": "sensor", "unit": "lux", "observable": True},
                "/actuator/light": {"value": "off", "type": "actuator", "writable": True},
                "/actuator/thermostat": {"value": "20.0", "type": "actuator", "writable": True},
                "/actuator/lock": {"value": "locked", "type": "actuator", "writable": True},
                "/actuator/alarm": {"value": "disarmed", "type": "actuator", "writable": True},
                "/info/device": {"value": "Smart IoT Device v1.0", "type": "info"},
                "/info/firmware": {"value": "v2.3.1", "type": "info"},
                "/info/manufacturer": {"value": "IoTCorp", "type": "info"},
                "/admin/shell": {"type": "shell", "writable": True},
                "/admin/config": {"type": "config", "writable": True},
                "/admin/reboot": {"type": "command", "writable": True},
                "/.well-known/core": {"type": "discovery"},
            },
            "device_info": {
                "type": "smart_sensor_hub",
                "firmware": "v2.3.1",
                "model": "SH-200",
                "manufacturer": "IoTCorp"
            }
        }
        
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        else:
            self.config = default_config
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=2)
            print(f"Created default config file: {config_file}")
    
    def setup_logging(self):
        """Setup logging"""
        log_dir = Path(self.config.get("log_directory", "logs/coap_honeypot_logs"))
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / self.config.get("log_file", "coap_honeypot.log")
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def start(self):
        """Start CoAP honeypot"""
        self.running = True
        host = self.config.get("host", "0.0.0.0")
        port = self.config.get("port", 5683)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host, port))
        
        self.logger.info(f"CoAP honeypot started on {host}:{port}")
        print(f"CoAP honeypot listening on {host}:{port}")
        print(f"Logs will be saved to: {self.config.get('log_directory')}")
        print("\nSimulated CoAP Resources:")
        for path, resource in self.iot_device.resources.items():
            info = f"  {path}"
            if "value" in resource:
                info += f" = {resource['value']}"
            if resource.get("writable"):
                info += " [writable]"
            if resource.get("observable"):
                info += " [observable]"
            print(info)
        
        print("\nTest with coap-client:")
        print(f"  Discovery: coap-client -m get coap://localhost:{port}/.well-known/core")
        print(f"  Get sensor: coap-client -m get coap://localhost:{port}/sensor/temp")
        print(f"  Set actuator: coap-client -m put coap://localhost:{port}/actuator/light -e 'on'")
        print(f"  Shell command: coap-client -m post coap://localhost:{port}/admin/shell -e 'help'")
        print("\nPress Ctrl+C to stop\n")
        
        try:
            while self.running:
                data, addr = sock.recvfrom(4096)
                self.logger.info(f"CoAP request from {addr[0]}:{addr[1]}")
                
                # Handle in thread
                session = CoAPSession(sock, addr, data, self.config, self.logger, self.iot_device)
                thread = threading.Thread(target=session.handle)
                thread.daemon = True
                thread.start()
        
        except KeyboardInterrupt:
            print("\nShutting down CoAP honeypot...")
            self.logger.info("CoAP honeypot shutting down")
        finally:
            sock.close()

if __name__ == "__main__":
    honeypot = CoAPHoneypot("configs/coap_honeypot_config.json")
    honeypot.start()