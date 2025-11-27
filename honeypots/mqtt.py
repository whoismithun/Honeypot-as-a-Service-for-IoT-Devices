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

class MQTTPacket:
    """MQTT packet parser and builder"""
    # MQTT Control Packet Types
    CONNECT = 0x10
    CONNACK = 0x20
    PUBLISH = 0x30
    PUBACK = 0x40
    SUBSCRIBE = 0x82
    SUBACK = 0x90
    UNSUBSCRIBE = 0xA0
    UNSUBACK = 0xB0
    PINGREQ = 0xC0
    PINGRESP = 0xD0
    DISCONNECT = 0xE0
    
    @staticmethod
    def encode_remaining_length(length):
        """Encode remaining length as per MQTT spec"""
        result = bytearray()
        while True:
            byte = length % 128
            length = length // 128
            if length > 0:
                byte |= 0x80
            result.append(byte)
            if length == 0:
                break
        return bytes(result)
    
    @staticmethod
    def decode_remaining_length(data, offset=1):
        """Decode remaining length from MQTT packet"""
        multiplier = 1
        value = 0
        index = offset
        
        while True:
            if index >= len(data):
                return None, index
            byte = data[index]
            value += (byte & 127) * multiplier
            multiplier *= 128
            index += 1
            if (byte & 128) == 0:
                break
        
        return value, index
    
    @staticmethod
    def decode_string(data, offset):
        """Decode MQTT UTF-8 string"""
        if offset + 2 > len(data):
            return None, offset
        length = struct.unpack('!H', data[offset:offset+2])[0]
        offset += 2
        if offset + length > len(data):
            return None, offset
        string = data[offset:offset+length].decode('utf-8', errors='ignore')
        return string, offset + length
    
    @staticmethod
    def encode_string(string):
        """Encode string as MQTT UTF-8 string"""
        encoded = string.encode('utf-8')
        return struct.pack('!H', len(encoded)) + encoded

class IoTDevice:
    """Simulates an IoT device with sensors and actuators"""
    def __init__(self, config):
        self.config = config
        self.devices = config.get("devices", {
            "sensor/temperature": {"type": "sensor", "value": 22.5, "unit": "celsius"},
            "sensor/humidity": {"type": "sensor", "value": 45.0, "unit": "percent"},
            "sensor/motion": {"type": "sensor", "value": False, "unit": "boolean"},
            "light/living_room": {"type": "actuator", "state": "off"},
            "light/bedroom": {"type": "actuator", "state": "off"},
            "thermostat/setpoint": {"type": "actuator", "value": 20.0, "unit": "celsius"},
            "door/front": {"type": "sensor", "state": "closed"},
            "camera/front": {"type": "sensor", "status": "active"},
            "alarm/status": {"type": "actuator", "state": "disarmed"},
        })
        self.admin_topics = ["admin/command", "admin/config", "admin/firmware"]
    
    def get_value(self, topic):
        """Get device value for a topic"""
        if topic in self.devices:
            device = self.devices[topic]
            if "value" in device:
                return str(device["value"])
            elif "state" in device:
                return device["state"]
            elif "status" in device:
                return device["status"]
        return None
    
    def set_value(self, topic, value):
        """Set device value for a topic"""
        if topic in self.devices:
            device = self.devices[topic]
            if device["type"] == "actuator":
                if "value" in device:
                    try:
                        device["value"] = float(value)
                        return True
                    except:
                        pass
                elif "state" in device:
                    device["state"] = value
                    return True
        return False
    
    def list_topics(self, pattern=""):
        """List available topics matching pattern"""
        if not pattern or pattern == "#":
            return list(self.devices.keys())
        
        # Simple wildcard matching
        if pattern.endswith("/#"):
            prefix = pattern[:-2]
            return [t for t in self.devices.keys() if t.startswith(prefix)]
        elif pattern.endswith("/+"):
            parts = pattern[:-2].split("/")
            return [t for t in self.devices.keys() if t.split("/")[:-1] == parts]
        
        return [t for t in self.devices.keys() if t == pattern]

class MQTTSession:
    """Handles individual MQTT client sessions"""
    def __init__(self, client_socket, addr, config, logger, iot_device):
        self.socket = client_socket
        self.addr = addr
        self.config = config
        self.logger = logger
        self.iot_device = iot_device
        self.client_id = None
        self.username = None
        self.authenticated = False
        self.subscriptions = []
        self.session_log = []
        self.running = False
        self.msg_id = 1
    
    def send_packet(self, packet_type, payload=b''):
        """Send MQTT packet"""
        try:
            remaining_length = MQTTPacket.encode_remaining_length(len(payload))
            packet = bytes([packet_type]) + remaining_length + payload
            self.socket.sendall(packet)
            return True
        except Exception as e:
            self.logger.error(f"Error sending packet: {e}")
            return False
    
    def recv_packet(self):
        """Receive and parse MQTT packet"""
        try:
            # Read fixed header
            header = self.socket.recv(1)
            if not header:
                return None, None
            
            packet_type = header[0] & 0xF0
            
            # Read remaining length
            multiplier = 1
            remaining_length = 0
            while True:
                byte_data = self.socket.recv(1)
                if not byte_data:
                    return None, None
                byte = byte_data[0]
                remaining_length += (byte & 127) * multiplier
                multiplier *= 128
                if (byte & 128) == 0:
                    break
            
            # Read payload
            payload = b''
            while len(payload) < remaining_length:
                chunk = self.socket.recv(remaining_length - len(payload))
                if not chunk:
                    return None, None
                payload += chunk
            
            return packet_type, payload
        
        except Exception as e:
            self.logger.debug(f"Error receiving packet: {e}")
            return None, None
    
    def log_activity(self, activity_type, data):
        """Log session activity"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "ip": self.addr[0],
            "port": self.addr[1],
            "client_id": self.client_id,
            "username": self.username,
            "type": activity_type,
            "data": data
        }
        self.session_log.append(entry)
        self.logger.info(json.dumps(entry))
    
    def handle_connect(self, payload):
        """Handle CONNECT packet"""
        try:
            offset = 0
            
            # Protocol name
            proto_name, offset = MQTTPacket.decode_string(payload, offset)
            # Protocol level
            proto_level = payload[offset]
            offset += 1
            # Connect flags
            connect_flags = payload[offset]
            offset += 1
            # Keep alive
            keep_alive = struct.unpack('!H', payload[offset:offset+2])[0]
            offset += 2
            
            # Client ID
            self.client_id, offset = MQTTPacket.decode_string(payload, offset)
            
            # Username/Password flags
            username_flag = (connect_flags & 0x80) != 0
            password_flag = (connect_flags & 0x40) != 0
            
            username = None
            password = None
            
            if username_flag:
                username, offset = MQTTPacket.decode_string(payload, offset)
                self.username = username
            
            if password_flag:
                password, offset = MQTTPacket.decode_string(payload, offset)
            
            self.log_activity("connect", {
                "protocol": proto_name,
                "protocol_level": proto_level,
                "client_id": self.client_id,
                "username": username,
                "password": password,
                "keep_alive": keep_alive
            })
            
            # Check authentication
            valid_creds = self.config.get("valid_credentials", {})
            if self.config.get("allow_all_logins", True):
                self.authenticated = True
                return_code = 0  # Connection accepted
            elif username and username in valid_creds and valid_creds[username] == password:
                self.authenticated = True
                return_code = 0
            elif not username_flag:
                self.authenticated = self.config.get("allow_anonymous", True)
                return_code = 0 if self.authenticated else 5  # Not authorized
            else:
                self.authenticated = False
                return_code = 4  # Bad username or password
            
            # Send CONNACK
            connack_payload = bytes([0, return_code])
            self.send_packet(MQTTPacket.CONNACK, connack_payload)
            
            return self.authenticated
        
        except Exception as e:
            self.logger.error(f"Error handling CONNECT: {e}")
            return False
    
    def handle_subscribe(self, payload):
        """Handle SUBSCRIBE packet"""
        try:
            offset = 0
            
            # Message ID
            msg_id = struct.unpack('!H', payload[offset:offset+2])[0]
            offset += 2
            
            topics = []
            qos_list = []
            
            # Parse topic filters
            while offset < len(payload):
                topic, offset = MQTTPacket.decode_string(payload, offset)
                qos = payload[offset]
                offset += 1
                
                topics.append(topic)
                qos_list.append(qos)
                self.subscriptions.append(topic)
            
            self.log_activity("subscribe", {
                "msg_id": msg_id,
                "topics": topics,
                "qos": qos_list
            })
            
            # Send SUBACK
            suback_payload = struct.pack('!H', msg_id) + bytes(qos_list)
            self.send_packet(MQTTPacket.SUBACK, suback_payload)
            
            # Publish retained messages for subscribed topics
            for topic in topics:
                available_topics = self.iot_device.list_topics(topic)
                for available_topic in available_topics:
                    value = self.iot_device.get_value(available_topic)
                    if value:
                        self.publish_message(available_topic, value)
        
        except Exception as e:
            self.logger.error(f"Error handling SUBSCRIBE: {e}")
    
    def handle_unsubscribe(self, payload):
        """Handle UNSUBSCRIBE packet"""
        try:
            offset = 0
            msg_id = struct.unpack('!H', payload[offset:offset+2])[0]
            offset += 2
            
            topics = []
            while offset < len(payload):
                topic, offset = MQTTPacket.decode_string(payload, offset)
                topics.append(topic)
                if topic in self.subscriptions:
                    self.subscriptions.remove(topic)
            
            self.log_activity("unsubscribe", {
                "msg_id": msg_id,
                "topics": topics
            })
            
            # Send UNSUBACK
            unsuback_payload = struct.pack('!H', msg_id)
            self.send_packet(MQTTPacket.UNSUBACK, unsuback_payload)
        
        except Exception as e:
            self.logger.error(f"Error handling UNSUBSCRIBE: {e}")
    
    def handle_publish(self, packet_type, payload):
        """Handle PUBLISH packet"""
        try:
            offset = 0
            
            # QoS level
            qos = (packet_type & 0x06) >> 1
            
            # Topic name
            topic, offset = MQTTPacket.decode_string(payload, offset)
            
            # Message ID (if QoS > 0)
            msg_id = None
            if qos > 0:
                msg_id = struct.unpack('!H', payload[offset:offset+2])[0]
                offset += 2
            
            # Message payload
            message = payload[offset:].decode('utf-8', errors='ignore')
            
            self.log_activity("publish", {
                "topic": topic,
                "message": message,
                "qos": qos,
                "msg_id": msg_id
            })
            
            # Check for admin commands
            if topic in self.iot_device.admin_topics:
                self.handle_admin_command(topic, message)
            else:
                # Update device state
                self.iot_device.set_value(topic, message)
            
            # Send PUBACK if QoS 1
            if qos == 1 and msg_id:
                puback_payload = struct.pack('!H', msg_id)
                self.send_packet(MQTTPacket.PUBACK, puback_payload)
        
        except Exception as e:
            self.logger.error(f"Error handling PUBLISH: {e}")
    
    def handle_admin_command(self, topic, command):
        """Handle administrative commands"""
        self.log_activity("admin_command", {
            "topic": topic,
            "command": command
        })
        
        try:
            if topic == "admin/command":
                # Parse command
                parts = command.split()
                if not parts:
                    return
                
                cmd = parts[0].lower()
                args = parts[1:] if len(parts) > 1 else []
                
                response = self.execute_command(cmd, args)
                self.publish_message("admin/response", response)
            
            elif topic == "admin/config":
                # Configuration update attempt
                self.publish_message("admin/response", "Config updated (simulated)")
            
            elif topic == "admin/firmware":
                # Firmware update attempt
                self.publish_message("admin/response", "Firmware update initiated (simulated)")
        
        except Exception as e:
            self.logger.error(f"Error handling admin command: {e}")
    
    def execute_command(self, cmd, args):
        """Execute administrative shell command"""
        if cmd == "help":
            return "Available commands: status, list, get, set, reboot, config"
        
        elif cmd == "status":
            return "System: Online | Clients: 1 | Uptime: 24h"
        
        elif cmd == "list":
            topics = self.iot_device.list_topics()
            return "Available topics:\n" + "\n".join(topics)
        
        elif cmd == "get":
            if args:
                topic = args[0]
                value = self.iot_device.get_value(topic)
                return f"{topic}: {value}" if value else "Topic not found"
            return "Usage: get <topic>"
        
        elif cmd == "set":
            if len(args) >= 2:
                topic, value = args[0], args[1]
                if self.iot_device.set_value(topic, value):
                    return f"Set {topic} = {value}"
                return "Failed to set value"
            return "Usage: set <topic> <value>"
        
        elif cmd == "reboot":
            return "Device rebooting... (simulated)"
        
        elif cmd == "config":
            return json.dumps(self.config.get("device_config", {}), indent=2)
        
        elif cmd == "ps":
            return "PID  COMMAND\n1    mqtt_broker\n2    sensor_reader\n3    actuator_control"
        
        elif cmd == "uname":
            return "Linux mqtt-iot 4.19.0 armv7l GNU/Linux"
        
        elif cmd == "ifconfig":
            return "eth0: inet 192.168.1.100  netmask 255.255.255.0"
        
        elif cmd == "cat":
            if args:
                file = args[0]
                if file == "/etc/passwd":
                    return "root:x:0:0:root:/root:/bin/sh\nmqtt:x:1000:1000::/home/mqtt:/bin/sh"
                elif file == "/etc/shadow":
                    return "Permission denied"
                return f"cat: {file}: No such file"
            return "Usage: cat <file>"
        
        else:
            return f"{cmd}: command not found"
    
    def publish_message(self, topic, message):
        """Publish a message to subscribed clients"""
        try:
            # Build PUBLISH packet
            topic_bytes = MQTTPacket.encode_string(topic)
            message_bytes = message.encode('utf-8')
            payload = topic_bytes + message_bytes
            
            self.send_packet(MQTTPacket.PUBLISH, payload)
        except Exception as e:
            self.logger.error(f"Error publishing message: {e}")
    
    def handle(self):
        """Main session handler"""
        self.running = True
        self.log_activity("connection", "MQTT client connected")
        
        try:
            while self.running:
                packet_type, payload = self.recv_packet()
                
                if packet_type is None:
                    break
                
                if packet_type == MQTTPacket.CONNECT:
                    if not self.handle_connect(payload):
                        self.logger.warning(f"Authentication failed for {self.addr[0]}")
                        break
                
                elif packet_type == MQTTPacket.SUBSCRIBE:
                    self.handle_subscribe(payload)
                
                elif packet_type == MQTTPacket.UNSUBSCRIBE:
                    self.handle_unsubscribe(payload)
                
                elif (packet_type & 0xF0) == MQTTPacket.PUBLISH:
                    self.handle_publish(packet_type, payload)
                
                elif packet_type == MQTTPacket.PINGREQ:
                    self.send_packet(MQTTPacket.PINGRESP)
                
                elif packet_type == MQTTPacket.DISCONNECT:
                    self.log_activity("disconnect", "Client disconnected gracefully")
                    break
        
        except Exception as e:
            self.logger.error(f"Session error: {e}")
        
        finally:
            self.running = False
            self.log_activity("disconnect", "Session ended")
            self.save_session_log()
            self.socket.close()
    
    def save_session_log(self):
        """Save session log to file"""
        # UPDATED: default to ../logs (same dir as main logs)
        log_dir = Path(self.config.get("log_directory", "../logs"))
        log_dir.mkdir(exist_ok=True, parents=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        client_id = self.client_id or "unknown"
        filename = log_dir / f"session_{self.addr[0]}_{client_id}_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump({
                "session_info": {
                    "ip": self.addr[0],
                    "port": self.addr[1],
                    "client_id": self.client_id,
                    "username": self.username,
                    "authenticated": self.authenticated,
                    "subscriptions": self.subscriptions
                },
                "activity": self.session_log
            }, f, indent=2)

class MQTTHoneypot:
    """Main MQTT honeypot broker"""
    def __init__(self, config_file="../configs/mqtt.json"):
        self.load_config(config_file)
        self.setup_logging()
        self.iot_device = IoTDevice(self.config)
        self.running = False
        self.clients = []
    
    def load_config(self, config_file):
        """Load configuration from file"""
        default_config = {
            "host": "0.0.0.0",
            "port": 1883,
            "broker_name": "IoT MQTT Broker",
            "allow_all_logins": True,
            "allow_anonymous": True,
            "valid_credentials": {
                "admin": "admin",
                "mqtt": "mqtt",
                "iot": "password",
                "device": "device123"
            },
            # UPDATED: logs path
            "log_directory": "../logs",
            "log_file": "mqtt.logs",
            "devices": {
                "sensor/temperature": {"type": "sensor", "value": 22.5, "unit": "celsius"},
                "sensor/humidity": {"type": "sensor", "value": 45.0, "unit": "percent"},
                "sensor/motion": {"type": "sensor", "value": False, "unit": "boolean"},
                "light/living_room": {"type": "actuator", "state": "off"},
                "light/bedroom": {"type": "actuator", "state": "off"},
                "thermostat/setpoint": {"type": "actuator", "value": 20.0, "unit": "celsius"},
                "door/front": {"type": "sensor", "state": "closed"},
                "camera/front": {"type": "sensor", "status": "active"},
                "alarm/status": {"type": "actuator", "state": "disarmed"},
                "admin/command": {"type": "admin"},
                "admin/config": {"type": "admin"},
                "admin/firmware": {"type": "admin"}
            },
            "device_config": {
                "device_type": "smart_home_hub",
                "firmware_version": "1.2.3",
                "model": "SH-100",
                "manufacturer": "IoTDevices Inc."
            }
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
        
        log_file = log_dir / self.config.get("log_file", "mqtt.logs")
        
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
        session = MQTTSession(client_socket, addr, self.config, self.logger, self.iot_device)
        self.clients.append(session)
        try:
            session.handle()
        except Exception as e:
            self.logger.error(f"Error handling client {addr}: {e}")
        finally:
            if session in self.clients:
                self.clients.remove(session)
    
    def start(self):
        """Start the MQTT honeypot broker"""
        self.running = True
        host = self.config.get("host", "0.0.0.0")
        port = self.config.get("port", 1883)
        
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(5)
        
        log_dir = Path(self.config.get("log_directory", "../logs"))
        log_file = log_dir / self.config.get("log_file", "mqtt.logs")
        
        self.logger.info(f"MQTT honeypot started on {host}:{port}")
        print(f"MQTT honeypot listening on {host}:{port}")
        print(f"Logs will be saved to: {log_file}")
        print("\nSimulated IoT Devices:")
        for topic, device in self.iot_device.devices.items():
            print(f"  - {topic}: {device}")
        print(f"\nConnect with: mosquitto_sub -h {host} -p {port} -t '#'")
        print("Press Ctrl+C to stop\n")
        
        try:
            while self.running:
                client_socket, addr = server.accept()
                self.logger.info(f"New MQTT connection from {addr[0]}:{addr[1]}")
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, addr)
                )
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            print("\nShutting down MQTT honeypot...")
            self.logger.info("MQTT honeypot shutting down")
        finally:
            server.close()

if __name__ == "__main__":
    honeypot = MQTTHoneypot("../configs/mqtt.json")
    honeypot.start()
