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

class ModbusPacket:
    """Modbus TCP packet parser and builder"""
    # Modbus Function Codes
    READ_COILS = 0x01
    READ_DISCRETE_INPUTS = 0x02
    READ_HOLDING_REGISTERS = 0x03
    READ_INPUT_REGISTERS = 0x04
    WRITE_SINGLE_COIL = 0x05
    WRITE_SINGLE_REGISTER = 0x06
    WRITE_MULTIPLE_COILS = 0x0F
    WRITE_MULTIPLE_REGISTERS = 0x10
    READ_DEVICE_ID = 0x2B
    DIAGNOSTIC = 0x08
    
    # Exception Codes
    ILLEGAL_FUNCTION = 0x01
    ILLEGAL_DATA_ADDRESS = 0x02
    ILLEGAL_DATA_VALUE = 0x03
    SLAVE_DEVICE_FAILURE = 0x04
    
    def __init__(self):
        self.transaction_id = 0
        self.protocol_id = 0
        self.length = 0
        self.unit_id = 1
        self.function_code = 0
        self.data = b''
    
    @staticmethod
    def parse(data):
        """Parse Modbus TCP packet"""
        if len(data) < 8:
            return None
        
        packet = ModbusPacket()
        
        # MBAP Header
        packet.transaction_id = struct.unpack('!H', data[0:2])[0]
        packet.protocol_id = struct.unpack('!H', data[2:4])[0]
        packet.length = struct.unpack('!H', data[4:6])[0]
        packet.unit_id = data[6]
        
        # PDU
        packet.function_code = data[7]
        packet.data = data[8:]
        
        return packet
    
    def build_response(self, data):
        """Build Modbus TCP response"""
        # MBAP Header
        response = struct.pack('!H', self.transaction_id)
        response += struct.pack('!H', self.protocol_id)
        response += struct.pack('!H', len(data) + 2)  # length includes unit_id + function + data
        response += struct.pack('!B', self.unit_id)
        response += data
        return response
    
    def build_exception(self, exception_code):
        """Build Modbus exception response"""
        function_code = self.function_code | 0x80
        data = struct.pack('!BB', function_code, exception_code)
        return self.build_response(data)

class SCADADevice:
    """Simulates SCADA/ICS device with registers and coils"""
    def __init__(self, config):
        self.config = config
        
        # Initialize registers (holding registers)
        self.holding_registers = config.get("holding_registers", {
            0: 0,      # System status
            1: 2250,   # Temperature (22.5°C * 100)
            2: 4500,   # Pressure (45.0 PSI * 100)
            3: 1500,   # Flow rate (15.0 L/s * 100)
            4: 8000,   # Voltage (80.0V * 100)
            5: 1200,   # Current (12.0A * 100)
            10: 100,   # Setpoint 1
            11: 200,   # Setpoint 2
            100: 0x1234,  # Device ID
            101: 0x0100,  # Firmware version
        })
        
        # Input registers (read-only sensors)
        self.input_registers = config.get("input_registers", {
            0: 2250,   # Temperature sensor
            1: 4500,   # Pressure sensor
            2: 1500,   # Flow sensor
            3: 8000,   # Voltage sensor
        })
        
        # Coils (digital outputs)
        self.coils = config.get("coils", {
            0: False,  # Pump 1
            1: False,  # Pump 2
            2: False,  # Valve 1
            3: False,  # Valve 2
            4: True,   # Emergency stop
            5: False,  # Alarm
            10: False, # Motor 1
            11: False, # Motor 2
        })
        
        # Discrete inputs (digital inputs)
        self.discrete_inputs = config.get("discrete_inputs", {
            0: False,  # Sensor 1
            1: True,   # Sensor 2
            2: False,  # Door open
            3: True,   # System ready
        })
        
        self.device_info = config.get("device_info", {
            "vendor": "SCADA Systems Inc.",
            "product_code": "PLC-500",
            "major_minor_revision": "v2.1",
            "vendor_url": "www.scadasystems.com",
            "product_name": "Industrial PLC Controller",
            "model_name": "PLC-500-A1"
        })
    
    def read_holding_registers(self, address, count):
        """Read holding registers"""
        values = []
        for i in range(count):
            addr = address + i
            values.append(self.holding_registers.get(addr, 0))
        return values
    
    def write_holding_register(self, address, value):
        """Write single holding register"""
        self.holding_registers[address] = value
        return True
    
    def write_holding_registers(self, address, values):
        """Write multiple holding registers"""
        for i, value in enumerate(values):
            self.holding_registers[address + i] = value
        return True
    
    def read_input_registers(self, address, count):
        """Read input registers"""
        values = []
        for i in range(count):
            addr = address + i
            values.append(self.input_registers.get(addr, 0))
        return values
    
    def read_coils(self, address, count):
        """Read coils"""
        values = []
        for i in range(count):
            addr = address + i
            values.append(self.coils.get(addr, False))
        return values
    
    def write_coil(self, address, value):
        """Write single coil"""
        self.coils[address] = value
        return True
    
    def write_coils(self, address, values):
        """Write multiple coils"""
        for i, value in enumerate(values):
            self.coils[address + i] = value
        return True
    
    def read_discrete_inputs(self, address, count):
        """Read discrete inputs"""
        values = []
        for i in range(count):
            addr = address + i
            values.append(self.discrete_inputs.get(addr, False))
        return values

class ModbusSession:
    """Handles individual Modbus TCP sessions"""
    def __init__(self, client_socket, addr, config, logger, scada_device):
        self.socket = client_socket
        self.addr = addr
        self.config = config
        self.logger = logger
        self.scada_device = scada_device
        self.session_log = []
        self.running = False
    
    def log_activity(self, activity_type, data):
        """Log session activity"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "ip": self.addr[0],
            "port": self.addr[1],
            "type": activity_type,
            "data": data
        }
        self.session_log.append(entry)
        self.logger.info(json.dumps(entry))
    
    def send_response(self, packet, data):
        """Send Modbus response"""
        try:
            response = packet.build_response(data)
            self.socket.sendall(response)
        except Exception as e:
            self.logger.error(f"Error sending response: {e}")
    
    def send_exception(self, packet, exception_code):
        """Send Modbus exception"""
        try:
            response = packet.build_exception(exception_code)
            self.socket.sendall(response)
        except Exception as e:
            self.logger.error(f"Error sending exception: {e}")
    
    def handle_read_coils(self, packet):
        """Handle Read Coils (0x01)"""
        if len(packet.data) < 4:
            self.send_exception(packet, ModbusPacket.ILLEGAL_DATA_VALUE)
            return
        
        address = struct.unpack('!H', packet.data[0:2])[0]
        count = struct.unpack('!H', packet.data[2:4])[0]
        
        self.log_activity("read_coils", {
            "address": address,
            "count": count
        })
        
        # Read coils
        coils = self.scada_device.read_coils(address, count)
        
        # Pack coils into bytes
        byte_count = (count + 7) // 8
        coil_bytes = bytearray(byte_count)
        for i, coil in enumerate(coils):
            if coil:
                byte_idx = i // 8
                bit_idx = i % 8
                coil_bytes[byte_idx] |= (1 << bit_idx)
        
        # Build response
        response_data = struct.pack('!BB', packet.function_code, byte_count) + bytes(coil_bytes)
        self.send_response(packet, response_data)
    
    def handle_read_discrete_inputs(self, packet):
        """Handle Read Discrete Inputs (0x02)"""
        if len(packet.data) < 4:
            self.send_exception(packet, ModbusPacket.ILLEGAL_DATA_VALUE)
            return
        
        address = struct.unpack('!H', packet.data[0:2])[0]
        count = struct.unpack('!H', packet.data[2:4])[0]
        
        self.log_activity("read_discrete_inputs", {
            "address": address,
            "count": count
        })
        
        # Read discrete inputs
        inputs = self.scada_device.read_discrete_inputs(address, count)
        
        # Pack into bytes
        byte_count = (count + 7) // 8
        input_bytes = bytearray(byte_count)
        for i, inp in enumerate(inputs):
            if inp:
                byte_idx = i // 8
                bit_idx = i % 8
                input_bytes[byte_idx] |= (1 << bit_idx)
        
        response_data = struct.pack('!BB', packet.function_code, byte_count) + bytes(input_bytes)
        self.send_response(packet, response_data)
    
    def handle_read_holding_registers(self, packet):
        """Handle Read Holding Registers (0x03)"""
        if len(packet.data) < 4:
            self.send_exception(packet, ModbusPacket.ILLEGAL_DATA_VALUE)
            return
        
        address = struct.unpack('!H', packet.data[0:2])[0]
        count = struct.unpack('!H', packet.data[2:4])[0]
        
        self.log_activity("read_holding_registers", {
            "address": address,
            "count": count
        })
        
        # Read registers
        registers = self.scada_device.read_holding_registers(address, count)
        
        # Build response
        byte_count = count * 2
        response_data = struct.pack('!BB', packet.function_code, byte_count)
        for reg in registers:
            response_data += struct.pack('!H', reg)
        
        self.send_response(packet, response_data)
    
    def handle_read_input_registers(self, packet):
        """Handle Read Input Registers (0x04)"""
        if len(packet.data) < 4:
            self.send_exception(packet, ModbusPacket.ILLEGAL_DATA_VALUE)
            return
        
        address = struct.unpack('!H', packet.data[0:2])[0]
        count = struct.unpack('!H', packet.data[2:4])[0]
        
        self.log_activity("read_input_registers", {
            "address": address,
            "count": count
        })
        
        # Read registers
        registers = self.scada_device.read_input_registers(address, count)
        
        # Build response
        byte_count = count * 2
        response_data = struct.pack('!BB', packet.function_code, byte_count)
        for reg in registers:
            response_data += struct.pack('!H', reg)
        
        self.send_response(packet, response_data)
    
    def handle_write_single_coil(self, packet):
        """Handle Write Single Coil (0x05)"""
        if len(packet.data) < 4:
            self.send_exception(packet, ModbusPacket.ILLEGAL_DATA_VALUE)
            return
        
        address = struct.unpack('!H', packet.data[0:2])[0]
        value = struct.unpack('!H', packet.data[2:4])[0]
        coil_value = (value == 0xFF00)
        
        self.log_activity("write_single_coil", {
            "address": address,
            "value": coil_value
        })
        
        # Write coil
        self.scada_device.write_coil(address, coil_value)
        
        # Echo request as response
        response_data = struct.pack('!B', packet.function_code) + packet.data[:4]
        self.send_response(packet, response_data)
    
    def handle_write_single_register(self, packet):
        """Handle Write Single Register (0x06)"""
        if len(packet.data) < 4:
            self.send_exception(packet, ModbusPacket.ILLEGAL_DATA_VALUE)
            return
        
        address = struct.unpack('!H', packet.data[0:2])[0]
        value = struct.unpack('!H', packet.data[2:4])[0]
        
        self.log_activity("write_single_register", {
            "address": address,
            "value": value
        })
        
        # Write register
        self.scada_device.write_holding_register(address, value)
        
        # Echo request as response
        response_data = struct.pack('!B', packet.function_code) + packet.data[:4]
        self.send_response(packet, response_data)
    
    def handle_write_multiple_coils(self, packet):
        """Handle Write Multiple Coils (0x0F)"""
        if len(packet.data) < 5:
            self.send_exception(packet, ModbusPacket.ILLEGAL_DATA_VALUE)
            return
        
        address = struct.unpack('!H', packet.data[0:2])[0]
        count = struct.unpack('!H', packet.data[2:4])[0]
        byte_count = packet.data[4]
        
        # Parse coil values
        coils = []
        for i in range(count):
            byte_idx = i // 8
            bit_idx = i % 8
            if byte_idx + 5 < len(packet.data):
                coil = bool(packet.data[5 + byte_idx] & (1 << bit_idx))
                coils.append(coil)
        
        self.log_activity("write_multiple_coils", {
            "address": address,
            "count": count,
            "values": coils
        })
        
        # Write coils
        self.scada_device.write_coils(address, coils)
        
        # Response
        response_data = struct.pack('!BHH', packet.function_code, address, count)
        self.send_response(packet, response_data)
    
    def handle_write_multiple_registers(self, packet):
        """Handle Write Multiple Registers (0x10)"""
        if len(packet.data) < 5:
            self.send_exception(packet, ModbusPacket.ILLEGAL_DATA_VALUE)
            return
        
        address = struct.unpack('!H', packet.data[0:2])[0]
        count = struct.unpack('!H', packet.data[2:4])[0]
        byte_count = packet.data[4]
        
        # Parse register values
        values = []
        for i in range(count):
            offset = 5 + (i * 2)
            if offset + 1 < len(packet.data):
                value = struct.unpack('!H', packet.data[offset:offset+2])[0]
                values.append(value)
        
        self.log_activity("write_multiple_registers", {
            "address": address,
            "count": count,
            "values": values
        })
        
        # Write registers
        self.scada_device.write_holding_registers(address, values)
        
        # Response
        response_data = struct.pack('!BHH', packet.function_code, address, count)
        self.send_response(packet, response_data)
    
    def handle_read_device_id(self, packet):
        """Handle Read Device Identification (0x2B/0x0E)"""
        self.log_activity("read_device_id", {
            "mei_type": packet.data[0] if len(packet.data) > 0 else None
        })
        
        device_info = self.scada_device.device_info
        
        # Simplified device ID response
        response_data = struct.pack('!BBB', packet.function_code, 0x0E, 0x01)
        response_data += struct.pack('!BBB', 0x00, 0x00, 0x03)  # Conformity, more follows, next obj id, num objects
        
        # Add vendor name
        vendor = device_info.get("vendor", "Unknown").encode('utf-8')
        response_data += struct.pack('!BBB', 0x00, len(vendor), 0x00) + vendor
        
        self.send_response(packet, response_data)
    
    def handle_diagnostic(self, packet):
        """Handle Diagnostic (0x08)"""
        if len(packet.data) < 2:
            self.send_exception(packet, ModbusPacket.ILLEGAL_DATA_VALUE)
            return
        
        sub_function = struct.unpack('!H', packet.data[0:2])[0]
        
        self.log_activity("diagnostic", {
            "sub_function": sub_function,
            "data": packet.data[2:].hex()
        })
        
        # Echo the request
        response_data = struct.pack('!B', packet.function_code) + packet.data
        self.send_response(packet, response_data)
    
    def handle(self):
        """Main session handler"""
        self.running = True
        self.log_activity("connection", "Modbus TCP client connected")
        
        try:
            while self.running:
                # Receive data
                data = self.socket.recv(1024)
                if not data:
                    break
                
                # Parse packet
                packet = ModbusPacket.parse(data)
                if not packet:
                    continue
                
                self.log_activity("request", {
                    "transaction_id": packet.transaction_id,
                    "unit_id": packet.unit_id,
                    "function_code": packet.function_code,
                    "data_hex": packet.data.hex()
                })
                
                # Route by function code
                if packet.function_code == ModbusPacket.READ_COILS:
                    self.handle_read_coils(packet)
                elif packet.function_code == ModbusPacket.READ_DISCRETE_INPUTS:
                    self.handle_read_discrete_inputs(packet)
                elif packet.function_code == ModbusPacket.READ_HOLDING_REGISTERS:
                    self.handle_read_holding_registers(packet)
                elif packet.function_code == ModbusPacket.READ_INPUT_REGISTERS:
                    self.handle_read_input_registers(packet)
                elif packet.function_code == ModbusPacket.WRITE_SINGLE_COIL:
                    self.handle_write_single_coil(packet)
                elif packet.function_code == ModbusPacket.WRITE_SINGLE_REGISTER:
                    self.handle_write_single_register(packet)
                elif packet.function_code == ModbusPacket.WRITE_MULTIPLE_COILS:
                    self.handle_write_multiple_coils(packet)
                elif packet.function_code == ModbusPacket.WRITE_MULTIPLE_REGISTERS:
                    self.handle_write_multiple_registers(packet)
                elif packet.function_code == ModbusPacket.DIAGNOSTIC:
                    self.handle_diagnostic(packet)
                elif packet.function_code == ModbusPacket.READ_DEVICE_ID:
                    self.handle_read_device_id(packet)
                else:
                    self.log_activity("unsupported_function", {
                        "function_code": packet.function_code
                    })
                    self.send_exception(packet, ModbusPacket.ILLEGAL_FUNCTION)
        
        except Exception as e:
            self.logger.error(f"Session error: {e}")
        
        finally:
            self.running = False
            self.log_activity("disconnect", "Session ended")
            self.save_session_log()
            self.socket.close()
    
    def save_session_log(self):
        """Save session log to file"""
        # UPDATED: default to ../logs, create parents
        log_dir = Path(self.config.get("log_directory", "../logs"))
        log_dir.mkdir(exist_ok=True, parents=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = log_dir / f"session_{self.addr[0]}_{self.addr[1]}_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump({
                "session_info": {
                    "ip": self.addr[0],
                    "port": self.addr[1],
                    "start": self.session_log[0]["timestamp"] if self.session_log else None,
                    "end": self.session_log[-1]["timestamp"] if self.session_log else None
                },
                "activity": self.session_log
            }, f, indent=2)

class ModbusHoneypot:
    """Main Modbus TCP honeypot server"""
    def __init__(self, config_file="../configs/modbus.json"):
        self.load_config(config_file)
        self.setup_logging()
        self.scada_device = SCADADevice(self.config)
        self.running = False
    
    def load_config(self, config_file):
        """Load configuration from file"""
        default_config = {
            "host": "0.0.0.0",
            "port": 502,
            "device_name": "Industrial PLC Controller",
            # UPDATED: logs path
            "log_directory": "../logs",
            "log_file": "modbus.logs",
            "holding_registers": {
                0: 1,      # System status (1=running)
                1: 2250,   # Temperature (22.5°C * 100)
                2: 4500,   # Pressure (45.0 PSI * 100)
                3: 1500,   # Flow rate (15.0 L/s * 100)
                4: 8000,   # Voltage (80.0V * 100)
                5: 1200,   # Current (12.0A * 100)
                6: 6000,   # RPM (6000)
                7: 500,    # Level (50.0% * 10)
                10: 2000,  # Setpoint 1 (target temp)
                11: 4000,  # Setpoint 2 (target pressure)
                12: 1000,  # Setpoint 3 (target flow)
                100: 0x1234,  # Device ID
                101: 0x0210,  # Firmware version (2.10)
                102: 0x0001,  # Configuration flags
            },
            "input_registers": {
                0: 2250,   # Temperature sensor
                1: 4500,   # Pressure sensor
                2: 1500,   # Flow sensor
                3: 8000,   # Voltage sensor
                4: 1200,   # Current sensor
                5: 6000,   # RPM sensor
            },
            "coils": {
                0: False,  # Pump 1
                1: False,  # Pump 2
                2: False,  # Valve 1 (inlet)
                3: False,  # Valve 2 (outlet)
                4: True,   # Emergency stop (normally closed)
                5: False,  # Alarm
                6: False,  # Warning light
                10: False, # Motor 1
                11: False, # Motor 2
                12: False, # Heater
                13: False, # Cooler
            },
            "discrete_inputs": {
                0: False,  # High pressure alarm
                1: False,  # Low level alarm
                2: False,  # Door open
                3: True,   # System ready
                4: False,  # Maintenance mode
                5: True,   # Power OK
            },
            "device_info": {
                "vendor": "SCADA Systems Inc.",
                "product_code": "PLC-500",
                "major_minor_revision": "v2.1",
                "vendor_url": "www.scadasystems.com",
                "product_name": "Industrial PLC Controller",
                "model_name": "PLC-500-A1"
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
        # UPDATED: default to ../logs and parents=True
        log_dir = Path(self.config.get("log_directory", "../logs"))
        log_dir.mkdir(exist_ok=True, parents=True)
        
        log_file = log_dir / self.config.get("log_file", "modbus.logs")
        
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
        session = ModbusSession(client_socket, addr, self.config, self.logger, self.scada_device)
        try:
            session.handle()
        except Exception as e:
            self.logger.error(f"Error handling client {addr}: {e}")
    
    def start(self):
        """Start the Modbus TCP honeypot server"""
        self.running = True
        host = self.config.get("host", "0.0.0.0")
        port = self.config.get("port", 502)
        
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server.bind((host, port))
        except PermissionError:
            print(f"⚠️  Error: Port {port} requires root/admin privileges")
            print(f"Run with sudo or use a higher port (e.g., 5502)")
            print(f"Example: sudo python modbus_honeypot.py")
            return
        
        server.listen(5)
        
        log_dir = Path(self.config.get("log_directory", "../logs"))
        log_file = log_dir / self.config.get("log_file", "modbus.logs")
        
        self.logger.info(f"Modbus TCP honeypot started on {host}:{port}")
        print(f"Modbus TCP honeypot listening on {host}:{port}")
        print(f"Logs will be saved to: {log_file}")
        
        print("\n" + "="*60)
        print("SIMULATED SCADA/ICS DEVICE")
        print("="*60)
        
        print("\nHolding Registers (Read/Write):")
        for addr, value in sorted(self.scada_device.holding_registers.items())[:10]:
            print(f"  Register {addr}: {value}")
        
        print("\nInput Registers (Read-Only Sensors):")
        for addr, value in sorted(self.scada_device.input_registers.items()):
            print(f"  Register {addr}: {value}")
        
        print("\nCoils (Digital Outputs):")
        for addr, value in sorted(self.scada_device.coils.items())[:10]:
            print(f"  Coil {addr}: {'ON' if value else 'OFF'}")
        
        print("\nDiscrete Inputs (Digital Inputs):")
        for addr, value in sorted(self.scada_device.discrete_inputs.items()):
            print(f"  Input {addr}: {'ON' if value else 'OFF'}")
        
        print("\n" + "="*60)
        print("Test with modbus tools:")
        print(f"  Read holding registers: modpoll -m tcp -a 1 -r 1 -c 10 localhost {port}")
        print(f"  Write single register: modpoll -m tcp -a 1 -r 10 -c 1 localhost {port} 2500")
        print(f"  Read coils: modpoll -m tcp -a 1 -t 0 -r 0 -c 10 localhost {port}")
        print("="*60)
        print("\nPress Ctrl+C to stop\n")
        
        try:
            while self.running:
                client_socket, addr = server.accept()
                self.logger.info(f"New Modbus connection from {addr[0]}:{addr[1]}")
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, addr)
                )
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            print("\nShutting down Modbus honeypot...")
            self.logger.info("Modbus honeypot shutting down")
        finally:
            server.close()

if __name__ == "__main__":
    honeypot = ModbusHoneypot("../configs/modbus.json")
    honeypot.start()
