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
import random

class DNP3Packet:
    """DNP3 packet parser and builder"""
    # DNP3 Function Codes
    CONFIRM = 0x00
    READ = 0x01
    WRITE = 0x02
    SELECT = 0x03
    OPERATE = 0x04
    DIRECT_OPERATE = 0x05
    DIRECT_OPERATE_NR = 0x06
    FREEZE = 0x07
    FREEZE_NR = 0x08
    FREEZE_CLEAR = 0x09
    FREEZE_CLEAR_NR = 0x0A
    FREEZE_AT_TIME = 0x0B
    COLD_RESTART = 0x0D
    WARM_RESTART = 0x0E
    INITIALIZE_DATA = 0x0F
    INITIALIZE_APPLICATION = 0x10
    ENABLE_UNSOLICITED = 0x14
    DISABLE_UNSOLICITED = 0x15
    RESPONSE = 0x81
    UNSOLICITED_RESPONSE = 0x82
    
    # Object Groups
    BINARY_INPUT = 1
    BINARY_OUTPUT = 10
    COUNTER = 20
    ANALOG_INPUT = 30
    ANALOG_OUTPUT = 40
    TIME_AND_DATE = 50
    CLASS_0_DATA = 60
    CLASS_1_DATA = 61
    CLASS_2_DATA = 62
    CLASS_3_DATA = 63
    DEVICE_ATTRIBUTES = 0
    
    # Variations
    BINARY_INPUT_ANY = 0
    BINARY_INPUT_PACKED = 1
    BINARY_INPUT_WITH_STATUS = 2
    
    ANALOG_INPUT_ANY = 0
    ANALOG_INPUT_32BIT = 1
    ANALOG_INPUT_16BIT = 2
    ANALOG_INPUT_32BIT_NO_FLAG = 3
    ANALOG_INPUT_16BIT_NO_FLAG = 4
    
    def __init__(self):
        self.start_bytes = 0x0564
        self.length = 0
        self.control = 0
        self.dest = 0
        self.src = 0
        self.crc = 0
        
        # Transport header
        self.transport_header = 0
        
        # Application layer
        self.app_control = 0
        self.function_code = 0
        self.objects = []
        self.data = b''
    
    @staticmethod
    def calculate_crc(data):
        """Calculate DNP3 CRC-16"""
        crc = 0
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xA6BC
                else:
                    crc >>= 1
        return (~crc) & 0xFFFF
    
    @staticmethod
    def parse(data):
        """Parse DNP3 packet"""
        if len(data) < 10:
            return None
        
        packet = DNP3Packet()
        
        # Parse header
        packet.start_bytes = struct.unpack('<H', data[0:2])[0]
        if packet.start_bytes != 0x0564:
            return None
        
        packet.length = data[2]
        packet.control = data[3]
        packet.dest = struct.unpack('<H', data[4:6])[0]
        packet.src = struct.unpack('<H', data[6:8])[0]
        packet.crc = struct.unpack('<H', data[8:10])[0]
        
        # Verify header CRC
        header_crc = DNP3Packet.calculate_crc(data[0:8])
        if header_crc != packet.crc:
            return None
        
        offset = 10
        
        # Remove CRCs from data blocks (every 16 bytes has 2 byte CRC)
        user_data = bytearray()
        while offset < len(data):
            block_size = min(16, len(data) - offset - 2)
            if block_size > 0:
                user_data.extend(data[offset:offset+block_size])
                offset += block_size + 2  # Skip CRC
        
        if len(user_data) < 2:
            return None
        
        # Parse transport header
        packet.transport_header = user_data[0]
        
        # Parse application layer
        packet.app_control = user_data[1]
        packet.function_code = user_data[2] if len(user_data) > 2 else 0
        
        packet.data = bytes(user_data[3:]) if len(user_data) > 3 else b''
        
        return packet
    
    def build_response(self, function_code, data=b''):
        """Build DNP3 response packet"""
        # Application layer
        app_data = bytes([self.app_control, function_code]) + data
        
        # Add transport header
        user_data = bytes([0xC0]) + app_data  # FIR=1, FIN=1, sequence=0
        
        # Calculate length
        length = len(user_data)
        
        # Add CRCs to data blocks
        data_with_crc = bytearray()
        offset = 0
        while offset < len(user_data):
            block = user_data[offset:offset+16]
            data_with_crc.extend(block)
            crc = self.calculate_crc(block)
            data_with_crc.extend(struct.pack('<H', crc))
            offset += 16
        
        # Build header
        header = struct.pack('<HBB', self.start_bytes, length, 0xC4)  # Control: DIR=1, PRM=1
        header += struct.pack('<H', self.src)  # Swap src/dest for response
        header += struct.pack('<H', self.dest)
        
        # Add header CRC
        header_crc = self.calculate_crc(header)
        header += struct.pack('<H', header_crc)
        
        return header + bytes(data_with_crc)

class UtilityDevice:
    """Simulates utility/SCADA device with DNP3 points"""
    def __init__(self, config):
        self.config = config
        
        # Binary inputs (status points)
        self.binary_inputs = config.get("binary_inputs", {
            0: {"value": True, "name": "Breaker_CB1_Closed"},
            1: {"value": True, "name": "Breaker_CB2_Closed"},
            2: {"value": False, "name": "Breaker_CB3_Closed"},
            3: {"value": False, "name": "Alarm_OverCurrent"},
            4: {"value": False, "name": "Alarm_UnderVoltage"},
            5: {"value": True, "name": "System_Normal"},
            6: {"value": False, "name": "Emergency_Stop"},
            7: {"value": True, "name": "SCADA_Connected"},
            8: {"value": False, "name": "Generator_Running"},
            9: {"value": True, "name": "Grid_Connected"},
        })
        
        # Binary outputs (control points)
        self.binary_outputs = config.get("binary_outputs", {
            0: {"value": False, "name": "Trip_CB1"},
            1: {"value": False, "name": "Trip_CB2"},
            2: {"value": False, "name": "Close_CB3"},
            3: {"value": False, "name": "Start_Generator"},
            4: {"value": False, "name": "Alarm_Reset"},
        })
        
        # Analog inputs (measurements)
        self.analog_inputs = config.get("analog_inputs", {
            0: {"value": 13800, "name": "Voltage_L1", "unit": "V"},
            1: {"value": 13750, "name": "Voltage_L2", "unit": "V"},
            2: {"value": 13820, "name": "Voltage_L3", "unit": "V"},
            3: {"value": 245, "name": "Current_L1", "unit": "A"},
            4: {"value": 238, "name": "Current_L2", "unit": "A"},
            5: {"value": 251, "name": "Current_L3", "unit": "A"},
            6: {"value": 5985, "name": "Active_Power", "unit": "kW"},
            7: {"value": 1250, "name": "Reactive_Power", "unit": "kVAR"},
            8: {"value": 6000, "name": "Frequency", "unit": "mHz"},  # 60.00 Hz
            9: {"value": 95, "name": "Power_Factor", "unit": "%"},
        })
        
        # Analog outputs (setpoints)
        self.analog_outputs = config.get("analog_outputs", {
            0: {"value": 13800, "name": "Voltage_Setpoint", "unit": "V"},
            1: {"value": 6000, "name": "Frequency_Setpoint", "unit": "mHz"},
            2: {"value": 5000, "name": "Power_Setpoint", "unit": "kW"},
        })
        
        # Counters (energy meters, pulse counters)
        self.counters = config.get("counters", {
            0: {"value": 123456, "name": "Energy_Import", "unit": "kWh"},
            1: {"value": 45678, "name": "Energy_Export", "unit": "kWh"},
            2: {"value": 9876, "name": "Event_Counter"},
        })
        
        self.device_attributes = {
            "vendor": "Electric Utility Systems",
            "device": "RTU-3000",
            "location": "Substation Alpha",
            "firmware": "v3.2.1"
        }
    
    def get_binary_input(self, index):
        """Get binary input value"""
        if index in self.binary_inputs:
            return self.binary_inputs[index]["value"]
        return False
    
    def get_binary_output(self, index):
        """Get binary output value"""
        if index in self.binary_outputs:
            return self.binary_outputs[index]["value"]
        return False
    
    def set_binary_output(self, index, value):
        """Set binary output value"""
        if index in self.binary_outputs:
            self.binary_outputs[index]["value"] = value
            return True
        return False
    
    def get_analog_input(self, index):
        """Get analog input value"""
        if index in self.analog_inputs:
            # Add small random variation to simulate real measurements
            base = self.analog_inputs[index]["value"]
            variation = random.randint(-10, 10)
            return base + variation
        return 0
    
    def get_analog_output(self, index):
        """Get analog output value"""
        if index in self.analog_outputs:
            return self.analog_outputs[index]["value"]
        return 0
    
    def set_analog_output(self, index, value):
        """Set analog output value"""
        if index in self.analog_outputs:
            self.analog_outputs[index]["value"] = value
            return True
        return False
    
    def get_counter(self, index):
        """Get counter value"""
        if index in self.counters:
            # Increment counter slightly to simulate energy consumption
            self.counters[index]["value"] += random.randint(0, 5)
            return self.counters[index]["value"]
        return 0

class DNP3Session:
    """Handles individual DNP3 sessions"""
    def __init__(self, client_socket, addr, config, logger, utility_device):
        self.socket = client_socket
        self.addr = addr
        self.config = config
        self.logger = logger
        self.utility_device = utility_device
        self.session_log = []
        self.running = False
        self.sequence = 0
    
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
    
    def send_response(self, packet, function_code, data=b''):
        """Send DNP3 response"""
        try:
            response = packet.build_response(function_code, data)
            self.socket.sendall(response)
        except Exception as e:
            self.logger.error(f"Error sending response: {e}")
    
    def parse_object_header(self, data, offset):
        """Parse DNP3 object header"""
        if offset + 3 > len(data):
            return None, offset
        
        group = data[offset]
        variation = data[offset + 1]
        qualifier = data[offset + 2]
        offset += 3
        
        # Parse range based on qualifier
        start_index = 0
        stop_index = 0
        
        if qualifier == 0x00 or qualifier == 0x01:  # Start-stop indices
            if offset + 4 > len(data):
                return None, offset
            start_index = struct.unpack('<H', data[offset:offset+2])[0]
            stop_index = struct.unpack('<H', data[offset+2:offset+4])[0]
            offset += 4
        elif qualifier == 0x06:  # No range field
            pass
        elif qualifier == 0x07 or qualifier == 0x08:  # Quantity
            if offset + 1 > len(data):
                return None, offset
            quantity = data[offset]
            offset += 1
            stop_index = quantity - 1
        
        return {
            "group": group,
            "variation": variation,
            "qualifier": qualifier,
            "start": start_index,
            "stop": stop_index
        }, offset
    
    def handle_read(self, packet):
        """Handle READ request"""
        objects = []
        offset = 0
        
        # Parse all object headers in request
        while offset < len(packet.data):
            obj, offset = self.parse_object_header(packet.data, offset)
            if obj is None:
                break
            objects.append(obj)
        
        self.log_activity("read", {
            "objects": objects
        })
        
        # Build response data
        response_data = b''
        
        for obj in objects:
            group = obj["group"]
            variation = obj["variation"]
            start = obj["start"]
            stop = obj["stop"]
            
            if group == DNP3Packet.BINARY_INPUT:
                # Binary inputs
                response_data += self.build_binary_input_response(start, stop, variation)
            
            elif group == DNP3Packet.BINARY_OUTPUT:
                # Binary outputs (status)
                response_data += self.build_binary_output_response(start, stop)
            
            elif group == DNP3Packet.ANALOG_INPUT:
                # Analog inputs
                response_data += self.build_analog_input_response(start, stop, variation)
            
            elif group == DNP3Packet.ANALOG_OUTPUT:
                # Analog outputs (status)
                response_data += self.build_analog_output_response(start, stop)
            
            elif group == DNP3Packet.COUNTER:
                # Counters
                response_data += self.build_counter_response(start, stop)
            
            elif group == DNP3Packet.CLASS_0_DATA:
                # Class 0 - All static data
                response_data += self.build_class_0_response()
        
        self.send_response(packet, DNP3Packet.RESPONSE, response_data)
    
    def build_binary_input_response(self, start, stop, variation):
        """Build binary input response"""
        data = bytearray()
        
        # Object header
        data.append(DNP3Packet.BINARY_INPUT)
        data.append(0x02)  # Variation 2 (with status)
        data.append(0x00)  # Qualifier: start-stop
        data.extend(struct.pack('<H', start))
        data.extend(struct.pack('<H', stop))
        
        # Data
        for i in range(start, stop + 1):
            value = self.utility_device.get_binary_input(i)
            flags = 0x01 if value else 0x00  # ONLINE flag
            data.append(flags | (0x80 if value else 0x00))  # STATE bit
        
        return bytes(data)
    
    def build_binary_output_response(self, start, stop):
        """Build binary output status response"""
        data = bytearray()
        
        data.append(DNP3Packet.BINARY_OUTPUT)
        data.append(0x02)  # Variation 2
        data.append(0x00)
        data.extend(struct.pack('<H', start))
        data.extend(struct.pack('<H', stop))
        
        for i in range(start, stop + 1):
            value = self.utility_device.get_binary_output(i)
            flags = 0x01 if value else 0x00
            data.append(flags | (0x80 if value else 0x00))
        
        return bytes(data)
    
    def build_analog_input_response(self, start, stop, variation):
        """Build analog input response"""
        data = bytearray()
        
        data.append(DNP3Packet.ANALOG_INPUT)
        data.append(0x01)  # Variation 1 (32-bit with flag)
        data.append(0x00)
        data.extend(struct.pack('<H', start))
        data.extend(struct.pack('<H', stop))
        
        for i in range(start, stop + 1):
            value = self.utility_device.get_analog_input(i)
            flags = 0x01  # ONLINE
            data.append(flags)
            data.extend(struct.pack('<i', value))  # 32-bit signed
        
        return bytes(data)
    
    def build_analog_output_response(self, start, stop):
        """Build analog output status response"""
        data = bytearray()
        
        data.append(DNP3Packet.ANALOG_OUTPUT)
        data.append(0x01)
        data.append(0x00)
        data.extend(struct.pack('<H', start))
        data.extend(struct.pack('<H', stop))
        
        for i in range(start, stop + 1):
            value = self.utility_device.get_analog_output(i)
            flags = 0x01
            data.append(flags)
            data.extend(struct.pack('<i', value))
        
        return bytes(data)
    
    def build_counter_response(self, start, stop):
        """Build counter response"""
        data = bytearray()
        
        data.append(DNP3Packet.COUNTER)
        data.append(0x01)  # 32-bit with flag
        data.append(0x00)
        data.extend(struct.pack('<H', start))
        data.extend(struct.pack('<H', stop))
        
        for i in range(start, stop + 1):
            value = self.utility_device.get_counter(i)
            flags = 0x01
            data.append(flags)
            data.extend(struct.pack('<I', value))  # 32-bit unsigned
        
        return bytes(data)
    
    def build_class_0_response(self):
        """Build Class 0 (all static data) response"""
        data = bytearray()
        
        # Binary inputs
        data.extend(self.build_binary_input_response(0, len(self.utility_device.binary_inputs) - 1, 2))
        
        # Analog inputs
        data.extend(self.build_analog_input_response(0, len(self.utility_device.analog_inputs) - 1, 1))
        
        # Counters
        data.extend(self.build_counter_response(0, len(self.utility_device.counters) - 1))
        
        return bytes(data)
    
    def handle_operate(self, packet, direct=False):
        """Handle OPERATE or DIRECT_OPERATE request"""
        offset = 0
        operations = []
        
        while offset < len(packet.data):
            obj, offset = self.parse_object_header(packet.data, offset)
            if obj is None:
                break
            
            group = obj["group"]
            
            if group == DNP3Packet.BINARY_OUTPUT:
                # Parse CROB (Control Relay Output Block)
                for i in range(obj["start"], obj["stop"] + 1):
                    if offset + 1 > len(packet.data):
                        break
                    
                    control_code = packet.data[offset]
                    offset += 1
                    
                    # Skip count, on-time, off-time
                    offset += 5 if offset + 5 <= len(packet.data) else len(packet.data) - offset
                    
                    # Determine operation
                    operation = (control_code & 0x0F)
                    trip = operation in [0x01, 0x41]  # LATCH_ON
                    close = operation in [0x02, 0x42]  # LATCH_OFF
                    
                    operations.append({
                        "index": i,
                        "operation": operation,
                        "trip": trip,
                        "close": close
                    })
                    
                    # Apply operation
                    if trip:
                        self.utility_device.set_binary_output(i, True)
                    elif close:
                        self.utility_device.set_binary_output(i, False)
        
        self.log_activity("operate" if not direct else "direct_operate", {
            "operations": operations
        })
        
        # Send success response
        self.send_response(packet, DNP3Packet.RESPONSE, b'\x00\x00')  # IIN bits
    
    def handle_write(self, packet):
        """Handle WRITE request"""
        offset = 0
        writes = []
        
        while offset < len(packet.data):
            obj, offset = self.parse_object_header(packet.data, offset)
            if obj is None:
                break
            
            group = obj["group"]
            
            if group == DNP3Packet.ANALOG_OUTPUT:
                for i in range(obj["start"], obj["stop"] + 1):
                    if offset + 5 > len(packet.data):
                        break
                    
                    flags = packet.data[offset]
                    value = struct.unpack('<i', packet.data[offset+1:offset+5])[0]
                    offset += 5
                    
                    writes.append({"index": i, "value": value})
                    self.utility_device.set_analog_output(i, value)
        
        self.log_activity("write", {"writes": writes})
        self.send_response(packet, DNP3Packet.RESPONSE, b'\x00\x00')
    
    def handle_cold_restart(self, packet):
        """Handle COLD_RESTART request"""
        self.log_activity("cold_restart", {"command": "device_restart"})
        
        # Respond with time delay (seconds until restart)
        response_data = struct.pack('<H', 5)  # 5 seconds
        self.send_response(packet, DNP3Packet.RESPONSE, response_data)
    
    def handle_warm_restart(self, packet):
        """Handle WARM_RESTART request"""
        self.log_activity("warm_restart", {"command": "application_restart"})
        
        response_data = struct.pack('<H', 3)  # 3 seconds
        self.send_response(packet, DNP3Packet.RESPONSE, response_data)
    
    def handle_enable_unsolicited(self, packet):
        """Handle ENABLE_UNSOLICITED request"""
        self.log_activity("enable_unsolicited", {"status": "enabled"})
        self.send_response(packet, DNP3Packet.RESPONSE, b'\x00\x00')
    
    def handle_disable_unsolicited(self, packet):
        """Handle DISABLE_UNSOLICITED request"""
        self.log_activity("disable_unsolicited", {"status": "disabled"})
        self.send_response(packet, DNP3Packet.RESPONSE, b'\x00\x00')
    
    def handle(self):
        """Main session handler"""
        self.running = True
        self.log_activity("connection", "DNP3 client connected")
        
        try:
            while self.running:
                data = self.socket.recv(4096)
                if not data:
                    break
                
                packet = DNP3Packet.parse(data)
                if not packet:
                    continue
                
                self.log_activity("request", {
                    "src": packet.src,
                    "dest": packet.dest,
                    "function_code": packet.function_code,
                    "data_length": len(packet.data)
                })
                
                # Route by function code
                if packet.function_code == DNP3Packet.READ:
                    self.handle_read(packet)
                
                elif packet.function_code == DNP3Packet.WRITE:
                    self.handle_write(packet)
                
                elif packet.function_code == DNP3Packet.OPERATE:
                    self.handle_operate(packet, direct=False)
                
                elif packet.function_code == DNP3Packet.DIRECT_OPERATE:
                    self.handle_operate(packet, direct=True)
                
                elif packet.function_code == DNP3Packet.DIRECT_OPERATE_NR:
                    self.handle_operate(packet, direct=True)
                
                elif packet.function_code == DNP3Packet.COLD_RESTART:
                    self.handle_cold_restart(packet)
                
                elif packet.function_code == DNP3Packet.WARM_RESTART:
                    self.handle_warm_restart(packet)
                
                elif packet.function_code == DNP3Packet.ENABLE_UNSOLICITED:
                    self.handle_enable_unsolicited(packet)
                
                elif packet.function_code == DNP3Packet.DISABLE_UNSOLICITED:
                    self.handle_disable_unsolicited(packet)
                
                else:
                    self.log_activity("unsupported_function", {
                        "function_code": packet.function_code
                    })
        
        except Exception as e:
            self.logger.error(f"Session error: {e}")
        
        finally:
            self.running = False
            self.log_activity("disconnect", "Session ended")
            self.save_session_log()
            self.socket.close()
    
    def save_session_log(self):
        """Save session log to file"""
        # UPDATED: use ../logs by default and create parents
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

class DNP3Honeypot:
    """Main DNP3 honeypot server"""
    def __init__(self, config_file="../configs/dnp3.json"):
        self.load_config(config_file)
        self.setup_logging()
        self.utility_device = UtilityDevice(self.config)
        self.running = False
    
    def load_config(self, config_file):
        """Load configuration from file"""
        default_config = {
            "host": "0.0.0.0",
            "port": 20000,
            "device_name": "Substation RTU",
            # UPDATED: logs path
            "log_directory": "../logs",
            "log_file": "dnp3.logs",
            "binary_inputs": {
                0: {"value": True, "name": "Breaker_CB1_Closed"},
                1: {"value": True, "name": "Breaker_CB2_Closed"},
                2: {"value": False, "name": "Breaker_CB3_Closed"},
                3: {"value": False, "name": "Alarm_OverCurrent"},
                4: {"value": False, "name": "Alarm_UnderVoltage"},
                5: {"value": True, "name": "System_Normal"},
                6: {"value": False, "name": "Emergency_Stop"},
                7: {"value": True, "name": "SCADA_Connected"},
                8: {"value": False, "name": "Generator_Running"},
                9: {"value": True, "name": "Grid_Connected"},
            },
            "binary_outputs": {
                0: {"value": False, "name": "Trip_CB1"},
                1: {"value": False, "name": "Trip_CB2"},
                2: {"value": False, "name": "Close_CB3"},
                3: {"value": False, "name": "Start_Generator"},
                4: {"value": False, "name": "Alarm_Reset"},
            },
            "analog_inputs": {
                0: {"value": 13800, "name": "Voltage_L1", "unit": "V"},
                1: {"value": 13750, "name": "Voltage_L2", "unit": "V"},
                2: {"value": 13820, "name": "Voltage_L3", "unit": "V"},
                3: {"value": 245, "name": "Current_L1", "unit": "A"},
                4: {"value": 238, "name": "Current_L2", "unit": "A"},
                5: {"value": 251, "name": "Current_L3", "unit": "A"},
                6: {"value": 5985, "name": "Active_Power", "unit": "kW"},
                7: {"value": 1250, "name": "Reactive_Power", "unit": "kVAR"},
                8: {"value": 6000, "name": "Frequency", "unit": "mHz"},
                9: {"value": 95, "name": "Power_Factor", "unit": "%"},
            },
            "analog_outputs": {
                0: {"value": 13800, "name": "Voltage_Setpoint", "unit": "V"},
                1: {"value": 6000, "name": "Frequency_Setpoint", "unit": "mHz"},
                2: {"value": 5000, "name": "Power_Setpoint", "unit": "kW"},
            },
            "counters": {
                0: {"value": 123456, "name": "Energy_Import", "unit": "kWh"},
                1: {"value": 45678, "name": "Energy_Export", "unit": "kWh"},
                2: {"value": 9876, "name": "Event_Counter"},
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
        # UPDATED: use ../logs and parents=True
        log_dir = Path(self.config.get("log_directory", "../logs"))
        log_dir.mkdir(exist_ok=True, parents=True)
        
        log_file = log_dir / self.config.get("log_file", "dnp3.logs")
        
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
        session = DNP3Session(client_socket, addr, self.config, self.logger, self.utility_device)
        try:
            session.handle()
        except Exception as e:
            self.logger.error(f"Error handling client {addr}: {e}")
    
    def start(self):
        """Start the DNP3 honeypot server"""
        self.running = True
        host = self.config.get("host", "0.0.0.0")
        port = self.config.get("port", 20000)
        
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(5)

        log_dir = Path(self.config.get("log_directory", "../logs"))
        log_file = log_dir / self.config.get("log_file", "dnp3.logs")
        
        self.logger.info(f"DNP3 honeypot started on {host}:{port}")
        print(f"DNP3 honeypot listening on {host}:{port}")
        print(f"Logs will be saved to: {log_file}")
        
        print("\n" + "="*70)
        print("SIMULATED ELECTRIC UTILITY SCADA DEVICE (DNP3)")
        print("="*70)
        
        print("\nBinary Inputs (Status Points):")
        for idx, point in sorted(self.utility_device.binary_inputs.items())[:10]:
            status = "CLOSED/ON" if point["value"] else "OPEN/OFF"
            print(f"  BI {idx:3d}: {point['name']:30s} [{status}]")
        
        print("\nBinary Outputs (Control Points):")
        for idx, point in sorted(self.utility_device.binary_outputs.items()):
            status = "ACTIVE" if point["value"] else "INACTIVE"
            print(f"  BO {idx:3d}: {point['name']:30s} [{status}]")
        
        print("\nAnalog Inputs (Measurements):")
        for idx, point in sorted(self.utility_device.analog_inputs.items())[:10]:
            unit = point.get("unit", "")
            print(f"  AI {idx:3d}: {point['name']:30s} = {point['value']:8d} {unit}")
        
        print("\nAnalog Outputs (Setpoints):")
        for idx, point in sorted(self.utility_device.analog_outputs.items()):
            unit = point.get("unit", "")
            print(f"  AO {idx:3d}: {point['name']:30s} = {point['value']:8d} {unit}")
        
        print("\nCounters (Energy Meters):")
        for idx, point in sorted(self.utility_device.counters.items()):
            unit = point.get("unit", "")
            print(f"  CNT {idx:3d}: {point['name']:30s} = {point['value']:8d} {unit}")
        
        print("\n" + "="*70)
        print("Test with OpenDNP3 or pydnp3:")
        print(f"  Master address: 1")
        print(f"  Outstation address: 10")
        print(f"  Port: {port}")
        print("="*70)
        print("\nPress Ctrl+C to stop\n")
        
        try:
            while self.running:
                client_socket, addr = server.accept()
                self.logger.info(f"New DNP3 connection from {addr[0]}:{addr[1]}")
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, addr)
                )
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            print("\nShutting down DNP3 honeypot...")
            self.logger.info("DNP3 honeypot shutting down")
        finally:
            server.close()

if __name__ == "__main__":
    honeypot = DNP3Honeypot("../configs/dnp3.json")
    honeypot.start()
