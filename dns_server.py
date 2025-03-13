#!/usr/bin/env python3

import socket
import struct
import json
import os

class DNSQuery:
    def __init__(self, data):
        self.data = data
        self.domain = ""
        self.record_type = None

        # Standard DNS query header fields
        self.transaction_id = data[0:2]
        self.flags = data[2:4]

        # Get question section
        question_count = struct.unpack(">H", data[4:6])[0]
        if question_count > 0:
            # Skip header (12 bytes)
            offset = 12

            # Parse question section
            length = data[offset]
            while length != 0:
                self.domain += (
                    data[offset + 1 : offset + 1 + length].decode("utf-8") + "."
                )
                offset += length + 1
                length = data[offset]

            # Remove trailing dot
            self.domain = self.domain[:-1]

            # Get record type (A=1, AAAA=28)
            self.record_type = struct.unpack(">H", data[offset + 1 : offset + 3])[0]

            # Store the question section end point for later use
            self.question_end = (
                offset + 5
            )  # offset + 1 (zero byte) + 2 (type) + 2 (class)

    def is_ipv4_query(self):
        return self.record_type == 1  # A record

    def is_ipv6_query(self):
        return self.record_type == 28  # AAAA record


class DNSServer:
    def __init__(self, config):
        self.config = config
        self.ipv4_answer = config.get("ipv4_answer", "1.2.3.4")
        self.ipv6_answer = config.get("ipv6_answer", "2001:db8::1")

        # DNS response codes
        self.dns_response_codes = {
            "NOERROR": 0,  # No error
            "FORMERR": 1,  # Format error
            "SERVFAIL": 2,  # Server failure
            "NXDOMAIN": 3,  # Non-existent domain
            "NOTIMP": 4,  # Not implemented
            "REFUSED": 5,  # Query refused
        }

        # Sequence counters to track position in the sequences
        self.sequence_positions = {"A": 0, "AAAA": 0}

        # Request sequences from config
        self.request_sequence_a = config.get("request_sequence_a", ["ok"])
        self.request_sequence_aaaa = config.get("request_sequence_aaaa", ["timeout"])

    def create_dns_response(self, query, ip_address):
        """Create a DNS response with the specified IP address"""
        # Copy transaction ID from request
        response = bytearray(query.transaction_id)

        # Set response flags (Standard query response, No error)
        # 0x8180: Response bit (0x8000) + Recursion Available (0x0080) + Recursion Desired (0x0100)
        flags = 0x8180
        response.extend(struct.pack(">H", flags))

        # Question and Answer counts
        response.extend(struct.pack(">H", 1))  # 1 question
        response.extend(struct.pack(">H", 1))  # 1 answer
        response.extend(struct.pack(">H", 0))  # 0 authority
        response.extend(struct.pack(">H", 0))  # 0 additional

        # Original DNS question, copied from query
        # Include the complete original question section
        response.extend(query.data[12 : query.question_end])

        # The answer section starts with a pointer to the domain name in the question section
        response.extend(b"\xc0\x0c")  # Name pointer to domain name in question section

        if query.is_ipv4_query():
            # Type (A record = 1), Class (IN = 1), TTL (300 seconds), Data length (4 bytes for IPv4)
            response.extend(struct.pack(">HHIH", 1, 1, 300, 4))

            # Convert the IPv4 address string to bytes
            for part in ip_address.split("."):
                response.extend(struct.pack("B", int(part)))

        elif query.is_ipv6_query():
            # Type (AAAA record = 28), Class (IN = 1), TTL (300 seconds), Data length (16 bytes for IPv6)
            response.extend(struct.pack(">HHIH", 28, 1, 300, 16))

            # Properly parse and convert the IPv6 address
            ipv6_bytes = self.ipv6_to_bytes(ip_address)
            response.extend(ipv6_bytes)

        return bytes(response)

    def ipv6_to_bytes(self, ipv6_address):
        """Convert an IPv6 address to its binary representation"""
        # Handle compressed IPv6 addresses
        if "::" in ipv6_address:
            # Count existing groups
            parts = ipv6_address.split(":")
            # Filter out empty parts from the split (but keeping the one resulting from ::)
            parts = [p for p in parts if p != ""] + [""]

            # Calculate how many zero groups to insert
            groups_present = len(parts) - 1 if "" in parts else len(parts)
            zeros_needed = 8 - groups_present

            # Expand the :: notation
            expanded = []
            for part in parts:
                if part == "":
                    expanded.extend(["0"] * (zeros_needed + 1))
                else:
                    expanded.append(part)
        else:
            expanded = ipv6_address.split(":")

        # Convert each hexadecimal group to bytes
        result = bytearray()
        for group in expanded[:8]:  # Ensure we only take 8 groups
            value = int(group, 16) if group else 0
            result.extend(struct.pack(">H", value))

        return bytes(result)

    def create_error_response(self, query, error_code):
        """Create a DNS error response with the specified error code"""
        # Copy transaction ID from request
        response = bytearray(query.transaction_id)

        # Set response flags (Standard query response, with error code)
        # 0x8000 = Response bit set
        # 0x0100 = Recursion desired bit (copy from query)
        # Error code in the lower 4 bits
        flags = 0x8000 | (struct.unpack(">H", query.flags)[0] & 0x0100) | error_code
        response.extend(struct.pack(">H", flags))

        # Question and Answer counts (1 question, 0 answers)
        response.extend(struct.pack(">H", 1))  # 1 question
        response.extend(struct.pack(">H", 0))  # 0 answer
        response.extend(struct.pack(">H", 0))  # 0 authority
        response.extend(struct.pack(">H", 0))  # 0 additional

        # Original DNS question, copied from query
        response.extend(query.data[12 : query.question_end])

        return bytes(response)

    def get_next_action(self, record_type):
        """Get the next action based on the record type and sequence"""
        if record_type == "A":
            sequence = self.request_sequence_a
            pos = self.sequence_positions["A"]
            action = sequence[pos % len(sequence)]
            self.sequence_positions["A"] = (pos + 1) % len(sequence)
        else:  # AAAA
            sequence = self.request_sequence_aaaa
            pos = self.sequence_positions["AAAA"]
            action = sequence[pos % len(sequence)]
            self.sequence_positions["AAAA"] = (pos + 1) % len(sequence)

        return action

    def handle_query(self, data, addr, socket):
        """Handle a DNS query"""
        query = DNSQuery(data)

        if query.is_ipv4_query():
            action = self.get_next_action("A")
            record_type = "A"
            ip_answer = self.ipv4_answer
        elif query.is_ipv6_query():
            action = self.get_next_action("AAAA")
            record_type = "AAAA"
            ip_answer = self.ipv6_answer
        else:
            print(
                f"Received unsupported query type {query.record_type} for {query.domain}"
            )
            return

        print(
            f"Received {record_type} query for {query.domain} from {addr[0]}:{addr[1]} - Action: {action}"
        )

        if action == "ok":
            response = self.create_dns_response(query, ip_answer)
            socket.sendto(response, addr)
            print(f"Sent {record_type} response for {query.domain}")
        elif action == "timeout":
            print(f"Simulating timeout for {record_type} query for {query.domain}")
            # Do nothing - packet is dropped
        elif action.upper() in self.dns_response_codes:
            # Send a specific error response based on the code
            error_name = action.upper()
            error_code = self.dns_response_codes[error_name]
            response = self.create_error_response(query, error_code)
            socket.sendto(response, addr)
            print(
                f"Sent {error_name} (code {error_code}) response for {record_type} query for {query.domain}"
            )
        else:
            print(f"Unknown action: {action}, ignoring query")

    def start(self, host="0.0.0.0", port=53):
        """Start the DNS server"""
        try:
            # UDP socket for DNS
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((host, port))
            print(f"DNS server running on {host}:{port}")
            print(f"A query sequence: {self.request_sequence_a}")
            print(f"AAAA query sequence: {self.request_sequence_aaaa}")
            print(f"Default IPv4 answer: {self.ipv4_answer}")
            print(f"Default IPv6 answer: {self.ipv6_answer}")
            print(
                f"Supported error responses: {', '.join(self.dns_response_codes.keys())}"
            )

            while True:
                data, addr = sock.recvfrom(512)
                self.handle_query(data, addr, sock)

        except Exception as e:
            print(f"Error: {e}")
        finally:
            sock.close()


def load_config(config_file="dns_config.json"):
    """Load configuration from JSON file or return default config"""
    default_config = {
        "request_sequence_a": ["ok"],
        "request_sequence_aaaa": ["timeout"],
        "ipv4_answer": "1.2.3.4",
        "ipv6_answer": "2001:db8::1",
        "host": "0.0.0.0",
        "port": 53,
    }

    if os.path.exists(config_file):
        try:
            with open(config_file, "r") as f:
                config = json.load(f)
                # Merge with defaults for any missing keys
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                return config
        except Exception as e:
            print(f"Error loading config file: {e}")
            print("Using default configuration")
            return default_config
    else:
        print(f"Config file {config_file} not found, using default configuration")
        return default_config


if __name__ == "__main__":
    config = load_config()

    print("Starting DNS server with sequence-based responses...")
    print("Note: Running on port 53 requires root/administrator privileges")
    print("To test: dig @localhost -t A example.com")
    print("For AAAA test: dig @localhost -t AAAA example.com")

    # Create sample config file if it doesn't exist
    if not os.path.exists("dns_config.json"):
        sample_config = {
            "request_sequence_a": ["timeout", "ok", "NXDOMAIN", "ok"],
            "request_sequence_aaaa": ["timeout", "SERVFAIL", "ok", "REFUSED"],
            "ipv4_answer": "1.2.3.4",
            "ipv6_answer": "2001:db8::1",
            "host": "0.0.0.0",
            "port": 53,
        }
        with open("dns_config.json", "w") as f:
            json.dump(sample_config, f, indent=4)
            print("Created sample config file: dns_config.json")

    server = DNSServer(config)
    server.start(config["host"], config["port"])
