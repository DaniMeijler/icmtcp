import socket
import threading
import time
from .utils.logger import Logger
from .icmtcp_tunnel import ICMTCPTunnel

DEFAULT_TCP_LISTEN_PORT = 1704
LOCALHOST_IP = "0.0.0.0"
TCP_PACKET_SIZE = 4096
CLIENT_TIMEOUT = 10  # seconds

logger = Logger(__name__)

class ICMTCPClient:
    def __init__(self, tunnel_ip, dest_address, dest_port, tcp_listen_port=DEFAULT_TCP_LISTEN_PORT):
        self.tcp_listen_port = tcp_listen_port
        self.dest_address = dest_address
        self.dest_port = dest_port
        self.tcp_server_socket = self.create_tcp_server_socket(
            LOCALHOST_IP, self.tcp_listen_port
        )
        self.icmp_tunnel = ICMTCPTunnel(tunnel_ip)
        self.active_tcp_connections = {}

    @staticmethod
    def create_tcp_server_socket(ip, port):
        """Create a TCP server socket bound to the specified IP and port."""
        try:
            tcp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_server_socket.bind((ip, port))

            # set option for immediate reuse of the socket
            tcp_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            logger.info(f"TCP server socket created and bound to {ip}:{port}")  

        except Exception as e:
            logger.error(f"Failed to create TCP server socket: {e}")
            raise e
        
        return tcp_server_socket
    
    def handle_tcp_connection(self, client_socket, client_address):
        """Handle client TCP session"""
        # Placeholder for handling TCP connection logic
        try:
            self.active_tcp_connections[client_address] = client_socket
            while True:
                data = client_socket.recv(TCP_PACKET_SIZE)
                if data:
                    logger.info(f"Received data: {data}")
                    self.icmp_tunnel.send_tcp_data(data, self.dest_address, self.dest_port)
                else:
                    logger.info("No data received, closing connection")
                    break
        
        except socket.timeout:
            logger.error("Client connection timed out, closing connection")
        
        except Exception as e:
            logger.error(f"Error handling TCP connection: {e}")
        
        finally:
            client_socket.close()
            self.active_tcp_connections.pop(client_address, None)
            logger.info(f"Client socket from address {client_address} closed")
    
    def tcp_to_tunnel_worker(self):
        """Worker function to handle incoming TCP connections."""
        self.tcp_server_socket.listen(5)
        logger.info(f"TCP server listening on {LOCALHOST_IP}:{self.tcp_listen_port}")

        while True:
            client_socket, client_address = self.tcp_server_socket.accept()
            logger.info(f"Accepted connection from {client_address}")
            client_socket.settimeout(CLIENT_TIMEOUT)
            threading.Thread(target=self.handle_tcp_connection, args=(client_socket, client_address,), daemon=True).start()

    def tunnel_to_tcp_worker(self):
        """Worker function to handle incoming ICMP packets and forward to TCP."""
        while True:
            while self.icmp_tunnel.recieved_tcp_packets:
                tcp_data, dest_host, dest_port = self.icmp_tunnel.recieved_tcp_packets.pop(0)
                if (dest_host, dest_port) in self.active_tcp_connections:
                    client_socket = self.active_tcp_connections[(dest_host, dest_port)]
                    client_socket.sendall(tcp_data)
                    logger.info(f"Forwarded TCP data to {dest_host}:{dest_port}")
                else:
                    logger.error(f"No active TCP connection for {dest_host}:{dest_port}")
            time.sleep(0.1)
    
    def start(self):
        """Start ICMTCP client"""
        tcp_to_tunnel_thread = threading.Thread(target=self.tcp_to_tunnel_worker, daemon=True)
        tunnel_to_tcp_thread = threading.Thread(target=self.tunnel_to_tcp_worker, daemon=True)
        tunnel_thread = threading.Thread(target=self.icmp_tunnel.run, daemon=True)
        tcp_to_tunnel_thread.start()
        tunnel_to_tcp_thread.start()
        tunnel_thread.start()
        logger.info("ICMTCP client started")

    def close(self):
        """Close the ICMTCP client"""
        self.tcp_server_socket.close()
        for sock in self.active_tcp_connections.values():
            sock.close()
        self.icmp_tunnel.close()
        logger.info("ICMTCP client closed")


