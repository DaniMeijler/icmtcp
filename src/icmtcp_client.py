import socket
import threading
import time
from .logger import Logger

DEFAULT_TCP_LISTEN_PORT = 1704
LOCALHOST_IP = "0.0.0.0"

logger = Logger(__name__)

class ICMTCPClient:
    def __init__(self, tunnel_ip, tcp_listen_port=DEFAULT_TCP_LISTEN_PORT):
        self.tunnel_ip = tunnel_ip
        self.tcp_listen_port = tcp_listen_port
        self.tcp_server_socket = self.create_tcp_server_socket(
            LOCALHOST_IP, self.tcp_listen_port
        )

    @staticmethod
    def create_tcp_server_socket(ip, port):
        """Create a TCP server socket bound to the specified IP and port."""
        tcp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_server_socket.bind((ip, port))

        # set option for immediate reuse of the socket
        tcp_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        logger.info(f"TCP server socket created and bound to {ip}:{port}")  
        return tcp_server_socket
    
    def tcp_server_worker(self):
        """Worker function to handle incoming TCP connections."""
        self.tcp_server_socket.listen(5)
        logger.info(f"TCP server listening on {LOCALHOST_IP}:{self.tcp_listen_port}")

        while True:
            client_socket, client_address = self.tcp_server_socket.accept()
            logger.info(f"Accepted connection from {client_address}")
            time.sleep(5)  # Placeholder for actual handling logic
            client_socket.close()
    
    def start(self):
        """Start ICMTCP client"""
        tcp_thread = threading.Thread(target=self.tcp_server_worker, daemon=True)
        tcp_thread.start()
        logger.info("ICMTCP client started")


