from .icmtcp_tunnel import ICMTCPTunnel
from .utils.logger import Logger
import socket
import select

TCP_PACKET_SIZE = 4096

logger = Logger(__name__)

class ICMTCPServer:
    def __init__(self, tunnel_ip):
        self.icmp_tunnel = ICMTCPTunnel(tunnel_ip)
        self.active_tcp_connections = {}

    @staticmethod
    def create_tcp_client_socket(ip, port):
        """Create a TCP client socket connected to the specified IP and port."""
        try:
            tcp_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_client_socket.connect((ip, port))
            logger.info(f"TCP client socket connected to {ip}:{port}")  

        except Exception as e:
            logger.error(f"Failed to create TCP client socket: {e}")
            raise e
        
        return tcp_client_socket

    def tunnel_to_tcp_worker(self):
        """Worker to send received TCP packets to their destinations"""
        while True:
            if self.icmp_tunnel.recieved_tcp_packets:
                tcp_data, dest_host, dest_port = self.icmp_tunnel.recieved_tcp_packets.pop(0)
                try:
                    if (dest_host, dest_port) not in self.active_tcp_connections:
                        tcp_socket = self.create_tcp_client_socket(dest_host, dest_port)
                        self.active_tcp_connections[(dest_host, dest_port)] = tcp_socket
                    else: 
                        tcp_socket = self.active_tcp_connections[(dest_host, dest_port)]

                    tcp_socket.sendall(tcp_data)
                    logger.info(f"Sent TCP data to {dest_host}:{dest_port}")

                except Exception as e:
                    logger.error(f"Failed to send TCP data to {dest_host}:{dest_port}: {e}")

    def find_source_socket_address(self, tcp_socket):
        for (host, port), s in self.active_tcp_connections.items():
            if s == tcp_socket:
                return host, port
        return None, None
    
    def remove_closed_connection(self, socket):
        for (host, port), s in list(self.active_tcp_connections.items()):
            if s == socket:
                del self.active_tcp_connections[(host, port)]
                logger.info(f"Removed closed connection to {host}:{port}")
                return
            
    def send_tcp_data_to_tunnel(self, tcp_data, source_socket):
        """Send TCP data received from a source socket to the ICMP tunnel"""
        dest_host, dest_port = self.find_source_socket_address(source_socket)
        if dest_host and dest_port:
            logger.info(f"Sending TCP data from {dest_host}:{dest_port} to ICMP tunnel")
            self.icmp_tunnel.send_tcp_data(tcp_data, dest_host, dest_port)
        else:
            logger.error("Source socket address not found, cannot send TCP data to tunnel")

    def tcp_to_tunnel_worker(self):
        """Worker to handle incoming TCP connections."""
        while True:
            readable_sockets, _, _ = select.select([sock for sock in self.active_tcp_connections.values()], [], [])
            for sock in readable_sockets:
                try:
                    data = sock.recv(TCP_PACKET_SIZE)
                    if data:
                        self.send_tcp_data_to_tunnel(data, sock)
                    else:
                        sock.close()
                        self.remove_closed_connection(sock)

                except Exception as e:
                    logger.error(f"Error handling TCP socket: {e}")

    def run(self):
        """Start ICMTCP server"""
        tunnel_thread = threading.Thread(target=self.icmp_tunnel.run, daemon=True)
        tcp_to_tunnel_thread = threading.Thread(target=self.tcp_to_tunnel_worker, daemon=True)
        tunnel_to_tcp_thread = threading.Thread(target=self.tunnel_to_tcp_worker, daemon=True)

        tunnel_thread.start()
        tcp_to_tunnel_thread.start()
        tunnel_to_tcp_thread.start()

        logger.info("ICMTCP server started")

    def close(self):
        """Close the ICMTCP server"""
        self.icmp_tunnel.close()
        for sock in self.active_tcp_connections.values():
            sock.close()
        logger.info("ICMTCP server closed")