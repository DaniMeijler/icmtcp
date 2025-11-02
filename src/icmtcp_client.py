import socket
import threading
import time
from utils.logger import Logger
from utils.icmtcp_tunnel import ICMTCPTunnel
import argparse

DEFAULT_TCP_LISTEN_PORT = 1704
LOCALHOST_IP = "0.0.0.0"
TCP_PACKET_SIZE = 4096
CLIENT_TIMEOUT = 100  # seconds

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
        self.client_tcp_connection = None

    @staticmethod
    def create_tcp_server_socket(ip, port):
        """
        @brief: Create and bind a TCP server socket
        @param ip: IP address to bind the socket
        @param port: Port number to bind the socket
        @returns: bound TCP server socket
        """
        try:
            tcp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_server_socket.bind((ip, port))

            # set option for immediate reuse of the socket
            tcp_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            logger.debug(f"TCP server socket created and bound to {ip}:{port}")  

        except Exception as e:
            logger.error(f"Failed to create TCP server socket: {e}")
            raise e
        
        return tcp_server_socket
    
    def handle_tcp_connection(self, client_socket, client_address):
        """
        @brief: Handle an individual TCP connection
        @param client_socket: socket object for the client connection
        @param client_address: address of the connected client
        """
        try:
            if self.client_tcp_connection is None:
                self.client_tcp_connection = client_socket
            else:
                logger.error(f"""New unknown client tried to connect from {client_address}
                              while handling active connection.""")
                raise Exception("Multi connection handeling not supported.")

            while True:
                data = client_socket.recv(TCP_PACKET_SIZE)
                if data:
                    logger.debug(f"Received data from tcp socket: {data}")
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
            self.client_tcp_connection = None
            logger.info(f"Client socket from address {client_address} closed")
    
    def tcp_to_tunnel_worker(self):
        """
        @brief: Worker function to accept TCP connections and forward data to ICMP tunnel
        """
        self.tcp_server_socket.listen(5)
        logger.info(f"TCP server listening on {LOCALHOST_IP}:{self.tcp_listen_port}")

        while True:
            client_socket, client_address = self.tcp_server_socket.accept()
            logger.info(f"Accepted connection from {client_address}")
            client_socket.settimeout(CLIENT_TIMEOUT)
            threading.Thread(target=self.handle_tcp_connection, args=(client_socket, client_address,), daemon=True).start()

    def tunnel_to_tcp_worker(self):
        """
        @brief: Worker function to forward received TCP data from ICMP tunnel to local TCP connections
        """
        while True:
            while self.icmp_tunnel.recieved_tcp_packets:
                tcp_data, _, _ = self.icmp_tunnel.recieved_tcp_packets.pop(0)
                if self.client_tcp_connection is not None:
                    self.client_tcp_connection.sendall(tcp_data)
                logger.debug(f"Sent back {len(tcp_data)} bytes to client through tcp connection.")
                logger.debug(f"data sent {tcp_data}")
            time.sleep(0.1)
    
    def start(self):
        """
        @brief: Start ICMTCP client
        """
        try:
            tcp_to_tunnel_thread = threading.Thread(target=self.tcp_to_tunnel_worker, daemon=True)
            tunnel_to_tcp_thread = threading.Thread(target=self.tunnel_to_tcp_worker, daemon=True)
            tunnel_thread = threading.Thread(target=self.icmp_tunnel.run, daemon=True)
            tcp_to_tunnel_thread.start()
            tunnel_to_tcp_thread.start()
            tunnel_thread.start()
            logger.info("ICMTCP client started")
        except Exception as e:
            logger.error(f"Exception occured in start routine: {e}")

    def close(self):
        """
        @brief: Close ICMTCP client
        """
        self.tcp_server_socket.close()
        if self.client_tcp_connection is not None:
            self.client_tcp_connection.close()
        self.icmp_tunnel.close()
        logger.info("ICMTCP client closed")

def parse_arguments():
    parser = argparse.ArgumentParser(description="ICMTCP Client")
    parser.add_argument("-t", "--tunnel_ip", help="IP address of the ICMTCP tunnel server", required=True)
    parser.add_argument("-d", "--dest_address", help="Destination IP address for TCP data", required=True)
    parser.add_argument("-p", "--dest_port", type=int, help="Destination port for TCP data", required=True)
    parser.add_argument("--tcp_listen_port", type=int, default=DEFAULT_TCP_LISTEN_PORT, help="Local TCP listen port (default: 1704)", required=False)
    return parser.parse_args()

def main():
    args = parse_arguments()
    client = ICMTCPClient(args.tunnel_ip, args.dest_address, args.dest_port, tcp_listen_port=args.tcp_listen_port)
    try:
        client.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down ICMTCP client")
    except Exception as e:
        logger.error(f"Error occured in client: {e}")
    finally:
        client.close()

if __name__ == '__main__':
    main()


