import socket
import threading
import time
from utils.logger import Logger
from utils.icmtcp_tunnel import ICMTCPTunnel
import argparse

DEFAULT_TCP_LISTEN_PORT = 1704
LOCALHOST_IP = "0.0.0.0"
TCP_PACKET_SIZE = 4096
DEFAULT_CLIENT_TIMEOUT = 100  # seconds

logger = Logger(__name__)

class ICMTCPClient:
    def __init__(self, tunnel_ip, dest_address, dest_port, tcp_listen_port=DEFAULT_TCP_LISTEN_PORT):
        """! The constructor for ICMTCPClient class.
        @param tunnel_ip The IP address of the ICMTCP server.
        @param dest_address The final destination IP address for the TCP data.
        @param dest_port The final destination port for the TCP data.
        @param tcp_listen_port The local TCP port to listen on for incoming connections.
        """
        self.tcp_listen_port = tcp_listen_port
        self.dest_address = dest_address
        self.dest_port = dest_port
        self.client_timeout = DEFAULT_CLIENT_TIMEOUT
        self.tcp_server_socket = self.create_tcp_server_socket(
            LOCALHOST_IP, tcp_listen_port
        )
        self.icmp_tunnel = ICMTCPTunnel(tunnel_ip)
        self.client_tcp_connection = None
        self.connection_lock = threading.Lock()

    @staticmethod
    def create_tcp_server_socket(ip: str, port: int) -> int:
        """!
        @brief Creates and binds a TCP server socket.
        @param ip The IP address to bind the socket to.
        @param port The port number to bind the socket to.
        @return The bound TCP server socket.
        @exception e Raises an exception on socket creation or binding failure.
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
    
    def _handle_tcp_connection(self, client_socket: int, client_address: tuple[str, int]) -> None:
        """!
        @brief Handles an individual TCP connection from a local client.
        @param client_socket The socket object for the client connection.
        @param client_address The address of the connected client.
        """
        try:
            with self.connection_lock:
                if self.client_tcp_connection is not None:
                    logger.error(f"Rejecting new connection from {client_address} as one is already active.")
                    client_socket.close()
                    return
                self.client_tcp_connection = client_socket
                logger.info(f"Accepted connection from {client_address}")

            while True:
                data = client_socket.recv(TCP_PACKET_SIZE)
                if data:
                    logger.debug(f"Received data from tcp socket: {data}")
                    self.icmp_tunnel.send_tcp_data(data, self.dest_address, self.dest_port)
                else:
                    logger.info(f"Connection closed by client {client_address} (received empty data).")
                    break
        
        except socket.timeout:
            logger.error("Client connection timed out, closing connection")
        
        except Exception as e:
            logger.error(f"Error handling TCP connection: {e}")
        
        finally:
            client_socket.close()
            with self.connection_lock:
                self.client_tcp_connection = None
            logger.info(f"Client socket from address {client_address} closed")
    
    def _tcp_to_tunnel_worker(self) -> None:
        """!
        @brief Worker thread function to accept TCP connections and forward data to the ICMP tunnel.
        
        This method listens for incoming local TCP connections and spawns a new thread to
          handle each one.
        """
        self.tcp_server_socket.listen(5)
        logger.info(f"TCP server listening on {LOCALHOST_IP}:{self.tcp_listen_port}")

        while True:
            client_socket, client_address = self.tcp_server_socket.accept()
            client_socket.settimeout(self.client_timeout)
            threading.Thread(target=self._handle_tcp_connection, args=(client_socket, client_address,), daemon=True).start()

    def _tunnel_to_tcp_worker(self) -> None:
        """!
        @brief Worker thread function to forward data from the ICMP tunnel to the local TCP connection.
        
        This method checks for reconstructed TCP packets from the tunnel and sends them to the 
            active local TCP client.
        """
        while True:
            while self.icmp_tunnel.recieved_tcp_packets:
                tcp_data, _, _ = self.icmp_tunnel.recieved_tcp_packets.pop(0)
                with self.connection_lock:
                    if self.client_tcp_connection:
                        self.client_tcp_connection.sendall(tcp_data)
                        logger.debug(f"Sent {len(tcp_data)} bytes to client through tcp connection.")
                    else:
                        logger.warning("Received data from tunnel, but no local TCP clients are connected.")
            time.sleep(0.1)
    
    def start(self) -> None:
        """!
        @brief Starts the ICMTCP client and its worker threads.
        
        Initializes and starts the ICMP tunnel thread, the TCP-to-tunnel worker,
        and the tunnel-to-TCP worker.
        """
        try:
            tcp_to_tunnel_thread = threading.Thread(target=self._tcp_to_tunnel_worker, daemon=True)
            tunnel_to_tcp_thread = threading.Thread(target=self._tunnel_to_tcp_worker, daemon=True)
            tunnel_thread = threading.Thread(target=self.icmp_tunnel.run, daemon=True)
            tcp_to_tunnel_thread.start()
            tunnel_to_tcp_thread.start()
            tunnel_thread.start()
            logger.info("ICMTCP client started")
        except Exception as e:
            logger.error(f"Exception occured in start routine: {e}")

    def close(self) -> None:
        """!
        @brief Shuts down the ICMTCP client and closes all sockets.
        """
        self.tcp_server_socket.close()
        with self.connection_lock:
            if self.client_tcp_connection:
                self.client_tcp_connection.close()
        self.icmp_tunnel.close()
        logger.info("ICMTCP client closed")

def parse_arguments():
    """! @brief Parses command-line arguments for the client. """
    parser = argparse.ArgumentParser(description="ICMTCP Client")
    parser.add_argument("-t", "--tunnel_ip", help="IP address of the ICMTCP tunnel server", required=True)
    parser.add_argument("-d", "--dest_address", help="Destination IP address for TCP data", required=True)
    parser.add_argument("-p", "--dest_port", type=int, help="Destination port for TCP data", required=True)
    parser.add_argument("--tcp_listen_port", type=int, default=DEFAULT_TCP_LISTEN_PORT, help="Local TCP listen port (default: 1704)", required=False)
    parser.add_argument("--client_timeout", type=int, default=DEFAULT_CLIENT_TIMEOUT, help=f"Timeout for inactive client connections in seconds (default: {DEFAULT_CLIENT_TIMEOUT})", required=False)
    return parser.parse_args()

def main():
    args = parse_arguments()
    client = ICMTCPClient(args.tunnel_ip, args.dest_address, args.dest_port, tcp_listen_port=args.tcp_listen_port)
    client.client_timeout = args.client_timeout
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
