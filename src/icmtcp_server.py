from utils.icmtcp_tunnel import ICMTCPTunnel
from utils.logger import Logger
import socket
import select
import threading
import argparse
import time

TCP_PACKET_SIZE = 4096

logger = Logger(__name__)

class ICMTCPServer:
    def __init__(self, tunnel_ip):
        """! The constructor for ICMTCPServer class.
        @param tunnel_ip The IP address of the ICMTCP client.
        """
        self.icmp_tunnel = ICMTCPTunnel(tunnel_ip)
        self.active_tcp_connections = {}
        self.connections_lock = threading.Lock()

    @staticmethod
    def create_tcp_client_socket(ip: str, port: int):
        """
        @brief Create and connect a TCP client socket.
        @param ip The destination IP address.
        @param port The destination port.
        @return The connected TCP client socket.
        @exception e Raises an exception on connection failure.
        """
        try:
            tcp_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tcp_client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            tcp_client_socket.connect((ip, port))
            logger.info(f"TCP client socket connected to {ip}:{port}")

        except Exception as e:
            logger.error(f"Failed to create TCP client socket: {e}")
            raise e

        return tcp_client_socket

    def _get_or_create_socket(self, dest_host: str, dest_port: int) -> socket.socket:
        """
        @brief Retrieves an existing TCP socket or creates a new one for a destination.
        @param dest_host The destination host IP address.
        @param dest_port The destination port.
        @return An active socket.socket object for the given destination.
        """
        key = (dest_host, dest_port)
        with self.connections_lock:
            tcp_socket = self.active_tcp_connections.get(key)
            if not tcp_socket:
                tcp_socket = self.create_tcp_client_socket(dest_host, dest_port)
                self.active_tcp_connections[key] = tcp_socket
        return tcp_socket

    def _close_and_remove_socket(self, sock: socket.socket) -> None:
        """
        @brief Cleanly shuts down, closes, and removes a socket from active_connections.
        @param sock The socket.socket object to close.
        """
        try:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            sock.close()
        except Exception:
            pass
        finally:
            self._remove_closed_connection(sock)

    def _try_send_with_reconnect(self, tcp_socket: socket.socket, tcp_data: bytes, 
                                 dest_host: str, dest_port: int, retries=3, initial_backoff=0.5) -> None:
        """
        @brief Attempts to send data, with automatic reconnection and retries on failure.
        @param tcp_socket The target socket for sending data.
        @param tcp_data The bytes to send.
        @param dest_host The destination host, used for reconnecting.
        @param dest_port The destination port, used for reconnecting.
        @param retries The number of times to retry reconnecting.
        @param initial_backoff The initial delay in seconds before the first retry.
        """
        success, err = self._send_once(tcp_socket, tcp_data, dest_host, dest_port)
        if success:
            return True

        logger.warning(f"Initial send failed to {dest_host}:{dest_port}: {err}")
        try:
            self._close_and_remove_socket(tcp_socket)
        except Exception:
            pass

        return self._attempt_reconnect_and_resend(dest_host, dest_port, tcp_data, retries=retries, initial_backoff=initial_backoff)

    def _send_once(self, sock, data, dest_host, dest_port):
        """
        @brief Performs a single attempt to send data over a socket.
        @param sock The socket to send data on.
        @param data The data to send.
        @param dest_host Destination host for logging.
        @param dest_port Destination port for logging.
        @return A tuple (bool, Exception) indicating success or failure with the error.
        """
        try:
            sock.sendall(data)
            logger.info(f"Sent TCP data to {dest_host}:{dest_port}")
            return True, None
        except (BrokenPipeError, ConnectionResetError, OSError) as send_err:
            return False, send_err
        except Exception as e:
            return False, e

    def _attempt_reconnect_and_resend(self, dest_host, dest_port, data, retries=3, initial_backoff=0.5):
        """
        @brief Attempts to reconnect and resend data after a connection failure.
        @param dest_host The destination host to reconnect to.
        @param dest_port The destination port to reconnect to.
        @param data The data to resend after reconnecting.
        @param retries The number of reconnect attempts.
        @param initial_backoff The initial backoff delay for retries.
        @return True if reconnection and resend were successful, False otherwise.
        """
        backoff = initial_backoff
        for i in range(retries):
            try:
                logger.info(f"Reconnecting to {dest_host}:{dest_port} (attempt {i+1}/{retries})")
                new_sock = self.create_tcp_client_socket(dest_host, dest_port)
                with self.connections_lock:
                    self.active_tcp_connections[(dest_host, dest_port)] = new_sock
                new_sock.sendall(data)
                logger.info(f"Resent TCP data to {dest_host}:{dest_port} after reconnect")
                return True
            except Exception as recon_err:
                logger.warning(f"Reconnect attempt {i+1} failed to {dest_host}:{dest_port}: {recon_err}")
                time.sleep(backoff)
                backoff *= 2

        logger.error(f"Failed to send TCP data to {dest_host}:{dest_port} after {retries} reconnect attempts")
        return False

    def _tunnel_to_tcp_worker(self):
        """
        @brief Worker thread function to forward data from the ICMP tunnel to TCP destinations.
        
        This method runs in a loop, taking packets from the ICMP tunnel's receive queue and forwarding them to the appropriate outbound TCP socket.
        """
        while True:
            if self.icmp_tunnel.recieved_tcp_packets:
                tcp_data, dest_host, dest_port = self.icmp_tunnel.recieved_tcp_packets.pop(0)
                try:
                    tcp_socket = self._get_or_create_socket(dest_host, dest_port)
                    success = self._try_send_with_reconnect(tcp_socket, tcp_data, dest_host, dest_port)
                    if not success:
                        logger.warning(f"Dropping packet for {dest_host}:{dest_port} after failed sends")
                except Exception as e:
                    logger.error(f"Failed to send TCP data to {dest_host}:{dest_port}: {e}")

    def _find_source_socket_address(self, tcp_socket):
        """
        @brief Finds the destination address associated with an active TCP socket.
        @param tcp_socket The TCP socket object.
        @return A tuple (host, port) if the socket is found, otherwise (None, None).
        """
        with self.connections_lock:
            for (host, port), s in self.active_tcp_connections.items():
                if s == tcp_socket:
                    return host, port
            return None, None
    
    def _remove_closed_connection(self, socket):
        """
        @brief Removes a closed TCP connection from the active connections dictionary.
        @param socket The closed TCP socket object.
        """
        with self.connections_lock:
            for (host, port), s in list(self.active_tcp_connections.items()):
                if s == socket:
                    del self.active_tcp_connections[(host, port)]
                    logger.info(f"Removed closed connection to {host}:{port}")
                    return
            
    def _send_tcp_data_to_tunnel(self, tcp_data, source_socket):
        """
        @brief Sends received TCP data back to the client through the ICMP tunnel.
        @param tcp_data The TCP data to send.
        @param source_socket The source TCP socket from which the data was read.
        """
        dest_host, dest_port = self._find_source_socket_address(source_socket)
        if dest_host and dest_port:
            logger.info(f"Sending TCP data from {dest_host}:{dest_port} to ICMP tunnel")
            self.icmp_tunnel.send_tcp_data(tcp_data, dest_host, dest_port)
        else:
            logger.error("Source socket address not found, cannot send TCP data to tunnel")

    def _tcp_to_tunnel_worker(self):
        """
        @brief Worker thread function to read data from TCP sockets and forward it to the ICMP tunnel.
        
        This method uses `select` to monitor all active outbound TCP connections for incoming data 
            and sends it back to the client through the tunnel.
        """
        while True:
            with self.connections_lock:
                sockets_to_check = list(self.active_tcp_connections.values())

            if not sockets_to_check:
                time.sleep(0.1) 
                continue

            try:
                readable_sockets, _, _ = select.select(sockets_to_check, [], [], 1.0)
            except ValueError:
                logger.warning("select() error, likely due to a closed socket. Retrying.")
                continue

            if readable_sockets:
                logger.debug(f"Found {len(readable_sockets)} readable sockets")
            
            for sock in readable_sockets:
                try:
                    data = sock.recv(TCP_PACKET_SIZE)
                    if data:
                        logger.debug(f"Received {len(data)} bytes from TCP socket")
                        self._send_tcp_data_to_tunnel(data, sock)
                    else:
                        logger.info("TCP socket closed by remote peer (received empty data)")
                        self._remove_closed_connection(sock)

                except Exception as e:
                    logger.error(f"Error handling TCP socket: {e}")

    def run(self):
        """
        @brief Starts the ICMTCP server and its worker threads.
        
        Initializes and starts the ICMP tunnel thread, the TCP-to-tunnel worker,
             and the tunnel-to-TCP worker.
        """
        tunnel_thread = threading.Thread(target=self.icmp_tunnel.run, daemon=True)
        tcp_to_tunnel_thread = threading.Thread(target=self._tcp_to_tunnel_worker, daemon=True)
        tunnel_to_tcp_thread = threading.Thread(target=self._tunnel_to_tcp_worker, daemon=True)

        tunnel_thread.start()
        tcp_to_tunnel_thread.start()
        tunnel_to_tcp_thread.start()

        logger.info("ICMTCP server started")

    def close(self):
        """
        @brief Shuts down the ICMTCP server and closes all active connections.
        """
        self.icmp_tunnel.close()
        with self.connections_lock:
            for sock in self.active_tcp_connections.values():
                sock.close()
            self.active_tcp_connections.clear()
        logger.info("ICMTCP server closed")

def parse_args():
    parser = argparse.ArgumentParser(description="ICMTCP Server")
    parser.add_argument("-t", "--tunnel_ip", help="IP address of the ICMTCP client", required=True)
    return parser.parse_args()

def main():
    args = parse_args()
    server = ICMTCPServer(args.tunnel_ip)
    try:
        server.run()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down ICMTCP client")
    except Exception as e:
        logger.error(f"Error occured: {e}")
    finally:
        server.close()

if __name__ == '__main__':
    main()