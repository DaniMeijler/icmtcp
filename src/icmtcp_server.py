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
        self.icmp_tunnel = ICMTCPTunnel(tunnel_ip)
        self.active_tcp_connections = {}

    @staticmethod
    def create_tcp_client_socket(ip, port):
        """
        @brief Create a TCP client socket and connect to the specified IP and port.
        @param ip The destination IP address
        @param port The destination port
        @returns The connected TCP client socket"""
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

    def _get_or_create_socket(self, dest_host, dest_port):
        """
        Return an existing socket for (dest_host, dest_port) or create and store a new one.
        """
        key = (dest_host, dest_port)
        tcp_socket = self.active_tcp_connections.get(key)
        if not tcp_socket:
            tcp_socket = self.create_tcp_client_socket(dest_host, dest_port)
            self.active_tcp_connections[key] = tcp_socket
        return tcp_socket

    def _close_and_remove_socket(self, sock):
        """
        Cleanly shutdown and close a socket and remove it from active connections.
        """
        try:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            sock.close()
        except Exception:
            # ignore errors during close
            pass
        finally:
            # Ensure it's removed from tracking
            self.remove_closed_connection(sock)

    def _try_send_with_reconnect(self, tcp_socket, tcp_data, dest_host, dest_port, retries=3, initial_backoff=0.5):
        """
        send data to tcp destination with reconnects if connection is lost.
        """
        success, err = self._send_once(tcp_socket, tcp_data, dest_host, dest_port)
        if success:
            return True

        # Log the original send failure and close/remove the socket
        logger.warning(f"Initial send failed to {dest_host}:{dest_port}: {err}")
        try:
            self._close_and_remove_socket(tcp_socket)
        except Exception:
            pass

        # Attempt to reconnect and resend
        return self._attempt_reconnect_and_resend(dest_host, dest_port, tcp_data, retries=retries, initial_backoff=initial_backoff)

    def _send_once(self, sock, data, dest_host, dest_port):
        """
        Try a single send on sock. Returns (True, None) on success or (False, exception) on failure.
        Only catches BrokenPipeError/ConnectionResetError/OSError as expected send failures.
        """
        try:
            sock.sendall(data)
            logger.info(f"Sent TCP data to {dest_host}:{dest_port}")
            return True, None
        except (BrokenPipeError, ConnectionResetError, OSError) as send_err:
            return False, send_err
        except Exception as e:
            # Unexpected exception - return as failure so caller can decide
            return False, e

    def _attempt_reconnect_and_resend(self, dest_host, dest_port, data, retries=3, initial_backoff=0.5):
        """
        Attempt to reconnect to dest_host:dest_port up to `retries` times.
        resend `data` once after a successful reconnect.

        Returns True on success, False otherwise.
        """
        backoff = initial_backoff
        for i in range(retries):
            try:
                logger.info(f"Reconnecting to {dest_host}:{dest_port} (attempt {i+1}/{retries})")
                new_sock = self.create_tcp_client_socket(dest_host, dest_port)
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

    def tunnel_to_tcp_worker(self):
        """
        @brief Worker function to handle incoming TCP data from ICMP tunnel and forward to TCP sockets.
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

    def find_source_socket_address(self, tcp_socket):
        """
        @brief Find the source address (host, port) for a given TCP socket
        @param tcp_socket The TCP socket to find the source address for
        @returns (host, port) tuple if found, else None"""
        for (host, port), s in self.active_tcp_connections.items():
            if s == tcp_socket:
                return host, port
        return None, None
    
    def remove_closed_connection(self, socket):
        """
        @brief Remove a closed TCP connection from active connections
        @param socket The TCP socket that has been closed
        """
        for (host, port), s in list(self.active_tcp_connections.items()):
            if s == socket:
                del self.active_tcp_connections[(host, port)]
                logger.info(f"Removed closed connection to {host}:{port}")
                return
            
    def send_tcp_data_to_tunnel(self, tcp_data, source_socket):
        """
        @brief Send recieved TCP data to the ICMP tunnel
        @param tcp_data The TCP data to send
        @param source_socket The source TCP socket
        """
        dest_host, dest_port = self.find_source_socket_address(source_socket)
        if dest_host and dest_port:
            logger.info(f"Sending TCP data from {dest_host}:{dest_port} to ICMP tunnel")
            self.icmp_tunnel.send_tcp_data(tcp_data, dest_host, dest_port)
        else:
            logger.error("Source socket address not found, cannot send TCP data to tunnel")

    def tcp_to_tunnel_worker(self):
        """
        @brief Worker function to handle incoming TCP data and forward to ICMP tunnel.
        """
        while True:
            # Log the current state of active connections
            socket_count = len(self.active_tcp_connections)
            if socket_count > 0:
                logger.debug(f"Checking {socket_count} active TCP connections for data")
                sockets_to_check = [sock for sock in self.active_tcp_connections.values()]
                logger.debug(f"Active connections: {[(host, port) for (host, port) in self.active_tcp_connections.keys()]}")
            else:
                time.sleep(0.1) 
                continue

            # Create list of sockets to check
            sockets_to_check = [sock for sock in self.active_tcp_connections.values()]
            logger.debug(f"Waiting on select() for {len(sockets_to_check)} sockets")
            readable_sockets, _, _ = select.select(sockets_to_check, [], [], 1.0)  # 1 second timeout
            
            if readable_sockets:
                logger.debug(f"Found {len(readable_sockets)} readable sockets")
            
            for sock in readable_sockets:
                try:
                    data = sock.recv(TCP_PACKET_SIZE)
                    if data:
                        logger.debug(f"Received {len(data)} bytes from TCP socket")
                        self.send_tcp_data_to_tunnel(data, sock)
                    else:
                        logger.debug("TCP socket closed by remote peer (received empty data)")
                        sock.close()
                        self.remove_closed_connection(sock)

                except Exception as e:
                    logger.error(f"Error handling TCP socket: {e}")

    def run(self):
        """
        @brief Start the ICMTCP server
        """
        tunnel_thread = threading.Thread(target=self.icmp_tunnel.run, daemon=True)
        tcp_to_tunnel_thread = threading.Thread(target=self.tcp_to_tunnel_worker, daemon=True)
        tunnel_to_tcp_thread = threading.Thread(target=self.tunnel_to_tcp_worker, daemon=True)

        tunnel_thread.start()
        tcp_to_tunnel_thread.start()
        tunnel_to_tcp_thread.start()

        logger.info("ICMTCP server started")

    def close(self):
        """
        @brief Close the ICMTCP server and all active connections
        """
        self.icmp_tunnel.close()
        for sock in self.active_tcp_connections.values():
            sock.close()
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