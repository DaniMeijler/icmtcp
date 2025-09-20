from icmtcp.packet.ip_packet import IPPacket
import socket

DEFAULT_LISTEN_PORT = 8082
DEFAULT_LISTEN_IP = "0.0.0.0"
DEFAULT_DEST_IP = "127.0.0.1"
DEFAULT_DEST_PORT = 8081
IP_MAX = 65535

class IPConnection(object):
    def __init__(self):
        self.listen_ip = DEFAULT_LISTEN_IP
        self.listen_port = DEFAULT_LISTEN_PORT
        self.sock = 0
        self.recieve_size = IP_MAX

    def open(self) -> None:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except Exception as e:
            print(e)
    
    def close(self) -> None:
        try:
            self.sock.close()
        except Exception as e:
            print(e)

    def send(self, packet: IPPacket) -> None:
        try:
            self.sock.sendto(packet.compile(), (packet.dst_ip, 0))
        except Exception as e:
            print(f"socket error {e}")
    
    def recieve(self) -> IPPacket:
        try:
            recieved = self.sock.recv(self.recieve_size)
        except Exception as e:
            print(f"socket error {e}")
            return None
        
        packet = IPPacket()
        packet.decompile(recieved)
        return packet


