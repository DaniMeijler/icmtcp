from icmtcp.packet.ip_packet import IPPacket
import socket

DEFAULT_LISTEN_IP = "0.0.0.0"
DEFAULT_LISTEN_PORT = 0
DEFAULT_DEST_IP = "127.0.0.1"
DEFAULT_DEST_PORT = 0
IP_MAX = 65535
DEFAULT_TIMEOUT = 5.0

class IPConnection(object):
    def __init__(self):
        self.listen_ip = DEFAULT_LISTEN_IP
        self.listen_port = DEFAULT_LISTEN_PORT
        self.sock = 0
        self.recieve_size = IP_MAX
        self.recieve_timeout = DEFAULT_TIMEOUT

    def open(self) -> None:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            self.sock.bind((self.listen_ip, self.listen_port))
            self.sock.settimeout(self.recieve_timeout)
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
        recieved = self._recieve_packet_raw()
        packet = IPPacket()
        packet.decompile(recieved)
        return packet
    
    def _recieve_packet_raw(self):
        while True:
            try:
                recieved = self.sock.recv(self.recieve_size)
                if self._is_valid_packet(recieved):
                    return recieved 
                
            except Exception as e:
                print(f"socket error {e}")
                return None
            
    def _is_valid_packet(self, raw_data: bytes) -> bool:
        try:
            IPPacket().decompile(raw_data)
            return True
        except Exception as e:
            return False
    
    


