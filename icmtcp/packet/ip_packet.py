from scapy.all import IP, Raw
import socket

class IPPacket(object):
    def __init__(self):
        self.src_ip = ''
        self.dst_ip = ''
        self.payload = ''

    def set(self, src_ip, dst_ip, payload):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.payload = payload

    def compile(self) -> bytes:
        packet = Raw(load=self.payload)
        return bytes(packet)
    
    def decompile(self, raw_bytes: bytes):
        packet = IP(raw_bytes)
        self.src_ip = packet.getlayer('IP').src
        self.dst_ip = packet.getlayer('IP').dst
        self.payload = packet.getlayer('Raw').load

    def send(self, sock: socket.socket) -> None:
        sock.sendto(self.compile(), (self.dst_ip, 0))
