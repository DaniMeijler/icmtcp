from scapy.all import IP, Raw, Packet
import socket

class IPPacket(object):
    def __init__(self):
        self.src_ip = '0.0.0.0'
        self.dst_ip = ''
        self.payload = ''

    def get_ip_layer(self) -> IP:
        return IP(src=self.src_ip, dst=self.dst_ip)
    
    def get_packet(self) -> Packet:
        return self.get_ip_layer() / Raw(load=self.payload)
    
    def __repr__(self) -> str:
        return self.get_packet().__repr__()

    def set(self, src_ip: str, dst_ip: str, payload: str) -> None:
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.payload = payload

    def compile(self) -> bytes:
        packet = Raw(load=self.payload)
        return bytes(packet)
    
    def decompile(self, raw_bytes: bytes) -> None:
        ip = IP(raw_bytes)
        self.src_ip = ip.getlayer('IP').src
        self.dst_ip = ip.getlayer('IP').dst
        self.payload = ip.getlayer('Raw').load

